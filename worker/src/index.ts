import { setTimeout as sleep } from "node:timers/promises";
import { env } from "./env.js";
import { withClient } from "./db.js";
import { withSession } from "./neo4j.js";
import { nmapScan } from "./nmapScan.js";

async function ensureCancelColumn() {
  await withClient(async (c) => {
    await c.query(`alter table scan_runs add column if not exists cancel_requested boolean not null default false`);
  });
}

async function claimNextJob() {
  return await withClient(async (c) => {
    await c.query("begin");
    try {
      const res = await c.query(
        `
        select id, type, payload
        from jobs
        where status = 'queued'
        order by created_at asc
        for update skip locked
        limit 1
        `
      );
      const job = res.rows[0];
      if (!job) {
        await c.query("commit");
        return null;
      }
      await c.query(`update jobs set status = 'running', updated_at = now() where id = $1`, [job.id]);
      await c.query("commit");
      return job as { id: string; type: string; payload: any };
    } catch (e) {
      await c.query("rollback");
      throw e;
    }
  });
}

async function setJobDone(jobId: string, ok: boolean, error?: string) {
  await withClient(async (c) => {
    await c.query(
      `update jobs set status = $2, error = $3, updated_at = now() where id = $1`,
      [jobId, ok ? "succeeded" : "failed", error ?? null]
    );
  });
}

async function upsertNeo4jTarget(target: { id: string; name: string; address: string }) {
  await withSession(async (s) => {
    await s.run(
      `
      merge (t:Target {id: $id})
      set t.name = $name, t.address = $address
      return t
      `,
      { id: target.id, name: target.name, address: target.address }
    );
  });
}

async function rebuildNeo4jForTarget(targetId: string) {
  // For prototype simplicity: rebuild relationships from Postgres state.
  const data = await withClient(async (c) => {
    const tRes = await c.query(`select id, name, address from targets where id = $1`, [targetId]);
    const sRes = await c.query(
      `select id, port, protocol, service_name, product, version from services where target_id = $1`,
      [targetId]
    );
    const fRes = await c.query(
      `select id, service_id, title, severity, status from findings where target_id = $1`,
      [targetId]
    );
    return { target: tRes.rows[0], services: sRes.rows, findings: fRes.rows };
  });

  await withSession(async (s) => {
    await s.run(
      `merge (t:Target {id: $id}) set t.name=$name, t.address=$address`,
      { id: data.target.id, name: data.target.name, address: data.target.address }
    );

    for (const svc of data.services) {
      await s.run(
        `
        merge (svc:Service {id: $id})
        set svc.port=$port, svc.protocol=$protocol, svc.name=$name, svc.product=$product, svc.version=$version
        with svc
        match (t:Target {id: $targetId})
        merge (t)-[:HAS_SERVICE]->(svc)
        `,
        {
          id: svc.id,
          targetId,
          port: svc.port,
          protocol: svc.protocol,
          name: svc.service_name ?? "",
          product: svc.product ?? "",
          version: svc.version ?? ""
        }
      );
    }

    for (const f of data.findings) {
      await s.run(
        `
        merge (f:Finding {id: $id})
        set f.title=$title, f.severity=$severity, f.status=$status
        `,
        { id: f.id, title: f.title, severity: f.severity, status: f.status }
      );

      if (f.service_id) {
        await s.run(
          `
          match (svc:Service {id: $svcId})
          match (f:Finding {id: $findingId})
          merge (svc)-[:HAS_FINDING]->(f)
          `,
          { svcId: f.service_id, findingId: f.id }
        );
      }
    }
  });
}

async function runScan(scanRunId: string) {
  await ensureCancelColumn();
  const ctx = await withClient(async (c) => {
    const runRes = await c.query(
      `select sr.id, sr.target_id, sr.profile, t.name as target_name, t.address as target_address
       from scan_runs sr
       join targets t on t.id = sr.target_id
       where sr.id = $1`,
      [scanRunId]
    );
    return runRes.rows[0] as {
      id: string;
      target_id: string;
      profile: string;
      target_name: string;
      target_address: string;
    };
  });

  await withClient(async (c) => {
    await c.query(`update scan_runs set status='running', started_at=now() where id=$1`, [scanRunId]);
    await c.query(
      `insert into scan_steps (scan_run_id, name, status, started_at)
       values ($1, 'Discovery', 'running', now()),
              ($1, 'Service Identification', 'queued', null),
              ($1, 'Checks & Findings', 'queued', null)`,
      [scanRunId]
    );
  });

  const discoveryStepId = await withClient(async (c) => {
    const res = await c.query(
      `select id from scan_steps where scan_run_id=$1 and name='Discovery' order by created_at asc limit 1`,
      [scanRunId]
    );
    return res.rows[0].id as string;
  });

  const nmapCmd = `nmap ${env.NMAP_ARGS} -oX /tmp/nmap.xml ${ctx.target_address}`;
  await appendStepLog(discoveryStepId, `Running: ${nmapCmd}\n`);

  const ac = new AbortController();
  const cancelPoll = setInterval(async () => {
    const cancelRequested = await withClient(async (c) => {
      const res = await c.query(`select cancel_requested from scan_runs where id=$1`, [scanRunId]);
      return Boolean(res.rows?.[0]?.cancel_requested);
    });
    if (cancelRequested) {
      await appendStepLog(discoveryStepId, "\nCancel requested. Stopping scan...\n");
      ac.abort();
    }
  }, 1000);

  let buffer = "";
  let lastFlush = Date.now();
  const flushIfNeeded = async (force = false) => {
    const now = Date.now();
    if (!force && now - lastFlush < 1500) return;
    if (!buffer) return;
    const out = buffer;
    buffer = "";
    lastFlush = now;
    await appendStepLog(discoveryStepId, out);
  };

  let scanOut: Awaited<ReturnType<typeof nmapScan>> | null = null;
  try {
    scanOut = await nmapScan(ctx.target_address, env.NMAP_ARGS, {
      onOutput: (chunk) => {
        buffer += chunk;
      },
      signal: ac.signal
    });
  } catch (e: any) {
    await flushIfNeeded(true);
    clearInterval(cancelPoll);

    const isCancelled = String(e?.message ?? "").toLowerCase().includes("aborted");
    await withClient(async (c) => {
      await c.query(`update scan_steps set status='failed', finished_at=now(), log=log || $2 where id=$1`, [
        discoveryStepId,
        isCancelled ? "\nScan cancelled.\n" : `\nScan failed: ${e?.message ?? String(e)}\n`
      ]);
      await c.query(`update scan_runs set status='failed', finished_at=now() where id=$1`, [scanRunId]);
    });
    throw e;
  } finally {
    clearInterval(cancelPoll);
    await flushIfNeeded(true);
  }

  if (!scanOut) throw new Error("Scan produced no output");

  const services = scanOut.services.map((s: any) => ({
    port: s.port,
    protocol: s.protocol,
    serviceName: s.serviceName,
    product: s.product,
    version: s.version,
    banner: s.banner
  }));

  const findings =
    deriveFindingsFromObserved(ctx.target_address, scanOut.services);

  // Step 1 finish
  await withClient(async (c) => {
    await c.query(`update scan_steps set status='succeeded', finished_at=now() where id=$1`, [discoveryStepId]);
    const step2 = await c.query(
      `select id from scan_steps where scan_run_id=$1 and name='Service Identification' order by created_at asc limit 1`,
      [scanRunId]
    );
    await c.query(`update scan_steps set status='running', started_at=now() where id=$1`, [step2.rows[0].id]);
  });

  await sleep(500);

  // Upsert services
  const serviceIdByPort = new Map<number, string>();
  await withClient(async (c) => {
    for (const s of services) {
      const res = await c.query(
        `
        insert into services (target_id, port, protocol, service_name, product, version, banner, first_seen_at, last_seen_at)
        values ($1, $2, $3, $4, $5, $6, $7, now(), now())
        on conflict (target_id, port, protocol)
        do update set service_name=excluded.service_name, product=excluded.product, version=excluded.version, banner=excluded.banner, last_seen_at=now()
        returning id
        `,
        [ctx.target_id, s.port, s.protocol, s.serviceName ?? null, s.product ?? null, s.version ?? null, s.banner ?? null]
      );
      serviceIdByPort.set(s.port, res.rows[0].id);
    }
  });

  // Step 2 finish, Step 3 start
  await withClient(async (c) => {
    const step2 = await c.query(
      `select id from scan_steps where scan_run_id=$1 and name='Service Identification' order by created_at asc limit 1`,
      [scanRunId]
    );
    await c.query(
      `update scan_steps set status='succeeded', finished_at=now(), log=log || $2 where id=$1`,
      [step2.rows[0].id, `Identified ${services.length} services\n`]
    );

    const step3 = await c.query(
      `select id from scan_steps where scan_run_id=$1 and name='Checks & Findings' order by created_at asc limit 1`,
      [scanRunId]
    );
    await c.query(`update scan_steps set status='running', started_at=now() where id=$1`, [step3.rows[0].id]);
  });

  await sleep(500);

  // Upsert findings
  await withClient(async (c) => {
    for (const f of findings) {
      const svcId = f.servicePort ? serviceIdByPort.get(f.servicePort) : undefined;
      await c.query(
        `
        insert into findings (target_id, service_id, title, severity, status, fingerprint, evidence_redacted, first_seen_at, last_seen_at, last_scan_run_id)
        values ($1, $2, $3, $4, 'open', $5, $6, now(), now(), $7)
        on conflict (fingerprint)
        do update set last_seen_at=now(), evidence_redacted=excluded.evidence_redacted, last_scan_run_id=excluded.last_scan_run_id
        `,
        [ctx.target_id, svcId ?? null, f.title, f.severity, f.fingerprint, f.evidenceRedacted, scanRunId]
      );
    }
  });

  await withClient(async (c) => {
    const step3 = await c.query(
      `select id from scan_steps where scan_run_id=$1 and name='Checks & Findings' order by created_at asc limit 1`,
      [scanRunId]
    );
    await c.query(
      `update scan_steps set status='succeeded', finished_at=now(), log=log || $2 where id=$1`,
      [step3.rows[0].id, `Created/updated ${findings.length} findings\n`]
    );
    await c.query(`update scan_runs set status='succeeded', finished_at=now() where id=$1`, [scanRunId]);
  });

  // Neo4j graph (demo wow)
  await upsertNeo4jTarget({ id: ctx.target_id, name: ctx.target_name, address: ctx.target_address });
  await rebuildNeo4jForTarget(ctx.target_id);
}

async function appendStepLog(stepId: string, text: string) {
  await withClient(async (c) => {
    await c.query(`update scan_steps set log = log || $2 where id = $1`, [stepId, text]);
  });
}

function deriveFindingsFromObserved(
  targetAddress: string,
  services: Array<{ port: number; protocol: string; serviceName?: string; product?: string; version?: string }>
) {
  // Deterministic "service exposure" findings for every open port, plus special policy findings.
  const mk = (key: string) => `fp:${key}`;

  const severityForPort = (port: number) => {
    // Demo-friendly baseline (tune later / replace with AI suggestions).
    if ([3389, 445].includes(port)) return "medium" as const;
    if ([5985, 5986, 22].includes(port)) return "low" as const;
    if ([80].includes(port)) return "low" as const;
    if ([443].includes(port)) return "info" as const;
    if ([21, 23, 25, 110, 139].includes(port)) return "medium" as const;
    return "info" as const;
  };

  const out: Array<{
    title: string;
    severity: "info" | "low" | "medium" | "high" | "critical";
    servicePort?: number;
    evidenceRedacted: string;
    fingerprint: string;
  }> = [];

  for (const s of services) {
    const label = [s.serviceName, s.product, s.version].filter(Boolean).join(" ").trim();
    out.push({
      title: `Open service exposure: ${s.port}/${s.protocol}${label ? ` (${label})` : ""}`,
      severity: severityForPort(s.port),
      servicePort: s.port,
      evidenceRedacted: `Observed open port ${s.port}/${s.protocol} on ${targetAddress}. Service: ${label || "unknown"}.`,
      fingerprint: mk(`${targetAddress}|${s.protocol}|${s.port}|exposure|${s.serviceName ?? ""}|${s.product ?? ""}|${s.version ?? ""}`)
    });
  }

  // Keep explicit policy findings (these are the ones you'd pitch as "violations")
  if (services.some((s) => s.protocol === "tcp" && s.port === 445)) {
    out.push({
      title: "Policy: SMB exposed on host",
      severity: "medium",
      servicePort: 445,
      evidenceRedacted: `Observed open port 445/tcp on ${targetAddress}. Restrict SMB to required subnets only.`,
      fingerprint: mk(`${targetAddress}|tcp|445|policy:smb-exposed`)
    });
  }

  if (services.some((s) => s.protocol === "tcp" && s.port === 3389)) {
    out.push({
      title: "Policy: RDP exposed on host",
      severity: "medium",
      servicePort: 3389,
      evidenceRedacted: `Observed open port 3389/tcp on ${targetAddress}. Restrict RDP to admin subnet/jumpbox and enforce MFA.`,
      fingerprint: mk(`${targetAddress}|tcp|3389|policy:rdp-exposed`)
    });
  }

  if (services.some((s) => s.protocol === "tcp" && (s.port === 5985 || s.port === 5986))) {
    out.push({
      title: "Policy: WinRM reachable (review access controls)",
      severity: "low",
      servicePort: services.some((s) => s.port === 5986) ? 5986 : 5985,
      evidenceRedacted: `Observed WinRM port open on ${targetAddress}. Ensure it is restricted and logged.`,
      fingerprint: mk(`${targetAddress}|tcp|5985-5986|policy:winrm-reachable`)
    });
  }

  return out;
}

async function main() {
  console.log(`[worker] starting (mode=${env.SCAN_MODE})`);
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const job = await claimNextJob();
    if (!job) {
      await sleep(env.POLL_INTERVAL_MS);
      continue;
    }

    try {
      if (job.type === "scan") {
        const scanRunId = job.payload.scanRunId as string;
        await runScan(scanRunId);
      } else {
        throw new Error(`Unknown job type: ${job.type}`);
      }
      await setJobDone(job.id, true);
    } catch (e: any) {
      await setJobDone(job.id, false, e?.message ?? String(e));
    }
  }
}

await main();

