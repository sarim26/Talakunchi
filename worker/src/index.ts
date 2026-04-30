import { setTimeout as sleep } from "node:timers/promises";
import dns from "node:dns/promises";
import net from "node:net";
import { env } from "./env.js";
import { runAgentScan } from "./agent.js";
import { runExploitAgent } from "./exploit.js";
import { withClient } from "./db.js";
import { withSession } from "./neo4j.js";
import { nmapScan } from "./nmapScan.js";
import { HydraCredSource, hydraFromNmapServices } from "./hydraScan.js";

type PipelineConfig = {
  maxConcurrentScans: number;
  requestRatePerMinute: number;
  auditEnabled: boolean;
  allowedWordlists: string[];
};

const DEFAULT_PIPELINE_CONFIG: PipelineConfig = {
  maxConcurrentScans: 2,
  requestRatePerMinute: 120,
  auditEnabled: true,
  allowedWordlists: []
};

async function ensureCancelColumn() {
  await withClient(async (c) => {
    await c.query(`alter table scan_runs add column if not exists cancel_requested boolean not null default false`);
  });
}

async function claimNextJob(config: PipelineConfig) {
  return await withClient(async (c) => {
    await c.query("begin");
    try {
      const limit = Math.max(1, Number(config.maxConcurrentScans) || 1);
      const runningScansRes = await c.query(
        `select count(*)::int as n
         from scan_runs
         where status = 'running'`
      );
      const runningScans = Number(runningScansRes.rows[0]?.n ?? 0);
      const canStartScan = runningScans < limit;

      const res = await c.query(
        `
        select id, type, payload
        from jobs
        where status = 'queued'
          and ($1::boolean or type <> 'scan')
        order by created_at asc
        for update skip locked
        limit 1
        `,
        [canStartScan]
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

async function ensureWorkflowTables() {
  await withClient(async (c) => {
    await c.query(`
      create table if not exists pipeline_configs (
        id int primary key,
        config jsonb not null,
        updated_at timestamptz not null default now()
      )
    `);
    await c.query(`
      create table if not exists audit_events (
        id uuid primary key default uuid_generate_v4(),
        actor text not null default 'system',
        action text not null,
        target text,
        payload jsonb not null default '{}'::jsonb,
        created_at timestamptz not null default now()
      )
    `);
    await c.query(`create index if not exists idx_audit_events_created_at on audit_events(created_at desc)`);
    await c.query(`
      create table if not exists recon_assets (
        id uuid primary key default uuid_generate_v4(),
        target_id uuid not null references targets(id) on delete cascade,
        asset_type text not null,
        value text not null,
        source text not null,
        confidence int not null default 50,
        metadata jsonb not null default '{}'::jsonb,
        first_seen_at timestamptz not null default now(),
        last_seen_at timestamptz not null default now(),
        unique (target_id, asset_type, value, source)
      )
    `);
    await c.query(`create index if not exists idx_recon_assets_target on recon_assets(target_id)`);

    await c.query(`
      create table if not exists command_approvals (
        id uuid primary key default uuid_generate_v4(),
        scan_run_id uuid not null references scan_runs(id) on delete cascade,
        command text not null,
        reasoning text,
        impact text not null default 'low',
        status text not null default 'pending', -- pending | approved | rejected
        decided_by text,
        created_at timestamptz not null default now(),
        decided_at timestamptz
      )
    `);
    await c.query(`create index if not exists idx_command_approvals_scan_run_id on command_approvals(scan_run_id)`);
    await c.query(`create index if not exists idx_command_approvals_status on command_approvals(status)`);
  });
}

async function upsertReconAsset(input: {
  targetId: string;
  assetType: string;
  value: string;
  source: string;
  confidence: number;
  metadata?: Record<string, unknown>;
}) {
  await withClient(async (c) => {
    await c.query(
      `insert into recon_assets (target_id, asset_type, value, source, confidence, metadata, first_seen_at, last_seen_at)
       values ($1, $2, $3, $4, $5, $6::jsonb, now(), now())
       on conflict (target_id, asset_type, value, source)
       do update set confidence = excluded.confidence, metadata = excluded.metadata, last_seen_at = now()`,
      [
        input.targetId,
        input.assetType,
        input.value,
        input.source,
        input.confidence,
        JSON.stringify(input.metadata ?? {})
      ]
    );
  });
}

async function runReconnaissance(targetId: string, targetAddress: string, stepId: string) {
  let found = 0;
  const isIpTarget = net.isIP(targetAddress) !== 0;

  await appendStepLog(stepId, `Recon start: ${targetAddress}\n`);

  if (isIpTarget) {
    await upsertReconAsset({
      targetId,
      assetType: "host",
      value: targetAddress,
      source: "host_discovery",
      confidence: 95,
      metadata: { reachable: true, method: "seed_target" }
    });
    found += 1;
    try {
      const ptr = await dns.reverse(targetAddress);
      for (const hostname of ptr.slice(0, 5)) {
        await upsertReconAsset({
          targetId,
          assetType: "hostname",
          value: hostname,
          source: "reverse_dns",
          confidence: 70,
          metadata: { ip: targetAddress }
        });
        found += 1;
      }
    } catch {
      await appendStepLog(stepId, "Reverse DNS: no PTR records\n");
    }
  } else {
    try {
      const lookup = await dns.lookup(targetAddress, { all: true });
      for (const rec of lookup.slice(0, 10)) {
        await upsertReconAsset({
          targetId,
          assetType: "ip",
          value: rec.address,
          source: "dns_lookup",
          confidence: 80,
          metadata: { family: rec.family, hostname: targetAddress }
        });
        found += 1;
      }
    } catch {
      await appendStepLog(stepId, "DNS lookup failed or no records\n");
    }
  }

  // Phase 2 MVP: placeholder passive OSINT signal for pipeline wiring.
  await upsertReconAsset({
    targetId,
    assetType: "osint_signal",
    value: targetAddress,
    source: "osint_stub",
    confidence: 40,
    metadata: { provider: "stub", note: "integrate Shodan/Censys connectors in next iteration" }
  });
  found += 1;

  await appendStepLog(stepId, `Recon complete. Assets discovered/updated: ${found}\n`);
  return found;
}

async function getPipelineConfig() {
  return withClient(async (c) => {
    const res = await c.query(`select config from pipeline_configs where id = 1`);
    const cfg = res.rows[0]?.config as PipelineConfig | undefined;
    if (cfg) return { ...DEFAULT_PIPELINE_CONFIG, ...cfg };
    await c.query(
      `insert into pipeline_configs (id, config, updated_at)
       values (1, $1::jsonb, now())
       on conflict (id) do update set config = excluded.config, updated_at = now()`,
      [JSON.stringify(DEFAULT_PIPELINE_CONFIG)]
    );
    return DEFAULT_PIPELINE_CONFIG;
  });
}

async function writeAuditEvent(action: string, payload: Record<string, unknown>, target?: string) {
  const cfg = await getPipelineConfig();
  if (!cfg.auditEnabled) return;
  await withClient(async (c) => {
    await c.query(
      `insert into audit_events (actor, action, target, payload) values ($1, $2, $3, $4::jsonb)`,
      ["worker", action, target ?? null, JSON.stringify(payload)]
    );
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

  const pipelineConfig = await getPipelineConfig();
  await writeAuditEvent("scan.started", { scanRunId, targetId: ctx.target_id, profile: ctx.profile }, ctx.target_address);

  await withClient(async (c) => {
    await c.query(`update scan_runs set status='running', started_at=now() where id=$1`, [scanRunId]);
    await c.query(
      `insert into scan_steps (scan_run_id, name, status, started_at)
       values ($1, 'Reconnaissance', 'running', now()),
              ($1, 'Discovery', 'queued', null),
              ($1, 'Service Identification', 'queued', null),
              ($1, 'Checks & Findings', 'queued', null)`,
      [scanRunId]
    );
  });

  const reconStepId = await withClient(async (c) => {
    const res = await c.query(
      `select id from scan_steps where scan_run_id=$1 and name='Reconnaissance' order by created_at asc limit 1`,
      [scanRunId]
    );
    return res.rows[0].id as string;
  });
  const reconCount = await runReconnaissance(ctx.target_id, ctx.target_address, reconStepId);
  await withClient(async (c) => {
    await c.query(`update scan_steps set status='succeeded', finished_at=now(), log=log || $2 where id=$1`, [
      reconStepId,
      `Recon assets: ${reconCount}\n`
    ]);
    const d = await c.query(
      `select id from scan_steps where scan_run_id=$1 and name='Discovery' order by created_at asc limit 1`,
      [scanRunId]
    );
    await c.query(`update scan_steps set status='running', started_at=now() where id=$1`, [d.rows[0].id]);
  });

  const discoveryStepId = await withClient(async (c) => {
    const res = await c.query(
      `select id from scan_steps where scan_run_id=$1 and name='Discovery' order by created_at asc limit 1`,
      [scanRunId]
    );
    return res.rows[0].id as string;
  });

  const nmapCmd = `nmap ${env.NMAP_ARGS} -oX <tempfile> ${ctx.target_address}`;
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

  const services = scanOut.services
    .filter((s: any) => s.state === "open")
    .map((s: any) => ({
    port: s.port,
    protocol: s.protocol,
    serviceName: s.serviceName,
    product: s.product,
    version: s.version,
    banner: s.banner
    }));

  if (scanOut.status === "down") {
    await appendStepLog(discoveryStepId, `Host appears down from Nmap output: ${scanOut.host}\n`);
  }

  let findings = deriveFindingsFromObserved(ctx.target_address, services);

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

  if (env.HYDRA_ENABLED) {
    const hydraCredSource = buildHydraCredSource();
    if (!hydraCredSource) {
      const step3 = await withClient(async (c) => {
        const res = await c.query(
          `select id from scan_steps where scan_run_id=$1 and name='Checks & Findings' order by created_at asc limit 1`,
          [scanRunId]
        );
        return res.rows[0]?.id as string;
      });
      if (step3) {
        await appendStepLog(
          step3,
          "Hydra enabled but credential source is incomplete. Set HYDRA_USERNAME/HYDRA_USERLIST and HYDRA_PASSWORD/HYDRA_PASSLIST.\n"
        );
      }
    } else {
      const hydraOutput: string[] = [];
      try {
        const hydraResults = await hydraFromNmapServices(ctx.target_address, services, hydraCredSource, {
          threads: env.HYDRA_THREADS,
          stopOnFirstFind: env.HYDRA_STOP_ON_FIRST_FIND,
          timeoutMs: env.HYDRA_TIMEOUT_MS,
          signal: ac.signal,
          onOutput: (line) => {
            hydraOutput.push(line);
          }
        });

        const step3 = await withClient(async (c) => {
          const res = await c.query(
            `select id from scan_steps where scan_run_id=$1 and name='Checks & Findings' order by created_at asc limit 1`,
            [scanRunId]
          );
          return res.rows[0]?.id as string;
        });
        if (step3 && hydraOutput.length) {
          await appendStepLog(step3, hydraOutput.join(""));
        }

        const hydraCreds = hydraResults.flatMap((r) => r.credentials);
        findings = findings.concat(deriveFindingsFromHydra(hydraCreds));
      } catch (e: any) {
        const step3 = await withClient(async (c) => {
          const res = await c.query(
            `select id from scan_steps where scan_run_id=$1 and name='Checks & Findings' order by created_at asc limit 1`,
            [scanRunId]
          );
          return res.rows[0]?.id as string;
        });
        if (step3) {
          await appendStepLog(step3, `Hydra phase skipped due to error: ${e?.message ?? String(e)}\n`);
        }
      }
    }
  }

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
  await writeAuditEvent("scan.completed", { scanRunId, findings: findings.length, services: services.length }, ctx.target_address);

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

function maskSecret(value: string) {
  if (!value) return "";
  if (value.length <= 2) return "*".repeat(value.length);
  return `${value[0]}${"*".repeat(Math.max(1, value.length - 2))}${value[value.length - 1]}`;
}


function deriveFindingsFromHydra(
  credentials: Array<{
    host: string;
    port: number;
    service: string;
    username: string;
    password: string;
  }>
) {
  const mk = (key: string) => `fp:${key}`;
  return credentials.map((cred) => ({
    title: `Weak/default credentials accepted on ${cred.service} (${cred.port})`,
    severity: "high" as const,
    servicePort: cred.port,
    evidenceRedacted: `Hydra reported valid login on ${cred.host}:${cred.port}/${cred.service} with username "${cred.username}" and password "${maskSecret(cred.password)}".`,
    fingerprint: mk(`${cred.host}|${cred.port}|${cred.service}|hydra|${cred.username}`)
  }));
}

function buildHydraCredSource(): HydraCredSource | null {
  const username = env.HYDRA_USERNAME?.trim();
  const password = env.HYDRA_PASSWORD?.trim();
  const userList = env.HYDRA_USERLIST?.trim();
  const passList = env.HYDRA_PASSLIST?.trim();

  const usernameSource = username ? { username } : userList ? { userList } : null;
  const passwordSource = password ? { password } : passList ? { passwordList: passList } : null;
  if (!usernameSource || !passwordSource) return null;

  return { ...usernameSource, ...passwordSource } as HydraCredSource;
}

function shouldUseAgentMode() {
  if (!env.GEMINI_API_KEY) return false;
  return env.AGENT_ENABLED || env.SCAN_MODE === "agent";
}

function buildAgentOpts(config: PipelineConfig) {
  if (!env.GEMINI_API_KEY) {
    throw new Error("GEMINI_API_KEY is required when AGENT_ENABLED=true or SCAN_MODE=agent");
  }
  const preferredWordlist = config.allowedWordlists.find((w) => w.trim().length > 0);

  return {
    geminiApiKey: env.GEMINI_API_KEY,
    geminiModel: env.GEMINI_MODEL,
    maxSteps: env.AGENT_MAX_STEPS,
    cmdTimeoutMs: env.AGENT_CMD_TIMEOUT_MS,
    installTimeoutMs: env.AGENT_INSTALL_TIMEOUT_MS,
    whitelist: [] as string[],
    wordlistPath: preferredWordlist ?? env.HYDRA_PASSLIST
  };
}

function buildAgentWhitelist(targetAddress: string) {
  return [...new Set([
    targetAddress,
    ...env.AGENT_SCOPE.split(",").map((entry) => entry.trim()).filter(Boolean)
  ])];
}

function shouldAutoExploit() {
  return env.EXPLOIT_ENABLED && Boolean(env.GEMINI_API_KEY);
}

function buildExploitOpts(config: PipelineConfig) {
  if (!env.GEMINI_API_KEY) {
    throw new Error("GEMINI_API_KEY is required when EXPLOIT_ENABLED=true");
  }
  const preferredWordlist = config.allowedWordlists.find((w) => w.trim().length > 0);
  return {
    geminiApiKey: env.GEMINI_API_KEY,
    geminiModel: env.GEMINI_MODEL,
    maxSteps: env.EXPLOIT_MAX_STEPS,
    cmdTimeoutMs: env.EXPLOIT_CMD_TIMEOUT_MS,
    installTimeoutMs: env.EXPLOIT_INSTALL_TIMEOUT_MS,
    whitelist: [] as string[],
    wordlistPath: preferredWordlist ?? env.HYDRA_PASSLIST,
    lhostAllowList: env.EXPLOIT_LHOST_ALLOWLIST
      ? env.EXPLOIT_LHOST_ALLOWLIST.split(",").map((s) => s.trim()).filter(Boolean)
      : undefined
  };
}

async function targetHasServices(scanRunId: string) {
  return await withClient(async (c) => {
    const res = await c.query(
      `select 1
       from services s
       join scan_runs sr on sr.target_id = s.target_id
       where sr.id = $1
       limit 1`,
      [scanRunId]
    );
    return res.rows.length > 0;
  });
}

async function enqueueExploitJob(scanRunId: string) {
  await withClient(async (c) => {
    await c.query(
      `insert into jobs (type, status, payload)
       values ('exploit', 'queued', $1::jsonb)`,
      [JSON.stringify({ scanRunId })]
    );
  });
}

async function maybeEnqueueExploit(scanRunId: string) {
  if (!shouldAutoExploit()) return;
  try {
    if (!(await targetHasServices(scanRunId))) {
      await writeAuditEvent("exploit.auto.skipped", { scanRunId, reason: "no services" });
      return;
    }
    await enqueueExploitJob(scanRunId);
    await writeAuditEvent("exploit.auto.queued", { scanRunId });
  } catch (e: any) {
    console.error("[worker] failed to enqueue exploit job", e?.message ?? e);
  }
}

let lastScanStartAtMs = 0;
async function enforceScanRate(config: PipelineConfig) {
  const rpm = Math.max(1, Number(config.requestRatePerMinute) || 1);
  const minGapMs = Math.ceil(60_000 / rpm);
  const waitMs = minGapMs - (Date.now() - lastScanStartAtMs);
  if (waitMs > 0) await sleep(waitMs);
  lastScanStartAtMs = Date.now();
}

async function main() {
  await ensureWorkflowTables();
  await getPipelineConfig();
  console.log(`[worker] starting (mode=${env.SCAN_MODE})`);
  if ((env.AGENT_ENABLED || env.SCAN_MODE === "agent") && !env.GEMINI_API_KEY) {
    console.warn("[worker] AGENT mode requested but GEMINI_API_KEY is missing; falling back to deterministic scan mode.");
  }
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const pipelineConfig = await getPipelineConfig();
    const job = await claimNextJob(pipelineConfig);
    if (!job) {
      await sleep(env.POLL_INTERVAL_MS);
      continue;
    }

    try {
      if (job.type === "scan") {
        const scanRunId = job.payload.scanRunId as string;
        await enforceScanRate(pipelineConfig);
        if (shouldUseAgentMode()) {
          const runCtx = await withClient(async (c) => {
            const res = await c.query(
              `select t.address as target_address
               from scan_runs sr
               join targets t on t.id = sr.target_id
               where sr.id = $1`,
              [scanRunId]
            );
            return res.rows[0] as { target_address: string };
          });
          const agentOpts = buildAgentOpts(pipelineConfig);
          agentOpts.whitelist = buildAgentWhitelist(runCtx.target_address);
          await runAgentScan(scanRunId, agentOpts);
        } else {
          await runScan(scanRunId);
        }
        await maybeEnqueueExploit(scanRunId);
      } else if (job.type === "exploit") {
        const scanRunId = job.payload.scanRunId as string;
        const runCtx = await withClient(async (c) => {
          const res = await c.query(
            `select t.address as target_address
             from scan_runs sr
             join targets t on t.id = sr.target_id
             where sr.id = $1`,
            [scanRunId]
          );
          return res.rows[0] as { target_address: string } | undefined;
        });
        if (!runCtx) throw new Error(`exploit job: scan run ${scanRunId} not found`);
        const exploitOpts = buildExploitOpts(pipelineConfig);
        exploitOpts.whitelist = buildAgentWhitelist(runCtx.target_address);
        await runExploitAgent(scanRunId, exploitOpts);
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

