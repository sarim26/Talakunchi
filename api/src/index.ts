import Fastify from "fastify";
import cors from "@fastify/cors";
import { z } from "zod";
import { env } from "./env.js";
import { withClient } from "./db.js";
import { withSession } from "./neo4j.js";
import { CreateScanSchema, CreateTargetSchema, PipelineConfigSchema, UpdateFindingSchema } from "./schemas.js";
import { explainWithOllama, generateAgentRunReportWithOllama, listOllamaModels, summariseAgentRunWithOllama } from "./llm/ollama.js";

const app = Fastify({ logger: true });

type PipelineConfig = z.infer<typeof PipelineConfigSchema>;

const DEFAULT_PIPELINE_CONFIG: PipelineConfig = {
  maxConcurrentScans: 2,
  requestRatePerMinute: 120,
  auditEnabled: true,
  // Prefer Kali-provided SecLists by default.
  allowedWordlists: ["/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt"]
};

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

    await c.query(`
      create table if not exists scan_messages (
        id uuid primary key default uuid_generate_v4(),
        scan_run_id uuid not null references scan_runs(id) on delete cascade,
        role text not null, -- user | assistant | system
        content text not null,
        created_at timestamptz not null default now()
      )
    `);
    await c.query(`create index if not exists idx_scan_messages_run on scan_messages(scan_run_id, created_at asc)`);
  });
}

async function getPipelineConfig() {
  return withClient(async (c) => {
    const res = await c.query(`select config from pipeline_configs where id = 1`);
    const parsed = PipelineConfigSchema.safeParse(res.rows[0]?.config);
    if (parsed.success) {
      const merged = { ...DEFAULT_PIPELINE_CONFIG, ...parsed.data };
      if (!Array.isArray(parsed.data.allowedWordlists) || parsed.data.allowedWordlists.length === 0) {
        merged.allowedWordlists = DEFAULT_PIPELINE_CONFIG.allowedWordlists;
      }
      return merged;
    }
    await c.query(
      `insert into pipeline_configs (id, config, updated_at)
       values (1, $1::jsonb, now())
       on conflict (id) do update set config = excluded.config, updated_at = now()`,
      [JSON.stringify(DEFAULT_PIPELINE_CONFIG)]
    );
    return DEFAULT_PIPELINE_CONFIG;
  });
}

async function putPipelineConfig(input: PipelineConfig) {
  const parsed = PipelineConfigSchema.parse(input);
  await withClient(async (c) => {
    await c.query(
      `insert into pipeline_configs (id, config, updated_at)
       values (1, $1::jsonb, now())
       on conflict (id) do update set config = excluded.config, updated_at = now()`,
      [JSON.stringify(parsed)]
    );
  });
  return parsed;
}

async function writeAuditEvent(action: string, payload: Record<string, unknown>, target?: string, actor = "api") {
  const cfg = await getPipelineConfig();
  if (!cfg.auditEnabled) return;
  await withClient(async (c) => {
    await c.query(
      `insert into audit_events (actor, action, target, payload) values ($1, $2, $3, $4::jsonb)`,
      [actor, action, target ?? null, JSON.stringify(payload)]
    );
  });
}

// Minimal error helpers (avoid extra plugin in prototype)
app.setErrorHandler((err, _req, reply) => {
  if ((err as any)?.statusCode) {
    reply.status((err as any).statusCode).send({ error: (err as any).message });
    return;
  }
  const msg = err instanceof Error ? err.message : String(err);
  reply.status(500).send({ error: msg });
});

await app.register(cors, {
  origin: true
});

app.get("/health", async () => ({ ok: true }));

app.get("/api/pipeline/config", async () => {
  return getPipelineConfig();
});

app.put("/api/pipeline/config", async (req) => {
  const body = PipelineConfigSchema.parse(req.body);
  const config = await putPipelineConfig(body);
  await writeAuditEvent("pipeline.config.updated", { config }, undefined, "operator");
  return config;
});

app.get("/api/audit-events", async (req) => {
  const q = req.query as any;
  const limit = q.limit ? Math.min(500, Math.max(1, Number(q.limit))) : 100;
  const rows = await withClient(async (c) => {
    const res = await c.query(
      `select id, actor, action, target, payload, created_at
       from audit_events
       order by created_at desc
       limit $1`,
      [limit]
    );
    return res.rows;
  });
  return rows.map((r) => ({
    id: r.id,
    actor: r.actor,
    action: r.action,
    target: r.target,
    payload: r.payload ?? {},
    createdAt: r.created_at
  }));
});

// --- Demo admin: reset database (two-step confirmation) ---
const resetState: { code: string | null; expiresAt: number } = { code: null, expiresAt: 0 };
function newResetCode() {
  const code = Math.random().toString(36).slice(2, 8).toUpperCase();
  resetState.code = code;
  resetState.expiresAt = Date.now() + 2 * 60 * 1000;
  return code;
}

app.post("/api/admin/reset/request", async (_req, reply) => {
  const code = newResetCode();
  return reply.send({ code, expiresInSeconds: 120 });
});

app.post("/api/admin/reset/confirm", async (req, reply) => {
  const body = z.object({ code: z.string().min(1) }).parse(req.body);
  if (!resetState.code || Date.now() > resetState.expiresAt) {
    return reply.code(400).send({ error: "Reset code expired. Request a new one." });
  }
  if (body.code.trim().toUpperCase() !== resetState.code) {
    return reply.code(400).send({ error: "Reset code mismatch." });
  }

  // Wipe Postgres tables (demo only)
  await withClient(async (c) => {
    await c.query("begin");
    try {
      await c.query("truncate table finding_events restart identity cascade");
      await c.query("truncate table findings restart identity cascade");
      await c.query("truncate table services restart identity cascade");
      await c.query("truncate table scan_steps restart identity cascade");
      await c.query("truncate table scan_runs restart identity cascade");
      await c.query("truncate table jobs restart identity cascade");
      await c.query("truncate table targets restart identity cascade");
      await c.query("truncate table audit_events restart identity cascade");
      await c.query(`do $$ begin
        if exists (select 1 from information_schema.tables where table_name='agent_events') then
          execute 'truncate table agent_events restart identity cascade';
        end if;
        if exists (select 1 from information_schema.tables where table_name='agent_invocations') then
          execute 'truncate table agent_invocations restart identity cascade';
        end if;
        if exists (select 1 from information_schema.tables where table_name='agent_runs') then
          execute 'truncate table agent_runs restart identity cascade';
        end if;
      end $$`);
      await c.query("commit");
    } catch (e) {
      await c.query("rollback");
      throw e;
    }
  });

  // Wipe Neo4j (demo only)
  await withSession(async (s) => {
    await s.run("match (n) detach delete n");
  });

  resetState.code = null;
  resetState.expiresAt = 0;
  return reply.send({ ok: true });
});

app.get("/api/ai/models", async (_req, reply) => {
  try {
    const models = await listOllamaModels();
    return reply.send({ provider: "ollama", url: env.OLLAMA_URL, models });
  } catch (err) {
    return reply.code(502).send({ provider: "ollama", url: env.OLLAMA_URL, error: (err as Error).message });
  }
});

app.post("/api/targets", async (req, reply) => {
  const body = CreateTargetSchema.parse(req.body);
  const row = await withClient(async (c) => {
    const res = await c.query(
      `insert into targets (name, address, tags, owner)
       values ($1, $2, $3, $4)
       returning id, name, address, tags, owner, created_at`,
      [body.name, body.address, body.tags, body.owner ?? null]
    );
    return res.rows[0];
  });

  await writeAuditEvent(
    "target.created",
    { id: row.id, name: row.name, address: row.address, tags: row.tags },
    row.address,
    "operator"
  );

  return reply.code(201).send({
    id: row.id,
    name: row.name,
    address: row.address,
    tags: row.tags,
    owner: row.owner,
    createdAt: row.created_at
  });
});

app.get("/api/targets", async () => {
  const rows = await withClient(async (c) => {
    const res = await c.query(
      `select id, name, address, tags, owner, created_at
       from targets
       order by created_at desc`
    );
    return res.rows;
  });
  return rows.map((r) => ({
    id: r.id,
    name: r.name,
    address: r.address,
    tags: r.tags,
    owner: r.owner,
    createdAt: r.created_at
  }));
});

app.get("/api/services", async (req) => {
  const q = req.query as any;
  const targetId = q.targetId ? z.string().uuid().parse(q.targetId) : undefined;
  if (!targetId) return [];

  const rows = await withClient(async (c) => {
    const res = await c.query(
      `select id, target_id, port, protocol, service_name, product, version, banner, first_seen_at, last_seen_at
       from services
       where target_id = $1
       order by port asc`,
      [targetId]
    );
    return res.rows;
  });
  return rows.map((r) => ({
    id: r.id,
    targetId: r.target_id,
    port: r.port,
    protocol: r.protocol,
    serviceName: r.service_name ?? null,
    product: r.product ?? null,
    version: r.version ?? null,
    banner: r.banner ?? null,
    firstSeenAt: r.first_seen_at,
    lastSeenAt: r.last_seen_at
  }));
});

app.get("/api/recon-assets", async (req) => {
  const q = req.query as any;
  const targetId = q.targetId ? z.string().uuid().parse(q.targetId) : undefined;
  if (!targetId) return [];

  const rows = await withClient(async (c) => {
    const res = await c.query(
      `select id, target_id, asset_type, value, source, confidence, metadata, first_seen_at, last_seen_at
       from recon_assets
       where target_id = $1
       order by last_seen_at desc`,
      [targetId]
    );
    return res.rows;
  });
  return rows.map((r) => ({
    id: r.id,
    targetId: r.target_id,
    assetType: r.asset_type,
    value: r.value,
    source: r.source,
    confidence: r.confidence,
    metadata: r.metadata ?? {},
    firstSeenAt: r.first_seen_at,
    lastSeenAt: r.last_seen_at
  }));
});

app.post("/api/scans", async (req, reply) => {
  const body = CreateScanSchema.parse(req.body);
  const target = await withClient(async (c) => {
    const res = await c.query(`select id, address from targets where id = $1`, [body.targetId]);
    return res.rows[0] as { id: string; address: string } | undefined;
  });
  if (!target) return reply.code(404).send({ error: "Target not found" });

  const scanRun = await withClient(async (c) => {
    await c.query("begin");
    try {
      const runRes = await c.query(
        `insert into scan_runs (target_id, profile, status, requested_by)
         values ($1, $2, 'queued', $3)
         returning id, target_id, profile, status, requested_by, created_at`,
        [body.targetId, body.profile, body.requestedBy]
      );
      const run = runRes.rows[0];

      await c.query(
        `insert into jobs (type, status, payload)
         values ('scan', 'queued', $1::jsonb)`,
        [
          JSON.stringify({
            scanRunId: run.id
          })
        ]
      );

      await c.query("commit");
      return run;
    } catch (e) {
      await c.query("rollback");
      throw e;
    }
  });

  await writeAuditEvent(
    "scan.queued",
    { scanRunId: scanRun.id, targetId: scanRun.target_id, profile: scanRun.profile },
    target.address,
    "operator"
  );

  return reply.code(202).send({
    id: scanRun.id,
    targetId: scanRun.target_id,
    profile: scanRun.profile,
    status: scanRun.status,
    requestedBy: scanRun.requested_by,
    createdAt: scanRun.created_at
  });
});

async function ensureCancelColumn() {
  await withClient(async (c) => {
    await c.query(`alter table scan_runs add column if not exists cancel_requested boolean not null default false`);
  });
}

await ensureCancelColumn();
await ensureWorkflowTables();
await getPipelineConfig();

app.post("/api/scans/:id/cancel", async (req, reply) => {
  const scanRunId = z.string().uuid().parse((req.params as any).id);
  await withClient(async (c) => {
    await c.query(`update scan_runs set cancel_requested = true where id = $1`, [scanRunId]);
    // If the scan hasn't started yet, also mark queued job as failed so worker never starts it.
    await c.query(
      `update jobs set status='failed', error='cancelled before start', updated_at=now()
       where type='scan' and status='queued' and payload->>'scanRunId' = $1`,
      [scanRunId]
    );
  });
  await writeAuditEvent("scan.cancel_requested", { scanRunId }, undefined, "operator");
  return reply.send({ ok: true });
});

app.get("/api/scans/:id/messages", async (req) => {
  const scanRunId = z.string().uuid().parse((req.params as any).id);
  const rows = await withClient(async (c) => {
    const res = await c.query(
      `select id, role, content, created_at
       from scan_messages
       where scan_run_id = $1
       order by created_at asc
       limit 200`,
      [scanRunId]
    );
    return res.rows;
  });
  return rows.map((r) => ({ id: r.id, role: r.role, content: r.content, createdAt: r.created_at }));
});

app.post("/api/scans/:id/messages", async (req, reply) => {
  const scanRunId = z.string().uuid().parse((req.params as any).id);
  const body = z
    .object({
      role: z.enum(["user", "assistant", "system"]).default("user"),
      content: z.string().min(1).max(8000),
      /** If true, queue a new scan job that continues using message context. */
      resume: z.coerce.boolean().optional().default(false)
    })
    .parse(req.body ?? {});

  const inserted = await withClient(async (c) => {
    await c.query("begin");
    try {
      const ins = await c.query(
        `insert into scan_messages (scan_run_id, role, content)
         values ($1, $2, $3)
         returning id, role, content, created_at`,
        [scanRunId, body.role, body.content]
      );

      if (body.resume) {
        // Reset run status so worker can pick it up again.
        await c.query(
          `update scan_runs
           set status='queued', cancel_requested=false, finished_at=null
           where id=$1`,
          [scanRunId]
        );
        await c.query(
          `insert into jobs (type, status, payload)
           values ('scan', 'queued', $1::jsonb)`,
          [JSON.stringify({ scanRunId, resume: true })]
        );
      }

      await c.query("commit");
      return ins.rows[0] as { id: string; role: string; content: string; created_at: any };
    } catch (e) {
      await c.query("rollback");
      throw e;
    }
  });

  await writeAuditEvent(
    "scan.message",
    { scanRunId, role: inserted.role, resumeQueued: body.resume },
    undefined,
    "operator"
  );

  return reply.send({ id: inserted.id, role: inserted.role, content: inserted.content, createdAt: inserted.created_at });
});

app.post("/api/scans/:id/resume", async (req, reply) => {
  const scanRunId = z.string().uuid().parse((req.params as any).id);
  const body = z
    .object({
      note: z.string().optional()
    })
    .parse(req.body ?? {});

  await withClient(async (c) => {
    await c.query("begin");
    try {
      if (body.note?.trim()) {
        await c.query(
          `insert into scan_messages (scan_run_id, role, content) values ($1, 'user', $2)`,
          [scanRunId, body.note.trim()]
        );
      }
      await c.query(
        `update scan_runs set status='queued', cancel_requested=false, finished_at=null where id=$1`,
        [scanRunId]
      );
      await c.query(
        `insert into jobs (type, status, payload) values ('scan', 'queued', $1::jsonb)`,
        [JSON.stringify({ scanRunId, resume: true })]
      );
      await c.query("commit");
    } catch (e) {
      await c.query("rollback");
      throw e;
    }
  });

  await writeAuditEvent("scan.resume_queued", { scanRunId }, undefined, "operator");
  return reply.send({ ok: true });
});

app.get("/api/scans", async () => {
  const rows = await withClient(async (c) => {
    const res = await c.query(
      `select sr.id, sr.target_id, t.name as target_name, t.address as target_address,
              sr.profile, sr.status, sr.requested_by, sr.started_at, sr.finished_at, sr.created_at
       from scan_runs sr
       join targets t on t.id = sr.target_id
       order by sr.created_at desc
       limit 50`
    );
    return res.rows;
  });
  return rows.map((r) => ({
    id: r.id,
    targetId: r.target_id,
    target: { name: r.target_name, address: r.target_address },
    profile: r.profile,
    status: r.status,
    requestedBy: r.requested_by,
    startedAt: r.started_at,
    finishedAt: r.finished_at,
    createdAt: r.created_at
  }));
});

app.get("/api/scans/:id", async (req) => {
  const scanRunId = z.string().uuid().parse((req.params as any).id);

  const result = await withClient(async (c) => {
    const runRes = await c.query(
      `select sr.id, sr.target_id, t.name as target_name, t.address as target_address,
              sr.profile, sr.status, sr.requested_by, sr.started_at, sr.finished_at, sr.created_at
       from scan_runs sr
       join targets t on t.id = sr.target_id
       where sr.id = $1`,
      [scanRunId]
    );
    const run = runRes.rows[0];
    const stepsRes = await c.query(
      `select id, name, status, started_at, finished_at, log, created_at
       from scan_steps
       where scan_run_id = $1
       order by created_at asc`,
      [scanRunId]
    );
    return { run, steps: stepsRes.rows };
  });

  return {
    id: result.run.id,
    targetId: result.run.target_id,
    target: { name: result.run.target_name, address: result.run.target_address },
    profile: result.run.profile,
    status: result.run.status,
    requestedBy: result.run.requested_by,
    startedAt: result.run.started_at,
    finishedAt: result.run.finished_at,
    createdAt: result.run.created_at,
    steps: result.steps.map((s) => ({
      id: s.id,
      name: s.name,
      status: s.status,
      startedAt: s.started_at,
      finishedAt: s.finished_at,
      log: s.log,
      createdAt: s.created_at
    }))
  };
});

// Make sure verification columns/table exist on legacy databases.
async function ensureFindingVerificationSchema() {
  await withClient(async (c) => {
    await c.query(`alter table findings add column if not exists confidence text not null default 'medium'`);
    await c.query(`alter table findings add column if not exists requires_verification boolean not null default true`);
    await c.query(`alter table findings add column if not exists claim_type text`);
    await c.query(`
      create table if not exists finding_evidence (
        id uuid primary key default uuid_generate_v4(),
        fingerprint text not null,
        target_id uuid references targets(id) on delete cascade,
        agent_run_id uuid,
        invocation_id uuid,
        tool text not null,
        status text not null default 'observed',
        evidence text not null default '',
        created_at timestamptz not null default now()
      )
    `);
    await c.query(`create index if not exists idx_finding_evidence_fp on finding_evidence(fingerprint, created_at asc)`);
    await c.query(`create index if not exists idx_finding_evidence_target on finding_evidence(target_id)`);
  });
}
await ensureFindingVerificationSchema();

type EvidenceRow = {
  tool: string;
  status: string;
  evidence: string;
  createdAt: string | Date;
  invocationId: string | null;
};

/**
 * Compute verification status from raw evidence rows.
 *
 * Promotion rules (mirrors plan):
 *  - confidence='high' and requires_verification=false → confirmed (Situation 2)
 *  - 2+ distinct tools with status='observed' for the fingerprint → confirmed (Situation 1)
 *  - any verifier_no_response / verifier_failed and no second 'observed' → unverified (Situation 3)
 *  - otherwise → pending
 */
function computeVerification(
  finding: { confidence: string; requiresVerification: boolean; sourceTool: string | null },
  evidence: EvidenceRow[]
): {
  status: "confirmed" | "unverified" | "pending";
  confirmedByTools: string[];
  attempts: Array<{ tool: string; outcome: string; at: string | Date; invocationId: string | null }>;
} {
  const observedTools = new Set<string>();
  const attempts: Array<{ tool: string; outcome: string; at: string | Date; invocationId: string | null }> = [];
  let hasFailedAttempt = false;
  for (const e of evidence) {
    if (e.status === "observed") observedTools.add(e.tool);
    if (e.status === "verifier_failed" || e.status === "verifier_no_response") hasFailedAttempt = true;
    attempts.push({ tool: e.tool, outcome: e.status, at: e.createdAt, invocationId: e.invocationId });
  }
  const tools = [...observedTools];
  if (finding.confidence === "high" && !finding.requiresVerification) {
    return { status: "confirmed", confirmedByTools: tools.length > 0 ? tools : finding.sourceTool ? [finding.sourceTool] : [], attempts };
  }
  if (tools.length >= 2) {
    return { status: "confirmed", confirmedByTools: tools, attempts };
  }
  if (hasFailedAttempt) {
    return { status: "unverified", confirmedByTools: tools, attempts };
  }
  return { status: "pending", confirmedByTools: tools, attempts };
}

app.get("/api/findings", async (req) => {
  const q = req.query as any;
  const targetId = q.targetId ? z.string().uuid().parse(q.targetId) : undefined;
  const severity = q.severity ? z.enum(["info", "low", "medium", "high", "critical"]).parse(q.severity) : undefined;
  const status = q.status
    ? z
        .enum(["open", "triaged", "in_progress", "fixed", "verified", "false_positive", "accepted_risk"])
        .parse(q.status)
    : undefined;
  const verification = q.verification
    ? z.enum(["confirmed", "unverified", "pending"]).parse(q.verification)
    : undefined;

  const rows = await withClient(async (c) => {
    const where: string[] = [];
    const params: any[] = [];
    if (targetId) {
      params.push(targetId);
      where.push(`f.target_id = $${params.length}`);
    }
    if (severity) {
      params.push(severity);
      where.push(`f.severity = $${params.length}`);
    }
    if (status) {
      params.push(status);
      where.push(`f.status = $${params.length}`);
    }
    const whereSql = where.length ? `where ${where.join(" and ")}` : "";
    const res = await c.query(
      `
      select f.id, f.title, f.severity, f.status, f.evidence_redacted, f.first_seen_at, f.last_seen_at,
             f.fingerprint, f.confidence, f.requires_verification, f.claim_type,
             t.id as target_id, t.name as target_name, t.address as target_address,
             s.port as service_port, s.protocol as service_protocol, s.service_name as service_name
      from findings f
      join targets t on t.id = f.target_id
      left join services s on s.id = f.service_id
      ${whereSql}
      order by f.last_seen_at desc
      limit 200
      `,
      params
    );
    return res.rows;
  });

  // Batch-fetch evidence for every fingerprint in one query, then bucket per finding.
  const fingerprints = rows.map((r) => r.fingerprint as string).filter(Boolean);
  const evidenceByFp = new Map<string, EvidenceRow[]>();
  if (fingerprints.length > 0) {
    await withClient(async (c) => {
      const res = await c.query(
        `select fingerprint, tool, status, evidence, created_at, invocation_id
         from finding_evidence
         where fingerprint = any($1::text[])
         order by created_at asc`,
        [fingerprints]
      );
      for (const row of res.rows) {
        const fp = String(row.fingerprint);
        if (!evidenceByFp.has(fp)) evidenceByFp.set(fp, []);
        evidenceByFp.get(fp)!.push({
          tool: String(row.tool),
          status: String(row.status),
          evidence: String(row.evidence ?? ""),
          createdAt: row.created_at,
          invocationId: row.invocation_id ?? null
        });
      }
    });
  }

  const enriched = rows.map((r) => {
    const ev = evidenceByFp.get(r.fingerprint) ?? [];
    const sourceTool = ev.find((e) => e.status === "observed")?.tool ?? null;
    const vc = computeVerification(
      { confidence: r.confidence ?? "medium", requiresVerification: r.requires_verification ?? true, sourceTool },
      ev
    );
    return {
      id: r.id,
      title: r.title,
      severity: r.severity,
      status: r.status,
      evidenceRedacted: r.evidence_redacted,
      firstSeenAt: r.first_seen_at,
      lastSeenAt: r.last_seen_at,
      target: { id: r.target_id, name: r.target_name, address: r.target_address },
      service: r.service_port
        ? { port: r.service_port, protocol: r.service_protocol, name: r.service_name ?? null }
        : null,
      verification: {
        status: vc.status,
        confirmedByTools: vc.confirmedByTools,
        attempts: vc.attempts,
        confidence: r.confidence ?? "medium",
        claimType: r.claim_type ?? null
      }
    };
  });

  return verification ? enriched.filter((f) => f.verification.status === verification) : enriched;
});

app.get("/api/findings/:id/evidence", async (req, reply) => {
  const findingId = z.string().uuid().parse((req.params as any).id);
  const row = await withClient(async (c) => {
    const r = await c.query(
      `select f.id, f.fingerprint, f.title, f.severity, f.confidence, f.requires_verification, f.claim_type
       from findings f where f.id = $1`,
      [findingId]
    );
    return r.rows[0];
  });
  if (!row) return reply.code(404).send({ error: "finding not found" });

  const events = await withClient(async (c) => {
    const r = await c.query(
      `select tool, status, evidence, created_at, invocation_id
       from finding_evidence
       where fingerprint = $1
       order by created_at asc`,
      [row.fingerprint]
    );
    return r.rows;
  });

  const evidence: EvidenceRow[] = events.map((e: any) => ({
    tool: String(e.tool),
    status: String(e.status),
    evidence: String(e.evidence ?? ""),
    createdAt: e.created_at,
    invocationId: e.invocation_id ?? null
  }));
  const sourceTool = evidence.find((e) => e.status === "observed")?.tool ?? null;
  const vc = computeVerification(
    { confidence: row.confidence ?? "medium", requiresVerification: row.requires_verification ?? true, sourceTool },
    evidence
  );
  return {
    id: row.id,
    fingerprint: row.fingerprint,
    title: row.title,
    severity: row.severity,
    claimType: row.claim_type ?? null,
    verification: {
      status: vc.status,
      confirmedByTools: vc.confirmedByTools,
      attempts: vc.attempts,
      confidence: row.confidence ?? "medium"
    },
    evidence
  };
});

app.patch("/api/findings/:id", async (req) => {
  const findingId = z.string().uuid().parse((req.params as any).id);
  const body = UpdateFindingSchema.parse(req.body);

  const updated = await withClient(async (c) => {
    const res = await c.query(
      `update findings
       set status = coalesce($2, status),
           severity = coalesce($3, severity)
       where id = $1
       returning id, status, severity`,
      [findingId, body.status ?? null, body.severity ?? null]
    );
    return res.rows[0];
  });

  return { id: updated.id, status: updated.status, severity: updated.severity };
});

app.post("/api/findings/:id/explain", async (req, reply) => {
  const findingId = z.string().uuid().parse((req.params as any).id);

  const finding = await withClient(async (c) => {
    const res = await c.query(
      `select f.id, f.title, f.severity, f.evidence_redacted, t.name as target_name, t.address as target_address,
              s.port as service_port, s.protocol as service_protocol, s.service_name as service_name
       from findings f
       join targets t on t.id = f.target_id
       left join services s on s.id = f.service_id
       where f.id = $1`,
      [findingId]
    );
    return res.rows[0];
  });
  if (!finding) return reply.code(404).send({ error: "Finding not found" });

  const input = {
    title: finding.title as string,
    severity: finding.severity as string,
    targetName: finding.target_name as string,
    targetAddress: finding.target_address as string,
    service: finding.service_port
      ? { port: Number(finding.service_port), protocol: String(finding.service_protocol), name: finding.service_name ?? null }
      : null,
    evidenceRedacted: String(finding.evidence_redacted ?? "")
  };

  if (env.AI_MODE === "ollama") {
    try {
      const out = await explainWithOllama(input);
      return { mode: "ollama", ...out };
    } catch (err) {
      return reply.code(502).send({
        mode: "ollama",
        error: (err as Error).message,
        summary: "Ollama explain failed; verify the local Ollama server is reachable.",
        whyItMatters: "Check OLLAMA_URL and that the model is pulled (e.g. `ollama pull qwen3:8b`).",
        remediation: ["Verify OLLAMA_URL", "Pull the model with `ollama pull qwen3:8b`"],
        verification: ["Retry explain after model is available."]
      });
    }
  }

  // Mock fallback.
  return {
    mode: "mock",
    summary: `This finding indicates a potentially risky exposure on ${input.targetName} (${input.targetAddress}).`,
    whyItMatters:
      "Even in staging, these issues often mirror production misconfigurations and can lead to real incidents if carried into production.",
    remediation: [
      "Confirm the service is required for this host/environment.",
      "Restrict access to trusted subnets only (firewall/NSG).",
      "Patch/upgrade the component and enforce secure configuration baselines."
    ],
    verification: ["Re-run the scan profile and confirm the finding no longer appears."]
  };
});

// --- Agentic Recon (MCP) endpoints ---
async function ensureAgentTablesApi() {
  await withClient(async (c) => {
    await c.query(`
      create table if not exists agent_runs (
        id uuid primary key default uuid_generate_v4(),
        target_id uuid not null references targets(id) on delete cascade,
        status text not null default 'queued',
        manager_model text not null default '',
        specialist_model text not null default '',
        prompter_model text not null default '',
        max_steps int not null default 25,
        steps_taken int not null default 0,
        invocation_count int not null default 0,
        finding_count int not null default 0,
        service_count int not null default 0,
        notes text,
        initial_nmap_profile text,
        initial_nmap_ports int[],
        initial_nmap_extra_args text,
        started_at timestamptz,
        finished_at timestamptz,
        created_at timestamptz not null default now()
      )
    `);
    await c.query(`alter table agent_runs add column if not exists initial_nmap_profile text`);
    await c.query(`alter table agent_runs add column if not exists initial_nmap_ports int[]`);
    await c.query(`alter table agent_runs add column if not exists initial_nmap_extra_args text`);
    await c.query(`create index if not exists idx_agent_runs_target on agent_runs(target_id, created_at desc)`);
    await c.query(`
      create table if not exists agent_invocations (
        id uuid primary key default uuid_generate_v4(),
        agent_run_id uuid not null references agent_runs(id) on delete cascade,
        tool text not null,
        intent text,
        args jsonb not null default '{}'::jsonb,
        status text not null default 'running',
        envelope jsonb,
        log text not null default '',
        started_at timestamptz not null default now(),
        finished_at timestamptz
      )
    `);
    await c.query(`create index if not exists idx_agent_invocations_run on agent_invocations(agent_run_id, started_at asc)`);
    await c.query(`
      create table if not exists agent_events (
        id uuid primary key default uuid_generate_v4(),
        agent_run_id uuid not null references agent_runs(id) on delete cascade,
        invocation_id uuid references agent_invocations(id) on delete cascade,
        kind text not null,
        payload jsonb not null default '{}'::jsonb,
        created_at timestamptz not null default now()
      )
    `);
    await c.query(`create index if not exists idx_agent_events_run on agent_events(agent_run_id, created_at asc)`);
  });
}
await ensureAgentTablesApi();

const StartAgentRunSchema = z.object({
  targetId: z.string().uuid(),
  maxSteps: z.coerce.number().int().positive().max(60).optional(),
  notes: z.string().optional(),
  initialNmap: z
    .object({
      profile: z.enum(["fast", "targeted", "deep", "full"]).optional(),
      ports: z.array(z.number().int().positive().max(65535)).optional(),
      extraArgs: z.string().optional()
    })
    .optional()
});

app.post("/api/agent-runs", async (req, reply) => {
  const body = StartAgentRunSchema.parse(req.body);
  const target = await withClient(async (c) => {
    const r = await c.query(`select id, name, address from targets where id = $1`, [body.targetId]);
    return r.rows[0] as { id: string; name: string; address: string } | undefined;
  });
  if (!target) return reply.code(404).send({ error: "Target not found" });

  const created = await withClient(async (c) => {
    await c.query("begin");
    try {
      const r = await c.query(
        `insert into agent_runs (
           target_id, status, manager_model, specialist_model, prompter_model, max_steps, notes,
           initial_nmap_profile, initial_nmap_ports, initial_nmap_extra_args
         )
         values ($1, 'queued', '', '', '', $2, $3, $4, $5, $6)
         returning id, max_steps`,
        [
          body.targetId,
          body.maxSteps ?? 20,
          body.notes ?? null,
          body.initialNmap?.profile ?? "deep",
          body.initialNmap?.ports ?? null,
          body.initialNmap?.extraArgs ?? null
        ]
      );
      const runId = r.rows[0].id as string;
      await c.query(
        `insert into jobs (type, status, payload) values ('recon-mcp','queued', $1::jsonb)`,
        [JSON.stringify({ agentRunId: runId, targetId: body.targetId })]
      );
      await c.query("commit");
      return { id: runId, maxSteps: r.rows[0].max_steps as number };
    } catch (e) {
      await c.query("rollback");
      throw e;
    }
  });
  await writeAuditEvent("agent.recon.queued", { agentRunId: created.id, targetId: body.targetId }, target.address, "operator");
  return reply.code(202).send({ id: created.id, status: "queued" });
});

app.get("/api/agent-runs", async (req) => {
  const q = req.query as { targetId?: string; limit?: string };
  const limit = q.limit ? Math.min(200, Math.max(1, Number(q.limit))) : 50;
  const rows = await withClient(async (c) => {
    if (q.targetId) {
      const r = await c.query(
        `select ar.*, t.name as target_name, t.address as target_address
         from agent_runs ar join targets t on t.id = ar.target_id
         where ar.target_id = $1
         order by ar.created_at desc limit $2`,
        [q.targetId, limit]
      );
      return r.rows;
    }
    const r = await c.query(
      `select ar.*, t.name as target_name, t.address as target_address
       from agent_runs ar join targets t on t.id = ar.target_id
       order by ar.created_at desc limit $1`,
      [limit]
    );
    return r.rows;
  });
  return rows.map((r) => ({
    id: r.id,
    targetId: r.target_id,
    target: { id: r.target_id, name: r.target_name, address: r.target_address },
    status: r.status,
    managerModel: r.manager_model,
    specialistModel: r.specialist_model,
    prompterModel: r.prompter_model,
    maxSteps: r.max_steps,
    stepsTaken: r.steps_taken,
    invocationCount: r.invocation_count,
    findingCount: r.finding_count,
    serviceCount: r.service_count,
    notes: r.notes ?? null,
    startedAt: r.started_at,
    finishedAt: r.finished_at,
    createdAt: r.created_at
  }));
});

app.get("/api/agent-runs/:id", async (req, reply) => {
  const id = z.string().uuid().parse((req.params as any).id);
  const data = await withClient(async (c) => {
    const r = await c.query(
      `select ar.*, t.name as target_name, t.address as target_address
       from agent_runs ar join targets t on t.id = ar.target_id where ar.id = $1`,
      [id]
    );
    return r.rows[0];
  });
  if (!data) return reply.code(404).send({ error: "agent_run not found" });
  return {
    id: data.id,
    targetId: data.target_id,
    target: { id: data.target_id, name: data.target_name, address: data.target_address },
    status: data.status,
    managerModel: data.manager_model,
    specialistModel: data.specialist_model,
    prompterModel: data.prompter_model,
    maxSteps: data.max_steps,
    stepsTaken: data.steps_taken,
    invocationCount: data.invocation_count,
    findingCount: data.finding_count,
    serviceCount: data.service_count,
    notes: data.notes ?? null,
    startedAt: data.started_at,
    finishedAt: data.finished_at,
    createdAt: data.created_at
  };
});

app.get("/api/agent-runs/:id/invocations", async (req) => {
  const id = z.string().uuid().parse((req.params as any).id);
  const rows = await withClient(async (c) => {
    const r = await c.query(
      `select id, tool, intent, args, status, envelope, log, started_at, finished_at
       from agent_invocations where agent_run_id = $1 order by started_at asc`,
      [id]
    );
    return r.rows;
  });
  return rows.map((r) => ({
    id: r.id,
    tool: r.tool,
    intent: r.intent,
    args: r.args ?? {},
    status: r.status,
    envelope: r.envelope ?? null,
    log: r.log ?? "",
    startedAt: r.started_at,
    finishedAt: r.finished_at
  }));
});

app.get("/api/agent-runs/:id/events", async (req) => {
  const id = z.string().uuid().parse((req.params as any).id);
  const q = req.query as { since?: string; limit?: string };
  const limit = q.limit ? Math.min(500, Math.max(1, Number(q.limit))) : 200;
  const rows = await withClient(async (c) => {
    if (q.since) {
      const r = await c.query(
        `select id, invocation_id, kind, payload, created_at
         from agent_events
         where agent_run_id = $1 and created_at > $2
         order by created_at asc limit $3`,
        [id, new Date(q.since), limit]
      );
      return r.rows;
    }
    const r = await c.query(
      `select id, invocation_id, kind, payload, created_at
       from agent_events where agent_run_id = $1
       order by created_at asc limit $2`,
      [id, limit]
    );
    return r.rows;
  });
  return rows.map((r) => ({
    id: r.id,
    invocationId: r.invocation_id ?? null,
    kind: r.kind,
    payload: r.payload ?? {},
    createdAt: r.created_at
  }));
});

/**
 * Run-level AI explain. Replaces the per-finding explain UX.
 * Reads agent_runs / invocations / events for the run, hands the compact bundle
 * to Ollama, and returns a structured executive summary the UI can render.
 */
app.post("/api/agent-runs/:id/explain", async (req, reply) => {
  const id = z.string().uuid().parse((req.params as any).id);

  const run = await withClient(async (c) => {
    const r = await c.query(
      `select ar.id, ar.status, ar.steps_taken, ar.invocation_count, ar.finding_count, ar.service_count,
              t.name as target_name, t.address as target_address, t.id as target_id
         from agent_runs ar join targets t on t.id = ar.target_id
         where ar.id = $1`,
      [id]
    );
    return r.rows[0];
  });
  if (!run) return reply.code(404).send({ error: "agent_run not found" });

  const invocations = await withClient(async (c) => {
    const r = await c.query(
      `select tool, status, envelope, started_at, finished_at, args
         from agent_invocations
         where agent_run_id = $1
         order by started_at asc`,
      [id]
    );
    return r.rows;
  });

  const decisions = await withClient(async (c) => {
    const r = await c.query(
      `select payload, created_at
         from agent_events
         where agent_run_id = $1 and kind = 'manager.decision'
         order by created_at asc
         limit 60`,
      [id]
    );
    return r.rows;
  });

  const services = await withClient(async (c) => {
    const r = await c.query(
      `select port, protocol, service_name, product, version
         from services where target_id = $1
         order by port asc`,
      [run.target_id]
    );
    return r.rows;
  });

  const findings = await withClient(async (c) => {
    const r = await c.query(
      `select title, severity, evidence_redacted
         from findings where target_id = $1
         order by case severity
                    when 'critical' then 0 when 'high' then 1
                    when 'medium' then 2 when 'low' then 3 else 4 end asc,
                  last_seen_at desc
         limit 80`,
      [run.target_id]
    );
    return r.rows;
  });

  const toolsUsed = invocations.map((i: any) => {
    const env_ = (i.envelope ?? {}) as { artifacts?: { commands?: string[] }; durationMs?: number };
    const cmd = Array.isArray(env_.artifacts?.commands) && env_.artifacts!.commands!.length > 0 ? String(env_.artifacts!.commands![0]) : null;
    return {
      tool: String(i.tool),
      status: String(i.status),
      durationMs: typeof env_.durationMs === "number" ? env_.durationMs : null,
      commandSnippet: cmd ? cmd.slice(0, 240) : null
    };
  });

  const summaryInput = {
    target: { name: String(run.target_name), address: String(run.target_address) },
    status: String(run.status),
    steps: Number(run.steps_taken ?? 0),
    invocationCount: Number(run.invocation_count ?? 0),
    findingCount: Number(run.finding_count ?? 0),
    serviceCount: Number(run.service_count ?? 0),
    toolsUsed,
    services: services.map((s: any) => ({
      port: Number(s.port),
      protocol: String(s.protocol),
      name: s.service_name ?? null,
      product: s.product ?? null,
      version: s.version ?? null
    })),
    findings: findings.map((f: any) => ({
      title: String(f.title),
      severity: String(f.severity),
      evidence: f.evidence_redacted ? String(f.evidence_redacted).slice(0, 400) : null
    })),
    decisions: decisions.map((d: any, idx: number) => {
      const p = (d.payload ?? {}) as { step?: number; decision?: { tool?: string; intentGoal?: string; reasoning?: string; action?: string; reason?: string } };
      const dec = p.decision ?? {};
      return {
        step: typeof p.step === "number" ? p.step : idx + 1,
        tool: dec.tool,
        intent: dec.intentGoal,
        reasoning: dec.reasoning,
        reason: dec.action === "stop" ? dec.reason : undefined
      };
    })
  };

  if (env.AI_MODE === "ollama") {
    try {
      const out = await summariseAgentRunWithOllama(summaryInput);
      return { mode: "ollama", run: { id: run.id, status: run.status }, ...out };
    } catch (err) {
      return reply.code(502).send({
        mode: "ollama",
        error: (err as Error).message,
        overallRisk: "info",
        headline: "AI summary unavailable.",
        keyExposures: [],
        prioritizedFixes: [],
        whatWeDid: summaryInput.toolsUsed.slice(0, 8).map((t) => `${t.tool} (${t.status})`),
        verificationSteps: ["Verify Ollama is reachable and the explain model is pulled, then retry."]
      });
    }
  }

  // Mock fallback (AI_MODE=mock) – useful for offline dev.
  return {
    mode: "mock",
    run: { id: run.id, status: run.status },
    overallRisk: findings.find((f: any) => f.severity === "critical")
      ? "critical"
      : findings.find((f: any) => f.severity === "high")
        ? "high"
        : findings.find((f: any) => f.severity === "medium")
          ? "medium"
          : "low",
    headline: `${summaryInput.target.name}: ${summaryInput.findingCount} findings across ${summaryInput.serviceCount} services in ${summaryInput.invocationCount} agent invocations.`,
    keyExposures: summaryInput.findings.slice(0, 5).map((f) => `${f.severity.toUpperCase()}: ${f.title}`),
    prioritizedFixes: [
      { priority: "p1", recommendation: "Patch and harden services flagged with high/critical findings." },
      { priority: "p2", recommendation: "Restrict network exposure of unused services." }
    ],
    whatWeDid: summaryInput.toolsUsed.slice(0, 8).map((t) => `${t.tool} (${t.status})`),
    verificationSteps: ["Re-run the agentic recon and confirm findings disappear or are downgraded."]
  };
});

/**
 * Run-level detailed AI report (markdown).
 * Returns a long-form markdown report suitable for PDF export client-side.
 */
app.post("/api/agent-runs/:id/report", async (req, reply) => {
  const id = z.string().uuid().parse((req.params as any).id);

  const run = await withClient(async (c) => {
    const r = await c.query(
      `select ar.id, ar.status, ar.steps_taken, ar.invocation_count, ar.finding_count, ar.service_count,
              t.name as target_name, t.address as target_address, t.id as target_id
         from agent_runs ar join targets t on t.id = ar.target_id
         where ar.id = $1`,
      [id]
    );
    return r.rows[0];
  });
  if (!run) return reply.code(404).send({ error: "agent_run not found" });

  const invocations = await withClient(async (c) => {
    const r = await c.query(
      `select tool, status, envelope, started_at, finished_at, args
         from agent_invocations
         where agent_run_id = $1
         order by started_at asc`,
      [id]
    );
    return r.rows;
  });

  const decisions = await withClient(async (c) => {
    const r = await c.query(
      `select payload, created_at
         from agent_events
         where agent_run_id = $1 and kind = 'manager.decision'
         order by created_at asc
         limit 80`,
      [id]
    );
    return r.rows;
  });

  const services = await withClient(async (c) => {
    const r = await c.query(
      `select port, protocol, service_name, product, version
         from services where target_id = $1
         order by port asc`,
      [run.target_id]
    );
    return r.rows;
  });

  const findings = await withClient(async (c) => {
    const r = await c.query(
      `select title, severity, evidence_redacted
         from findings where target_id = $1
         order by case severity
                    when 'critical' then 0 when 'high' then 1
                    when 'medium' then 2 when 'low' then 3 else 4 end asc,
                  last_seen_at desc
         limit 140`,
      [run.target_id]
    );
    return r.rows;
  });

  const toolsUsed = invocations.map((i: any) => {
    const env_ = (i.envelope ?? {}) as { artifacts?: { commands?: string[] }; durationMs?: number };
    const cmd = Array.isArray(env_.artifacts?.commands) && env_.artifacts!.commands!.length > 0 ? String(env_.artifacts!.commands![0]) : null;
    return {
      tool: String(i.tool),
      status: String(i.status),
      durationMs: typeof env_.durationMs === "number" ? env_.durationMs : null,
      commandSnippet: cmd ? cmd.slice(0, 240) : null
    };
  });

  const reportInput = {
    target: { name: String(run.target_name), address: String(run.target_address) },
    status: String(run.status),
    steps: Number(run.steps_taken ?? 0),
    invocationCount: Number(run.invocation_count ?? 0),
    findingCount: Number(run.finding_count ?? 0),
    serviceCount: Number(run.service_count ?? 0),
    toolsUsed,
    services: services.map((s: any) => ({
      port: Number(s.port),
      protocol: String(s.protocol),
      name: s.service_name ?? null,
      product: s.product ?? null,
      version: s.version ?? null
    })),
    findings: findings.map((f: any) => ({
      title: String(f.title),
      severity: String(f.severity),
      evidence: f.evidence_redacted ? String(f.evidence_redacted).slice(0, 700) : null
    })),
    decisions: decisions.map((d: any, idx: number) => {
      const p = (d.payload ?? {}) as { step?: number; decision?: { tool?: string; intentGoal?: string; reasoning?: string; action?: string; reason?: string } };
      const dec = p.decision ?? {};
      return {
        step: typeof p.step === "number" ? p.step : idx + 1,
        tool: dec.tool,
        intent: dec.intentGoal,
        reasoning: dec.reasoning,
        reason: dec.action === "stop" ? dec.reason : undefined
      };
    })
  };

  if (env.AI_MODE === "ollama") {
    try {
      const out = await generateAgentRunReportWithOllama(reportInput);
      return { mode: "ollama", run: { id: run.id, status: run.status }, ...out };
    } catch (err) {
      return reply.code(502).send({
        mode: "ollama",
        error: (err as Error).message,
        title: `Security recon report: ${String(run.target_name)}`,
        markdown: `# Security recon report: ${String(run.target_name)}\n\nAI report unavailable.\n\n- Error: ${(err as Error).message}\n`,
        run: { id: run.id, status: run.status }
      });
    }
  }

  // Mock fallback
  return {
    mode: "mock",
    run: { id: run.id, status: run.status },
    title: `Security recon report: ${String(run.target_name)}`,
    markdown:
      `# Security recon report: ${String(run.target_name)}\\n\\n` +
      `Target: ${String(run.target_address)}\\n\\n` +
      `Findings: ${Number(run.finding_count ?? 0)}\\nServices: ${Number(run.service_count ?? 0)}\\n\\n` +
      `## Findings (top)\\n` +
      findings
        .slice(0, 15)
        .map((f: any) => `- **${String(f.severity).toUpperCase()}**: ${String(f.title)}`)
        .join("\\n") +
      `\\n`
  };
});

app.get("/api/agent-tools", async () => {
  // Stable list: keep in lock-step with worker/src/agents/registry.ts
  return [
    { name: "recon.nmap", description: "Run an nmap scan to discover open ports and detect services on a target host.", tags: ["recon", "network"] },
    {
      name: "recon.dns_enum",
      description: "Enumerate DNS records (A/AAAA/MX/NS/TXT/CNAME), reverse PTR and attempt safe zone transfers (dig + dnsx).",
      tags: ["recon", "dns"]
    },
    {
      name: "recon.http_probe",
      description:
        "Probe HTTP/HTTPS with httpx: full URLs on the target, path-only paths (e.g. /uploads/) expanded per ports/context, or nmap-style services rows.",
      tags: ["recon", "web"]
    },
    {
      name: "recon.ssh_enum",
      description: "Audit SSH banner, supported algorithms and known CVEs using ssh-audit (JSON output).",
      tags: ["recon", "ssh"]
    },
    {
      name: "recon.smb_enum",
      description: "Enumerate SMB on the target with enum4linux-ng (JSON output): dialects, signing, anonymous share listing.",
      tags: ["recon", "smb"]
    },
    {
      name: "recon.tls_check",
      description: "Inspect TLS certificate, protocols and known vulnerabilities on TLS-enabled ports using testssl.",
      tags: ["recon", "tls"]
    },
    {
      name: "recon.cve_enricher",
      description: "Enrich detected services with known-vulnerable software heuristics (no remote scanning).",
      tags: ["recon", "enrichment"]
    },
    {
      name: "recon.spider",
      description: "Crawl a discovered HTTP(S) endpoint with Katana to enumerate URLs, JS endpoints, robots.txt and sitemap entries.",
      tags: ["recon", "web"]
    },
    {
      name: "recon.waybackurls",
      description:
        "Query the Wayback Machine (CDX) for historical URLs of the target host. Expect empty results for private RFC1918 IPs and hosts never crawled on the public web.",
      tags: ["recon", "web", "amplification"]
    },
    {
      name: "recon.gobuster",
      description:
        "Brute-force common web content paths on a discovered HTTP(S) endpoint. Structured args are merged from the execution-writer LLM after the prompter step.",
      tags: ["recon", "web"]
    },
    {
      name: "recon.ffuf",
      description:
        "Fuzz a specific web path with ffuf using a SecLists wordlist. Structured args are merged from the execution-writer LLM after the prompter step.",
      tags: ["recon", "web", "fuzz"]
    },
    {
      name: "system.tool_installer",
      description:
        "Install missing CLI tools on the remote Kali host: optional args.installCommand for non-apt recipes, else apt-get (auto-recovery).",
      tags: ["system", "installer"]
    }
  ];
});

app.get("/api/graph/target/:id", async (req) => {
  const targetId = z.string().uuid().parse((req.params as any).id);

  type Pair = { from: unknown; to: unknown };
  const graph = await withSession(async (s) => {
    const res = await s.run(
      `
      match (t:Target {id: $targetId})
      optional match (t)-[:HAS_SERVICE]->(svc:Service)
      with t, collect(distinct svc) as services
      optional match (t)-[:HAS_SERVICE]->(s2:Service)-[:HAS_FINDING]->(fViaSvc:Finding)
      optional match (t)-[:HAS_FINDING]->(fViaTgt:Finding)
      return t,
             services,
             collect(distinct {from: s2.id, to: fViaSvc.id}) as serviceFindingPairsRaw,
             collect(distinct fViaSvc) as findingsFromSvcNodes,
             collect(distinct fViaTgt) as findingsFromTgtNodes
      `,
      { targetId }
    );

    const rec = res.records[0];
    if (!rec) return { target: null, services: [], findings: [], nodes: [], edges: [] };

    const tNode = rec.get("t");
    if (!tNode) return { target: null, services: [], findings: [], nodes: [], edges: [] };

    const t = (tNode as any).properties as Record<string, unknown>;
    const tid = String(t.id);

    const services = (rec.get("services") as any[])
      .filter((n) => n != null)
      .map((n) => n.properties as Record<string, unknown>);
    const fromSvcFindingNodes = ((rec.get("findingsFromSvcNodes") as any[]) ?? []).filter(Boolean);
    const fromTgtFindingNodes = ((rec.get("findingsFromTgtNodes") as any[]) ?? []).filter(Boolean);

    const findingPropsById = new Map<string, Record<string, unknown>>();
    for (const n of [...fromSvcFindingNodes, ...fromTgtFindingNodes]) {
      const fp = n.properties as Record<string, unknown>;
      if (fp?.id != null) findingPropsById.set(String(fp.id), fp);
    }
    const findings = [...findingPropsById.values()];
    const targetLinkedIds = new Set(fromTgtFindingNodes.map((n) => String(n.properties.id)));

    const svcLabel = (s: Record<string, unknown>) =>
      `${s.port ?? ""}/${s.protocol ?? ""}\n${s.name ?? "service"}`;
    const findingLabel = (f: Record<string, unknown>) =>
      `${String(f.severity ?? "").toUpperCase()}\n${String(f.title ?? "")}`;

    const edges = [
      ...services.map((sv) => ({
        id: `t->s:${tid}:${sv.id}`,
        source: `target:${tid}`,
        target: `service:${String(sv.id)}`
      })),
      ...(rec.get("serviceFindingPairsRaw") as Pair[])
        .map((p) => ({ from: p?.from, to: p?.to }))
        .filter((p) => p.from != null && p.to != null)
        .map((p) => ({
          id: `s->f:${String(p.from)}:${String(p.to)}`,
          source: `service:${String(p.from)}`,
          target: `finding:${String(p.to)}`
        })),
      ...findings
        .filter((f) => targetLinkedIds.has(String(f.id)))
        .map((f) => ({
          id: `t->f:${tid}:${String(f.id)}`,
          source: `target:${tid}`,
          target: `finding:${String(f.id)}`
        }))
    ];

    const nodes = [
      {
        id: `target:${tid}`,
        kind: "Target" as const,
        data: { ...t, label: `${t.name ?? "Target"}\n${t.address ?? ""}` }
      },
      ...services.map((sv) => ({
        id: `service:${String(sv.id)}`,
        kind: "Service" as const,
        data: { ...sv, label: svcLabel(sv) }
      })),
      ...findings.map((f) => ({
        id: `finding:${String(f.id)}`,
        kind: "Finding" as const,
        data: { ...f, label: findingLabel(f) }
      }))
    ];

    return { target: t, services, findings, nodes, edges };
  });
  return graph;
});

await app.listen({ port: env.PORT, host: "0.0.0.0" });

process.on("SIGINT", async () => {
  await app.close();
  process.exit(0);
});

