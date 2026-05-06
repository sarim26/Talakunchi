import Fastify from "fastify";
import cors from "@fastify/cors";
import { z } from "zod";
import { env } from "./env.js";
import { withClient } from "./db.js";
import { withSession } from "./neo4j.js";
import { CreateScanSchema, CreateTargetSchema, PipelineConfigSchema, UpdateFindingSchema } from "./schemas.js";
import { explainWithGemini } from "./llm/gemini.js";
const app = Fastify({ logger: true });
const DEFAULT_PIPELINE_CONFIG = {
    maxConcurrentScans: 2,
    requestRatePerMinute: 120,
    auditEnabled: true,
    allowedWordlists: []
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
        if (parsed.success)
            return parsed.data;
        await c.query(`insert into pipeline_configs (id, config, updated_at)
       values (1, $1::jsonb, now())
       on conflict (id) do update set config = excluded.config, updated_at = now()`, [JSON.stringify(DEFAULT_PIPELINE_CONFIG)]);
        return DEFAULT_PIPELINE_CONFIG;
    });
}
async function putPipelineConfig(input) {
    const parsed = PipelineConfigSchema.parse(input);
    await withClient(async (c) => {
        await c.query(`insert into pipeline_configs (id, config, updated_at)
       values (1, $1::jsonb, now())
       on conflict (id) do update set config = excluded.config, updated_at = now()`, [JSON.stringify(parsed)]);
    });
    return parsed;
}
async function writeAuditEvent(action, payload, target, actor = "api") {
    const cfg = await getPipelineConfig();
    if (!cfg.auditEnabled)
        return;
    await withClient(async (c) => {
        await c.query(`insert into audit_events (actor, action, target, payload) values ($1, $2, $3, $4::jsonb)`, [actor, action, target ?? null, JSON.stringify(payload)]);
    });
}
// Minimal error helpers (avoid extra plugin in prototype)
app.setErrorHandler((err, _req, reply) => {
    if (err?.statusCode) {
        reply.status(err.statusCode).send({ error: err.message });
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
    const q = req.query;
    const limit = q.limit ? Math.min(500, Math.max(1, Number(q.limit))) : 100;
    const rows = await withClient(async (c) => {
        const res = await c.query(`select id, actor, action, target, payload, created_at
       from audit_events
       order by created_at desc
       limit $1`, [limit]);
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
const resetState = { code: null, expiresAt: 0 };
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
            await c.query("commit");
        }
        catch (e) {
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
    if (env.AI_MODE !== "gemini")
        return reply.send({ provider: env.AI_MODE, models: [] });
    if (!env.GEMINI_API_KEY)
        return reply.code(400).send({ error: "GEMINI_API_KEY is not set" });
    const { GoogleGenerativeAI } = await import("@google/generative-ai");
    const client = new GoogleGenerativeAI(env.GEMINI_API_KEY);
    // listModels exists in recent versions of the SDK; if not, return a hint.
    const anyClient = client;
    if (typeof anyClient.listModels !== "function") {
        return reply.send({
            provider: "gemini",
            models: [],
            note: "SDK does not expose listModels(); set GEMINI_MODEL manually."
        });
    }
    const models = await anyClient.listModels();
    return reply.send({
        provider: "gemini",
        models: (models?.models ?? models ?? []).map((m) => ({
            name: m.name,
            supportedGenerationMethods: m.supportedGenerationMethods
        }))
    });
});
app.post("/api/targets", async (req, reply) => {
    const body = CreateTargetSchema.parse(req.body);
    const row = await withClient(async (c) => {
        const res = await c.query(`insert into targets (name, address, tags, owner)
       values ($1, $2, $3, $4)
       returning id, name, address, tags, owner, created_at`, [body.name, body.address, body.tags, body.owner ?? null]);
        return res.rows[0];
    });
    await writeAuditEvent("target.created", { id: row.id, name: row.name, address: row.address, tags: row.tags }, row.address, "operator");
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
        const res = await c.query(`select id, name, address, tags, owner, created_at
       from targets
       order by created_at desc`);
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
    const q = req.query;
    const targetId = q.targetId ? z.string().uuid().parse(q.targetId) : undefined;
    if (!targetId)
        return [];
    const rows = await withClient(async (c) => {
        const res = await c.query(`select id, target_id, port, protocol, service_name, product, version, banner, first_seen_at, last_seen_at
       from services
       where target_id = $1
       order by port asc`, [targetId]);
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
    const q = req.query;
    const targetId = q.targetId ? z.string().uuid().parse(q.targetId) : undefined;
    if (!targetId)
        return [];
    const rows = await withClient(async (c) => {
        const res = await c.query(`select id, target_id, asset_type, value, source, confidence, metadata, first_seen_at, last_seen_at
       from recon_assets
       where target_id = $1
       order by last_seen_at desc`, [targetId]);
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
        return res.rows[0];
    });
    if (!target)
        return reply.code(404).send({ error: "Target not found" });
    const scanRun = await withClient(async (c) => {
        await c.query("begin");
        try {
            const runRes = await c.query(`insert into scan_runs (target_id, profile, status, requested_by)
         values ($1, $2, 'queued', $3)
         returning id, target_id, profile, status, requested_by, created_at`, [body.targetId, body.profile, body.requestedBy]);
            const run = runRes.rows[0];
            await c.query(`insert into jobs (type, status, payload)
         values ('scan', 'queued', $1::jsonb)`, [
                JSON.stringify({
                    scanRunId: run.id
                })
            ]);
            await c.query("commit");
            return run;
        }
        catch (e) {
            await c.query("rollback");
            throw e;
        }
    });
    await writeAuditEvent("scan.queued", { scanRunId: scanRun.id, targetId: scanRun.target_id, profile: scanRun.profile }, target.address, "operator");
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
    const scanRunId = z.string().uuid().parse(req.params.id);
    await withClient(async (c) => {
        await c.query(`update scan_runs set cancel_requested = true where id = $1`, [scanRunId]);
        // If the scan hasn't started yet, also mark queued job as failed so worker never starts it.
        await c.query(`update jobs set status='failed', error='cancelled before start', updated_at=now()
       where type='scan' and status='queued' and payload->>'scanRunId' = $1`, [scanRunId]);
    });
    await writeAuditEvent("scan.cancel_requested", { scanRunId }, undefined, "operator");
    return reply.send({ ok: true });
});
app.get("/api/scans/:id/messages", async (req) => {
    const scanRunId = z.string().uuid().parse(req.params.id);
    const rows = await withClient(async (c) => {
        const res = await c.query(`select id, role, content, created_at
       from scan_messages
       where scan_run_id = $1
       order by created_at asc
       limit 200`, [scanRunId]);
        return res.rows;
    });
    return rows.map((r) => ({ id: r.id, role: r.role, content: r.content, createdAt: r.created_at }));
});
app.post("/api/scans/:id/messages", async (req, reply) => {
    const scanRunId = z.string().uuid().parse(req.params.id);
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
            const ins = await c.query(`insert into scan_messages (scan_run_id, role, content)
         values ($1, $2, $3)
         returning id, role, content, created_at`, [scanRunId, body.role, body.content]);
            if (body.resume) {
                // Reset run status so worker can pick it up again.
                await c.query(`update scan_runs
           set status='queued', cancel_requested=false, finished_at=null
           where id=$1`, [scanRunId]);
                await c.query(`insert into jobs (type, status, payload)
           values ('scan', 'queued', $1::jsonb)`, [JSON.stringify({ scanRunId, resume: true })]);
            }
            await c.query("commit");
            return ins.rows[0];
        }
        catch (e) {
            await c.query("rollback");
            throw e;
        }
    });
    await writeAuditEvent("scan.message", { scanRunId, role: inserted.role, resumeQueued: body.resume }, undefined, "operator");
    return reply.send({ id: inserted.id, role: inserted.role, content: inserted.content, createdAt: inserted.created_at });
});
app.post("/api/scans/:id/resume", async (req, reply) => {
    const scanRunId = z.string().uuid().parse(req.params.id);
    const body = z
        .object({
        note: z.string().optional()
    })
        .parse(req.body ?? {});
    await withClient(async (c) => {
        await c.query("begin");
        try {
            if (body.note?.trim()) {
                await c.query(`insert into scan_messages (scan_run_id, role, content) values ($1, 'user', $2)`, [scanRunId, body.note.trim()]);
            }
            await c.query(`update scan_runs set status='queued', cancel_requested=false, finished_at=null where id=$1`, [scanRunId]);
            await c.query(`insert into jobs (type, status, payload) values ('scan', 'queued', $1::jsonb)`, [JSON.stringify({ scanRunId, resume: true })]);
            await c.query("commit");
        }
        catch (e) {
            await c.query("rollback");
            throw e;
        }
    });
    await writeAuditEvent("scan.resume_queued", { scanRunId }, undefined, "operator");
    return reply.send({ ok: true });
});
app.post("/api/exploit-runs", async (req, reply) => {
    const body = z
        .object({
        scanRunId: z.string().uuid().optional(),
        targetId: z.string().uuid().optional(),
        requestedBy: z.string().optional()
    })
        .parse(req.body ?? {});
    if (!body.scanRunId && !body.targetId) {
        return reply.code(400).send({ error: "Provide scanRunId or targetId" });
    }
    const scanRunId = await withClient(async (c) => {
        if (body.scanRunId) {
            const res = await c.query(`select id from scan_runs where id = $1`, [body.scanRunId]);
            if (res.rows[0])
                return res.rows[0].id;
            return null;
        }
        const res = await c.query(`select id from scan_runs
       where target_id = $1 and status = 'succeeded'
       order by finished_at desc nulls last, created_at desc
       limit 1`, [body.targetId]);
        return res.rows[0]?.id ?? null;
    });
    if (!scanRunId) {
        return reply
            .code(404)
            .send({ error: "No matching succeeded scan run found. Run a scan first or pass an explicit scanRunId." });
    }
    const target = await withClient(async (c) => {
        const res = await c.query(`select t.address from scan_runs sr join targets t on t.id = sr.target_id where sr.id = $1`, [scanRunId]);
        return res.rows[0];
    });
    await withClient(async (c) => {
        await c.query(`insert into jobs (type, status, payload)
       values ('exploit', 'queued', $1::jsonb)`, [JSON.stringify({ scanRunId, requestedBy: body.requestedBy ?? "operator" })]);
    });
    await writeAuditEvent("exploit.queued", { scanRunId, requestedBy: body.requestedBy ?? "operator" }, target?.address, "operator");
    return reply.code(202).send({ scanRunId, status: "queued" });
});
app.get("/api/command-approvals", async (req, reply) => {
    const q = req.query;
    const scanRunId = q.scanRunId ? z.string().uuid().parse(q.scanRunId) : undefined;
    if (!scanRunId)
        return [];
    const rows = await withClient(async (c) => {
        const res = await c.query(`
      select id,
             scan_run_id,
             command,
             reasoning,
             impact,
             status,
             created_at,
             decided_at,
             decided_by
        from command_approvals
       where scan_run_id = $1
         and status = 'pending'
       order by created_at asc
       limit 50
      `, [scanRunId]);
        return res.rows;
    });
    return rows.map((r) => ({
        id: r.id,
        scanRunId: r.scan_run_id,
        command: r.command,
        reasoning: r.reasoning ?? "",
        impact: r.impact ?? "low",
        status: r.status,
        createdAt: r.created_at,
        decidedAt: r.decided_at ?? null,
        decidedBy: r.decided_by ?? null
    }));
});
app.patch("/api/command-approvals/:id", async (req, reply) => {
    const approvalId = z.string().uuid().parse(req.params.id);
    const body = z.object({ decision: z.enum(["approved", "rejected"]), note: z.string().optional() }).parse(req.body ?? {});
    const updated = await withClient(async (c) => {
        const res = await c.query(`
      update command_approvals
         set status = $2,
             decided_by = $3,
             decided_at = now()
       where id = $1
      returning id, status
      `, [approvalId, body.decision, "operator"]);
        return res.rows[0];
    });
    if (!updated)
        return reply.code(404).send({ error: "Approval not found" });
    await writeAuditEvent("approval.decision", { approvalId, decision: body.decision, note: body.note ?? null }, undefined, "operator");
    return reply.send({ id: updated.id, status: updated.status });
});
app.get("/api/scans", async () => {
    const rows = await withClient(async (c) => {
        const res = await c.query(`select sr.id, sr.target_id, t.name as target_name, t.address as target_address,
              sr.profile, sr.status, sr.requested_by, sr.started_at, sr.finished_at, sr.created_at
       from scan_runs sr
       join targets t on t.id = sr.target_id
       order by sr.created_at desc
       limit 50`);
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
    const scanRunId = z.string().uuid().parse(req.params.id);
    const result = await withClient(async (c) => {
        const runRes = await c.query(`select sr.id, sr.target_id, t.name as target_name, t.address as target_address,
              sr.profile, sr.status, sr.requested_by, sr.started_at, sr.finished_at, sr.created_at
       from scan_runs sr
       join targets t on t.id = sr.target_id
       where sr.id = $1`, [scanRunId]);
        const run = runRes.rows[0];
        const stepsRes = await c.query(`select id, name, status, started_at, finished_at, log, created_at
       from scan_steps
       where scan_run_id = $1
       order by created_at asc`, [scanRunId]);
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
app.get("/api/findings", async (req) => {
    const q = req.query;
    const targetId = q.targetId ? z.string().uuid().parse(q.targetId) : undefined;
    const severity = q.severity ? z.enum(["info", "low", "medium", "high", "critical"]).parse(q.severity) : undefined;
    const status = q.status
        ? z
            .enum(["open", "triaged", "in_progress", "fixed", "verified", "false_positive", "accepted_risk"])
            .parse(q.status)
        : undefined;
    const rows = await withClient(async (c) => {
        const where = [];
        const params = [];
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
        const res = await c.query(`
      select f.id, f.title, f.severity, f.status, f.evidence_redacted, f.first_seen_at, f.last_seen_at,
             t.id as target_id, t.name as target_name, t.address as target_address,
             s.port as service_port, s.protocol as service_protocol, s.service_name as service_name
      from findings f
      join targets t on t.id = f.target_id
      left join services s on s.id = f.service_id
      ${whereSql}
      order by f.last_seen_at desc
      limit 200
      `, params);
        return res.rows;
    });
    return rows.map((r) => ({
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
            : null
    }));
});
app.patch("/api/findings/:id", async (req) => {
    const findingId = z.string().uuid().parse(req.params.id);
    const body = UpdateFindingSchema.parse(req.body);
    const updated = await withClient(async (c) => {
        const res = await c.query(`update findings
       set status = coalesce($2, status),
           severity = coalesce($3, severity)
       where id = $1
       returning id, status, severity`, [findingId, body.status ?? null, body.severity ?? null]);
        return res.rows[0];
    });
    return { id: updated.id, status: updated.status, severity: updated.severity };
});
app.post("/api/findings/:id/explain", async (req, reply) => {
    const findingId = z.string().uuid().parse(req.params.id);
    const finding = await withClient(async (c) => {
        const res = await c.query(`select f.id, f.title, f.severity, f.evidence_redacted, t.name as target_name, t.address as target_address,
              s.port as service_port, s.protocol as service_protocol, s.service_name as service_name
       from findings f
       join targets t on t.id = f.target_id
       left join services s on s.id = f.service_id
       where f.id = $1`, [findingId]);
        return res.rows[0];
    });
    if (!finding)
        return reply.code(404).send({ error: "Finding not found" });
    const input = {
        title: finding.title,
        severity: finding.severity,
        targetName: finding.target_name,
        targetAddress: finding.target_address,
        service: finding.service_port
            ? { port: Number(finding.service_port), protocol: String(finding.service_protocol), name: finding.service_name ?? null }
            : null,
        evidenceRedacted: String(finding.evidence_redacted ?? "")
    };
    if (env.AI_MODE === "gemini") {
        if (!env.GEMINI_API_KEY) {
            return {
                mode: "gemini",
                error: "GEMINI_API_KEY is not set",
                summary: "Gemini is enabled but not configured.",
                whyItMatters: "Set GEMINI_API_KEY in your environment (Docker Compose .env) and retry.",
                remediation: ["Set GEMINI_API_KEY and restart the API container."],
                verification: ["Click Explain (AI) again."]
            };
        }
        const out = await explainWithGemini({
            apiKey: env.GEMINI_API_KEY,
            model: env.GEMINI_MODEL,
            input
        });
        return { mode: "gemini", ...out };
    }
    // Safe fallback.
    return {
        mode: "mock",
        summary: `This finding indicates a potentially risky exposure on ${input.targetName} (${input.targetAddress}).`,
        whyItMatters: "Even in staging, these issues often mirror production misconfigurations and can lead to real incidents if carried into production.",
        remediation: [
            "Confirm the service is required for this host/environment.",
            "Restrict access to trusted subnets only (firewall/NSG).",
            "Patch/upgrade the component and enforce secure configuration baselines."
        ],
        verification: ["Re-run the scan profile and confirm the finding no longer appears."]
    };
});
app.get("/api/graph/target/:id", async (req) => {
    const targetId = z.string().uuid().parse(req.params.id);
    const graph = await withSession(async (s) => {
        const res = await s.run(`
      match (t:Target {id: $targetId})
      optional match (t)-[:HAS_SERVICE]->(svc:Service)
      optional match (svc)-[:HAS_FINDING]->(f:Finding)
      with t, collect(distinct svc) as services, collect(distinct f) as findings
      optional match (t)-[:HAS_SERVICE]->(svc2:Service)
      optional match (svc2)-[:HAS_FINDING]->(f2:Finding)
      return t,
             services,
             findings,
             collect(distinct { from: svc2.id, to: f2.id }) as serviceFindingPairs
      `, { targetId });
        const rec = res.records[0];
        if (!rec)
            return { target: null, services: [], findings: [], edges: [] };
        const t = rec.get("t").properties;
        const services = rec.get("services").filter(Boolean).map((n) => n.properties);
        const findings = rec.get("findings").filter(Boolean).map((n) => n.properties);
        const pairs = rec.get("serviceFindingPairs").filter((p) => p?.from && p?.to);
        const edges = [
            ...services.map((s) => ({
                id: `t->s:${t.id}:${s.id}`,
                source: `target:${t.id}`,
                target: `service:${s.id}`
            })),
            ...pairs.map((p) => ({
                id: `s->f:${p.from}:${p.to}`,
                source: `service:${p.from}`,
                target: `finding:${p.to}`
            }))
        ];
        const nodes = [
            { id: `target:${t.id}`, kind: "Target", data: t },
            ...services.map((s) => ({ id: `service:${s.id}`, kind: "Service", data: s })),
            ...findings.map((f) => ({ id: `finding:${f.id}`, kind: "Finding", data: f }))
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
