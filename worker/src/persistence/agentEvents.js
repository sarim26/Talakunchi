/**
 * Persistence layer for the MCP recon system.
 *
 * - agent_runs           : one row per orchestrated run
 * - agent_invocations    : one row per tool invocation
 * - agent_events         : append-only telemetry stream (manager decisions,
 *                          tool start/finish, log lines, facts)
 *
 * Tables are created on first import via ensureAgentTables(). Callers obtain
 * an EventSink for a given run and pass it into MCPServer.invoke().
 */
import { withClient } from "../db.js";
import { mitreTechniquesFor } from "./mitre.js";
export async function ensureAgentTables() {
    await withClient(async (c) => {
        await c.query(`
      create table if not exists agent_runs (
        id uuid primary key default uuid_generate_v4(),
        target_id uuid not null references targets(id) on delete cascade,
        status text not null default 'queued',
        cancel_requested boolean not null default false,
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
        // Backfill/upgrade older installs (safe if columns already exist).
        await c.query(`alter table agent_runs add column if not exists cancel_requested boolean not null default false`);
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
        // Confidence + verification metadata on findings (Layer 1).
        // Stored on the row so the API can compute verification status without
        // re-scanning the evidence table for every query.
        await c.query(`alter table findings add column if not exists confidence text not null default 'medium'`);
        await c.query(`alter table findings add column if not exists requires_verification boolean not null default true`);
        await c.query(`alter table findings add column if not exists claim_type text`);
        await c.query(`alter table findings add column if not exists mitre_techniques text[] not null default '{}'`);
        // Evidence chain: every tool observation, plus verifier outcomes
        // (verifier_failed / verifier_no_response) so unverified findings stay
        // unverified instead of silently disappearing.
        await c.query(`
      create table if not exists finding_evidence (
        id uuid primary key default uuid_generate_v4(),
        fingerprint text not null,
        target_id uuid references targets(id) on delete cascade,
        agent_run_id uuid references agent_runs(id) on delete cascade,
        invocation_id uuid references agent_invocations(id) on delete cascade,
        tool text not null,
        status text not null default 'observed',
        evidence text not null default '',
        created_at timestamptz not null default now()
      )
    `);
        await c.query(`create index if not exists idx_finding_evidence_fp on finding_evidence(fingerprint, created_at asc)`);
        await c.query(`create index if not exists idx_finding_evidence_target on finding_evidence(target_id)`);
        await c.query(`create index if not exists idx_finding_evidence_run on finding_evidence(agent_run_id)`);
    });
}
export async function createAgentRun(spec) {
    return withClient(async (c) => {
        const r = await c.query(`insert into agent_runs (
         target_id, status, manager_model, specialist_model, prompter_model, max_steps, notes,
         initial_nmap_profile, initial_nmap_ports, initial_nmap_extra_args
       )
       values ($1, 'queued', $2, $3, $4, $5, $6, $7, $8, $9)
       returning id`, [
            spec.targetId,
            spec.managerModel,
            spec.specialistModel,
            spec.prompterModel,
            spec.maxSteps,
            spec.notes ?? null,
            spec.initialNmapProfile ?? null,
            spec.initialNmapPorts ?? null,
            spec.initialNmapExtraArgs ?? null
        ]);
        return r.rows[0].id;
    });
}
export async function setAgentRunStatus(id, status, extra) {
    await withClient(async (c) => {
        await c.query(`update agent_runs
       set status = $2,
           steps_taken = coalesce($3, steps_taken),
           invocation_count = coalesce($4, invocation_count),
           finding_count = coalesce($5, finding_count),
           service_count = coalesce($6, service_count),
           notes = coalesce($7, notes),
           started_at = case when started_at is null and $2 in ('running','succeeded','failed') then now() else started_at end,
           finished_at = case when $2 in ('succeeded','failed') then now() else finished_at end
       where id = $1`, [
            id,
            status,
            extra?.stepsTaken ?? null,
            extra?.invocationCount ?? null,
            extra?.findingCount ?? null,
            extra?.serviceCount ?? null,
            extra?.notes ?? null
        ]);
    });
}
export function createEventSink(agentRunId) {
    return {
        emitDecision: async (payload) => {
            await withClient(async (c) => {
                await c.query(`insert into agent_events (agent_run_id, kind, payload) values ($1, 'manager.decision', $2::jsonb)`, [agentRunId, JSON.stringify(payload)]);
            });
        },
        invocationStarted: async ({ name, intent, args }) => {
            return withClient(async (c) => {
                const r = await c.query(`insert into agent_invocations (agent_run_id, tool, intent, args, status)
           values ($1, $2, $3, $4::jsonb, 'running')
           returning id`, [agentRunId, name, intent ?? null, JSON.stringify(args ?? {})]);
                const invocationId = r.rows[0].id;
                await c.query(`insert into agent_events (agent_run_id, invocation_id, kind, payload)
           values ($1, $2, 'agent.started', $3::jsonb)`, [agentRunId, invocationId, JSON.stringify({ name, intent })]);
                return invocationId;
            });
        },
        invocationLog: async (invocationId, line) => {
            await withClient(async (c) => {
                await c.query(`update agent_invocations set log = log || $2 where id = $1`, [invocationId, line]);
            });
        },
        invocationFact: async (invocationId, fact) => {
            await withClient(async (c) => {
                await c.query(`insert into agent_events (agent_run_id, invocation_id, kind, payload)
           values ((select agent_run_id from agent_invocations where id = $1), $1, 'agent.fact', $2::jsonb)`, [invocationId, JSON.stringify(fact)]);
            });
        },
        invocationFinished: async (invocationId, envelope) => {
            await withClient(async (c) => {
                await c.query(`update agent_invocations
           set status = $2, envelope = $3::jsonb, finished_at = now()
           where id = $1`, [invocationId, envelope.status, JSON.stringify(envelope)]);
                await c.query(`insert into agent_events (agent_run_id, invocation_id, kind, payload)
           values ((select agent_run_id from agent_invocations where id = $1), $1, 'agent.finished', $2::jsonb)`, [invocationId, JSON.stringify({ status: envelope.status, durationMs: envelope.durationMs, error: envelope.error })]);
            });
        }
    };
}
export async function persistDiscoveredServices(targetId, services) {
    const map = new Map();
    if (services.length === 0)
        return map;
    await withClient(async (c) => {
        for (const s of services) {
            const r = await c.query(`insert into services (target_id, port, protocol, service_name, product, version, banner, first_seen_at, last_seen_at)
         values ($1, $2, $3, $4, $5, $6, $7, now(), now())
         on conflict (target_id, port, protocol)
         do update set service_name = excluded.service_name,
                       product = excluded.product,
                       version = excluded.version,
                       banner = coalesce(excluded.banner, services.banner),
                       last_seen_at = now()
         returning id`, [targetId, s.port, s.protocol, s.name ?? null, s.product ?? null, s.version ?? null, s.banner ?? null]);
            map.set(s.port, r.rows[0].id);
        }
    });
    return map;
}
/**
 * Persist findings + record their evidence chain.
 *
 * Each call writes:
 *   1. an upsert into `findings` (verification metadata stays sticky once high)
 *   2. an `finding_evidence` row with status='observed' per finding
 *   3. when `verifiesFingerprint` is set, an additional 'observed' row keyed
 *      to the original finding — this is what promotes the original to
 *      verificationStatus='confirmed' (Situation 1: gold-standard).
 */
export async function persistFindings(targetId, findings, serviceIdByPort, ctx) {
    if (findings.length === 0)
        return;
    const tool = ctx?.tool ?? "unknown";
    const invocationId = ctx?.invocationId ?? null;
    const agentRunId = ctx?.agentRunId ?? null;
    await withClient(async (c) => {
        for (const f of findings) {
            const fp = f.fingerprint ?? `mcp|${targetId}|${f.title}`;
            const svcId = f.port ? serviceIdByPort.get(f.port) ?? null : null;
            const confidence = f.confidence ?? "medium";
            const requiresVerification = typeof f.requiresVerification === "boolean"
                ? f.requiresVerification
                : confidence !== "high";
            const mitre = mitreTechniquesFor({ title: f.title, claimType: f.claimType });
            await c.query(`insert into findings (
           target_id, service_id, title, severity, status,
           fingerprint, evidence_redacted,
           confidence, requires_verification, claim_type, mitre_techniques,
           first_seen_at, last_seen_at
         )
         values ($1, $2, $3, $4, 'open', $5, $6, $7, $8, $9, $10, now(), now())
         on conflict (fingerprint)
         do update set
           last_seen_at = now(),
           evidence_redacted = excluded.evidence_redacted,
           confidence = case
             when findings.confidence = 'high' then findings.confidence
             else excluded.confidence
           end,
           requires_verification = case
             when findings.confidence = 'high' or excluded.confidence = 'high' then false
             else findings.requires_verification
           end,
           claim_type = coalesce(findings.claim_type, excluded.claim_type),
           mitre_techniques = case
             when array_length(excluded.mitre_techniques, 1) is null then findings.mitre_techniques
             else excluded.mitre_techniques
           end`, [targetId, svcId, f.title, f.severity, fp, f.evidence, confidence, requiresVerification, f.claimType ?? null, mitre]);
            await c.query(`insert into finding_evidence (fingerprint, target_id, agent_run_id, invocation_id, tool, status, evidence)
         values ($1, $2, $3, $4, $5, 'observed', $6)`, [fp, targetId, agentRunId, invocationId, tool, f.evidence]);
            // Situation 1: this tool corroborates a previously emitted claim.
            // We record evidence keyed to the ORIGINAL fingerprint so verifier
            // status calculations can count distinct tools per fingerprint.
            if (f.verifiesFingerprint && f.verifiesFingerprint !== fp) {
                await c.query(`insert into finding_evidence (fingerprint, target_id, agent_run_id, invocation_id, tool, status, evidence)
           values ($1, $2, $3, $4, $5, 'observed', $6)`, [
                    f.verifiesFingerprint,
                    targetId,
                    agentRunId,
                    invocationId,
                    tool,
                    `Corroborated by ${tool}: ${f.evidence}`.slice(0, 1000)
                ]);
            }
        }
    });
}
/**
 * Record that a verifier tool was attempted against a set of fingerprints but
 * did not produce a corroborating observation. This is Situation 3 from the
 * verification design: the original finding stays Unverified (permanent for
 * this run) rather than silently rotting in the Pending bucket.
 */
export async function recordVerifierAttempts(targetId, attempts, ctx) {
    if (attempts.length === 0)
        return;
    await withClient(async (c) => {
        for (const a of attempts) {
            await c.query(`insert into finding_evidence (fingerprint, target_id, agent_run_id, invocation_id, tool, status, evidence)
         values ($1, $2, $3, $4, $5, $6, $7)`, [
                a.fingerprint,
                targetId,
                ctx?.agentRunId ?? null,
                ctx?.invocationId ?? null,
                a.tool,
                a.status,
                a.evidence ?? ""
            ]);
        }
    });
}
