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
import type { ToolEnvelope } from "../mcp/types.js";

export type AgentRunSpec = {
  id: string;
  targetId: string;
  targetHost: string;
  status: "queued" | "running" | "succeeded" | "failed";
  managerModel: string;
  specialistModel: string;
  prompterModel: string;
  maxSteps: number;
  initialNmapProfile?: string | null;
  initialNmapPorts?: number[] | null;
  initialNmapExtraArgs?: string | null;
};

export async function ensureAgentTables() {
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
    // Backfill/upgrade older installs (safe if columns already exist).
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

export async function createAgentRun(spec: Omit<AgentRunSpec, "id" | "status"> & { notes?: string }): Promise<string> {
  return withClient(async (c) => {
    const r = await c.query(
      `insert into agent_runs (
         target_id, status, manager_model, specialist_model, prompter_model, max_steps, notes,
         initial_nmap_profile, initial_nmap_ports, initial_nmap_extra_args
       )
       values ($1, 'queued', $2, $3, $4, $5, $6, $7, $8, $9)
       returning id`,
      [
        spec.targetId,
        spec.managerModel,
        spec.specialistModel,
        spec.prompterModel,
        spec.maxSteps,
        spec.notes ?? null,
        spec.initialNmapProfile ?? null,
        spec.initialNmapPorts ?? null,
        spec.initialNmapExtraArgs ?? null
      ]
    );
    return r.rows[0].id as string;
  });
}

export async function setAgentRunStatus(id: string, status: AgentRunSpec["status"], extra?: Partial<{ stepsTaken: number; invocationCount: number; findingCount: number; serviceCount: number; notes: string }>) {
  await withClient(async (c) => {
    await c.query(
      `update agent_runs
       set status = $2,
           steps_taken = coalesce($3, steps_taken),
           invocation_count = coalesce($4, invocation_count),
           finding_count = coalesce($5, finding_count),
           service_count = coalesce($6, service_count),
           notes = coalesce($7, notes),
           started_at = case when started_at is null and $2 in ('running','succeeded','failed') then now() else started_at end,
           finished_at = case when $2 in ('succeeded','failed') then now() else finished_at end
       where id = $1`,
      [
        id,
        status,
        extra?.stepsTaken ?? null,
        extra?.invocationCount ?? null,
        extra?.findingCount ?? null,
        extra?.serviceCount ?? null,
        extra?.notes ?? null
      ]
    );
  });
}

export type EventSink = {
  emitDecision: (payload: Record<string, unknown>) => Promise<void>;
  invocationStarted: (input: { name: string; intent?: string; args?: unknown }) => Promise<string>;
  invocationLog: (invocationId: string, line: string) => Promise<void>;
  invocationFact: (invocationId: string, fact: { type: string; value: unknown; source?: string }) => Promise<void>;
  invocationFinished: (invocationId: string, envelope: ToolEnvelope) => Promise<void>;
};

export function createEventSink(agentRunId: string): EventSink {
  return {
    emitDecision: async (payload) => {
      await withClient(async (c) => {
        await c.query(
          `insert into agent_events (agent_run_id, kind, payload) values ($1, 'manager.decision', $2::jsonb)`,
          [agentRunId, JSON.stringify(payload)]
        );
      });
    },
    invocationStarted: async ({ name, intent, args }) => {
      return withClient(async (c) => {
        const r = await c.query(
          `insert into agent_invocations (agent_run_id, tool, intent, args, status)
           values ($1, $2, $3, $4::jsonb, 'running')
           returning id`,
          [agentRunId, name, intent ?? null, JSON.stringify(args ?? {})]
        );
        const invocationId = r.rows[0].id as string;
        await c.query(
          `insert into agent_events (agent_run_id, invocation_id, kind, payload)
           values ($1, $2, 'agent.started', $3::jsonb)`,
          [agentRunId, invocationId, JSON.stringify({ name, intent })]
        );
        return invocationId;
      });
    },
    invocationLog: async (invocationId, line) => {
      await withClient(async (c) => {
        await c.query(
          `update agent_invocations set log = log || $2 where id = $1`,
          [invocationId, line]
        );
      });
    },
    invocationFact: async (invocationId, fact) => {
      await withClient(async (c) => {
        await c.query(
          `insert into agent_events (agent_run_id, invocation_id, kind, payload)
           values ((select agent_run_id from agent_invocations where id = $1), $1, 'agent.fact', $2::jsonb)`,
          [invocationId, JSON.stringify(fact)]
        );
      });
    },
    invocationFinished: async (invocationId, envelope) => {
      await withClient(async (c) => {
        await c.query(
          `update agent_invocations
           set status = $2, envelope = $3::jsonb, finished_at = now()
           where id = $1`,
          [invocationId, envelope.status, JSON.stringify(envelope)]
        );
        await c.query(
          `insert into agent_events (agent_run_id, invocation_id, kind, payload)
           values ((select agent_run_id from agent_invocations where id = $1), $1, 'agent.finished', $2::jsonb)`,
          [invocationId, JSON.stringify({ status: envelope.status, durationMs: envelope.durationMs, error: envelope.error })]
        );
      });
    }
  };
}

export async function persistDiscoveredServices(targetId: string, services: Array<{ port: number; protocol: string; name?: string; product?: string; version?: string; banner?: string }>): Promise<Map<number, string>> {
  const map = new Map<number, string>();
  if (services.length === 0) return map;
  await withClient(async (c) => {
    for (const s of services) {
      const r = await c.query(
        `insert into services (target_id, port, protocol, service_name, product, version, banner, first_seen_at, last_seen_at)
         values ($1, $2, $3, $4, $5, $6, $7, now(), now())
         on conflict (target_id, port, protocol)
         do update set service_name = excluded.service_name,
                       product = excluded.product,
                       version = excluded.version,
                       banner = coalesce(excluded.banner, services.banner),
                       last_seen_at = now()
         returning id`,
        [targetId, s.port, s.protocol, s.name ?? null, s.product ?? null, s.version ?? null, s.banner ?? null]
      );
      map.set(s.port, r.rows[0].id);
    }
  });
  return map;
}

export async function persistFindings(targetId: string, findings: Array<{ title: string; severity: string; port?: number | null; protocol?: string | null; evidence: string; fingerprint?: string }>, serviceIdByPort: Map<number, string>) {
  if (findings.length === 0) return;
  await withClient(async (c) => {
    for (const f of findings) {
      const fp = f.fingerprint ?? `mcp|${targetId}|${f.title}`;
      const svcId = f.port ? serviceIdByPort.get(f.port) ?? null : null;
      await c.query(
        `insert into findings (target_id, service_id, title, severity, status, fingerprint, evidence_redacted, first_seen_at, last_seen_at)
         values ($1, $2, $3, $4, 'open', $5, $6, now(), now())
         on conflict (fingerprint)
         do update set last_seen_at = now(), evidence_redacted = excluded.evidence_redacted`,
        [targetId, svcId, f.title, f.severity, fp, f.evidence]
      );
    }
  });
}
