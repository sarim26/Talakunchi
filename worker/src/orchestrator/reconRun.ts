/**
 * Recon orchestrator — manager LLM → prompter → (execution writer) → tool invoke.
 *
 * The manager chooses the next tool from the manifest (see manager.ts for the
 * only non-LLM overrides: blocked-tool retry and missing-tool installer).
 * The prompter turns intent into prose; executionCommandWriter fills argSchema
 * when present; then the MCP tool runs and results merge into context.
 */
import { env } from "../env.js";
import { withClient } from "../db.js";
import { rebuildNeo4jForTarget, upsertNeo4jTarget } from "../neo4jSync.js";
import { buildReconMCPServer } from "../agents/registry.js";
import { decideNextAction, getLastManagerOllamaError, type ManagerContext } from "../agents/manager.js";
import { extractToolOutputHints, recommendationsFromOutputHints } from "../agents/outputHints.js";
import { generatePrompt } from "../agents/prompter.js";
import { draftExecutionPayload, shouldUseExecutionWriter } from "../agents/executionCommandWriter.js";
import { getWordlistCatalog } from "../agents/wordlists.js";
import { pickVerifierFor } from "../agents/verification.js";
import { isHostInScope, resolveEngagementScope } from "../scope.js";
import { emptyWebScanHints, mergeWebScanHints, webScanFromEnvelopeMeta, type WebScanHints } from "../agents/webTarget.js";
import {
  createEventSink,
  createAgentRun,
  ensureAgentTables,
  persistDiscoveredServices,
  persistFindings,
  recordVerifierAttempts,
  setAgentRunStatus
} from "../persistence/agentEvents.js";
import type { ToolEnvelope, ToolFinding } from "../mcp/types.js";

export type StartReconRunInput = {
  targetId: string;
  notes?: string;
  maxSteps?: number;
  initialNmap?: {
    profile?: "fast" | "targeted" | "deep" | "full";
    ports?: number[];
    extraArgs?: string;
  };
};

export async function startReconRun(input: StartReconRunInput): Promise<string> {
  await ensureAgentTables();
  const target = await withClient(async (c) => {
    const r = await c.query(`select id, name, address from targets where id = $1`, [input.targetId]);
    return r.rows[0] as { id: string; name: string; address: string } | undefined;
  });
  if (!target) throw new Error(`Target not found: ${input.targetId}`);

  const runId = await createAgentRun({
    targetId: target.id,
    targetHost: target.address,
    managerModel: env.OLLAMA_MANAGER_MODEL,
    specialistModel: env.executionWriterModel,
    prompterModel: env.OLLAMA_PROMPTER_MODEL,
    maxSteps: input.maxSteps ?? env.RECON_MAX_STEPS,
    notes: input.notes,
    initialNmapProfile: input.initialNmap?.profile ?? "deep",
    initialNmapPorts: input.initialNmap?.ports ?? null,
    initialNmapExtraArgs: input.initialNmap?.extraArgs ?? null
  });

  await withClient(async (c) => {
    await c.query(
      `insert into jobs (type, status, payload) values ('recon-mcp', 'queued', $1::jsonb)`,
      [JSON.stringify({ agentRunId: runId, targetId: target.id })]
    );
  });

  return runId;
}

/** Operator-triggered second phase: gated exploit tools on the same agent run. */
export async function startExploitPhase(agentRunId: string, maxSteps = 8): Promise<void> {
  await queueExploitPhase(agentRunId, maxSteps);
}

/** Re-queue recon phase on a finished run (same run id, fresh recon steps). */
export async function restartReconPhase(agentRunId: string, maxSteps = 20): Promise<void> {
  await ensureAgentTables();
  const updated = await withClient(async (c) => {
    const r = await c.query(
      `update agent_runs
       set phase = 'recon', status = 'queued', max_steps = $2, steps_taken = 0,
           finished_at = null, cancel_requested = false, started_at = null
       where id = $1 and status = 'succeeded'
       returning target_id`,
      [agentRunId, maxSteps]
    );
    return r.rows[0] as { target_id: string } | undefined;
  });
  if (!updated) throw new Error("Run is not eligible for recon restart (must be succeeded)");

  await withClient(async (c) => {
    await c.query(`insert into jobs (type, status, payload) values ('recon-mcp', 'queued', $1::jsonb)`, [
      JSON.stringify({ agentRunId, targetId: updated.target_id, phase: "recon" })
    ]);
    await c.query(`insert into agent_events (agent_run_id, kind, payload) values ($1, 'run.recon_restarted', $2::jsonb)`, [
      agentRunId,
      JSON.stringify({ maxSteps })
    ]);
  });
}

/** Re-queue exploit phase (from completed recon or re-run after completed exploit). */
export async function restartExploitPhase(agentRunId: string, maxSteps = 8): Promise<void> {
  await queueExploitPhase(agentRunId, maxSteps, { allowExploitRerun: true });
}

async function queueExploitPhase(
  agentRunId: string,
  maxSteps: number,
  opts?: { allowExploitRerun?: boolean }
): Promise<void> {
  await ensureAgentTables();
  const phaseClause = opts?.allowExploitRerun
    ? `and status = 'succeeded'`
    : `and status = 'succeeded' and coalesce(phase, 'recon') = 'recon'`;

  const updated = await withClient(async (c) => {
    const r = await c.query(
      `update agent_runs
       set phase = 'exploit', status = 'queued', max_steps = $2, steps_taken = 0,
           finished_at = null, cancel_requested = false, started_at = null
       where id = $1 ${phaseClause}
       returning target_id`,
      [agentRunId, maxSteps]
    );
    return r.rows[0] as { target_id: string } | undefined;
  });
  if (!updated) {
    throw new Error(
      opts?.allowExploitRerun
        ? "Run is not eligible for exploit restart (must be succeeded)"
        : "Run is not eligible for exploit phase (must be succeeded recon)"
    );
  }

  await withClient(async (c) => {
    await c.query(`insert into jobs (type, status, payload) values ('recon-mcp', 'queued', $1::jsonb)`, [
      JSON.stringify({ agentRunId, targetId: updated.target_id, phase: "exploit" })
    ]);
    await c.query(`insert into agent_events (agent_run_id, kind, payload) values ($1, 'run.exploit_queued', $2::jsonb)`, [
      agentRunId,
      JSON.stringify({ maxSteps, rerun: Boolean(opts?.allowExploitRerun) })
    ]);
  });
}

async function hydrateManagerContextFromDb(
  agentRunId: string,
  targetId: string
): Promise<Pick<
  ManagerContext,
  "knownPorts" | "knownServices" | "knownFindings" | "discoveredEndpoints" | "invocationHistory" | "webScan" | "toolFacts"
>> {
  const services = await withClient(async (c) => {
    const r = await c.query(
      `select port, protocol, service_name, product, version from services where target_id = $1 order by port asc`,
      [targetId]
    );
    return r.rows as Array<{ port: number; protocol: string; service_name: string | null; product: string | null; version: string | null }>;
  });

  const invocations = await withClient(async (c) => {
    const r = await c.query(
      `select tool, status, envelope from agent_invocations where agent_run_id = $1 order by started_at asc`,
      [agentRunId]
    );
    return r.rows as Array<{ tool: string; status: string; envelope: ToolEnvelope | null }>;
  });

  const findings = await withClient(async (c) => {
    const r = await c.query(
      `select title, severity, fingerprint, evidence_redacted, confidence, requires_verification, claim_type
       from findings where target_id = $1 order by last_seen_at desc limit 120`,
      [targetId]
    );
    return r.rows as Array<{
      title: string;
      severity: string;
      fingerprint: string;
      evidence_redacted: string;
      confidence: string;
      requires_verification: boolean;
      claim_type: string | null;
    }>;
  });

  const knownServices = services.map((s) => ({
    port: s.port,
    protocol: s.protocol,
    name: s.service_name ?? undefined,
    product: s.product ?? undefined,
    version: s.version ?? undefined
  }));
  const knownPorts = [...new Set(knownServices.map((s) => s.port))];

  const discoveredEndpoints: ManagerContext["discoveredEndpoints"] = [];
  const endpointSeen = new Set<string>();
  const toolFacts: ManagerContext["toolFacts"] = [];
  let webScan: WebScanHints = emptyWebScanHints("", null);

  const interestingFactTypes = new Set([
    "msf_search",
    "msf_summary",
    "msf_module_missing",
    "msf_result",
    "sqlmap_summary",
    "commix_summary",
    "sqli"
  ]);

  for (const inv of invocations) {
    const env = inv.envelope;
    if (!env) continue;
    const metaPatch = webScanFromEnvelopeMeta(env.meta as Record<string, unknown> | undefined);
    if (metaPatch) webScan = mergeWebScanHints(webScan, metaPatch);
    for (const f of env.facts ?? []) {
      if (interestingFactTypes.has(f.type)) {
        toolFacts.push({ type: f.type, value: f.value, source: f.source });
      }
      if (f.type === "virtual_host" && f.value && typeof f.value === "object") {
        const vv = f.value as { vhost?: string; connectIp?: string; cdnVendor?: string };
        if (vv.vhost) {
          webScan = mergeWebScanHints(webScan, {
            vhost: vv.vhost,
            connectIp: vv.connectIp ?? webScan.connectIp,
            cdnVendor: vv.cdnVendor ?? webScan.cdnVendor,
            cdnDetected: true
          });
        }
      }
      if (f.type !== "web_url" && f.type !== "web_path" && f.type !== "http_endpoint") continue;
      const v = (f.value ?? {}) as { url?: string; method?: string; status?: number | null };
      if (!v.url) continue;
      const method = v.method ?? "GET";
      const key = `${method} ${v.url}`;
      if (endpointSeen.has(key)) continue;
      endpointSeen.add(key);
      discoveredEndpoints.push({ url: v.url, method, status: typeof v.status === "number" ? v.status : null, sourceTool: inv.tool });
    }
  }

  const knownFindings: ToolFinding[] = findings.map((f) => ({
    title: f.title,
    severity: f.severity as ToolFinding["severity"],
    evidence: f.evidence_redacted,
    fingerprint: f.fingerprint,
    confidence: (f.confidence as ToolFinding["confidence"]) ?? "medium",
    requiresVerification: f.requires_verification,
    claimType: f.claim_type ?? undefined
  }));

  const invocationHistory = invocations.map((inv) => ({
    tool: inv.tool,
    status: inv.status,
    summary: `${inv.tool} (${inv.status})`
  }));

  return { knownPorts, knownServices, knownFindings, discoveredEndpoints, invocationHistory, webScan, toolFacts };
}

async function loadPipelineScopeConfig(): Promise<{ allowedCidrs: string[]; enforceScope: boolean }> {
  const cfg = await withClient(async (c) => {
    const r = await c.query(`select config from pipeline_configs where id = 1`);
    return r.rows[0]?.config as { allowedCidrs?: unknown; enforceScope?: unknown } | undefined;
  }).catch(() => undefined);
  const allowedCidrs = Array.isArray(cfg?.allowedCidrs)
    ? (cfg!.allowedCidrs as unknown[]).filter((x): x is string => typeof x === "string")
    : [];
  return { allowedCidrs, enforceScope: cfg?.enforceScope === true };
}

export async function runReconLoop(agentRunId: string): Promise<void> {
  await ensureAgentTables();
  await withClient(async (c) => {
    await c.query(`alter table targets add column if not exists vhost text`);
    await c.query(`alter table targets add column if not exists scope text[] not null default '{}'::text[]`);
    await c.query(`alter table targets add column if not exists hydra_userlist text`);
    await c.query(`alter table targets add column if not exists hydra_passlist text`);
    await c.query(`alter table targets add column if not exists hydra_username text`);
    await c.query(`alter table targets add column if not exists hydra_password text`);
  });

  const data = await withClient(async (c) => {
    const r = await c.query(
      `select ar.id, ar.target_id, ar.max_steps, ar.phase,
              ar.initial_nmap_profile, ar.initial_nmap_ports, ar.initial_nmap_extra_args,
              t.name as target_name, t.address as target_address, t.vhost as target_vhost,
              t.scope as target_scope,
              t.hydra_userlist, t.hydra_passlist, t.hydra_username, t.hydra_password
       from agent_runs ar
       join targets t on t.id = ar.target_id
       where ar.id = $1`,
      [agentRunId]
    );
    return r.rows[0] as
      | {
          id: string;
          target_id: string;
          max_steps: number;
          phase: string | null;
          initial_nmap_profile: string | null;
          initial_nmap_ports: number[] | null;
          initial_nmap_extra_args: string | null;
          target_name: string;
          target_address: string;
          target_vhost: string | null;
          target_scope: string[] | null;
          hydra_userlist: string | null;
          hydra_passlist: string | null;
          hydra_username: string | null;
          hydra_password: string | null;
        }
      | undefined;
  });
  if (!data) throw new Error(`agent_run ${agentRunId} not found`);
  const run = data;
  const runPhase: "recon" | "exploit" = run.phase === "exploit" ? "exploit" : "recon";

  if (runPhase === "exploit" && env.RECON_MODE !== "gated_exploit") {
    await setAgentRunStatus(agentRunId, "failed", {
      notes: "Exploit phase requires RECON_MODE=gated_exploit on the worker"
    });
    return;
  }

  const pipelineScope = await loadPipelineScopeConfig();
  const scope = resolveEngagementScope({
    targetAddress: run.target_address,
    targetVhost: run.target_vhost,
    targetScope: run.target_scope,
    envScope: env.AGENT_SCOPE,
    pipelineAllowedCidrs: pipelineScope.allowedCidrs,
    pipelineEnforceScope: pipelineScope.enforceScope
  });
  if (scope.enforce && !isHostInScope(run.target_address, scope.entries)) {
    const reason = `Target ${run.target_address} is outside the configured engagement scope (${scope.entries.join(", ") || "none"}).`;
    await withClient(async (c) => {
      await c.query(
        `insert into audit_events (actor, action, target, payload) values ('worker', 'recon.scope.blocked', $1, $2::jsonb)`,
        [run.target_address, JSON.stringify({ agentRunId, entries: scope.entries })]
      );
    });
    await setAgentRunStatus(agentRunId, "failed", { notes: reason });
    return;
  }

  await setAgentRunStatus(agentRunId, "running");

  const server = buildReconMCPServer();
  const sink = createEventSink(agentRunId);

  const ac = new AbortController();
  let cancelSeen = false;
  const cancelPoll = setInterval(async () => {
    if (cancelSeen) return;
    const cancelRequested = await withClient(async (c) => {
      const res = await c.query(`select cancel_requested from agent_runs where id=$1`, [agentRunId]);
      return Boolean(res.rows?.[0]?.cancel_requested);
    }).catch(() => false);
    if (cancelRequested) {
      cancelSeen = true;
      ac.abort();
    }
  }, 1000);

  const wordlistCatalog = await getWordlistCatalog().catch(() => undefined);
  await withClient(async (c) => {
    await c.query(
      `insert into agent_events (agent_run_id, kind, payload) values ($1, 'wordlist.catalog', $2::jsonb)`,
      [
        agentRunId,
        JSON.stringify({
          root: wordlistCatalog?.root,
          rootExists: !!wordlistCatalog?.rootExists,
          totalEntries: wordlistCatalog?.entries.length ?? 0,
          defaults: wordlistCatalog?.defaults ?? null
        })
      ]
    );
  });

  const targetVhost = run.target_vhost?.trim() || null;
  const webScan: WebScanHints = emptyWebScanHints(run.target_address, targetVhost);

  const hydrated =
    runPhase === "exploit"
      ? await hydrateManagerContextFromDb(agentRunId, run.target_id)
      : null;

  const engagementCreds = {
    username: run.hydra_username,
    password: run.hydra_password,
    userlist: run.hydra_userlist,
    passlist: run.hydra_passlist
  };

  const ctx: ManagerContext = {
    targetHost: run.target_address,
    targetName: run.target_name,
    stepsRemaining: run.max_steps,
    knownPorts: hydrated?.knownPorts ?? [],
    knownServices: hydrated?.knownServices ?? [],
    knownFindings: hydrated?.knownFindings ?? [],
    knownDomains: [],
    discoveredEndpoints: hydrated?.discoveredEndpoints ?? [],
    webScan: hydrated?.webScan?.vhost
      ? mergeWebScanHints(webScan, hydrated.webScan)
      : webScan,
    pendingVerifications: [],
    invocationHistory: hydrated?.invocationHistory ?? [],
    toolFacts: hydrated?.toolFacts ?? [],
    pendingRecommendations: [],
    wordlistCatalog,
    recentFailures: [],
    recentToolOutputs: [],
    installedToolsAttempted: [],
    installedToolsInstalled: [],
    blockedOnMissingTool: null,
    runPhase,
    engagementCreds,
    runHints: {
      initialNmapProfile: run.initial_nmap_profile,
      initialNmapPorts: run.initial_nmap_ports,
      initialNmapExtraArgs: run.initial_nmap_extra_args
    }
  };

  const allFindings: ToolFinding[] = [];
  const attemptsByTool = new Map<string, number>();
  let hadFailure = false;

  /**
   * Run a single tool inside the current step. Returns the produced envelope +
   * invocationId so the caller can merge results back into `ctx` (sequentially,
   * outside any Promise.all so we never race on shared state).
   */
  async function runSingleTool(
    step: number,
    toolName: string,
    intentGoal: string,
    args: Record<string, unknown> | undefined
  ): Promise<{ toolName: string; intentGoal: string; args: Record<string, unknown> | undefined; invocationId: string; envelope: ToolEnvelope } | null> {
    const toolDef = server.list().find((t) => t.name === toolName);
    if (!toolDef) {
      await sink.emitDecision({ step, error: `Manager picked unknown tool ${toolName}` });
      return null;
    }

    // If the manager is re-invoking a tool that was previously blocked on a
    // missing dependency, clear the block so we don't keep forcing retries.
    if (ctx.blockedOnMissingTool && ctx.blockedOnMissingTool.tool === toolName) {
      ctx.blockedOnMissingTool = null;
    }

    const selectedWordlist = typeof args?.wordlist === "string" ? String(args.wordlist) : undefined;
    const prompt = await generatePrompt({
      agent: toolDef,
      intentGoal,
      targetHost: run.target_address,
      knownPorts: ctx.knownPorts,
      knownServices: ctx.knownServices,
      wordlistCatalog,
      selectedWordlist,
      discoveredEndpoints: ctx.discoveredEndpoints
    });
    await withClient(async (c) => {
      await c.query(
        `insert into agent_events (agent_run_id, kind, payload) values ($1, 'prompter.output', $2::jsonb)`,
        [agentRunId, JSON.stringify({ step, tool: toolDef.name, prompt })]
      );
    });

    // For tools with structured argSchema, run the execution-writer LLM after the prompter.
    // It turns the prompter prose into a JSON args payload merged with what
    // the manager already provided, then we hand off to the tool with a
    // short execution-only intent (the rich text stays in telemetry).
    let invokeArgs: Record<string, unknown> = args ?? {};
    let invokeIntent: string = prompt;
    if (shouldUseExecutionWriter(toolDef)) {
      const writer = await draftExecutionPayload({
        tool: toolDef,
        prompterText: prompt,
        intentGoal,
        managerArgs: args,
        context: {
          target: {
            targetId: run.target_id,
            host: run.target_address,
            vhost: targetVhost ?? undefined,
            name: run.target_name
          },
          knownPorts: ctx.knownPorts,
          knownServices: ctx.knownServices,
          discoveredEndpoints: ctx.discoveredEndpoints,
          priorFindings: allFindings,
          wordlistCatalog,
          webScan: ctx.webScan,
          scopeEntries: scope.entries,
          scopeEnforce: scope.enforce
        }
      });
      invokeArgs = writer.finalArgs;
      invokeIntent = `Execute ${toolDef.name} with the supplied args. Do not infer a different target or scope.`;
      await withClient(async (c) => {
        await c.query(
          `insert into agent_events (agent_run_id, kind, payload) values ($1, 'execution_writer.output', $2::jsonb)`,
          [
            agentRunId,
            JSON.stringify({
              step,
              tool: toolDef.name,
              source: writer.source,
              model: writer.modelUsed,
              draftArgs: writer.draftArgs,
              finalArgs: writer.finalArgs,
              diag: writer.diag ?? null
            })
          ]
        );
      });
    }

    const { invocationId, envelope } = await server.invoke(
      toolDef.name,
      {
        target: {
          targetId: run.target_id,
          host: run.target_address,
          vhost: targetVhost ?? undefined,
          name: run.target_name
        },
        intent: invokeIntent,
        args: invokeArgs,
        signal: ac.signal,
        context: {
          knownPorts: ctx.knownPorts,
          knownServices: ctx.knownServices,
          knownDomains: ctx.knownDomains ?? [],
          priorFindings: allFindings,
          discoveredEndpoints: ctx.discoveredEndpoints.map((e) => ({
            url: e.url,
            method: e.method,
            status: e.status,
            sourceTool: e.sourceTool
          })),
          webScan: ctx.webScan,
          scopeEntries: scope.entries,
          scopeEnforce: scope.enforce,
          engagementCreds,
          knownPresentTools: ctx.installedToolsInstalled ?? [],
          runId: agentRunId,
          invocationId: ""
        }
      },
      sink
    );
    return { toolName: toolDef.name, intentGoal, args: invokeArgs, invocationId, envelope };
  }

  /**
   * Merge a single invocation's envelope into the shared `ctx` and persist
   * services/findings. Runs serially so we never race on shared state.
   */
  async function mergeEnvelope(
    step: number,
    toolName: string,
    args: Record<string, unknown> | undefined,
    invocationId: string,
    envelope: ToolEnvelope
  ) {
    if (envelope.status === "failed") {
      hadFailure = true;
      const prev = attemptsByTool.get(toolName) ?? 0;
      attemptsByTool.set(toolName, prev + 1);

      const meta = envelope.meta as Record<string, unknown> | undefined;
      const presenceCheckFailed = meta?.presenceCheckFailed === true;
      const missingTool = typeof meta?.missingTool === "string" ? String(meta.missingTool) : undefined;
      const missingToolInstallCommand =
        typeof meta?.missingToolInstallCommand === "string" ? String(meta.missingToolInstallCommand) : undefined;

      const failure = {
        tool: toolName,
        attempt: prev,
        args: (args ?? {}) as Record<string, unknown>,
        error: envelope.error,
        stdoutSnippet: envelope.artifacts?.stdoutSnippet,
        stderrSnippet: envelope.artifacts?.stderrSnippet,
        missingTool,
        missingToolInstallCommand,
        presenceCheckFailed
      };
      ctx.recentFailures = [...(ctx.recentFailures ?? []), failure].slice(-10);

      await withClient(async (c) => {
        await c.query(
          `insert into agent_events (agent_run_id, kind, payload) values ($1, 'agent.failure', $2::jsonb)`,
          [agentRunId, JSON.stringify({ step, ...failure })]
        );
      });

      // SSH flake / presence timeout — do NOT apt-install. Retry the specialist once.
      if (presenceCheckFailed) {
        if (prev < 1) {
          ctx.pendingRecommendations.unshift({
            agent: toolName,
            reason: `Presence check failed (SSH flake?) for ${toolName} — retry without installer`,
            priority: 96,
            args: (args ?? {}) as Record<string, unknown>
          });
        }
      } else if (missingTool) {
        const alreadyProven =
          (ctx.installedToolsInstalled ?? []).includes(missingTool) ||
          toolAlreadyProvenThisRun(ctx, missingTool);
        if (alreadyProven) {
          // e.g. nmap already succeeded earlier — false "missing" from flaky SSH.
          if (prev < 1) {
            ctx.pendingRecommendations.unshift({
              agent: toolName,
              reason: `'${missingTool}' already worked this run — retry ${toolName} (skip installer)`,
              priority: 97,
              args: (args ?? {}) as Record<string, unknown>
            });
          }
        } else {
          ctx.blockedOnMissingTool = { tool: toolName, args: (args ?? {}) as Record<string, unknown>, missingTool };
          if (server.has("system.tool_installer") && !(ctx.installedToolsAttempted ?? []).includes(missingTool)) {
            const installArgs: Record<string, unknown> = { tool: missingTool };
            if (missingToolInstallCommand) installArgs.installCommand = missingToolInstallCommand;
            ctx.pendingRecommendations.unshift({
              agent: "system.tool_installer",
              reason: `Install missing tool '${missingTool}' for ${toolName}`,
              priority: 100,
              args: installArgs
            });
          }
        }
      } else if (prev < 1) {
        ctx.pendingRecommendations.unshift({
          agent: toolName,
          reason: `Recover from failure: ${envelope.error ?? "unknown error"}`,
          priority: 95
        });
      }
    }

    // Mark binaries proven by successful specialists so later false "missing" checks skip apt.
    if (envelope.status === "succeeded" || envelope.status === "partial") {
      const proven = inferProvenBinary(toolName);
      if (proven) {
        const ok = ctx.installedToolsInstalled ?? [];
        if (!ok.includes(proven)) ctx.installedToolsInstalled = [...ok, proven];
      }
    }

    if (toolName === "system.tool_installer") {
      const installedTool = (args as { tool?: string } | undefined)?.tool;
      if (installedTool) {
        const list = ctx.installedToolsAttempted ?? [];
        if (!list.includes(installedTool)) ctx.installedToolsAttempted = [...list, installedTool];
        if (envelope.status === "succeeded") {
          const ok = ctx.installedToolsInstalled ?? [];
          if (!ok.includes(installedTool)) ctx.installedToolsInstalled = [...ok, installedTool];
        }
      }
    }

    const newServices = (envelope.facts ?? [])
      .filter((f) => f.type === "service")
      .map((f) => f.value as { port: number; protocol: string; name?: string; product?: string; version?: string; banner?: string });

    const serviceIdByPort = newServices.length > 0
      ? await persistDiscoveredServices(run.target_id, newServices)
      : new Map<number, string>();
    if (envelope.findings?.length) {
      await persistFindings(run.target_id, envelope.findings, serviceIdByPort, {
        tool: toolName,
        invocationId,
        agentRunId
      });
      allFindings.push(...envelope.findings);
    }

    for (const svc of newServices) {
      if (!ctx.knownServices.some((k) => k.port === svc.port && k.protocol === svc.protocol)) {
        ctx.knownServices.push(svc);
      }
      if (!ctx.knownPorts.includes(svc.port)) ctx.knownPorts.push(svc.port);
    }

    // Layer 3: merge web URLs into discoveredEndpoints so the manager sees
    // them on subsequent steps. We dedupe on URL+method.
    const webFacts = (envelope.facts ?? []).filter(
      (f) => f.type === "web_url" || f.type === "web_path" || f.type === "http_endpoint"
    );
    for (const wf of webFacts) {
      const v = (wf.value ?? {}) as { url?: string; method?: string; status?: number | null };
      if (!v.url) continue;
      const method = v.method ?? "GET";
      if (ctx.discoveredEndpoints.some((e) => e.url === v.url && (e.method ?? "GET") === method)) continue;
      ctx.discoveredEndpoints.push({
        url: v.url,
        method,
        status: typeof v.status === "number" ? v.status : null,
        sourceTool: toolName
      });
    }

    for (const f of envelope.facts ?? []) {
      if (
        f.type === "msf_search" ||
        f.type === "msf_summary" ||
        f.type === "msf_module_missing" ||
        f.type === "msf_result" ||
        f.type === "sqlmap_summary" ||
        f.type === "commix_summary" ||
        f.type === "sqli"
      ) {
        ctx.toolFacts = [...(ctx.toolFacts ?? []), { type: f.type, value: f.value, source: f.source }];
      }
      if (f.type === "subdomain" && typeof f.value === "string") {
        const sd = f.value.trim();
        if (sd && !(ctx.knownDomains ?? []).includes(sd)) {
          ctx.knownDomains = [...(ctx.knownDomains ?? []), sd];
        }
      }
      if (f.type === "virtual_host" && f.value && typeof f.value === "object") {
        const vv = f.value as { vhost?: string; connectIp?: string; cdnVendor?: string };
        if (vv.vhost) {
          ctx.webScan = mergeWebScanHints(ctx.webScan, {
            vhost: vv.vhost,
            connectIp: vv.connectIp ?? ctx.webScan.connectIp,
            cdnVendor: vv.cdnVendor ?? ctx.webScan.cdnVendor,
            cdnDetected: true
          });
        }
      }
    }

    const metaPatch = webScanFromEnvelopeMeta(envelope.meta as Record<string, unknown> | undefined);
    if (metaPatch) {
      ctx.webScan = mergeWebScanHints(ctx.webScan, metaPatch);
    }

    ctx.invocationHistory.push({
      tool: toolName,
      status: envelope.status,
      summary: `${envelope.findings?.length ?? 0} findings, ${envelope.facts?.length ?? 0} facts`
    });

    // Capture stdout snippets + plain-English retry hints for ALL tools (recon + exploit).
    {
      const stdoutSnippet = envelope.artifacts?.stdoutSnippet;
      const stderrSnippet = envelope.artifacts?.stderrSnippet;
      const combined = `${stdoutSnippet ?? ""}\n${stderrSnippet ?? ""}\n${envelope.error ?? ""}`;
      const hints = extractToolOutputHints(toolName, combined, args);
      const metaHints = (envelope.meta as { outputHints?: Array<{ plainEnglish?: string; suggestedArgs?: Record<string, unknown> }> } | undefined)
        ?.outputHints;
      const mergedHints = [
        ...hints,
        ...(Array.isArray(metaHints)
          ? metaHints.map((h) => ({
              plainEnglish: h.plainEnglish ?? "",
              suggestedArgs: h.suggestedArgs
            }))
          : [])
      ].filter((h) => h.plainEnglish);

      let factPlain: string | undefined;
      for (const f of envelope.facts ?? []) {
        if (f.value && typeof f.value === "object" && "plainEnglish" in (f.value as object)) {
          const pe = (f.value as { plainEnglish?: string }).plainEnglish;
          if (pe?.trim()) {
            factPlain = pe.trim();
            break;
          }
        }
      }

      const plain = mergedHints[0]?.plainEnglish || factPlain || undefined;
      ctx.recentToolOutputs = [
        ...(ctx.recentToolOutputs ?? []),
        {
          tool: toolName,
          status: envelope.status,
          plainEnglish: plain,
          stdoutSnippet: stdoutSnippet ? String(stdoutSnippet).slice(0, 1800) : undefined,
          stderrSnippet: stderrSnippet ? String(stderrSnippet).slice(0, 600) : undefined,
          suggestedArgs: mergedHints.find((h) => h.suggestedArgs)?.suggestedArgs,
          hints: mergedHints.map((h) => h.plainEnglish).slice(0, 4)
        }
      ].slice(-10);

      const autoRecs = recommendationsFromOutputHints(toolName, mergedHints, args);
      for (const rec of autoRecs) {
        const exists = (envelope.recommendations ?? []).some(
          (r) => r.agent === rec.agent && JSON.stringify(r.args ?? {}) === JSON.stringify(rec.args ?? {})
        );
        if (!exists) {
          (envelope.recommendations as ToolEnvelope["recommendations"]) = [
            ...(envelope.recommendations ?? []),
            rec
          ];
        }
      }
    }

    const incomingRecs = envelope.recommendations ?? [];
    for (const rec of incomingRecs) {
      const dup = ctx.pendingRecommendations.some(
        (p) => p.agent === rec.agent && JSON.stringify(p.args ?? {}) === JSON.stringify(rec.args ?? {})
      );
      if (!dup) ctx.pendingRecommendations.push(rec);
    }

    // Drop only prior queued recs for this tool that we just consumed (keep NEW follow-ups from this envelope).
    ctx.pendingRecommendations = ctx.pendingRecommendations.filter((p) => {
      if (p.agent !== toolName) return true;
      if (incomingRecs.some((r) => r.agent === p.agent && JSON.stringify(r.args ?? {}) === JSON.stringify(p.args ?? {}))) {
        return true;
      }
      return false;
    });

    // Session loop: once credentials are confirmed, queue gated read-only post-ex (exploit phase only).
    if (
      ctx.runPhase === "exploit" &&
      server.has("postex.session_recon") &&
      (envelope.findings ?? []).some((f) => f.claimType === "weak_credentials") &&
      !ctx.pendingRecommendations.some((p) => p.agent === "postex.session_recon")
    ) {
      ctx.pendingRecommendations.unshift({
        agent: "postex.session_recon",
        reason: "Weak credentials confirmed; run gated read-only post-exploitation session recon.",
        priority: 85
      });
    }

    ctx.knownFindings.push(...envelope.findings.slice(0, 3));

    await reconcileVerifications(toolName, invocationId, envelope);
  }

  /**
   * Maintain the verification queue after each tool runs:
   *  1. Any fingerprint corroborated by this envelope (via `verifiesFingerprint`)
   *     is removed from the pending queue.
   *  2. If this tool was a queued verifier and it did not corroborate its target
   *     fingerprint, record a `verifier_no_response` so the original finding
   *     moves Pending -> Unverified instead of lingering.
   *  3. New open-port findings that still require verification are enqueued.
   */
  async function reconcileVerifications(
    toolName: string,
    invocationId: string,
    envelope: ToolEnvelope
  ) {
    const corroborated = new Set(
      (envelope.findings ?? [])
        .map((f) => f.verifiesFingerprint)
        .filter((fp): fp is string => typeof fp === "string" && fp.length > 0)
    );
    if (corroborated.size > 0) {
      ctx.pendingVerifications = ctx.pendingVerifications.filter((p) => !corroborated.has(p.fingerprint));
    }

    const attemptedByThisTool = ctx.pendingVerifications.filter((p) => p.verifierTool === toolName);
    if (attemptedByThisTool.length > 0) {
      const failures = attemptedByThisTool.filter((p) => !corroborated.has(p.fingerprint));
      if (failures.length > 0) {
        await recordVerifierAttempts(
          run.target_id,
          failures.map((p) => ({
            fingerprint: p.fingerprint,
            tool: toolName,
            status: "verifier_no_response" as const,
            evidence: `Verifier ${toolName} ran but did not corroborate ${p.fingerprint}`
          })),
          { invocationId, agentRunId }
        );
      }
      // Each fingerprint is attempted once; drop them whether or not they held.
      ctx.pendingVerifications = ctx.pendingVerifications.filter((p) => p.verifierTool !== toolName);
    }

    for (const f of envelope.findings ?? []) {
      const v = pickVerifierFor(f, server);
      if (!v) continue;
      if (v.verifierTool === toolName) continue; // a tool cannot verify its own claim
      if (ctx.pendingVerifications.some((p) => p.fingerprint === v.fingerprint)) continue;
      ctx.pendingVerifications.push(v);
    }
  }

  let stoppedForCancel = false;
  try {
    for (let step = 1; step <= run.max_steps; step += 1) {
      if (ac.signal.aborted) {
        stoppedForCancel = true;
        break;
      }
      ctx.stepsRemaining = run.max_steps - step + 1;

      const decision = await decideNextAction(server, ctx);

      await sink.emitDecision({
        step,
        decision,
        ollamaError: getLastManagerOllamaError() ?? null,
        snapshot: {
          knownPorts: ctx.knownPorts,
          services: ctx.knownServices.length,
          findings: allFindings.length,
          pendingVerifications: ctx.pendingVerifications.length,
          discoveredEndpoints: ctx.discoveredEndpoints.length
        }
      });

      if (decision.action === "stop") break;

      const args = decision.args as Record<string, unknown> | undefined;
      const got = await runSingleTool(step, decision.tool, decision.intentGoal, args);
      if (got) {
        await mergeEnvelope(step, got.toolName, got.args, got.invocationId, got.envelope);
      }

      await setAgentRunStatus(agentRunId, "running", {
        stepsTaken: step,
        invocationCount: ctx.invocationHistory.length,
        findingCount: allFindings.length,
        serviceCount: ctx.knownServices.length
      });
    }

    if (stoppedForCancel) {
      await withClient(async (c) => {
        await c.query(`insert into agent_events (agent_run_id, kind, payload) values ($1, 'run.cancelled', $2::jsonb)`, [
          agentRunId,
          JSON.stringify({ agentRunId })
        ]);
      }).catch(() => undefined);
      await setAgentRunStatus(agentRunId, "failed", { notes: "Cancelled by operator" });
      return;
    }

    await upsertNeo4jTarget({ id: run.target_id, name: run.target_name, address: run.target_address }).catch(() => {});
    await rebuildNeo4jForTarget(run.target_id).catch(() => {});

    await setAgentRunStatus(agentRunId, "succeeded", {
      stepsTaken: ctx.invocationHistory.length,
      invocationCount: ctx.invocationHistory.length,
      findingCount: allFindings.length,
      serviceCount: ctx.knownServices.length,
      notes:
        runPhase === "exploit"
          ? `Exploit phase complete: ${ctx.invocationHistory.length} invocations, ${allFindings.length} findings${hadFailure ? " (with some failed steps)" : ""}`
          : `MCP recon complete: ${ctx.invocationHistory.length} agent invocations, ${allFindings.length} findings${hadFailure ? " (with some failed steps)" : ""}`
    });
  } finally {
    clearInterval(cancelPoll);
  }
}

/** Map specialist tool → primary remote binary it needs. */
function inferProvenBinary(toolName: string): string | null {
  const map: Record<string, string> = {
    "recon.nmap": "nmap",
    "recon.port_recheck": "nmap",
    "recon.ftp_enum": "nmap",
    "recon.smtp_enum": "nmap",
    "recon.db_banner": "nmap",
    "recon.rdp_enum": "nmap",
    "recon.http_probe": "httpx",
    "recon.spider": "katana",
    "recon.gobuster": "gobuster",
    "recon.ffuf": "ffuf",
    "recon.dns_enum": "dnsx",
    "recon.smb_enum": "enum4linux-ng",
    "recon.ssh_enum": "ssh-audit",
    "recon.tls_check": "testssl.sh",
    "recon.nuclei": "nuclei",
    "recon.waf_detect": "wafw00f",
    "recon.hydra": "hydra",
    "exploit.sqlmap": "sqlmap",
    "exploit.commix": "commix",
    "exploit.msf_search": "msfconsole",
    "exploit.msf_module": "msfconsole",
    "exploit.crackmapexec": "nxc"
  };
  return map[toolName] ?? null;
}

function toolAlreadyProvenThisRun(ctx: ManagerContext, binary: string): boolean {
  if ((ctx.installedToolsInstalled ?? []).includes(binary)) return true;
  // Successful prior specialist that uses this binary.
  for (const h of ctx.invocationHistory ?? []) {
    if (h.status !== "succeeded" && h.status !== "partial") continue;
    if (inferProvenBinary(h.tool) === binary) return true;
  }
  return false;
}
