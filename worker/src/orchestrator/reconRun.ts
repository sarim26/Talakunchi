/**
 * Recon orchestrator — drives the manager → prompter → specialist loop.
 *
 * This is the "agent that connects all agents" the CEO described. The flow:
 *   1. manager picks the next tool + intent
 *   2. prompter translates the intent into a specialist-flavoured prompt
 *      (logged to the event stream so the UI can show what each agent saw)
 *   3. MCPServer.invoke runs the tool with a timeout and emits live events
 *   4. envelope is normalized; new services + findings are persisted; the
 *      tool's recommendations are merged into the manager's queue
 *   5. loop until the manager says "stop" or the budget is exhausted
 */
import { env } from "../env.js";
import { withClient } from "../db.js";
import { rebuildNeo4jForTarget, upsertNeo4jTarget } from "../neo4jSync.js";
import { buildReconMCPServer } from "../agents/registry.js";
import { decideNextAction, phaseForTool, type ManagerContext, type Phase } from "../agents/manager.js";
import { generatePrompt } from "../agents/prompter.js";
import { getWordlistCatalog } from "../agents/wordlists.js";
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
    specialistModel: env.OLLAMA_SPECIALIST_MODEL,
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

export async function runReconLoop(agentRunId: string): Promise<void> {
  await ensureAgentTables();

  const data = await withClient(async (c) => {
    const r = await c.query(
      `select ar.id, ar.target_id, ar.max_steps,
              ar.initial_nmap_profile, ar.initial_nmap_ports, ar.initial_nmap_extra_args,
              t.name as target_name, t.address as target_address
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
          initial_nmap_profile: string | null;
          initial_nmap_ports: number[] | null;
          initial_nmap_extra_args: string | null;
          target_name: string;
          target_address: string;
        }
      | undefined;
  });
  if (!data) throw new Error(`agent_run ${agentRunId} not found`);
  // Re-bind so TypeScript preserves the non-null narrowing inside nested
  // async helpers (it gets lost across closure boundaries otherwise).
  const run = data;

  await setAgentRunStatus(agentRunId, "running");

  const server = buildReconMCPServer();
  const sink = createEventSink(agentRunId);

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

  const ctx: ManagerContext = {
    targetHost: run.target_address,
    stepsRemaining: run.max_steps,
    phase: "network_discovery",
    knownPorts: [],
    knownServices: [],
    knownFindings: [],
    discoveredEndpoints: [],
    pendingVerifications: [],
    invocationHistory: [],
    pendingRecommendations: [],
    wordlistCatalog,
    recentFailures: [],
    installedToolsAttempted: [],
    installedToolsInstalled: [],
    blockedOnMissingTool: null
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
      selectedWordlist
    });
    await withClient(async (c) => {
      await c.query(
        `insert into agent_events (agent_run_id, kind, payload) values ($1, 'prompter.output', $2::jsonb)`,
        [agentRunId, JSON.stringify({ step, tool: toolDef.name, prompt })]
      );
    });

    const { invocationId, envelope } = await server.invoke(
      toolDef.name,
      {
        target: { targetId: run.target_id, host: run.target_address },
        intent: prompt,
        args: args ?? {},
        context: {
          knownPorts: ctx.knownPorts,
          knownServices: ctx.knownServices,
          knownDomains: [],
          priorFindings: allFindings,
          runId: agentRunId,
          invocationId: ""
        }
      },
      sink
    );
    return { toolName: toolDef.name, intentGoal, args, invocationId, envelope };
  }

  /**
   * Merge a single invocation's envelope into the shared `ctx` and persist
   * services/findings. Runs serially so we don't have to worry about
   * inter-tool races even when several tools ran via invoke_parallel.
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
        missingToolInstallCommand
      };
      ctx.recentFailures = [...(ctx.recentFailures ?? []), failure].slice(-10);

      await withClient(async (c) => {
        await c.query(
          `insert into agent_events (agent_run_id, kind, payload) values ($1, 'agent.failure', $2::jsonb)`,
          [agentRunId, JSON.stringify({ step, ...failure })]
        );
      });

      if (missingTool) {
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
      } else if (prev < 1) {
        ctx.pendingRecommendations.unshift({
          agent: toolName,
          reason: `Recover from failure: ${envelope.error ?? "unknown error"}`,
          priority: 95
        });
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
    const webFacts = (envelope.facts ?? []).filter((f) => f.type === "web_url" || f.type === "web_path");
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

    // Layer 1: queue verifier expectations.
    // When a tool emits open-port findings that still need corroboration, ask
    // recon.http_probe to attempt verification on the next step.
    if (toolName === "recon.nmap") {
      for (const f of envelope.findings ?? []) {
        if (f.claimType === "open_port" && f.requiresVerification !== false && f.fingerprint) {
          const probeable = [80, 443, 8080, 8443].includes(Number(f.port));
          if (probeable && !ctx.pendingVerifications.some((v) => v.fingerprint === f.fingerprint)) {
            ctx.pendingVerifications.push({
              fingerprint: f.fingerprint,
              verifierTool: "recon.http_probe"
            });
          }
        }
      }
    }

    // After recon.http_probe ran, any open-port fingerprint it didn't observe
    // is marked as "verifier_no_response" so the original finding stays
    // unverified permanently (Situation 3).
    if (toolName === "recon.http_probe") {
      const observedPorts = new Set<number>();
      for (const f of envelope.findings ?? []) {
        if (f.claimType === "http_reachable" && typeof f.port === "number") observedPorts.add(f.port);
        if (f.verifiesFingerprint) {
          // strip port out of fingerprint of form open-port|host|tcp|<port>
          const m = /^open-port\|[^|]+\|[^|]+\|(\d+)$/.exec(f.verifiesFingerprint);
          if (m) observedPorts.add(Number(m[1]));
        }
      }
      const failures: Array<{ fingerprint: string; tool: string; status: "verifier_failed" | "verifier_no_response"; evidence?: string }> = [];
      ctx.pendingVerifications = ctx.pendingVerifications.filter((v) => {
        if (v.verifierTool !== "recon.http_probe") return true;
        const m = /^open-port\|[^|]+\|[^|]+\|(\d+)$/.exec(v.fingerprint);
        if (!m) return true;
        const port = Number(m[1]);
        if (observedPorts.has(port)) return false; // confirmed (handled by verifiesFingerprint path)
        failures.push({
          fingerprint: v.fingerprint,
          tool: "recon.http_probe",
          status: envelope.status === "failed" ? "verifier_failed" : "verifier_no_response",
          evidence: `httpx attempted but did not corroborate port ${port}`
        });
        return false;
      });
      if (failures.length > 0) {
        await recordVerifierAttempts(run.target_id, failures, { invocationId, agentRunId });
      }
    }

    ctx.invocationHistory.push({
      tool: toolName,
      status: envelope.status,
      summary: `${envelope.findings?.length ?? 0} findings, ${envelope.facts?.length ?? 0} facts`
    });

    for (const rec of envelope.recommendations ?? []) {
      if (!ctx.pendingRecommendations.some((p) => p.agent === rec.agent)) ctx.pendingRecommendations.push(rec);
    }

    ctx.knownFindings.push(...envelope.findings.slice(0, 3));
  }

  for (let step = 1; step <= run.max_steps; step += 1) {
    ctx.stepsRemaining = run.max_steps - step + 1;

    // Step 1 is always recon.nmap (configurable per run).
    const decision =
      step === 1 && server.has("recon.nmap")
        ? ({
            action: "invoke" as const,
            tool: "recon.nmap",
            intentGoal: "Initial network scan (required first step)",
            args: {
              profile: run.initial_nmap_profile ?? "deep",
              ports: run.initial_nmap_ports ?? undefined,
              extraArgs: run.initial_nmap_extra_args ?? undefined
            }
          })
        : await decideNextAction(server, ctx);

    await sink.emitDecision({
      step,
      decision,
      snapshot: {
        knownPorts: ctx.knownPorts,
        services: ctx.knownServices.length,
        findings: allFindings.length,
        phase: ctx.phase ?? null,
        pendingVerifications: ctx.pendingVerifications.length,
        discoveredEndpoints: ctx.discoveredEndpoints.length
      }
    });

    if (decision.action === "stop") break;

    if (decision.action === "invoke_parallel") {
      const phase: Phase = decision.phase;
      ctx.phase = phase;
      await withClient(async (c) => {
        await c.query(
          `insert into agent_events (agent_run_id, kind, payload) values ($1, 'phase.started', $2::jsonb)`,
          [
            agentRunId,
            JSON.stringify({
              step,
              phase,
              tools: decision.invocations.map((i) => i.tool),
              reasoning: decision.reasoning ?? null
            })
          ]
        );
      });

      // Run all tools in parallel. Each task does its own remoteScript over
      // SSH; they share the same Kali host so we keep the parallel width
      // bounded by the schema (max 4).
      const results = await Promise.allSettled(
        decision.invocations.map((inv) => runSingleTool(step, inv.tool, inv.intentGoal, inv.args))
      );

      const phaseOutcomes: Array<{ tool: string; status: string; error?: string }> = [];
      for (const r of results) {
        if (r.status === "rejected") {
          phaseOutcomes.push({ tool: "unknown", status: "rejected", error: String(r.reason) });
          continue;
        }
        const got = r.value;
        if (!got) continue;
        await mergeEnvelope(step, got.toolName, got.args, got.invocationId, got.envelope);
        phaseOutcomes.push({ tool: got.toolName, status: got.envelope.status, error: got.envelope.error });
      }

      await withClient(async (c) => {
        await c.query(
          `insert into agent_events (agent_run_id, kind, payload) values ($1, 'phase.finished', $2::jsonb)`,
          [agentRunId, JSON.stringify({ step, phase, outcomes: phaseOutcomes })]
        );
      });
    } else {
      // Single tool.
      const args = "args" in decision ? (decision.args as Record<string, unknown> | undefined) : undefined;
      ctx.phase = phaseForTool(decision.tool) ?? ctx.phase;
      const got = await runSingleTool(step, decision.tool, decision.intentGoal, args);
      if (got) await mergeEnvelope(step, got.toolName, got.args, got.invocationId, got.envelope);
    }

    await setAgentRunStatus(agentRunId, "running", {
      stepsTaken: step,
      invocationCount: ctx.invocationHistory.length,
      findingCount: allFindings.length,
      serviceCount: ctx.knownServices.length
    });
  }

  await upsertNeo4jTarget({ id: run.target_id, name: run.target_name, address: run.target_address }).catch(() => {});
  await rebuildNeo4jForTarget(run.target_id).catch(() => {});

  await setAgentRunStatus(agentRunId, "succeeded", {
    stepsTaken: ctx.invocationHistory.length,
    invocationCount: ctx.invocationHistory.length,
    findingCount: allFindings.length,
    serviceCount: ctx.knownServices.length,
    notes: `MCP recon complete: ${ctx.invocationHistory.length} agent invocations, ${allFindings.length} findings${hadFailure ? " (with some failed steps)" : ""}`
  });
}
