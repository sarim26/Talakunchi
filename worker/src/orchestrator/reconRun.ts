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
import { decideNextAction, type ManagerContext } from "../agents/manager.js";
import { generatePrompt } from "../agents/prompter.js";
import { draftExecutionPayload, shouldUseExecutionWriter } from "../agents/executionCommandWriter.js";
import { getWordlistCatalog } from "../agents/wordlists.js";
import {
  createEventSink,
  createAgentRun,
  ensureAgentTables,
  persistDiscoveredServices,
  persistFindings,
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
    blockedOnMissingTool: null,
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
          target: { targetId: run.target_id, host: run.target_address },
          knownPorts: ctx.knownPorts,
          knownServices: ctx.knownServices,
          discoveredEndpoints: ctx.discoveredEndpoints,
          priorFindings: allFindings,
          wordlistCatalog
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
        target: { targetId: run.target_id, host: run.target_address },
        intent: invokeIntent,
        args: invokeArgs,
        context: {
          knownPorts: ctx.knownPorts,
          knownServices: ctx.knownServices,
          knownDomains: [],
          priorFindings: allFindings,
          discoveredEndpoints: ctx.discoveredEndpoints.map((e) => ({
            url: e.url,
            method: e.method,
            status: e.status,
            sourceTool: e.sourceTool
          })),
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

    const decision = await decideNextAction(server, ctx);

    await sink.emitDecision({
      step,
      decision,
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
