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
import { decideNextAction, type ManagerContext } from "../agents/manager.js";
import { generatePrompt } from "../agents/prompter.js";
import { getWordlistCatalog } from "../agents/wordlists.js";
import {
  createEventSink,
  createAgentRun,
  ensureAgentTables,
  persistDiscoveredServices,
  persistFindings,
  setAgentRunStatus
} from "../persistence/agentEvents.js";
import type { ToolFinding } from "../mcp/types.js";

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
    targetHost: data.target_address,
    stepsRemaining: data.max_steps,
    knownPorts: [],
    knownServices: [],
    knownFindings: [],
    invocationHistory: [],
    pendingRecommendations: [],
    wordlistCatalog,
    recentFailures: []
  };

  const allFindings: ToolFinding[] = [];
  const attemptsByTool = new Map<string, number>();
  let hadFailure = false;

  for (let step = 1; step <= data.max_steps; step += 1) {
    ctx.stepsRemaining = data.max_steps - step + 1;

    // Step 1 is always recon.nmap (configurable per run).
    const decision =
      step === 1 && server.has("recon.nmap")
        ? ({
            action: "invoke",
            tool: "recon.nmap",
            intentGoal: "Initial network scan (required first step)",
            args: {
              profile: data.initial_nmap_profile ?? "deep",
              ports: data.initial_nmap_ports ?? undefined,
              extraArgs: data.initial_nmap_extra_args ?? undefined
            }
          } as const)
        : await decideNextAction(server, ctx);
    await sink.emitDecision({ step, decision, snapshot: { knownPorts: ctx.knownPorts, services: ctx.knownServices.length, findings: allFindings.length } });

    if (decision.action === "stop") break;

    const toolDef = server.list().find((t) => t.name === decision.tool);
    if (!toolDef) {
      await sink.emitDecision({ step, error: `Manager picked unknown tool ${decision.tool}` });
      continue;
    }

    const decisionArgs = "args" in decision ? (decision.args as Record<string, unknown> | undefined) : undefined;
    const selectedWordlist = typeof decisionArgs?.wordlist === "string" ? String(decisionArgs.wordlist) : undefined;

    const prompt = await generatePrompt({
      agent: toolDef,
      intentGoal: decision.intentGoal,
      targetHost: data.target_address,
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

    const { envelope } = await server.invoke(
      toolDef.name,
      {
        target: { targetId: data.target_id, host: data.target_address },
        intent: prompt,
        args: decisionArgs ?? {},
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

    if (envelope.status === "failed") {
      hadFailure = true;
      const prev = attemptsByTool.get(toolDef.name) ?? 0;
      attemptsByTool.set(toolDef.name, prev + 1);

      const failure = {
        tool: toolDef.name,
        attempt: prev,
        args: (decisionArgs ?? {}) as Record<string, unknown>,
        error: envelope.error,
        stdoutSnippet: envelope.artifacts?.stdoutSnippet,
        stderrSnippet: envelope.artifacts?.stderrSnippet
      };
      ctx.recentFailures = [...(ctx.recentFailures ?? []), failure].slice(-10);

      await withClient(async (c) => {
        await c.query(
          `insert into agent_events (agent_run_id, kind, payload) values ($1, 'agent.failure', $2::jsonb)`,
          [agentRunId, JSON.stringify({ step, ...failure })]
        );
      });

      // Hint the manager to attempt a safe recovery on the next step. The manager
      // will see recentFailures and can pick adjusted args or an alternative tool.
      if (prev < 1) {
        ctx.pendingRecommendations.unshift({
          agent: toolDef.name,
          reason: `Recover from failure: ${envelope.error ?? "unknown error"}`,
          priority: 95
        });
      }
    }

    const newServices = (envelope.facts ?? [])
      .filter((f) => f.type === "service")
      .map((f) => f.value as { port: number; protocol: string; name?: string; product?: string; version?: string; banner?: string });

    const serviceIdByPort = newServices.length > 0 ? await persistDiscoveredServices(data.target_id, newServices) : new Map<number, string>();
    if (envelope.findings?.length) {
      await persistFindings(data.target_id, envelope.findings, serviceIdByPort);
      allFindings.push(...envelope.findings);
    }

    for (const svc of newServices) {
      if (!ctx.knownServices.some((k) => k.port === svc.port && k.protocol === svc.protocol)) {
        ctx.knownServices.push(svc);
      }
      if (!ctx.knownPorts.includes(svc.port)) ctx.knownPorts.push(svc.port);
    }

    ctx.invocationHistory.push({
      tool: toolDef.name,
      status: envelope.status,
      summary: `${envelope.findings?.length ?? 0} findings, ${envelope.facts?.length ?? 0} facts`
    });

    for (const rec of envelope.recommendations ?? []) {
      if (!ctx.pendingRecommendations.some((p) => p.agent === rec.agent)) ctx.pendingRecommendations.push(rec);
    }

    ctx.knownFindings.push(...envelope.findings.slice(0, 3));

    await setAgentRunStatus(agentRunId, "running", {
      stepsTaken: step,
      invocationCount: ctx.invocationHistory.length,
      findingCount: allFindings.length,
      serviceCount: ctx.knownServices.length
    });
  }

  await upsertNeo4jTarget({ id: data.target_id, name: data.target_name, address: data.target_address }).catch(() => {});
  await rebuildNeo4jForTarget(data.target_id).catch(() => {});

  await setAgentRunStatus(agentRunId, "succeeded", {
    stepsTaken: ctx.invocationHistory.length,
    invocationCount: ctx.invocationHistory.length,
    findingCount: allFindings.length,
    serviceCount: ctx.knownServices.length,
    notes: `MCP recon complete: ${ctx.invocationHistory.length} agent invocations, ${allFindings.length} findings${hadFailure ? " (with some failed steps)" : ""}`
  });
}
