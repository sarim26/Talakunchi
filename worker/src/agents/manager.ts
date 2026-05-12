/**
 * Manager agent.
 *
 * Receives the MCP manifest, accumulated facts, and step budget. Returns either
 * `invoke` (one tool + intent + optional args) or `stop`.
 *
 * Tool choice is **only** from the manager LLM, except for hard safety overrides:
 * retry after dependency install, and forced `system.tool_installer` when a tool
 * failed with `missingTool` and we have not attempted that install yet.
 */
import { z } from "zod";
import { env } from "../env.js";
import { chatJSON, safeParseJson } from "../llm/ollama.js";
import type { MCPServer } from "../mcp/server.js";
import type { ToolFinding } from "../mcp/types.js";
import type { WordlistCatalog } from "./wordlists.js";

export const ManagerDecisionSchema = z.union([
  z.object({
    action: z.literal("invoke"),
    tool: z.string().min(1),
    intentGoal: z.string().min(1),
    args: z.record(z.string(), z.any()).optional(),
    reasoning: z.string().optional()
  }),
  z.object({
    action: z.literal("stop"),
    reason: z.string().min(1)
  })
]);
export type ManagerDecision = z.infer<typeof ManagerDecisionSchema>;

/** Optional hints from the agent run row (e.g. nmap profile) for the LLM to use if it picks `recon.nmap`. */
export type ManagerRunHints = {
  initialNmapProfile: string | null;
  initialNmapPorts: number[] | null;
  initialNmapExtraArgs: string | null;
};

export type ManagerContext = {
  targetHost: string;
  stepsRemaining: number;
  knownPorts: number[];
  knownServices: Array<{ port: number; protocol: string; name?: string; product?: string; version?: string }>;
  knownFindings: ToolFinding[];
  discoveredEndpoints: Array<{ url: string; method?: string; status?: number | null; sourceTool: string }>;
  pendingVerifications: Array<{
    fingerprint: string;
    verifierTool: string;
    args?: Record<string, unknown>;
  }>;
  invocationHistory: Array<{
    tool: string;
    status: string;
    summary: string;
  }>;
  pendingRecommendations: Array<{
    agent: string;
    reason: string;
    priority: number;
    args?: Record<string, unknown>;
  }>;
  wordlistCatalog?: WordlistCatalog;
  recentFailures?: Array<{
    tool: string;
    attempt: number;
    args: Record<string, unknown>;
    error?: string;
    stdoutSnippet?: string;
    stderrSnippet?: string;
    missingTool?: string;
    missingToolInstallCommand?: string;
  }>;
  installedToolsAttempted?: string[];
  installedToolsInstalled?: string[];
  blockedOnMissingTool?: {
    tool: string;
    args: Record<string, unknown>;
    missingTool: string;
  } | null;
  /** From `agent_runs` — not a policy; the LLM may ignore or apply when choosing `recon.nmap`. */
  runHints?: ManagerRunHints;
};

export async function decideNextAction(server: MCPServer, ctx: ManagerContext, signal?: AbortSignal): Promise<ManagerDecision> {
  const blocked = ctx.blockedOnMissingTool ?? null;
  if (
    blocked &&
    server.has(blocked.tool) &&
    (ctx.installedToolsInstalled ?? []).includes(blocked.missingTool)
  ) {
    return {
      action: "invoke",
      tool: blocked.tool,
      intentGoal: `Retry ${blocked.tool} after installing '${blocked.missingTool}'`,
      args: blocked.args,
      reasoning: "Dependency installed; re-invoking previously blocked specialist"
    };
  }

  const lastFail = (ctx.recentFailures ?? []).slice(-1)[0];
  const missingTool = lastFail?.missingTool;
  if (
    missingTool &&
    server.has("system.tool_installer") &&
    !(ctx.installedToolsAttempted ?? []).includes(missingTool)
  ) {
    const installArgs: Record<string, unknown> = { tool: missingTool };
    if (lastFail.missingToolInstallCommand) installArgs.installCommand = lastFail.missingToolInstallCommand;
    return {
      action: "invoke",
      tool: "system.tool_installer",
      intentGoal: `Install missing tool '${missingTool}' so ${lastFail!.tool} can run`,
      args: installArgs,
      reasoning: "Auto-install missing tool before retrying the failed specialist"
    };
  }

  const llmDecision = await tryLlmDecision(server, ctx, signal);
  if (llmDecision) {
    if (llmDecision.action === "stop") return llmDecision;
    if (llmDecision.action === "invoke" && server.has(llmDecision.tool)) return llmDecision;
  }

  const fromRec = fallbackFromRecommendations(server, ctx);
  if (fromRec) return fromRec;

  if (ctx.stepsRemaining <= 0) {
    return { action: "stop", reason: "Step budget exhausted" };
  }
  return {
    action: "stop",
    reason:
      "Manager LLM did not return usable JSON after retries, no runnable queued recommendation matched, and steps remain. Check Ollama; try a stronger JSON-capable model or OLLAMA_MANAGER_MODEL with more context."
  };
}

async function tryLlmDecision(server: MCPServer, ctx: ManagerContext, signal?: AbortSignal): Promise<ManagerDecision | null> {
  const systemMsg = [
    "You are the MANAGER agent of a multi-agent penetration testing system.",
    "You alone decide which ONE specialist tool to invoke next, or whether to stop the run.",
    "Operate in read-only reconnaissance mode (no exploitation, no destructive operations).",
    "",
    'Return ONLY a JSON object matching ONE of:',
    '  { "action": "invoke", "tool": "<exact tool name from tools[].name>", "intentGoal": "<short english goal>", "args": { ... }, "reasoning": "<why>" }',
    '  { "action": "stop", "reason": "<short why we are stopping>" }',
    "",
    "Use the tools list as the authoritative registry. Pick the single best next step from context:",
    "  - No open ports yet → usually start with recon.nmap (or recon.dns_enum if you already have enough host intel).",
    "  - After services exist → choose the most informative specialist (http_probe, ssh_enum, smb_enum, tls_check, cve_enricher, spider, waybackurls, gobuster, ffuf, etc.).",
    "  - Follow tool `requires` hints; do not invoke a tool whose preconditions are clearly unmet.",
    "  - Prefer system.tool_installer only when a prior failure indicated a missing remote CLI (recentFailures.missingTool) — the orchestrator may force-install before you run again.",
    "",
    "Downstream: a prompter turns your intentGoal into prose; an execution-writer LLM fills JSON `args` per the tool's argSchema (not raw shell — the worker maps args → CLI safely).",
    "You never see raw tool stdout. Use `knownFindings`, `discoveredEndpoints` (truncated sample), `discoveredEndpointCount`, and `history` as summaries.",
    "",
    "Args discipline:",
    "- recon.http_probe: prefer `services` (from nmap) and/or explicit `urls`; optional `ports` when using context fallback.",
    "- recon.spider: pass `http_targets` (array of seed URLs on the target host) and/or `url`.",
    "- recon.gobuster / recon.ffuf: pass `url` or `targetUrl` (with FUZZ) on the target host — do not rely on silent inference.",
    "",
    "Rules:",
    "- Choose exactly one tool per step (no batching).",
    "- Stop when diminishing returns, budget is low, or nothing safe remains.",
    "- Use history to avoid useless repeats unless a retry is justified (e.g. after install or new evidence)."
  ].join("\n");

  const attempts: Array<{ mode: ManagerPayloadMode; temp: number; maxTokens: number }> = [
    { mode: "full", temp: 0.15, maxTokens: 1600 },
    { mode: "full", temp: 0.1, maxTokens: 1600 },
    { mode: "minimal", temp: 0.05, maxTokens: 1200 }
  ];

  for (let i = 0; i < attempts.length; i += 1) {
    const { mode, temp, maxTokens } = attempts[i]!;
    const userMsg = JSON.stringify(buildManagerUserPayload(server, ctx, mode), null, 2);
    try {
      const r = await chatJSON({
        model: env.OLLAMA_MANAGER_MODEL,
        messages: [
          { role: "system", content: systemMsg },
          { role: "user", content: userMsg }
        ],
        temperature: temp,
        maxTokens,
        signal
      });
      const normalized = normalizeManagerDecisionRaw(r.value ?? safeParseJson<unknown>(r.raw));
      const parsed = ManagerDecisionSchema.safeParse(normalized);
      if (!parsed.success) {
        if (i === attempts.length - 1) {
          console.warn(`[manager] zod after ${attempts.length} tries: ${parsed.error.errors.slice(0, 4).map((e) => e.message).join("; ")}`);
        }
        continue;
      }
      const d = parsed.data;
      if (d.action === "stop") return d;
      const tool = resolveRegisteredTool(server, d.tool);
      if (!tool) {
        console.warn(`[manager] unknown tool "${d.tool}" (payload mode=${mode})`);
        continue;
      }
      if (tool !== d.tool) {
        return {
          ...d,
          tool,
          reasoning: [d.reasoning, `(normalized tool id from "${d.tool}")`].filter(Boolean).join(" ")
        };
      }
      return d;
    } catch (e) {
      console.warn(`[manager] Ollama attempt ${i + 1} (${mode}): ${(e as Error).message}`);
    }
  }
  return null;
}

type ManagerPayloadMode = "full" | "minimal";

/** Unwrap { decision: {...} }, lowercase action, etc. */
function normalizeManagerDecisionRaw(value: unknown): unknown {
  if (value === null || value === undefined) return null;
  if (typeof value !== "object" || Array.isArray(value)) return value;
  let o = value as Record<string, unknown>;
  if (o.decision && typeof o.decision === "object" && !Array.isArray(o.decision)) {
    o = o.decision as Record<string, unknown>;
  }
  if (o.result && typeof o.result === "object" && !Array.isArray(o.result)) {
    o = o.result as Record<string, unknown>;
  }
  const action = o.action;
  if (typeof action === "string") o.action = action.toLowerCase().trim();
  return o;
}

function resolveRegisteredTool(server: MCPServer, tool: string): string | null {
  const t = tool.trim();
  if (!t) return null;
  if (server.has(t)) return t;
  const names = server.list().map((x) => x.name);
  const lower = t.toLowerCase();
  const ci = names.find((n) => n.toLowerCase() === lower);
  if (ci) return ci;
  if (!t.includes(".")) {
    if (server.has(`recon.${t}`)) return `recon.${t}`;
    if (server.has(`system.${t}`)) return `system.${t}`;
  }
  return null;
}

/** When the manager model fails, continue with the best tool the last specialist already suggested. */
function fallbackFromRecommendations(server: MCPServer, ctx: ManagerContext): ManagerDecision | null {
  const list = [...(ctx.pendingRecommendations ?? [])].sort((a, b) => b.priority - a.priority);
  for (const p of list) {
    if (!server.has(p.agent)) continue;
    if (!recommendationHasRunnableArgs(p)) continue;
    return {
      action: "invoke",
      tool: p.agent,
      intentGoal: p.reason.slice(0, 400),
      args: p.args ?? {},
      reasoning:
        "Automatic fallback: manager model produced no usable JSON after retries; running highest-priority recommendation queued by a prior tool."
    };
  }
  return null;
}

function recommendationHasRunnableArgs(p: { agent: string; args?: Record<string, unknown> }): boolean {
  const a = p.args ?? {};
  if (p.agent === "recon.gobuster") return typeof a.url === "string" && a.url.length > 0;
  if (p.agent === "recon.ffuf") return typeof a.targetUrl === "string" && /FUZZ/.test(a.targetUrl);
  return true;
}

/** Keep manager prompts small: long URL lists after spider blow up JSON size and break small models. */
function truncateUrlForPlanner(url: string, max = 140): string {
  if (url.length <= max) return url;
  return `${url.slice(0, Math.max(0, max - 1))}…`;
}

function buildManagerUserPayload(server: MCPServer, ctx: ManagerContext, mode: ManagerPayloadMode): Record<string, unknown> {
  const epAll = ctx.discoveredEndpoints ?? [];
  if (mode === "minimal") {
    return {
      tools: server.list().map((t) => ({ name: t.name, requires: t.requires })),
      target: ctx.targetHost,
      stepsRemaining: ctx.stepsRemaining,
      knownPorts: ctx.knownPorts,
      knownServices: ctx.knownServices.slice(0, 20),
      discoveredEndpointCount: epAll.length,
      pendingRecommendations: ctx.pendingRecommendations.slice(0, 10),
      knownFindingsSample: ctx.knownFindings.slice(-6).map((f) => ({
        title: f.title.length > 120 ? `${f.title.slice(0, 117)}…` : f.title,
        severity: f.severity
      })),
      history: ctx.invocationHistory.slice(-10),
      recentFailures: (ctx.recentFailures ?? []).slice(-3),
      runHints: ctx.runHints ?? null
    };
  }

  const epTail = epAll.slice(-18);
  return {
    tools: server.manifestCompact(),
    target: ctx.targetHost,
    stepsRemaining: ctx.stepsRemaining,
    knownPorts: ctx.knownPorts,
    knownServices: ctx.knownServices.slice(0, 40),
    discoveredEndpoints: epTail.map((e) => ({
      url: truncateUrlForPlanner(e.url),
      method: e.method ?? "GET",
      status: e.status ?? null,
      sourceTool: e.sourceTool
    })),
    discoveredEndpointCount: epAll.length,
    pendingVerifications: (ctx.pendingVerifications ?? []).slice(-10),
    pendingRecommendations: ctx.pendingRecommendations.slice(0, 12),
    knownFindings: ctx.knownFindings.slice(-20).map((f) => ({
      title: f.title.length > 180 ? `${f.title.slice(0, 177)}…` : f.title,
      severity: f.severity
    })),
    history: ctx.invocationHistory.slice(-20),
    recentFailures: (ctx.recentFailures ?? []).slice(-5),
    runHints: ctx.runHints ?? null
  };
}
