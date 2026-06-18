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

  // Deterministic coverage-first rule: if key services exist but their
  // enumerators haven't run yet, prioritize them before web expansion loops.
  const coverage = coverageFirstDecision(server, ctx);
  if (coverage) return coverage;

  // Drain pending verifications before exploratory LLM steps so unconfirmed
  // findings get corroborated (or marked unverified) deterministically.
  const verification = verificationFirstDecision(server, ctx);
  if (verification) return verification;

  const llmDecision = await tryLlmDecision(server, ctx, signal);
  if (llmDecision) {
    if (llmDecision.action === "stop") return llmDecision;
    if (llmDecision.action === "invoke" && server.has(llmDecision.tool)) return llmDecision;
  }

  const fromRec = fallbackFromRecommendations(server, ctx);
  if (fromRec) return fromRec;

  // Cold-start safety net: if the LLM failed and we have no host intel yet,
  // start with nmap deterministically instead of stopping on step 1.
  const initialNmap = fallbackInitialNmap(server, ctx);
  if (initialNmap) return initialNmap;

  if (ctx.stepsRemaining <= 0) {
    return { action: "stop", reason: "Step budget exhausted" };
  }
  return {
    action: "stop",
    reason: managerStopReasonAfterLlmFailure(lastManagerOllamaError)
  };
}

/**
 * Last error string returned by the manager Ollama call (cleared on each
 * `tryLlmDecision`). Used to produce a specific stop reason and telemetry.
 */
let lastManagerOllamaError: string | undefined;

/** Expose the last manager Ollama error so the orchestrator can record it in telemetry. */
export function getLastManagerOllamaError(): string | undefined {
  return lastManagerOllamaError;
}

/** Turn the raw Ollama failure into an actionable stop reason. */
function managerStopReasonAfterLlmFailure(ollamaError?: string): string {
  const e = ollamaError ?? "";
  if (/system memory|more system memory|out of memory|cuda/i.test(e)) {
    return `Ollama could not load ${env.OLLAMA_MANAGER_MODEL} (insufficient memory / GPU error). Use a smaller model in OLLAMA_MANAGER_MODEL (e.g. qwen3:8b), free RAM, or run 'ollama stop'. Detail: ${e.slice(0, 200)}`;
  }
  if (/not found|404|no such model/i.test(e)) {
    return `Ollama model "${env.OLLAMA_MANAGER_MODEL}" is not available. Pull it first: 'ollama pull ${env.OLLAMA_MANAGER_MODEL}'.`;
  }
  if (e) {
    return `Manager LLM call to Ollama failed and no deterministic fallback applied. Detail: ${e.slice(0, 200)}`;
  }
  return "Manager LLM did not return usable JSON after retries, no runnable queued recommendation matched, and steps remain. Check Ollama; try a stronger JSON-capable model or OLLAMA_MANAGER_MODEL with more context.";
}

/**
 * Deterministic cold-start: no ports/services discovered yet and nmap has not
 * been run — start recon with nmap even if the manager LLM is unavailable.
 */
function fallbackInitialNmap(server: MCPServer, ctx: ManagerContext): ManagerDecision | null {
  if (!server.has("recon.nmap")) return null;
  const history = ctx.invocationHistory ?? [];
  if (history.some((h) => h.tool === "recon.nmap")) return null;
  if ((ctx.knownPorts ?? []).length > 0 || (ctx.knownServices ?? []).length > 0) return null;

  const hints = ctx.runHints;
  const profile =
    hints?.initialNmapProfile === "fast" ||
    hints?.initialNmapProfile === "targeted" ||
    hints?.initialNmapProfile === "deep" ||
    hints?.initialNmapProfile === "full"
      ? hints.initialNmapProfile
      : "deep";
  const args: Record<string, unknown> = { profile };
  if (hints?.initialNmapPorts?.length) args.ports = hints.initialNmapPorts;
  if (hints?.initialNmapExtraArgs?.trim()) args.extraArgs = hints.initialNmapExtraArgs.trim();

  return {
    action: "invoke",
    tool: "recon.nmap",
    intentGoal: `Discover open ports and services on ${ctx.targetHost} (${profile} scan)`,
    args,
    reasoning:
      "Automatic fallback: manager LLM unavailable; starting with recon.nmap (no ports or services known yet)."
  };
}

function coverageFirstDecision(server: MCPServer, ctx: ManagerContext): ManagerDecision | null {
  const services = ctx.knownServices ?? [];
  const history = ctx.invocationHistory ?? [];
  const ran = new Set(history.map((h) => (h.tool || "").trim()).filter(Boolean));

  const hasSmb = services.some((s) => s.protocol === "tcp" && (s.port === 445 || s.port === 139 || /^smb/i.test(s.name ?? "") || /^netbios/i.test(s.name ?? "")));
  if (hasSmb && server.has("recon.smb_enum") && !ran.has("recon.smb_enum")) {
    return {
      action: "invoke",
      tool: "recon.smb_enum",
      intentGoal: "Enumerate SMB shares, users, and signing posture (coverage-first)",
      args: { services },
      reasoning: "Coverage-first: SMB (139/445) is present but smb_enum has not been run yet"
    };
  }

  const hasSsh = services.some((s) => s.protocol === "tcp" && (s.port === 22 || /^ssh$/i.test(s.name ?? "") || /openssh/i.test(`${s.product ?? ""} ${s.name ?? ""}`)));
  if (hasSsh && server.has("recon.ssh_enum") && !ran.has("recon.ssh_enum")) {
    return {
      action: "invoke",
      tool: "recon.ssh_enum",
      intentGoal: "Audit SSH configuration and known CVEs with ssh-audit (coverage-first)",
      args: { services },
      reasoning: "Coverage-first: SSH is present but ssh_enum has not been run yet"
    };
  }

  // Infra specialists: when a matching port is present and the specialist has
  // not run yet, prioritize it (same coverage-first principle as SMB/SSH).
  const nameOf = (s: { name?: string; product?: string }) => `${s.product ?? ""} ${s.name ?? ""}`;
  const infraCoverage: Array<{ tool: string; match: (s: { port: number; protocol: string; name?: string; product?: string }) => boolean; goal: string }> = [
    { tool: "recon.rdp_enum", match: (s) => s.protocol === "tcp" && (s.port === 3389 || /ms-wbt-server|rdp/i.test(nameOf(s))), goal: "Enumerate RDP encryption and NTLM info (coverage-first)" },
    { tool: "recon.ftp_enum", match: (s) => s.protocol === "tcp" && (s.port === 21 || /\bftp\b/i.test(nameOf(s))), goal: "Check FTP for anonymous login and banner (coverage-first)" },
    { tool: "recon.smtp_enum", match: (s) => s.protocol === "tcp" && ([25, 587, 465].includes(s.port) || /smtp/i.test(nameOf(s))), goal: "Enumerate SMTP commands and open-relay posture (coverage-first)" },
    { tool: "recon.ldap_enum", match: (s) => s.protocol === "tcp" && ([389, 636, 3268, 3269].includes(s.port) || /ldap/i.test(nameOf(s))), goal: "Test LDAP anonymous bind and read naming contexts (coverage-first)" },
    { tool: "recon.nfs_enum", match: (s) => s.protocol === "tcp" && (s.port === 2049 || /\bnfs\b/i.test(nameOf(s))), goal: "List exported NFS shares with showmount (coverage-first)" },
    { tool: "recon.redis_enum", match: (s) => s.protocol === "tcp" && (s.port === 6379 || /redis/i.test(nameOf(s))), goal: "Check Redis for unauthenticated access (coverage-first)" },
    { tool: "recon.snmp_enum", match: (s) => s.protocol === "udp" && (s.port === 161 || /snmp/i.test(nameOf(s))), goal: "Probe SNMP for readable community strings (coverage-first)" },
    { tool: "recon.db_banner", match: (s) => s.protocol === "tcp" && [3306, 5432, 1433, 1521, 27017].includes(s.port), goal: "Grab database server banners/info (coverage-first)" }
  ];
  for (const c of infraCoverage) {
    if (services.some(c.match) && server.has(c.tool) && !ran.has(c.tool)) {
      return { action: "invoke", tool: c.tool, intentGoal: c.goal, args: { services }, reasoning: `Coverage-first: a matching service is present but ${c.tool} has not been run yet` };
    }
  }

  // If services exist but the enrich step hasn't run, do it once to attach
  // vulnerability context before spending more steps on web brute force.
  if (services.length > 0 && server.has("recon.cve_enricher") && !ran.has("recon.cve_enricher")) {
    return {
      action: "invoke",
      tool: "recon.cve_enricher",
      intentGoal: "Enrich discovered services with offline CVE heuristics (coverage-first)",
      args: { services },
      reasoning: "Coverage-first: services are known but cve_enricher has not been run yet"
    };
  }

  return null;
}

/** Pick the next queued verification whose verifier tool is registered. */
function verificationFirstDecision(server: MCPServer, ctx: ManagerContext): ManagerDecision | null {
  for (const v of ctx.pendingVerifications ?? []) {
    if (!v.verifierTool || !server.has(v.verifierTool)) continue;
    return {
      action: "invoke",
      tool: v.verifierTool,
      intentGoal: `Corroborate unconfirmed finding ${v.fingerprint} using ${v.verifierTool}`,
      args: v.args ?? {},
      reasoning: `Verification-first: ${v.fingerprint} is still unconfirmed; running ${v.verifierTool} to corroborate it.`
    };
  }
  return null;
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
    "  - Optional, low priority: for PUBLIC hostnames you may run recon.passive_dns / recon.osint before nmap to gather passive intel; these no-op without API keys, so skip them otherwise.",
    "  - After services exist → choose the most informative specialist (http_probe, ssh_enum, smb_enum, tls_check, cve_enricher, spider, waybackurls, gobuster, ffuf, etc.).",
    "  - Infra services map to dedicated specialists: 3389→rdp_enum, 21→ftp_enum, 25/587/465→smtp_enum, 389/636→ldap_enum, 2049→nfs_enum, 6379→redis_enum, 161/udp→snmp_enum, 3306/5432/1433→db_banner. Run these when the matching port is open.",
    "  - recon.nuclei (safe tags) and recon.waf_detect operate on web origins: run recon.http_probe first so HTTP seeds/discoveredEndpoints exist, then use them.",
    "  - recon.hydra (only present in gated mode) is a credentialed check on auth services; it pauses for human approval before running. Choose it only when an auth service (ssh/ftp/rdp/smb/db) is open and credential testing is in scope.",
    "  - Follow tool `requires` hints; do not invoke a tool whose preconditions are clearly unmet.",
    "  - Prefer system.tool_installer only when a prior failure indicated a missing remote CLI (recentFailures.missingTool) — the orchestrator may force-install before you run again.",
    "",
    "Downstream: a prompter turns your intentGoal into prose; an execution-writer LLM fills JSON `args` per the tool's argSchema (not raw shell — the worker maps args → CLI safely).",
    "You never see raw tool stdout. Use `knownFindings`, `discoveredEndpoints` (truncated sample), `discoveredEndpointCount`, and `history` as summaries.",
    "",
    "Args discipline:",
    "- recon.http_probe: prefer `services` (from nmap) and/or explicit `urls`; optional `ports` when using context fallback.",
    "- recon.spider: pass `http_targets` (array of seed URLs on the target host) and/or `url`.",
    "- recon.gobuster: pass `url` and/or `http_targets` (base URLs on the target host, e.g. http://TARGET:80/). Optional `targetUrl` without FUZZ is treated like `url`; do not use placeholder/example IPs.",
    "- recon.ffuf: pass `targetUrl` with a FUZZ marker on the target host (e.g. http://TARGET:80/FUZZ).",
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

  lastManagerOllamaError = undefined;
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
      lastManagerOllamaError = (e as Error).message;
      console.warn(`[manager] Ollama attempt ${i + 1} (${mode}): ${lastManagerOllamaError}`);
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
  if (p.agent === "recon.gobuster") {
    if (typeof a.url === "string" && a.url.trim().length > 0) return true;
    if (Array.isArray(a.http_targets) && a.http_targets.some((x) => typeof x === "string" && /^https?:\/\//i.test(x.trim())))
      return true;
    if (typeof a.targetUrl === "string" && /^https?:\/\//i.test(a.targetUrl.trim())) return true;
    return false;
  }
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
