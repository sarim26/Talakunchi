/**
 * Manager agent.
 *
 * Receives:
 *   - the MCP server manifest (available tools)
 *   - facts gathered so far (services, findings, history of invocations)
 *   - budget (max steps remaining)
 *
 * Returns a structured decision:
 *   { action: "invoke", tool: string, intentGoal: string, args?: Record<string, unknown> }
 *   { action: "stop", reason: string }
 *
 * Uses an Ollama LLM (qwen3:8b by default) but always falls back to a
 * deterministic policy so a missing/down LLM never breaks the pipeline.
 */
import { z } from "zod";
import { env } from "../env.js";
import { chatJSON } from "../llm/ollama.js";
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

export type ManagerContext = {
  targetHost: string;
  stepsRemaining: number;
  knownPorts: number[];
  knownServices: Array<{ port: number; protocol: string; name?: string; product?: string; version?: string }>;
  knownFindings: ToolFinding[];
  invocationHistory: Array<{
    tool: string;
    status: string;
    summary: string;
  }>;
  pendingRecommendations: Array<{ agent: string; reason: string; priority: number }>;
  /** Optional wordlist catalog so the manager can include `args.wordlist` when invoking tools that accept one. */
  wordlistCatalog?: WordlistCatalog;
  /**
   * Bounded failure history so the manager can attempt safe recovery actions.
   * This is intentionally compact (snippets only) to preserve context window.
   */
  recentFailures?: Array<{
    tool: string;
    attempt: number;
    args: Record<string, unknown>;
    error?: string;
    stdoutSnippet?: string;
    stderrSnippet?: string;
  }>;
};

export async function decideNextAction(server: MCPServer, ctx: ManagerContext, signal?: AbortSignal): Promise<ManagerDecision> {
  const llmDecision = await tryLlmDecision(server, ctx, signal);
  if (llmDecision && server.has(llmDecision.action === "invoke" ? llmDecision.tool : "")) {
    return llmDecision;
  }
  if (llmDecision && llmDecision.action === "stop") return llmDecision;
  return deterministicDecision(server, ctx);
}

async function tryLlmDecision(server: MCPServer, ctx: ManagerContext, signal?: AbortSignal): Promise<ManagerDecision | null> {
  const systemMsg = [
    "You are the MANAGER agent of a multi-agent penetration testing system.",
    "You decide which specialist tool to invoke next, or stop the run.",
    "Operate in read-only reconnaissance mode (no exploitation, no destructive operations).",
    "",
    'Return ONLY a JSON object matching ONE of:',
    '  { "action": "invoke", "tool": "<tool-name>", "intentGoal": "<short english goal>", "args": { ... }, "reasoning": "<why>" }',
    '  { "action": "stop", "reason": "<short why we are stopping>" }',
    "",
    "Rules:",
    "- Choose tool from the manifest below.",
    "- Do not pick a tool whose preconditions are not yet satisfied (e.g. recon.gobuster needs an HTTP endpoint).",
    "- If there are recentFailures, prefer safe recovery actions: retry with reduced scope (e.g. fewer threads), adjust timeouts, pick a different valid wordlist, or choose an alternative recon tool.",
    "- Stop early if no productive next step is available."
  ].join("\n");

  const userMsg = JSON.stringify(
    {
      manifest: server.manifest(),
      target: ctx.targetHost,
      stepsRemaining: ctx.stepsRemaining,
      knownPorts: ctx.knownPorts,
      knownServices: ctx.knownServices.slice(0, 30),
      pendingRecommendations: ctx.pendingRecommendations.slice(0, 10),
      knownFindings: ctx.knownFindings.slice(-15).map((f) => ({ title: f.title, severity: f.severity })),
      history: ctx.invocationHistory.slice(-15),
      recentFailures: (ctx.recentFailures ?? []).slice(-5)
    },
    null,
    2
  );

  try {
    const r = await chatJSON({
      model: env.OLLAMA_MANAGER_MODEL,
      messages: [
        { role: "system", content: systemMsg },
        { role: "user", content: userMsg }
      ],
      temperature: 0.2,
      maxTokens: 600,
      signal
    });
    const parsed = ManagerDecisionSchema.safeParse(r.value);
    if (parsed.success) return parsed.data;
  } catch {
    // fallthrough
  }
  return null;
}

/**
 * Deterministic policy: chosen if LLM is unavailable / produces invalid output.
 * Mirrors the tag-based recommendation engine encoded in each specialist tool.
 */
function deterministicDecision(server: MCPServer, ctx: ManagerContext): ManagerDecision {
  const have = (name: string) => server.has(name);
  const hasInvoked = (name: string) => ctx.invocationHistory.some((h) => h.tool === name);
  const hasOpenPort = (...ports: number[]) => ctx.knownServices.some((s) => ports.includes(s.port));

  if (ctx.stepsRemaining <= 0) return { action: "stop", reason: "Step budget exhausted" };

  const lastFail = (ctx.recentFailures ?? []).slice(-1)[0];
  if (lastFail && have(lastFail.tool) && lastFail.attempt < 1) {
    // Safe deterministic recovery: retry once with reduced knobs for common tools.
    const nextArgs: Record<string, unknown> = { ...(lastFail.args ?? {}) };
    if (lastFail.tool === "recon.gobuster") {
      const t = Number(nextArgs.threads ?? 20);
      nextArgs.threads = Math.max(5, Math.min(20, Math.floor(t / 2) || 10));
      // If the manager previously chose a bad wordlist, drop it to allow defaults.
      delete nextArgs.wordlist;
    }
    return {
      action: "invoke",
      tool: lastFail.tool,
      intentGoal: `Recover from previous failure of ${lastFail.tool} (attempt ${lastFail.attempt + 1})`,
      args: nextArgs,
      reasoning: "Deterministic recovery retry with reduced scope"
    };
  }

  const top = [...ctx.pendingRecommendations].sort((a, b) => b.priority - a.priority).find((r) => server.has(r.agent) && !hasInvoked(r.agent));
  if (top) {
    return {
      action: "invoke",
      tool: top.agent,
      intentGoal: top.reason,
      reasoning: `Following prior recommendation (priority ${top.priority})`
    };
  }

  if (have("recon.nmap") && !hasInvoked("recon.nmap")) {
    return {
      action: "invoke",
      tool: "recon.nmap",
      intentGoal: "Discover open ports and detect basic service banners",
      args: { profile: "fast" },
      reasoning: "No port data yet; start with nmap fast profile"
    };
  }

  if (have("recon.dns_enum") && !hasInvoked("recon.dns_enum")) {
    return { action: "invoke", tool: "recon.dns_enum", intentGoal: "Enumerate DNS records and subdomains" };
  }

  if (hasOpenPort(80, 443, 8080, 8443) && have("recon.http_probe") && !hasInvoked("recon.http_probe")) {
    return { action: "invoke", tool: "recon.http_probe", intentGoal: "Probe HTTP/HTTPS endpoints" };
  }
  if (hasOpenPort(443, 8443) && have("recon.tls_check") && !hasInvoked("recon.tls_check")) {
    return { action: "invoke", tool: "recon.tls_check", intentGoal: "Inspect TLS certificate / supported protocols" };
  }
  if (hasOpenPort(445, 139) && have("recon.smb_enum") && !hasInvoked("recon.smb_enum")) {
    return { action: "invoke", tool: "recon.smb_enum", intentGoal: "Enumerate SMB shares + signing posture" };
  }
  if (hasOpenPort(22) && have("recon.ssh_enum") && !hasInvoked("recon.ssh_enum")) {
    return { action: "invoke", tool: "recon.ssh_enum", intentGoal: "Capture SSH banner + algorithms" };
  }
  if (ctx.knownServices.length > 0 && have("recon.cve_enricher") && !hasInvoked("recon.cve_enricher")) {
    return { action: "invoke", tool: "recon.cve_enricher", intentGoal: "Match service banners to known-vulnerable software" };
  }
  if (ctx.knownServices.some((s) => /http/i.test(s.name ?? "")) && have("recon.gobuster") && !hasInvoked("recon.gobuster")) {
    const wordlist = ctx.wordlistCatalog?.defaults.webContent ?? undefined;
    return {
      action: "invoke",
      tool: "recon.gobuster",
      intentGoal: "Discover common web content paths",
      args: wordlist ? { wordlist } : undefined
    };
  }

  return { action: "stop", reason: "No further productive recon steps in deterministic policy" };
}
