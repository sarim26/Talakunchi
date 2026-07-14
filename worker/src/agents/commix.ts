import { ToolDefinition, ToolEnvelope, ToolFinding } from "../mcp/types.js";
import { env } from "../env.js";
import { remoteScript, requireRemoteTool, snippet } from "./shared.js";
import { resolveWebScanFromInput } from "./webTarget.js";
import {
  collectTargetHttpUrls,
  quoteShell,
  requireGatedExploitMode,
  runGatedApproval
} from "./exploitGated.js";

const COMMIX_INSTALL = "apt-get update -y && apt-get install -y commix";

/**
 * exploit.commix — gated command injection testing on parameterized URLs.
 */
export const commixTool: ToolDefinition = {
  name: "exploit.commix",
  description:
    "Gated command injection check (commix) on HTTP(S) URLs with parameters. Requires Pipeline approval.",
  tags: ["exploit", "web", "gated"],
  requires: ["http_targets"],
  defaultTimeoutMs: 20 * 60 * 1000,
  argSchema: {
    urls: { type: "array", items: { type: "string" } },
    url: { type: "string" },
    http_targets: { type: "array", items: { type: "string" } },
    level: { type: "number", default: 2 }
  },
  handler: async (input, emit): Promise<ToolEnvelope> => {
    const blocked = requireGatedExploitMode("exploit.commix");
    if (blocked) return blocked;
    if (!env.COMMIX_ENABLED) {
      return {
        status: "skipped",
        error: "exploit.commix is disabled (set COMMIX_ENABLED=true).",
        artifacts: { commands: [] },
        facts: [],
        findings: [],
        recommendations: [],
        meta: {}
      };
    }

    const webScan = resolveWebScanFromInput(input.target.host, input.target.vhost, input.context?.webScan);
    const urls = collectTargetHttpUrls({
      host: input.target.host,
      vhost: webScan.vhost,
      args: input.args as Record<string, unknown>,
      discoveredEndpoints: input.context?.discoveredEndpoints
    }).filter((u) => /[?&][^=]+=/.test(u));

    if (urls.length === 0) {
      return {
        status: "skipped",
        error: "No parameterized HTTP(S) URLs for commix.",
        artifacts: { commands: [] },
        facts: [],
        findings: [],
        recommendations: [],
        meta: {}
      };
    }

    const presence = await requireRemoteTool("commix", input.signal, { installCommand: COMMIX_INSTALL });
    if (presence.missing) return presence.envelope;

    const level = Math.min(3, Math.max(1, Number((input.args as { level?: number })?.level ?? 2)));
    const targets = urls.slice(0, 4);
    const planned = `commix on ${targets.join(", ")}`;

    const approval = await runGatedApproval({
      agentRunId: input.context?.runId,
      tool: "exploit.commix",
      command: planned,
      reasoning: input.intent ?? "Command injection testing on web parameters",
      impact: "high",
      args: { urls: targets, level },
      signal: input.signal,
      emitLog: (s) => emit.log(s)
    });
    if (!approval.approved) return approval.envelope;

    const findings: ToolFinding[] = [];
    const facts: ToolEnvelope["facts"] = [];
    const commands: string[] = [];
    let stdoutAll = "";
    const scanned: Array<{ url: string; injectable: boolean; notes: string[] }> = [];

    for (const targetUrl of targets) {
      const script = [
        "set +e",
        `URL=${quoteShell(targetUrl)}`,
        `commix --url="$URL" --batch --level=${level} --smart --timeout=20 2>&1 || true`
      ].join("\n");
      emit.log(`[commix] ${targetUrl}`);
      const r = await remoteScript(script, input.signal, (s) => emit.log(s));
      commands.push(`commix --url=${targetUrl}`);
      stdoutAll += r.stdout;

      const injectable = /injectable|command injection|os-shell|The payload/i.test(r.stdout);
      const notes: string[] = [];
      if (/WAF|IPS|blocked|forbidden/i.test(r.stdout)) notes.push("possible_waf_or_block");
      if (/timeout|timed out/i.test(r.stdout)) notes.push("timeout");
      scanned.push({ url: targetUrl, injectable, notes });

      if (injectable) {
        facts.push({ type: "cmdi", value: { url: targetUrl, snippet: snippet(r.stdout, 400) }, source: "commix" });
        findings.push({
          title: `Command injection likely on ${targetUrl}`,
          severity: "critical",
          evidence: snippet(r.stdout, 500),
          fingerprint: `cmdi|${targetUrl}`,
          confidence: "high",
          requiresVerification: false,
          claimType: "rce"
        });
      }
    }

    if (findings.length === 0) {
      facts.push({
        type: "commix_summary",
        value: { urlsTested: targets, level, result: "no_injection_detected", perUrl: scanned },
        source: "commix"
      });
    }

    return {
      status: "succeeded",
      facts,
      findings,
      recommendations: [],
      artifacts: { commands, stdoutSnippet: snippet(stdoutAll, 2000) },
      meta: { approvalId: approval.approvalId, commandSummary: planned }
    };
  }
};
