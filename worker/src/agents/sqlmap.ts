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

const SQLMAP_INSTALL = "apt-get update -y && apt-get install -y sqlmap";

/**
 * exploit.sqlmap — gated SQL injection testing on discovered web URLs.
 * Requires human approval. Bounded flags (no os-shell/pwn).
 */
export const sqlmapTool: ToolDefinition = {
  name: "exploit.sqlmap",
  description:
    "Gated SQL injection check (sqlmap) on target HTTP(S) URLs with query parameters or forms. Requires Pipeline approval.",
  tags: ["exploit", "web", "gated"],
  requires: ["http_targets"],
  defaultTimeoutMs: 25 * 60 * 1000,
  argSchema: {
    urls: { type: "array", items: { type: "string" }, description: "Target URLs to test (must be on engagement host)" },
    url: { type: "string", description: "Single URL alternative" },
    http_targets: { type: "array", items: { type: "string" }, description: "Alias for urls" },
    level: { type: "number", default: 2, description: "sqlmap --level (1-3)" },
    risk: { type: "number", default: 2, description: "sqlmap --risk (1-3)" }
  },
  handler: async (input, emit): Promise<ToolEnvelope> => {
    const blocked = requireGatedExploitMode("exploit.sqlmap");
    if (blocked) return blocked;
    if (!env.SQLMAP_ENABLED) {
      return {
        status: "skipped",
        error: "exploit.sqlmap is disabled (set SQLMAP_ENABLED=true).",
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
    });

  const injectable = urls.filter((u) => /[?&][^=]+=/.test(u) || /phpmyadmin|dvwa|login|admin|id=/i.test(u));
    const targets = injectable.length > 0 ? injectable : urls;
    if (targets.length === 0) {
      return {
        status: "skipped",
        error: "No target HTTP(S) URLs for sqlmap. Pass urls/http_targets or run recon spider/gobuster first.",
        artifacts: { commands: [] },
        facts: [],
        findings: [],
        recommendations: [],
        meta: {}
      };
    }

    const presence = await requireRemoteTool("sqlmap", input.signal, { installCommand: SQLMAP_INSTALL });
    if (presence.missing) return presence.envelope;

    const level = Math.min(3, Math.max(1, Number((input.args as { level?: number })?.level ?? 2)));
    const risk = Math.min(3, Math.max(1, Number((input.args as { risk?: number })?.risk ?? 2)));
    const planned = `sqlmap on ${targets.length} URL(s): ${targets.slice(0, 3).join(", ")}${targets.length > 3 ? "…" : ""}`;

    const approval = await runGatedApproval({
      agentRunId: input.context?.runId,
      tool: "exploit.sqlmap",
      command: planned,
      reasoning: input.intent ?? "SQL injection testing on discovered web endpoints",
      impact: "high",
      args: { urls: targets.slice(0, 8), level, risk },
      signal: input.signal,
      emitLog: (s) => emit.log(s)
    });
    if (!approval.approved) return approval.envelope;

    const findings: ToolFinding[] = [];
    const facts: ToolEnvelope["facts"] = [];
    const commands: string[] = [];
    let stdoutAll = "";

    for (const targetUrl of targets.slice(0, 6)) {
      const outDir = `/tmp/sqlmap_${Date.now()}_$$`;
      const script = [
        "set +e",
        `URL=${quoteShell(targetUrl)}`,
        `OUT=${quoteShell(outDir)}`,
        [
          "sqlmap",
          `-u "$URL"`,
          "--batch",
          `--level=${level}`,
          `--risk=${risk}`,
          "--threads=2",
          "--timeout=15",
          '--answers="crack=N,continue=N,quit=N"',
          "--output-dir=\"$OUT\"",
          "--flush-session",
          "2>&1"
        ].join(" "),
        `rm -rf "$OUT" 2>/dev/null || true`
      ].join("\n");

      emit.log(`[sqlmap] ${targetUrl}`);
      const r = await remoteScript(script, input.signal, (s) => emit.log(s));
      commands.push(`sqlmap -u ${targetUrl}`);
      stdoutAll += r.stdout;

      const vulnerable = /is vulnerable|sqlmap identified the following injection|Parameter:/i.test(r.stdout);
      const dbms = /back-end DBMS:\s*([^\n]+)/i.exec(r.stdout)?.[1]?.trim();
      if (vulnerable) {
        facts.push({
          type: "sqli",
          value: { url: targetUrl, dbms: dbms ?? null, snippet: snippet(r.stdout, 400) },
          source: "sqlmap"
        });
        findings.push({
          title: `SQL injection likely on ${targetUrl}`,
          severity: "critical",
          evidence: snippet(r.stdout, 500),
          fingerprint: `sqli|${targetUrl}`,
          confidence: "high",
          requiresVerification: false,
          claimType: "sqli"
        });
      }
    }

    return {
      status: "succeeded",
      facts,
      findings,
      recommendations: findings.length
        ? [{ agent: "exploit.commix", reason: "SQLi found — check same host for command injection vectors", priority: 70 }]
        : [],
      artifacts: { commands, stdoutSnippet: snippet(stdoutAll, 2000) },
      meta: { approvalId: approval.approvalId, urlsTested: targets.length, sqliFound: findings.length, commandSummary: planned }
    };
  }
};
