import { ToolDefinition, ToolEnvelope } from "../mcp/types.js";
import { remoteScript, snippet } from "./shared.js";

/**
 * recon.http_probe — checks each candidate web port for a live HTTP/S response,
 * extracts status, server header, title, and basic redirects.
 *
 * Uses curl on the SSH host (no external services).
 */
export const httpProbeTool: ToolDefinition = {
  name: "recon.http_probe",
  description: "Probe HTTP/HTTPS endpoints on a target to capture status code, server header and title.",
  tags: ["recon", "web"],
  requires: ["services"],
  defaultTimeoutMs: 5 * 60 * 1000,
  argSchema: {
    ports: { type: "array", items: { type: "number" } }
  },
  handler: async (input, emit): Promise<ToolEnvelope> => {
    const knownPorts = (input.context?.knownServices ?? [])
      .filter((s) => /^http|^https|^web/i.test(s.name ?? "") || [80, 443, 8080, 8443].includes(s.port))
      .map((s) => ({ port: s.port, scheme: s.port === 443 || s.port === 8443 ? "https" : "http" }));

    const fromArgs = ((input.args as Record<string, unknown> | undefined)?.ports as number[] | undefined) ?? [];
    for (const p of fromArgs) {
      const scheme = p === 443 || p === 8443 ? "https" : "http";
      if (!knownPorts.some((kp) => kp.port === p)) knownPorts.push({ port: p, scheme });
    }

    if (knownPorts.length === 0) {
      return {
        status: "skipped",
        error: "No HTTP/HTTPS candidate ports in context",
        artifacts: { commands: [] },
        facts: [],
        findings: [],
        recommendations: [],
        meta: {}
      };
    }

    const host = input.target.host;
    const lines: string[] = [
      `set -euo pipefail`,
      `HOST=${quote(host)}`,
      `for ENTRY in ${knownPorts.map((p) => `${p.scheme}:${p.port}`).join(" ")}; do`,
      `  SCHEME=\${ENTRY%%:*}`,
      `  PORT=\${ENTRY##*:}`,
      `  URL="$SCHEME://$HOST:$PORT/"`,
      `  echo "==== $URL ===="`,
      `  curl -k -sS -o /tmp/_t.body -D /tmp/_t.head -m 8 -w 'HTTPCODE:%{http_code}\\nFINAL:%{url_effective}\\n' "$URL" || echo "CURL_ERR"`,
      `  head -c 4096 /tmp/_t.head || true`,
      `  echo "---- body-head ----"`,
      `  head -c 1024 /tmp/_t.body || true`,
      `  echo`,
      `done`
    ];

    emit.log(`Probing ${knownPorts.length} HTTP/S endpoints on ${host}`);
    const r = await remoteScript(lines.join("\n"), input.signal, (s) => emit.log(s));

    const blocks = r.stdout.split(/^==== /m).slice(1);
    const facts: ToolEnvelope["facts"] = [];
    const findings: ToolEnvelope["findings"] = [];

    for (const block of blocks) {
      const headerLine = block.split("\n")[0];
      const url = `==== ${headerLine}`.replace(/^====\s*/, "").replace(/\s*====\s*$/, "").trim();
      const statusMatch = /HTTPCODE:(\d{3})/.exec(block);
      const code = statusMatch ? Number(statusMatch[1]) : null;
      const serverMatch = /^Server:\s*(.+)$/im.exec(block);
      const titleMatch = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(block);

      facts.push({
        type: "http_endpoint",
        value: {
          url,
          status: code,
          server: serverMatch ? serverMatch[1].trim() : null,
          title: titleMatch ? titleMatch[1].trim().slice(0, 200) : null
        },
        source: "curl"
      });

      if (code && code >= 200 && code < 400) {
        findings.push({
          title: `Reachable web endpoint: ${url}`,
          severity: code >= 500 ? "low" : "info",
          evidence: `HTTP ${code}${serverMatch ? ` Server: ${serverMatch[1].trim()}` : ""}`,
          fingerprint: `http|${url}`
        });
      } else if (code && code >= 500) {
        findings.push({
          title: `Web endpoint returns ${code}: ${url}`,
          severity: "low",
          evidence: `HTTP ${code} from ${url}`,
          fingerprint: `http5xx|${url}`
        });
      }
    }

    const recs: ToolEnvelope["recommendations"] = [];
    if (facts.length > 0) {
      recs.push({ agent: "recon.gobuster", reason: "Discovered web endpoints — enumerate paths", priority: 60 });
      if (knownPorts.some((kp) => kp.scheme === "https")) {
        recs.push({ agent: "recon.tls_check", reason: "Verify TLS configuration", priority: 70 });
      }
    }

    return {
      status: facts.length > 0 ? "succeeded" : "partial",
      durationMs: r.durationMs,
      artifacts: { commands: r.commands, stdoutSnippet: snippet(r.stdout), stderrSnippet: snippet(r.stderr) },
      facts,
      findings,
      recommendations: recs,
      meta: { exitCode: r.exitCode, probed: knownPorts.length }
    };
  }
};

function quote(s: string) {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}
