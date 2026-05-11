import { ToolDefinition, ToolEnvelope } from "../mcp/types.js";
import { remoteScript, requireRemoteTool, snippet } from "./shared.js";

const WAYBACK_BIN = "waybackurls";
const INTERESTING_PATH = /(phpmyadmin|drupal|wp-admin|wp-login|admin|login|signin|signup|register|uploads?|backup|config|setup|test|debug|api|graphql|swagger|openapi|actuator|jenkins|kibana|grafana|metrics|console|jmx-console|server-status)/i;

/**
 * Suggested non-apt install: golang + go install.
 * Used by system.tool_installer when the binary is missing.
 */
const WAYBACK_INSTALL_COMMAND = [
  "$SUDO apt-get update -y && $SUDO apt-get install -y golang-go",
  "export PATH=\"$PATH:$(go env GOPATH)/bin\"",
  "go install github.com/tomnomnom/waybackurls@latest"
].join(" && ");

/**
 * recon.waybackurls — backup endpoint amplifier.
 *
 * Layer 3 fallback for when Katana (recon.spider) discovers too few URLs.
 * Pulls historical URLs for the target host from the Wayback Machine and
 * emits them as `web_url` facts so the manager (or recon.ffuf) can target
 * paths that no longer appear in live navigation.
 *
 * Strictly read-only: it queries archive.org, not the target. We still scope
 * results to the run's target hostname so we never widen the run.
 */
export const waybackUrlsTool: ToolDefinition = {
  name: "recon.waybackurls",
  description:
    "Backup endpoint discovery: query the Wayback Machine for historical URLs of the target host (used when katana finds few endpoints).",
  tags: ["recon", "web", "amplification"],
  requires: ["target"],
  defaultTimeoutMs: 3 * 60 * 1000,
  argSchema: {
    host: { type: "string", description: "Hostname to query (defaults to the run's target host)" },
    limit: { type: "number", default: 500 }
  },
  handler: async (input, emit): Promise<ToolEnvelope> => {
    const args = (input.args ?? {}) as { host?: string; limit?: number };
    const host = (args.host && args.host.trim()) || input.target.host;
    const limit = Math.max(10, Math.min(2000, Number(args.limit ?? 500)));

    if (host !== input.target.host) {
      return {
        status: "skipped",
        error: `Refusing to query non-target host: ${host}`,
        artifacts: { commands: [] },
        facts: [],
        findings: [],
        recommendations: [],
        meta: {}
      };
    }

    const presence = await requireRemoteTool(WAYBACK_BIN, input.signal, { installCommand: WAYBACK_INSTALL_COMMAND });
    if (presence.missing) return presence.envelope;

    const script = [
      `set +e`,
      // waybackurls reads hostnames from stdin; we feed exactly one.
      `printf '%s\\n' ${quote(host)} | ${WAYBACK_BIN} | head -n ${limit}`
    ].join("\n");

    emit.log(`Pulling Wayback Machine URLs for ${host} (limit ${limit})`);
    const r = await remoteScript(script, input.signal, (s) => emit.log(s));

    const facts: ToolEnvelope["facts"] = [];
    const findings: ToolEnvelope["findings"] = [];
    const seen = new Set<string>();

    for (const raw of r.stdout.split("\n")) {
      const line = raw.trim();
      if (!line || !/^https?:\/\//i.test(line)) continue;
      let url: URL;
      try {
        url = new URL(line);
      } catch {
        continue;
      }
      // Keep only URLs on the run's target host (defence-in-depth).
      if (url.hostname !== host) continue;
      const href = url.href;
      if (seen.has(href)) continue;
      seen.add(href);

      facts.push({
        type: "web_url",
        value: { url: href, status: null, method: "GET" },
        source: "waybackurls"
      });

      // Promote high-signal historical paths so operators see them even if
      // they 404 today — they're often great clues about removed admin UIs.
      if (INTERESTING_PATH.test(url.pathname)) {
        const fp = `waybackurls|${host}|${url.pathname}`;
        if (!findings.some((f) => f.fingerprint === fp)) {
          findings.push({
            title: `Historical web path observed: ${url.pathname}`,
            severity: "info",
            evidence: `Archived URL: ${href}`,
            fingerprint: fp,
            confidence: "medium",
            requiresVerification: true,
            claimType: "historical_web_path"
          });
        }
      }
    }

    return {
      status: facts.length > 0 ? "succeeded" : "partial",
      durationMs: r.durationMs,
      artifacts: { commands: r.commands, stdoutSnippet: snippet(r.stdout), stderrSnippet: snippet(r.stderr) },
      facts,
      findings,
      recommendations:
        facts.length > 0
          ? [
              {
                agent: "recon.ffuf",
                reason: "Historical URLs found — fuzz them to confirm which still exist",
                priority: 60
              }
            ]
          : [],
      meta: {
        exitCode: r.exitCode,
        host,
        urlsDiscovered: facts.length,
        commandSummary: `Pull Wayback Machine URLs for ${host} (limit ${limit}) and emit each unique URL as a web_url fact.`
      }
    };
  }
};

function quote(s: string) {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}
