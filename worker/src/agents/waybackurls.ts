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
    "Backup endpoint discovery: query the Wayback CDX for historical URLs of the target host. Usually empty for private IPs (RFC1918) and hosts never archived on the public web.",
  tags: ["recon", "web", "amplification"],
  requires: ["target"],
  defaultTimeoutMs: 3 * 60 * 1000,
  argSchema: {
    host: {
      type: "string",
      description: "Host to query (must match run target). Wayback CDX is usually empty for RFC1918/private IPs and hosts never crawled on the public web."
    },
    limit: { type: "number", default: 500 }
  },
  handler: async (input, emit): Promise<ToolEnvelope> => {
    const args = (input.args ?? {}) as { host?: string; limit?: number; target?: string };
    const rawHost = (args.host && args.host.trim()) || input.target.host;
    const host = rawHost.trim();
    const limit = Math.max(10, Math.min(2000, Number(args.limit ?? 500)));

    if (normHost(host) !== normHost(input.target.host)) {
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

    // Write full waybackurls output to a temp file, then head(1) the file.
    // `… | waybackurls | head` closes the pipe early → SIGPIPE on waybackurls and
    // can yield empty stdout even when CDX returns rows; buffering to disk avoids that.
    const script = [
      `set +e`,
      `TMP=$(mktemp) || exit 1`,
      `ERR=$(mktemp) || { rm -f "$TMP"; exit 1; }`,
      `printf '%s\\n' ${quote(host)} | ${WAYBACK_BIN} >"$TMP" 2>"$ERR" || true`,
      `head -n ${limit} "$TMP"`,
      `if [ -s "$ERR" ]; then cat "$ERR" >&2; fi`,
      `rm -f "$TMP" "$ERR"`
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
      if (normHost(url.hostname) !== normHost(host)) continue;
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

    const errTail = (r.stderr ?? "").trim();
    const privateIp = isPrivateOrReservedIp(host);
    const noRowsHint =
      facts.length === 0
        ? privateIp
          ? "CDX usually has no public crawl history for private (RFC1918) IPs like this target — Wayback is scoped to the public web."
          : "CDX returned no URLs for this host (never publicly crawled, or archive gap). Check stderr for HTTP errors from archive.org."
        : undefined;

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
        noArchivedUrls: facts.length === 0,
        ...(noRowsHint ? { noRowsHint } : {}),
        ...(errTail ? { waybackStderrSnippet: snippet(errTail, 800) } : {}),
        commandSummary: `Pull Wayback Machine URLs for ${host} (limit ${limit}) and emit each unique URL as a web_url fact.`
      }
    };
  }
};

function normHost(h: string): string {
  return h.trim().replace(/\.$/, "").toLowerCase();
}

/** Rough check for addresses that almost never appear in public Wayback CDX. */
function isPrivateOrReservedIp(host: string): boolean {
  const h = normHost(host);
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return false;
  const oct = h.split(".").map((x) => Number(x));
  if (oct.some((n) => !Number.isFinite(n) || n > 255)) return false;
  const [a, b] = oct;
  if (a === 10) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  return false;
}

function quote(s: string) {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}
