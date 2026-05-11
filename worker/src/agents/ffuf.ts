import { ToolDefinition, ToolEnvelope } from "../mcp/types.js";
import { remoteScript, requireRemoteTool, snippet } from "./shared.js";
import { getWordlistCatalog, isWordlistAllowed } from "./wordlists.js";

const FFUF_BIN = "ffuf";

/**
 * recon.ffuf — surgical web path fuzzing.
 *
 * Unlike recon.gobuster which always starts at `/`, this tool accepts a
 * concrete `targetUrl` containing a `FUZZ` placeholder so the manager can
 * point it at exactly the path spider discovered (e.g. `/api/v1/FUZZ`).
 *
 * Args:
 *   - targetUrl    : URL with a FUZZ marker (must match the run's target host)
 *   - wordlist     : Absolute path under SecLists (manager-selected)
 *   - matchCodes   : Comma-separated HTTP codes considered "interesting"
 *   - threads      : Concurrent workers (default 40)
 *   - timeoutSec   : Per-request timeout (default 6s)
 */
export const ffufTool: ToolDefinition = {
  name: "recon.ffuf",
  description:
    "Fuzz a specific web path with ffuf using a SecLists wordlist. The targetUrl must contain a FUZZ placeholder (e.g. http://host/api/v1/FUZZ).",
  tags: ["recon", "web", "fuzz"],
  requires: ["http_targets"],
  defaultTimeoutMs: 6 * 60 * 1000,
  argSchema: {
    targetUrl: { type: "string", description: "URL with FUZZ placeholder, scoped to the run's target host." },
    wordlist: { type: "string" },
    matchCodes: { type: "string", default: "200,204,301,302,307,401,403" },
    threads: { type: "number", default: 40 },
    timeoutSec: { type: "number", default: 6 }
  },
  handler: async (input, emit): Promise<ToolEnvelope> => {
    const args = (input.args ?? {}) as {
      targetUrl?: string;
      wordlist?: string;
      matchCodes?: string;
      threads?: number;
      timeoutSec?: number;
    };

    // Build a default targetUrl if the manager didn't pass one: probe the
    // root with `/FUZZ` against the reachable web endpoint we know about.
    let targetUrl = args.targetUrl;
    if (targetUrl) {
      try {
        const u = new URL(targetUrl.replace(/FUZZ/g, "x"));
        if (u.hostname !== input.target.host) targetUrl = undefined;
      } catch {
        targetUrl = undefined;
      }
    }
    if (!targetUrl) {
      const httpFact = (input.context?.priorFindings ?? []).find((f) => /Reachable web endpoint:/i.test(f.title));
      if (httpFact) {
        const m = /Reachable web endpoint:\s*(\S+)/.exec(httpFact.title);
        if (m) targetUrl = `${m[1].replace(/\/$/, "")}/FUZZ`;
      }
    }
    if (!targetUrl) {
      const known = (input.context?.knownServices ?? []).find((s) => [80, 8080, 443, 8443].includes(s.port));
      if (known) {
        const scheme = known.port === 443 || known.port === 8443 ? "https" : "http";
        targetUrl = `${scheme}://${input.target.host}:${known.port}/FUZZ`;
      }
    }
    if (!targetUrl || !/FUZZ/.test(targetUrl)) {
      return {
        status: "skipped",
        error: "No targetUrl with FUZZ placeholder available; run recon.http_probe + recon.spider first.",
        artifacts: { commands: [] },
        facts: [],
        findings: [],
        recommendations: [],
        meta: {}
      };
    }

    const presence = await requireRemoteTool(FFUF_BIN, input.signal);
    if (presence.missing) return presence.envelope;

    const catalog = await getWordlistCatalog({ signal: input.signal });
    let wordlist: string | null = null;
    let wordlistSource: "manager" | "default" | "missing" = "missing";
    if (args.wordlist && isWordlistAllowed(catalog, args.wordlist)) {
      wordlist = args.wordlist;
      wordlistSource = "manager";
    } else if (catalog.defaults.webContent) {
      wordlist = catalog.defaults.webContent;
      wordlistSource = "default";
    }
    if (!wordlist) {
      return {
        status: "failed",
        error:
          `No usable wordlist found. SecLists root ${catalog.root} does not contain a Web-Content list. ` +
          `Install SecLists on the SSH host or pass an absolute path that resolves under ${catalog.root}.`,
        artifacts: { commands: [] },
        facts: [],
        findings: [],
        recommendations: [],
        meta: { catalogRoot: catalog.root, rootExists: catalog.rootExists }
      };
    }

    const matchCodes = String(args.matchCodes ?? "200,204,301,302,307,401,403").replace(/\s+/g, "");
    const threads = Math.max(1, Math.min(80, Number(args.threads ?? 40)));
    const timeoutSec = Math.max(2, Math.min(30, Number(args.timeoutSec ?? 6)));

    // ffuf is configured for JSON output via -of json; we read the resulting
    // file. Streaming JSONL via -mc is possible but using a tempfile is
    // simpler and avoids interleaved log output.
    const outPath = `/tmp/_ffuf_$$.json`;
    const script = [
      `set -euo pipefail`,
      `URL=${quote(targetUrl)}`,
      `WORDLIST=${quote(wordlist)}`,
      `OUT=${outPath}`,
      `rm -f "$OUT"`,
      `if [ ! -f "$WORDLIST" ]; then echo "WORDLIST_MISSING: $WORDLIST"; exit 0; fi`,
      `${FFUF_BIN} -u "$URL" -w "$WORDLIST" -mc ${matchCodes} -t ${threads} -timeout ${timeoutSec} -of json -o "$OUT" -s 2>&1 || true`,
      `if [ -f "$OUT" ]; then`,
      `  echo "==== FFUF_JSON ===="`,
      `  cat "$OUT"`,
      `else`,
      `  echo "==== FFUF_JSON ===="`,
      `  echo '{"_error":"no_output"}'`,
      `fi`
    ].join("\n");

    emit.log(`Running ffuf against ${targetUrl} (wordlist=${wordlistSource})`);
    const r = await remoteScript(script, input.signal, (s) => emit.log(s));

    if (/WORDLIST_MISSING/.test(r.stdout)) {
      return {
        status: "failed",
        error: `Wordlist not present on tools host: ${wordlist}`,
        artifacts: { commands: r.commands, stdoutSnippet: snippet(r.stdout), stderrSnippet: snippet(r.stderr) },
        facts: [],
        findings: [],
        recommendations: [],
        meta: { wordlist, wordlistSource }
      };
    }

    const facts: ToolEnvelope["facts"] = [];
    const findings: ToolEnvelope["findings"] = [];

    const jsonStart = r.stdout.indexOf("{", r.stdout.indexOf("==== FFUF_JSON ===="));
    const jsonEnd = r.stdout.lastIndexOf("}");
    if (jsonStart >= 0 && jsonEnd > jsonStart) {
      try {
        const parsed = JSON.parse(r.stdout.slice(jsonStart, jsonEnd + 1)) as Record<string, unknown>;
        const results = Array.isArray((parsed as any).results) ? ((parsed as any).results as Array<Record<string, unknown>>) : [];
        for (const row of results) {
          const url = typeof row.url === "string" ? (row.url as string) : "";
          const status = typeof row.status === "number" ? (row.status as number) : null;
          const length = typeof row.length === "number" ? (row.length as number) : null;
          if (!url) continue;
          facts.push({
            type: "web_path",
            value: { url, status, length },
            source: "ffuf"
          });

          let path = "";
          try {
            path = new URL(url).pathname || "";
          } catch {
            path = url;
          }
          if (
            status !== null &&
            [200, 301, 302, 401, 403].includes(status) &&
            /(admin|login|api|graphql|swagger|openapi|actuator|wp-admin|wp-login|phpmyadmin|backup|config|setup|debug|jenkins|kibana|grafana)/i.test(path)
          ) {
            findings.push({
              title: `Interesting web path discovered: ${path}`,
              severity: status === 200 ? "medium" : "low",
              evidence: `${url} → HTTP ${status}${length !== null ? ` (${length}b)` : ""}`,
              fingerprint: `ffuf|${targetUrl}|${path}|${status}`,
              // ffuf actually retrieved this response from the server.
              confidence: "high",
              requiresVerification: false,
              claimType: "web_path"
            });
          }
        }
      } catch {
        // fall through to empty
      }
    }

    return {
      status: facts.length > 0 ? "succeeded" : "partial",
      durationMs: r.durationMs,
      artifacts: { commands: r.commands, stdoutSnippet: snippet(r.stdout), stderrSnippet: snippet(r.stderr) },
      facts,
      findings,
      recommendations: [],
      meta: {
        exitCode: r.exitCode,
        targetUrl,
        wordlist,
        wordlistSource,
        matched: facts.length,
        commandSummary: `Fuzz ${targetUrl} with ffuf (codes ${matchCodes}, threads ${threads}) and lift matches as web_path facts.`
      }
    };
  }
};

function quote(s: string) {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}
