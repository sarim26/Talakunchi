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
    http_targets: {
      type: "array",
      items: { type: "string" },
      description:
        "Optional base URLs to fuzz (http/https, hostname must match target). If targetUrl is omitted, each base is converted to `${base}/FUZZ` (or `${base}{basePath}/FUZZ`)."
    },
    targetUrl: { type: "string", description: "URL with FUZZ placeholder, scoped to the run's target host." },
    basePath: {
      type: "string",
      description:
        "Optional path prefix when using http_targets (e.g. /api/v1). Each base becomes `${base}/api/v1/FUZZ`."
    },
    wordlist: { type: "string" },
    matchCodes: { type: "string", default: "200,204,301,302,307,401,403" },
    threads: { type: "number", default: 40 },
    timeoutSec: { type: "number", default: 6 }
  },
  handler: async (input, emit): Promise<ToolEnvelope> => {
    const args = (input.args ?? {}) as {
      http_targets?: unknown;
      targetUrl?: string;
      basePath?: string;
      wordlist?: string;
      matchCodes?: string;
      threads?: number;
      timeoutSec?: number;
    };

    const targets = collectTargetUrls(args, input.target.host);
    if (targets.length === 0) {
      return {
        status: "skipped",
        error:
          "No ffuf target. Provide `targetUrl` containing FUZZ (e.g. http://host:80/FUZZ) or provide `http_targets` (base URLs) optionally with `basePath`.",
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

    const allFacts: ToolEnvelope["facts"] = [];
    const allFindings: ToolEnvelope["findings"] = [];
    const allCommands: string[] = [];
    let totalDurationMs = 0;
    let stdoutAgg = "";
    let stderrAgg = "";
    let anyWordlistMissing = false;
    let anyRunOk = false;

    for (const targetUrl of targets) {
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
      totalDurationMs += r.durationMs ?? 0;
      allCommands.push(...r.commands);
      stdoutAgg += (stdoutAgg ? "\n" : "") + r.stdout;
      stderrAgg += (stderrAgg ? "\n" : "") + (r.stderr ?? "");

      if (/WORDLIST_MISSING/.test(r.stdout)) {
        anyWordlistMissing = true;
        continue;
      }

      const { facts, findings } = parseFfufJson(r.stdout, targetUrl);
      if (facts.length > 0) anyRunOk = true;
      allFacts.push(...facts);
      allFindings.push(...findings);
    }

    if (anyWordlistMissing) {
      return {
        status: "failed",
        error: `Wordlist not present on tools host: ${wordlist}`,
        artifacts: { commands: allCommands, stdoutSnippet: snippet(stdoutAgg), stderrSnippet: snippet(stderrAgg) },
        facts: [],
        findings: [],
        recommendations: [],
        meta: { wordlist, wordlistSource }
      };
    }

    return {
      status: allFacts.length > 0 ? "succeeded" : anyRunOk ? "partial" : "partial",
      durationMs: totalDurationMs,
      artifacts: { commands: allCommands, stdoutSnippet: snippet(stdoutAgg), stderrSnippet: snippet(stderrAgg) },
      facts: allFacts,
      findings: allFindings,
      recommendations: [],
      meta: {
        exitCode: null,
        targets,
        wordlist,
        wordlistSource,
        matched: allFacts.length,
        commandSummary: `Fuzz ${targets.length} target URL(s) with ffuf (codes ${matchCodes}, threads ${threads}) and lift matches as web_path facts.`
      }
    };
  }
};

function quote(s: string) {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

function normHost(h: string): string {
  return h.trim().replace(/\.$/, "").toLowerCase();
}

function toBaseFromTargetUrl(raw: string): string | null {
  const t = raw.trim();
  if (!t) return null;
  try {
    const u = new URL(t.replace(/FUZZ/g, "x"));
    u.pathname = u.pathname.replace(/x/g, "").replace(/\/+$/, "/");
    return u.toString();
  } catch {
    return null;
  }
}

function joinPath(base: string, basePath?: string): string {
  try {
    const u = new URL(base);
    if (!basePath || !basePath.trim()) return u.toString().replace(/\/+$/, "/");
    const clean = "/" + basePath.replace(/^\/+/, "").replace(/\/+$/, "");
    u.pathname = (u.pathname || "/").replace(/\/+$/, "") + clean + "/";
    return u.toString();
  } catch {
    return base;
  }
}

function ensureFuzz(u: string): string {
  return u.replace(/\/+$/, "/") + "FUZZ";
}

function collectTargetUrls(
  args: { http_targets?: unknown; targetUrl?: string; basePath?: string },
  targetHost: string
): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const add = (raw: string) => {
    const t = raw.trim();
    if (!t) return;
    if (!/FUZZ/.test(t)) return;
    try {
      const u = new URL(t.replace(/FUZZ/g, "x"));
      if (normHost(u.hostname) !== normHost(targetHost)) return;
      const href = t;
      if (seen.has(href)) return;
      seen.add(href);
      out.push(href);
    } catch {
      // ignore
    }
  };

  if (typeof args.targetUrl === "string") add(args.targetUrl);

  if (out.length === 0 && Array.isArray(args.http_targets)) {
    for (const item of args.http_targets) {
      if (typeof item !== "string") continue;
      try {
        const base = new URL(item.trim());
        if (normHost(base.hostname) !== normHost(targetHost)) continue;
        if (base.protocol !== "http:" && base.protocol !== "https:") continue;
        const withPath = joinPath(base.toString(), args.basePath);
        const final = ensureFuzz(withPath);
        if (seen.has(final)) continue;
        seen.add(final);
        out.push(final);
      } catch {
        // ignore invalid
      }
    }
  }

  // If targetUrl was provided but lacked FUZZ, try to convert to a base and append FUZZ.
  if (out.length === 0 && typeof args.targetUrl === "string") {
    const base = toBaseFromTargetUrl(args.targetUrl);
    if (base) {
      try {
        const u = new URL(base);
        if (normHost(u.hostname) === normHost(targetHost)) out.push(ensureFuzz(joinPath(base, args.basePath)));
      } catch {
        // ignore
      }
    }
  }

  return out;
}

function parseFfufJson(stdout: string, targetUrl: string): { facts: ToolEnvelope["facts"]; findings: ToolEnvelope["findings"] } {
  const facts: ToolEnvelope["facts"] = [];
  const findings: ToolEnvelope["findings"] = [];

  const jsonStart = stdout.indexOf("{", stdout.indexOf("==== FFUF_JSON ===="));
  const jsonEnd = stdout.lastIndexOf("}");
  if (jsonStart < 0 || jsonEnd <= jsonStart) return { facts, findings };

  try {
    const parsed = JSON.parse(stdout.slice(jsonStart, jsonEnd + 1)) as Record<string, unknown>;
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
        /(admin|login|api|graphql|swagger|openapi|actuator|wp-admin|wp-login|phpmyadmin|backup|config|setup|debug|jenkins|kibana|grafana|drupal|uploads)|(?:^|\/)chats?(?:\/|$)/i.test(
          path
        )
      ) {
        findings.push({
          title: `Interesting web path discovered: ${path}`,
          severity: status === 200 ? "medium" : "low",
          evidence: `${url} → HTTP ${status}${length !== null ? ` (${length}b)` : ""}`,
          fingerprint: `ffuf|${targetUrl}|${path}|${status}`,
          confidence: "high",
          requiresVerification: false,
          claimType: "web_path"
        });
      }
    }
  } catch {
    // ignore
  }

  return { facts, findings };
}
