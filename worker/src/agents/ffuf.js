import { remoteScript, requireRemoteTool, snippet } from "./shared.js";
import { findingsFromWebFactsLlm } from "./webPathFindingsLlm.js";
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
export const ffufTool = {
    name: "recon.ffuf",
    description: "Fuzz a specific web path with ffuf using a SecLists wordlist. The targetUrl must contain a FUZZ placeholder (e.g. http://host/api/v1/FUZZ).",
    tags: ["recon", "web", "fuzz"],
    requires: ["http_targets"],
    defaultTimeoutMs: 6 * 60 * 1000,
    argSchema: {
        http_targets: {
            type: "array",
            items: { type: "string" },
            description: "Optional base URLs to fuzz (http/https, hostname must match target). If targetUrl is omitted, each base is converted to `${base}/FUZZ` (or `${base}{basePath}/FUZZ`)."
        },
        targetUrl: { type: "string", description: "URL with FUZZ placeholder, scoped to the run's target host." },
        basePath: {
            type: "string",
            description: "Optional path prefix when using http_targets (e.g. /api/v1). Each base becomes `${base}/api/v1/FUZZ`."
        },
        wordlist: { type: "string" },
        matchCodes: { type: "string", default: "200,204,301,302,307,401,403" },
        threads: { type: "number", default: 40 },
        timeoutSec: { type: "number", default: 6 }
    },
    handler: async (input, emit) => {
        const args = (input.args ?? {});
        const targets = collectTargetUrls(args, input.target.host);
        if (targets.length === 0) {
            return {
                status: "skipped",
                error: "No ffuf target. Provide `targetUrl` containing FUZZ (e.g. http://host:80/FUZZ) or provide `http_targets` (base URLs) optionally with `basePath`.",
                artifacts: { commands: [] },
                facts: [],
                findings: [],
                recommendations: [],
                meta: {}
            };
        }
        const presence = await requireRemoteTool(FFUF_BIN, input.signal);
        if (presence.missing)
            return presence.envelope;
        const catalog = await getWordlistCatalog({ signal: input.signal });
        let wordlist = null;
        let wordlistSource = "missing";
        if (args.wordlist && isWordlistAllowed(catalog, args.wordlist)) {
            wordlist = args.wordlist;
            wordlistSource = "manager";
        }
        else if (catalog.defaults.webContent) {
            wordlist = catalog.defaults.webContent;
            wordlistSource = "default";
        }
        if (!wordlist) {
            return {
                status: "failed",
                error: `No usable wordlist found. SecLists root ${catalog.root} does not contain a Web-Content list. ` +
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
        const allFacts = [];
        const allCommands = [];
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
            const facts = parseFfufJson(r.stdout);
            if (facts.length > 0)
                anyRunOk = true;
            allFacts.push(...facts);
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
        const webLlm = await findingsFromWebFactsLlm({
            tool: "recon.ffuf",
            targetHost: input.target.host,
            facts: allFacts,
            signal: input.signal,
            emitLog: (s) => emit.log(s)
        });
        return {
            status: allFacts.length > 0 ? "succeeded" : anyRunOk ? "partial" : "partial",
            durationMs: totalDurationMs,
            artifacts: { commands: allCommands, stdoutSnippet: snippet(stdoutAgg), stderrSnippet: snippet(stderrAgg) },
            facts: allFacts,
            findings: webLlm.findings,
            recommendations: [],
            meta: {
                exitCode: null,
                targets,
                wordlist,
                wordlistSource,
                matched: allFacts.length,
                webFindingsLlm: webLlm.meta,
                commandSummary: `Fuzz ${targets.length} target URL(s) with ffuf (codes ${matchCodes}, threads ${threads}) and lift matches as web_path facts.`
            }
        };
    }
};
function quote(s) {
    return `'${s.replace(/'/g, `'\\''`)}'`;
}
function normHost(h) {
    return h.trim().replace(/\.$/, "").toLowerCase();
}
function toBaseFromTargetUrl(raw) {
    const t = raw.trim();
    if (!t)
        return null;
    try {
        const u = new URL(t.replace(/FUZZ/g, "x"));
        u.pathname = u.pathname.replace(/x/g, "").replace(/\/+$/, "/");
        return u.toString();
    }
    catch {
        return null;
    }
}
function joinPath(base, basePath) {
    try {
        const u = new URL(base);
        if (!basePath || !basePath.trim())
            return u.toString().replace(/\/+$/, "/");
        const clean = "/" + basePath.replace(/^\/+/, "").replace(/\/+$/, "");
        u.pathname = (u.pathname || "/").replace(/\/+$/, "") + clean + "/";
        return u.toString();
    }
    catch {
        return base;
    }
}
function ensureFuzz(u) {
    return u.replace(/\/+$/, "/") + "FUZZ";
}
function collectTargetUrls(args, targetHost) {
    const out = [];
    const seen = new Set();
    const add = (raw) => {
        const t = raw.trim();
        if (!t)
            return;
        if (!/FUZZ/.test(t))
            return;
        try {
            const u = new URL(t.replace(/FUZZ/g, "x"));
            if (normHost(u.hostname) !== normHost(targetHost))
                return;
            const href = t;
            if (seen.has(href))
                return;
            seen.add(href);
            out.push(href);
        }
        catch {
            // ignore
        }
    };
    if (typeof args.targetUrl === "string")
        add(args.targetUrl);
    if (out.length === 0 && Array.isArray(args.http_targets)) {
        for (const item of args.http_targets) {
            if (typeof item !== "string")
                continue;
            try {
                const base = new URL(item.trim());
                if (normHost(base.hostname) !== normHost(targetHost))
                    continue;
                if (base.protocol !== "http:" && base.protocol !== "https:")
                    continue;
                const withPath = joinPath(base.toString(), args.basePath);
                const final = ensureFuzz(withPath);
                if (seen.has(final))
                    continue;
                seen.add(final);
                out.push(final);
            }
            catch {
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
                if (normHost(u.hostname) === normHost(targetHost))
                    out.push(ensureFuzz(joinPath(base, args.basePath)));
            }
            catch {
                // ignore
            }
        }
    }
    return out;
}
function parseFfufJson(stdout) {
    const facts = [];
    const jsonStart = stdout.indexOf("{", stdout.indexOf("==== FFUF_JSON ===="));
    const jsonEnd = stdout.lastIndexOf("}");
    if (jsonStart < 0 || jsonEnd <= jsonStart)
        return facts;
    try {
        const parsed = JSON.parse(stdout.slice(jsonStart, jsonEnd + 1));
        const results = Array.isArray(parsed.results) ? parsed.results : [];
        for (const row of results) {
            const url = typeof row.url === "string" ? row.url : "";
            const status = typeof row.status === "number" ? row.status : null;
            const length = typeof row.length === "number" ? row.length : null;
            if (!url)
                continue;
            facts.push({
                type: "web_path",
                value: { url, status, length },
                source: "ffuf"
            });
        }
    }
    catch {
        // ignore
    }
    return facts;
}
