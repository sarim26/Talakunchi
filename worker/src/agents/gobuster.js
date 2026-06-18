import { remoteScript, snippet } from "./shared.js";
import { getWordlistCatalog, isWordlistAllowed } from "./wordlists.js";
import { findingsFromWebFactsLlm } from "./webPathFindingsLlm.js";
/**
 * recon.gobuster — directory/file content discovery on previously-discovered
 * web endpoints. The wordlist comes from the SecLists catalog and is chosen
 * either by the manager (via args.wordlist) or falls back to the catalog
 * default. Hardcoded paths are no longer used.
 */
export const gobusterTool = {
    name: "recon.gobuster",
    description: "Brute-force common content paths on a discovered HTTP(S) endpoint using gobuster. Wordlist is chosen by the manager from the SecLists catalog. Pass `url` and/or `http_targets` (base URLs on the target host).",
    tags: ["recon", "web"],
    requires: ["http_targets"],
    defaultTimeoutMs: 6 * 60 * 1000,
    argSchema: {
        url: { type: "string", description: "Single base URL for gobuster dir mode (http/https, hostname must match target)." },
        http_targets: {
            type: "array",
            items: { type: "string" },
            description: "One or more base URLs to scan (same host as target). Each gets its own gobuster run; merged facts/findings."
        },
        targetUrl: {
            type: "string",
            description: "Optional base URL (same as url). If it contains FUZZ (ffuf-style), the marker is stripped and the remainder is used as the base."
        },
        basePath: {
            type: "string",
            description: "Optional path under each base URL to brute-force from (e.g. /admin/)."
        },
        wordlist: { type: "string", description: "Absolute path under /home/kali/Desktop/SecLists/. Manager should pick from the run-time catalog." },
        threads: { type: "number", default: 20 }
    },
    handler: async (input, emit) => {
        const args = (input.args ?? {});
        const bases = collectGobusterBaseUrls(args, input.target.host).map((u) => applyBasePath(u, args.basePath));
        if (bases.length === 0) {
            return {
                status: "skipped",
                error: "No HTTP target: pass `url`, `http_targets` (URLs on the target host), and/or `targetUrl` (base URL; FUZZ stripped if present). Run recon.http_probe first.",
                artifacts: { commands: [] },
                facts: [],
                findings: [],
                recommendations: [],
                meta: {}
            };
        }
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
        const threads = Math.max(1, Math.min(50, Number(args.threads ?? 20)));
        const allFacts = [];
        const allCommands = [];
        let totalDurationMs = 0;
        let stdoutAgg = "";
        let stderrAgg = "";
        let anyWordlistMissing = false;
        let anyFlagErr = false;
        let anyHardFailure = false;
        let anyRunOk = false;
        for (const url of bases) {
            const script = [
                `set -euo pipefail`,
                `URL=${quote(url)}`,
                `WORDLIST=${quote(wordlist)}`,
                `if [ ! -f "$WORDLIST" ]; then`,
                `  echo "WORDLIST_MISSING: $WORDLIST"`,
                `  exit 0`,
                `fi`,
                `gobuster dir -u "$URL" -w "$WORDLIST" -k --no-error --quiet -t ${threads} -b 404,403`
            ].join("\n");
            emit.log(`Running gobuster against ${url} (wordlist=${wordlistSource}: ${wordlist})`);
            const r = await remoteScript(script, input.signal, (s) => emit.log(s));
            totalDurationMs += r.durationMs ?? 0;
            allCommands.push(...r.commands);
            stdoutAgg += (stdoutAgg ? "\n" : "") + r.stdout;
            stderrAgg += (stderrAgg ? "\n" : "") + (r.stderr ?? "");
            if (r.stdout.includes("WORDLIST_MISSING")) {
                anyWordlistMissing = true;
                continue;
            }
            const flagErr = /Cannot use two forms of the same flag|unknown flag|flag provided but not defined/i.test(`${r.stdout}\n${r.stderr}`);
            if (flagErr) {
                anyFlagErr = true;
                anyHardFailure = true;
                continue;
            }
            if (r.exitCode != null && r.exitCode !== 0) {
                anyHardFailure = true;
                continue;
            }
            anyRunOk = true;
            const facts = collectGobusterFacts(r.stdout, url);
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
                meta: { wordlist, wordlistSource, bases }
            };
        }
        if (!anyRunOk && anyFlagErr) {
            return {
                status: "failed",
                error: "Gobuster CLI flag error (invalid args)",
                durationMs: totalDurationMs,
                artifacts: { commands: allCommands, stdoutSnippet: snippet(stdoutAgg), stderrSnippet: snippet(stderrAgg) },
                facts: [],
                findings: [],
                recommendations: [],
                meta: { exitCode: null, wordlist, wordlistSource, threads }
            };
        }
        if (!anyRunOk && anyHardFailure) {
            return {
                status: "failed",
                error: "Gobuster failed on all targets (non-zero exit)",
                durationMs: totalDurationMs,
                artifacts: { commands: allCommands, stdoutSnippet: snippet(stdoutAgg), stderrSnippet: snippet(stderrAgg) },
                facts: [],
                findings: [],
                recommendations: [],
                meta: { wordlist, wordlistSource, threads, bases }
            };
        }
        const status = (anyHardFailure && anyRunOk) || (anyFlagErr && anyRunOk) ? "partial" : "succeeded";
        const webLlm = await findingsFromWebFactsLlm({
            tool: "recon.gobuster",
            targetHost: input.target.host,
            facts: allFacts,
            signal: input.signal,
            emitLog: (s) => emit.log(s)
        });
        return {
            status,
            durationMs: totalDurationMs,
            artifacts: { commands: allCommands, stdoutSnippet: snippet(stdoutAgg), stderrSnippet: snippet(stderrAgg) },
            facts: allFacts,
            findings: webLlm.findings,
            recommendations: [],
            meta: {
                wordlist,
                wordlistSource,
                count: allFacts.length,
                bases,
                webFindingsLlm: webLlm.meta,
                commandSummary: `Brute-force common web paths on ${bases.length} base URL(s) using gobuster.`
            }
        };
    }
};
function normHost(h) {
    return h.trim().replace(/\.$/, "").toLowerCase();
}
/** Strip ffuf-style FUZZ marker and trailing slashes so `new URL` succeeds. */
function fuzzToBaseUrl(raw) {
    let s = raw.trim();
    if (!s)
        return s;
    if (/FUZZ/i.test(s)) {
        s = s.replace(/FUZZ/gi, "");
        s = s.replace(/\/+$/, "");
    }
    return s.trim();
}
function tryAddBaseUrl(raw, targetHost, seen, out) {
    if (!raw || typeof raw !== "string")
        return;
    const candidate = fuzzToBaseUrl(raw);
    if (!candidate)
        return;
    try {
        const u = new URL(candidate);
        if (normHost(u.hostname) !== normHost(targetHost))
            return;
        if (u.protocol !== "http:" && u.protocol !== "https:")
            return;
        const key = u.toString();
        if (seen.has(key))
            return;
        seen.add(key);
        out.push(u.toString());
    }
    catch {
        // ignore invalid urls
    }
}
function collectGobusterBaseUrls(args, targetHost) {
    const seen = new Set();
    const out = [];
    tryAddBaseUrl(args.url, targetHost, seen, out);
    tryAddBaseUrl(args.targetUrl, targetHost, seen, out);
    if (Array.isArray(args.http_targets)) {
        for (const item of args.http_targets) {
            if (typeof item === "string")
                tryAddBaseUrl(item, targetHost, seen, out);
        }
    }
    return out;
}
function applyBasePath(url, basePath) {
    if (!basePath || !String(basePath).trim())
        return url;
    try {
        const base = new URL(url);
        const pathClean = "/" + basePath.replace(/^\/+/, "").replace(/\/+$/, "") + "/";
        base.pathname = pathClean;
        return base.toString();
    }
    catch {
        return url;
    }
}
function collectGobusterFacts(stdout, url) {
    const facts = [];
    const lines = stdout
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l && /Status:\s*\d{3}/.test(l));
    for (const line of lines) {
        const codeMatch = /Status:\s*(\d{3})/.exec(line);
        if (!codeMatch?.[1])
            continue;
        const code = Number(codeMatch[1]);
        if (!Number.isFinite(code))
            continue;
        const redirectUrlMatch = /\[-->\s*(https?:\/\/[^\]\s]+)\s*\]/i.exec(line);
        const leadingTokenMatch = /^(\S+)\s+\(Status:\s*\d{3}\)/.exec(line);
        const leadingPathMatch = /^(\/\S+)\s+\(Status:\s*\d{3}\)/.exec(line);
        let fullUrl = null;
        let path = null;
        if (redirectUrlMatch?.[1]) {
            fullUrl = redirectUrlMatch[1];
            try {
                const u = new URL(fullUrl);
                path = u.pathname || "/";
            }
            catch {
                path = null;
            }
        }
        else if (leadingPathMatch?.[1]) {
            path = leadingPathMatch[1];
            fullUrl = `${url.replace(/\/$/, "")}${path}`;
        }
        else if (leadingTokenMatch?.[1]) {
            path = `/${leadingTokenMatch[1].replace(/^\/+/, "")}`;
            fullUrl = `${url.replace(/\/$/, "")}${path}`;
        }
        if (!fullUrl)
            continue;
        facts.push({ type: "web_path", value: { url: fullUrl, status: code }, source: "gobuster" });
    }
    return facts;
}
function quote(s) {
    return `'${s.replace(/'/g, `'\\''`)}'`;
}
