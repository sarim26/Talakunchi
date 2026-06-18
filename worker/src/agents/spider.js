import { remoteScript, requireRemoteTool, snippet } from "./shared.js";
const KATANA_BIN = "katana";
/** Suggested remote install when Katana is absent (not via apt). Uses $SUDO from tool_installer. */
const KATANA_INSTALL_COMMAND = [
    "$SUDO apt-get update -y && $SUDO apt-get install -y golang-go",
    "export PATH=\"$PATH:$(go env GOPATH)/bin\"",
    "go install github.com/projectdiscovery/katana/cmd/katana@latest"
].join(" && ");
const INTERESTING_PATH = /(phpmyadmin|drupal|wp-admin|wp-login|admin|login|signin|signup|register|uploads?|backup|config|setup|test|debug|api|graphql|swagger|openapi|actuator|jenkins|kibana|grafana|metrics|console|jmx-console|server-status)|(?:^|\/)chats?(?:\/|$)/i;
/**
 * recon.spider — Katana-based crawler. Seeds come **only** from structured
 * `args` (`http_targets` and/or `url`); the manager + execution-command-writer
 * are responsible for supplying them from context. Katana argv is built from
 * those args (depth, concurrency, etc.), not from hidden defaults beyond
 * schema defaults.
 */
export const spiderTool = {
    name: "recon.spider",
    description: "Crawl discovered HTTP(S) seed URLs with Katana. Pass `http_targets` (array) and/or `url`; each seed must be on the run target host.",
    tags: ["recon", "web"],
    requires: ["http_targets"],
    defaultTimeoutMs: 8 * 60 * 1000,
    argSchema: {
        http_targets: {
            type: "array",
            items: { type: "string" },
            description: "Seed URLs to crawl (http/https, hostname must match target)"
        },
        url: { type: "string", description: "Single seed URL (alternative to http_targets)" },
        depth: { type: "number", default: 3 },
        jsCrawl: { type: "boolean", default: true },
        concurrency: { type: "number", default: 10 },
        timeoutSec: { type: "number", default: 10 },
        includeSubdomains: { type: "boolean", default: false }
    },
    handler: async (input, emit) => {
        const args = (input.args ?? {});
        const seeds = collectSeeds(args, input.target.host);
        if (seeds.length === 0) {
            return {
                status: "skipped",
                error: "No crawl seeds in args. Provide `http_targets` (non-empty URL strings) and/or `url` for this target host (manager + execution writer fill these from http_probe).",
                artifacts: { commands: [] },
                facts: [],
                findings: [],
                recommendations: [],
                meta: {}
            };
        }
        const presence = await requireRemoteTool(KATANA_BIN, input.signal, { installCommand: KATANA_INSTALL_COMMAND });
        if (presence.missing)
            return presence.envelope;
        const depth = clampInt(args.depth ?? 3, 1, 6);
        const concurrency = clampInt(args.concurrency ?? 10, 1, 30);
        const timeoutSec = clampInt(args.timeoutSec ?? 10, 3, 30);
        const jsCrawl = args.jsCrawl !== false;
        const fieldScope = args.includeSubdomains ? "rdn" : "fqdn";
        const allFacts = [];
        const allFindings = [];
        const allCommands = [];
        let totalDuration = 0;
        let worstExit = null;
        const seen = new Set();
        const seenFindingFp = new Set();
        let stdoutAggregate = "";
        for (const seedUrl of seeds) {
            const flags = buildKatanaArgv(seedUrl, depth, concurrency, timeoutSec, fieldScope, jsCrawl);
            const script = [`set +e`, `${KATANA_BIN} ${flags.join(" ")}`].join("\n");
            emit.log(`Running katana against ${seedUrl} (depth=${depth}, concurrency=${concurrency}, jsCrawl=${jsCrawl})`);
            const r = await remoteScript(script, input.signal, (s) => emit.log(s));
            totalDuration += r.durationMs;
            stdoutAggregate += r.stdout;
            allCommands.push(...r.commands);
            if (r.exitCode != null)
                worstExit = worstExit === null ? r.exitCode : Math.max(worstExit, r.exitCode);
            const combined = `${r.stdout}\n${r.stderr}`;
            for (const line of combined.split("\n")) {
                const raw = stripAnsi(line).trim();
                if (!raw || raw.startsWith("+"))
                    continue;
                if (raw.startsWith("{")) {
                    ingestJsonlLine(raw, seedUrl, allFacts, allFindings, seen, seenFindingFp);
                    continue;
                }
                const plain = parsePlainUrlLine(raw);
                if (plain)
                    ingestPlainUrlLine(plain, seedUrl, allFacts, allFindings, seen, seenFindingFp);
            }
        }
        const recs = [];
        if (allFacts.length > 0 && seeds.length > 0) {
            recs.push({
                agent: "recon.gobuster",
                reason: "Spider discovered URLs — brute-force common paths to find more",
                priority: 55,
                args: { url: seeds[0] }
            });
        }
        const apiPathRegex = /\/(api|graphql|v\d+|rest|gql)(\/|$)/i;
        const ffufedTargets = new Set();
        for (const fact of allFacts) {
            if (fact.type !== "web_url")
                continue;
            const v = (fact.value ?? {});
            if (!v.url)
                continue;
            try {
                const u = new URL(v.url);
                if (!apiPathRegex.test(u.pathname))
                    continue;
                const dir = u.pathname.replace(/\/[^/]*$/, "/") || "/";
                const targetUrl = `${u.origin}${dir.endsWith("/") ? dir : dir + "/"}FUZZ`;
                if (ffufedTargets.has(targetUrl))
                    continue;
                ffufedTargets.add(targetUrl);
                recs.push({
                    agent: "recon.ffuf",
                    reason: `Spider found API-shaped path ${u.pathname} — fuzz ${dir} for more endpoints`,
                    priority: 70,
                    args: { targetUrl }
                });
                if (ffufedTargets.size >= 4)
                    break;
            }
            catch {
                // ignore
            }
        }
        if (allFacts.length < 10) {
            recs.push({
                agent: "recon.waybackurls",
                reason: `Katana returned only ${allFacts.length} URL(s) — query Wayback Machine for historical endpoints`,
                priority: 65
            });
        }
        return {
            status: allFacts.length > 0 ? "succeeded" : "partial",
            durationMs: totalDuration,
            artifacts: {
                commands: allCommands,
                stdoutSnippet: snippet(stdoutAggregate),
                stderrSnippet: undefined
            },
            facts: allFacts,
            findings: allFindings,
            recommendations: recs,
            meta: {
                exitCode: worstExit,
                seedUrls: seeds,
                depth,
                urlsDiscovered: allFacts.length,
                commandSummary: `Crawl ${seeds.length} seed URL(s) with katana (depth=${depth}, scope=${fieldScope}) and emit discovered URLs as facts`
            }
        };
    }
};
function collectSeeds(args, targetHost) {
    const ordered = [];
    const seen = new Set();
    const push = (raw) => {
        const s = raw.trim();
        if (!s)
            return;
        try {
            const u = new URL(s);
            if (u.hostname !== targetHost)
                return;
            if (u.protocol !== "http:" && u.protocol !== "https:")
                return;
            const href = u.href;
            if (seen.has(href))
                return;
            seen.add(href);
            ordered.push(href);
        }
        catch {
            // skip invalid
        }
    };
    if (Array.isArray(args.http_targets)) {
        for (const t of args.http_targets) {
            if (typeof t === "string")
                push(t);
        }
    }
    if (typeof args.url === "string")
        push(args.url);
    return ordered;
}
function buildKatanaArgv(url, depth, concurrency, timeoutSec, fieldScope, jsCrawl) {
    const flags = [
        `-u ${quote(url)}`,
        `-d ${depth}`,
        `-c ${concurrency}`,
        `-timeout ${timeoutSec}`,
        `-fs ${fieldScope}`,
        `-kf robotstxt sitemapxml`,
        `-iqp`,
        `-jsonl`,
        `-silent`,
        `-no-color`
    ];
    if (jsCrawl)
        flags.push("-jc");
    return flags;
}
function stripAnsi(s) {
    return s.replace(/\u001b\[[0-9;]*m/g, "");
}
function parsePlainUrlLine(line) {
    const t = line.trim();
    if (!/^https?:\/\//i.test(t))
        return undefined;
    const token = t.split(/\s+/)[0]?.replace(/["',);]+$/, "") ?? "";
    try {
        const u = new URL(token);
        if (u.protocol !== "http:" && u.protocol !== "https:")
            return undefined;
        return u.href;
    }
    catch {
        return undefined;
    }
}
function ingestJsonlLine(trimmed, seedUrl, facts, findings, seen, seenFindingFp) {
    let obj;
    try {
        obj = JSON.parse(trimmed);
    }
    catch {
        return;
    }
    const req = (obj.request ?? {});
    const res = (obj.response ?? {});
    const endpoint = typeof req.endpoint === "string" ? req.endpoint : typeof obj.url === "string" ? obj.url : undefined;
    if (!endpoint)
        return;
    const status = typeof res.status_code === "number" ? res.status_code : null;
    const method = typeof req.method === "string" ? req.method : "GET";
    const rawLen = res.content_length;
    const contentLength = typeof rawLen === "number" && Number.isFinite(rawLen)
        ? rawLen
        : typeof rawLen === "string" && Number.isFinite(Number(rawLen))
            ? Number(rawLen)
            : null;
    recordDiscoveredUrl(endpoint, method, status, seedUrl, facts, findings, seen, seenFindingFp, contentLength);
}
function ingestPlainUrlLine(endpoint, seedUrl, facts, findings, seen, seenFindingFp) {
    recordDiscoveredUrl(endpoint, "GET", null, seedUrl, facts, findings, seen, seenFindingFp, null);
}
function recordDiscoveredUrl(endpoint, method, status, seedUrl, facts, findings, seen, seenFindingFp, contentLength) {
    const key = `${method} ${endpoint}`;
    if (seen.has(key))
        return;
    seen.add(key);
    const value = { url: endpoint, status, method };
    if (contentLength != null)
        value.length = contentLength;
    facts.push({
        type: "web_url",
        value,
        source: "katana"
    });
    let path = "";
    try {
        path = new URL(endpoint).pathname || "";
    }
    catch {
        return;
    }
    if (!INTERESTING_PATH.test(path))
        return;
    if (status !== null && [200, 301, 302, 401, 403].includes(status)) {
        const fp = `spider|${seedUrl}|${path || endpoint}|${status}`;
        if (seenFindingFp.has(fp))
            return;
        seenFindingFp.add(fp);
        findings.push({
            title: `Interesting web path discovered: ${path || endpoint}`,
            severity: status === 200 ? "medium" : "low",
            evidence: `${endpoint} -> HTTP ${status} (${method})`,
            fingerprint: fp,
            confidence: "high",
            requiresVerification: false,
            claimType: "web_path"
        });
        return;
    }
    if (status === null) {
        const fp = `spider|${seedUrl}|${path || endpoint}|plain`;
        if (seenFindingFp.has(fp))
            return;
        seenFindingFp.add(fp);
        findings.push({
            title: `Interesting web path discovered: ${path || endpoint}`,
            severity: "low",
            evidence: `${endpoint} (Katana; HTTP status not captured in output)`,
            fingerprint: fp,
            confidence: "medium",
            requiresVerification: true,
            claimType: "web_path"
        });
    }
}
function clampInt(v, min, max) {
    const n = Math.floor(Number(v));
    if (!Number.isFinite(n))
        return min;
    return Math.max(min, Math.min(max, n));
}
function quote(s) {
    return `'${s.replace(/'/g, `'\\''`)}'`;
}
