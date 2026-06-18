import { remoteScript, requireRemoteTool, snippet } from "./shared.js";
const HTTPX_BIN = "httpx-toolkit";
/**
 * recon.http_probe — httpx JSON lines from explicit URLs or service rows.
 *
 * Resolution order:
 *   1) `args.urls` — full http(s) URLs on the target host, and/or **path-only**
 *      strings (e.g. `/uploads/`) expanded per `args.ports` and/or inferred web
 *      ports from `context.knownServices` (default port 80 if none).
 *   2) `args.services` — nmap-style rows (port + name); builds URLs for web-ish ports
 *   3) Legacy: infer candidate ports from `context.knownServices` plus optional `args.ports`
 */
export const httpProbeTool = {
    name: "recon.http_probe",
    description: "Probe HTTP/HTTPS with httpx: full URLs on the target, path-only paths (e.g. /uploads/) expanded per ports/context, or nmap-style services rows.",
    tags: ["recon", "web"],
    requires: ["services"],
    defaultTimeoutMs: 5 * 60 * 1000,
    argSchema: {
        ports: {
            type: "array",
            items: { type: "number" },
            description: "Ports for httpx when using path-only `urls`, or extra ports in context mode"
        },
        urls: {
            type: "array",
            items: { type: "string" },
            description: "Full http(s) URLs on the target host, and/or path-only entries (e.g. /uploads/) expanded against `ports` and/or known web services"
        },
        services: {
            type: "array",
            description: "Services from nmap (port, name, …); used to build URLs when urls is empty"
        }
    },
    handler: async (input, emit) => {
        const args = (input.args ?? {});
        const host = input.target.host;
        const fromArgsPorts = (args.ports ?? []).filter((p) => typeof p === "number" && Number.isFinite(p)).map((p) => Math.floor(p));
        const expansionPorts = webCandidatePortsForProbe(input.context?.knownServices, fromArgsPorts);
        const fromUrls = buildProbeUrlsFromUrlsArg(args.urls, host, expansionPorts);
        if (fromUrls.length > 0) {
            return runHttpx(fromUrls, host, input, emit, fromUrls.length, "urls");
        }
        const fromServices = probeRowsFromServices(args.services, host);
        if (fromServices.length > 0) {
            const urls = fromServices.map((kp) => `${kp.scheme}://${host}:${kp.port}/`);
            return runHttpx(urls, host, input, emit, fromServices.length, "services");
        }
        const knownPorts = (input.context?.knownServices ?? [])
            .filter((s) => /^http|^https|^web/i.test(s.name ?? "") || [80, 443, 8080, 8443].includes(s.port))
            .map((s) => ({ port: s.port, scheme: s.port === 443 || s.port === 8443 ? "https" : "http" }));
        for (const p of fromArgsPorts) {
            const scheme = p === 443 || p === 8443 ? "https" : "http";
            if (!knownPorts.some((kp) => kp.port === p))
                knownPorts.push({ port: p, scheme });
        }
        if (knownPorts.length === 0) {
            return {
                status: "skipped",
                error: "No HTTP/HTTPS candidate ports in context",
                artifacts: { commands: [] },
                facts: [],
                findings: [],
                recommendations: [],
                meta: {
                    commandSummary: `Probe HTTP/HTTPS endpoints on ${host} with httpx and capture status, headers, and title.`
                }
            };
        }
        const urls = knownPorts.map((kp) => `${kp.scheme}://${host}:${kp.port}/`);
        return runHttpx(urls, host, input, emit, knownPorts.length, "context", knownPorts);
    }
};
/** Ports used to expand path-only `urls` (explicit ports ∪ inferred web ports from context). */
function webCandidatePortsForProbe(knownServices, explicitPorts) {
    const set = new Set();
    for (const p of explicitPorts) {
        if (p >= 1 && p <= 65535)
            set.add(p);
    }
    for (const s of knownServices ?? []) {
        if (/^http|^https|^web/i.test(s.name ?? "") || [80, 443, 8080, 8443, 8000, 8888].includes(s.port)) {
            set.add(s.port);
        }
    }
    return [...set].sort((a, b) => a - b);
}
function originBaseUrl(host, port) {
    const https = port === 443 || port === 8443;
    const scheme = https ? "https" : "http";
    const def = https ? 443 : 80;
    if (port === def)
        return `${scheme}://${host}/`;
    return `${scheme}://${host}:${port}/`;
}
function tryAbsoluteProbeUrl(s, host) {
    try {
        const parsed = new URL(s.trim());
        if (parsed.hostname !== host)
            return null;
        if (parsed.protocol !== "http:" && parsed.protocol !== "https:")
            return null;
        return parsed.href;
    }
    catch {
        return null;
    }
}
/** Path segment(s) under the host — not a full URL; rejects traversal and odd whitespace. */
function toPathForProbe(s) {
    const t = s.trim();
    if (!t || t.length > 800)
        return null;
    if (/\s/.test(t))
        return null;
    if (t.includes(".."))
        return null;
    if (/^https?:\/\//i.test(t))
        return null;
    return t.startsWith("/") ? t : `/${t}`;
}
/**
 * Build absolute probe URLs from `args.urls`: each entry is either a full URL on
 * `host`, or a path expanded across `expansionPorts` (falls back to `[80]`).
 */
function buildProbeUrlsFromUrlsArg(urls, host, expansionPorts) {
    if (!Array.isArray(urls) || urls.length === 0)
        return [];
    const ports = expansionPorts.length > 0 ? expansionPorts : [80];
    const out = [];
    const seen = new Set();
    const add = (href) => {
        if (seen.has(href))
            return;
        seen.add(href);
        out.push(href);
    };
    for (const raw of urls) {
        if (typeof raw !== "string")
            continue;
        const s = raw.trim();
        if (!s)
            continue;
        const absolute = tryAbsoluteProbeUrl(s, host);
        if (absolute) {
            add(absolute);
            continue;
        }
        const path = toPathForProbe(s);
        if (!path)
            continue;
        for (const port of ports) {
            const base = originBaseUrl(host, port);
            try {
                add(new URL(path, base).href);
            }
            catch {
                // skip invalid combination
            }
        }
    }
    return out;
}
function probeRowsFromServices(services, _host) {
    if (!Array.isArray(services))
        return [];
    const rows = [];
    const seen = new Set();
    for (const raw of services) {
        if (!raw || typeof raw !== "object")
            continue;
        const s = raw;
        const port = Number(s.port);
        if (!Number.isFinite(port) || port < 1 || port > 65535)
            continue;
        if (seen.has(port))
            continue;
        seen.add(port);
        const name = typeof s.name === "string" ? s.name.toLowerCase() : "";
        const isWebish = /^http|^https|^web|^www/i.test(name) || [80, 443, 8080, 8443, 8000, 8888].includes(port);
        if (!isWebish)
            continue;
        const scheme = port === 443 || port === 8443 ? "https" : "http";
        rows.push({ port, scheme });
    }
    return rows;
}
async function runHttpx(urls, host, input, emit, probedCount, mode, knownPorts) {
    const presence = await requireRemoteTool(HTTPX_BIN, input.signal);
    if (presence.missing)
        return presence.envelope;
    const urlArgs = urls.map((u) => quote(u)).join(" ");
    const script = `printf '%s\\n' ${urlArgs} | ${HTTPX_BIN} -silent -json -title -status-code -web-server -tech-detect -follow-redirects -timeout 8 -no-color`;
    emit.log(mode === "urls"
        ? `Probing ${urls.length} explicit URL(s) on ${host} via httpx`
        : `Probing ${urls.length} HTTP/S endpoint(s) on ${host} via httpx (${mode})`);
    const r = await remoteScript(script, input.signal, (s) => emit.log(s));
    const facts = [];
    const findings = [];
    for (const line of r.stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed || trimmed[0] !== "{")
            continue;
        let obj;
        try {
            obj = JSON.parse(trimmed);
        }
        catch {
            continue;
        }
        const url = obj.url ?? obj.input ?? "";
        if (!url)
            continue;
        const statusRaw = obj["status-code"] ?? obj.status_code;
        const status = typeof statusRaw === "number"
            ? statusRaw
            : typeof statusRaw === "string" && Number.isFinite(Number(statusRaw))
                ? Number(statusRaw)
                : null;
        const server = typeof obj.webserver === "string" ? obj.webserver : null;
        const title = typeof obj.title === "string" ? obj.title.slice(0, 200) : null;
        const techRaw = obj.technologies ?? obj.tech;
        const tech = Array.isArray(techRaw) ? techRaw.filter((t) => typeof t === "string") : [];
        facts.push({
            type: "http_endpoint",
            value: { url, status, server, title, tech },
            source: "httpx"
        });
        let probedPort = null;
        try {
            const u = new URL(url);
            probedPort = Number(u.port || (u.protocol === "https:" ? 443 : 80));
        }
        catch {
            probedPort = null;
        }
        const verifiesFp = probedPort !== null ? `open-port|${input.target.host}|tcp|${probedPort}` : undefined;
        if (status !== null && status >= 200 && status < 400) {
            findings.push({
                title: `Reachable web endpoint: ${url}`,
                severity: "info",
                evidence: `HTTP ${status}${server ? ` Server: ${server}` : ""}${tech.length ? ` Tech: ${tech.join(", ")}` : ""}`,
                fingerprint: `http|${url}`,
                confidence: "high",
                requiresVerification: false,
                claimType: "http_reachable",
                verifiesFingerprint: verifiesFp
            });
        }
        else if (status !== null && status >= 500) {
            findings.push({
                title: `Web endpoint returns ${status}: ${url}`,
                severity: "low",
                evidence: `HTTP ${status} from ${url}`,
                fingerprint: `http5xx|${url}`,
                confidence: "high",
                requiresVerification: false,
                claimType: "http_5xx",
                verifiesFingerprint: verifiesFp
            });
        }
    }
    const recs = [];
    if (facts.length > 0) {
        recs.push({ agent: "recon.spider", reason: "Discovered web endpoints — crawl them with katana", priority: 65 });
        recs.push({ agent: "recon.gobuster", reason: "Discovered web endpoints — brute-force common paths", priority: 60 });
        const https = mode === "context"
            ? (knownPorts ?? []).some((kp) => kp.scheme === "https")
            : urls.some((u) => u.startsWith("https://"));
        if (https) {
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
        meta: {
            exitCode: r.exitCode,
            probed: probedCount,
            live: facts.length,
            resolutionMode: mode,
            commandSummary: `Probe ${probedCount} HTTP/HTTPS endpoint(s) on ${host} with httpx (JSON output) and emit live endpoints as facts.`
        }
    };
}
function quote(s) {
    return `'${s.replace(/'/g, `'\\''`)}'`;
}
