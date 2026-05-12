import { ToolDefinition, ToolEnvelope, type ToolInput } from "../mcp/types.js";
import { remoteScript, requireRemoteTool, snippet } from "./shared.js";

const HTTPX_BIN = "httpx-toolkit";

/**
 * recon.http_probe — httpx JSON lines from explicit URLs or service rows.
 *
 * Resolution order:
 *   1) `args.urls` — full http(s) URLs on the target host (manager / execution writer)
 *   2) `args.services` — nmap-style rows (port + name); builds URLs for web-ish ports
 *   3) Legacy: infer candidate ports from `context.knownServices` plus optional `args.ports`
 */
export const httpProbeTool: ToolDefinition = {
  name: "recon.http_probe",
  description: "Probe HTTP/HTTPS endpoints on a target with httpx and capture status, title, server header and detected tech.",
  tags: ["recon", "web"],
  requires: ["services"],
  defaultTimeoutMs: 5 * 60 * 1000,
  argSchema: {
    ports: { type: "array", items: { type: "number" }, description: "Extra ports when using context-based resolution" },
    urls: {
      type: "array",
      items: { type: "string" },
      description: "Full http(s) URLs on the target host; when non-empty, only these are probed"
    },
    services: {
      type: "array",
      description: "Services from nmap (port, name, …); used to build URLs when urls is empty"
    }
  },
  handler: async (input, emit): Promise<ToolEnvelope> => {
    const args = (input.args ?? {}) as {
      ports?: number[];
      urls?: unknown;
      services?: unknown;
    };
    const host = input.target.host;

    const fromUrls = normalizeProbeUrls(args.urls, host);
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

    const fromArgs = (args.ports ?? []).filter((p): p is number => typeof p === "number" && Number.isFinite(p));
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
        meta: {
          commandSummary: `Probe HTTP/HTTPS endpoints on ${host} with httpx and capture status, headers, and title.`
        }
      };
    }

    const urls = knownPorts.map((kp) => `${kp.scheme}://${host}:${kp.port}/`);
    return runHttpx(urls, host, input, emit, knownPorts.length, "context", knownPorts);
  }
};

type ProbeRow = { port: number; scheme: string };

function normalizeProbeUrls(urls: unknown, host: string): string[] {
  if (!Array.isArray(urls)) return [];
  const out: string[] = [];
  const seen = new Set<string>();
  for (const u of urls) {
    if (typeof u !== "string") continue;
    try {
      const parsed = new URL(u.trim());
      if (parsed.hostname !== host) continue;
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") continue;
      const href = parsed.href;
      if (seen.has(href)) continue;
      seen.add(href);
      out.push(href);
    } catch {
      // skip
    }
  }
  return out;
}

function probeRowsFromServices(services: unknown, _host: string): ProbeRow[] {
  if (!Array.isArray(services)) return [];
  const rows: ProbeRow[] = [];
  const seen = new Set<number>();
  for (const raw of services) {
    if (!raw || typeof raw !== "object") continue;
    const s = raw as Record<string, unknown>;
    const port = Number(s.port);
    if (!Number.isFinite(port) || port < 1 || port > 65535) continue;
    if (seen.has(port)) continue;
    seen.add(port);
    const name = typeof s.name === "string" ? s.name.toLowerCase() : "";
    const isWebish = /^http|^https|^web|^www/i.test(name) || [80, 443, 8080, 8443, 8000, 8888].includes(port);
    if (!isWebish) continue;
    const scheme = port === 443 || port === 8443 ? "https" : "http";
    rows.push({ port, scheme });
  }
  return rows;
}

async function runHttpx(
  urls: string[],
  host: string,
  input: ToolInput,
  emit: { log: (s: string) => void },
  probedCount: number,
  mode: "urls" | "services" | "context",
  knownPorts?: ProbeRow[]
): Promise<ToolEnvelope> {
  const presence = await requireRemoteTool(HTTPX_BIN, input.signal);
  if (presence.missing) return presence.envelope;

  const urlArgs = urls.map((u) => quote(u)).join(" ");
  const script = `printf '%s\\n' ${urlArgs} | ${HTTPX_BIN} -silent -json -title -status-code -web-server -tech-detect -follow-redirects -timeout 8 -no-color`;

  emit.log(
    mode === "urls"
      ? `Probing ${urls.length} explicit URL(s) on ${host} via httpx`
      : `Probing ${urls.length} HTTP/S endpoint(s) on ${host} via httpx (${mode})`
  );
  const r = await remoteScript(script, input.signal, (s) => emit.log(s));

  const facts: ToolEnvelope["facts"] = [];
  const findings: ToolEnvelope["findings"] = [];

  for (const line of r.stdout.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed[0] !== "{") continue;
    let obj: Record<string, unknown>;
    try {
      obj = JSON.parse(trimmed) as Record<string, unknown>;
    } catch {
      continue;
    }

    const url = (obj.url as string) ?? (obj.input as string) ?? "";
    if (!url) continue;
    const statusRaw = (obj as Record<string, unknown>)["status-code"] ?? obj.status_code;
    const status =
      typeof statusRaw === "number"
        ? (statusRaw as number)
        : typeof statusRaw === "string" && Number.isFinite(Number(statusRaw))
          ? Number(statusRaw)
          : null;
    const server = typeof obj.webserver === "string" ? (obj.webserver as string) : null;
    const title = typeof obj.title === "string" ? (obj.title as string).slice(0, 200) : null;
    const techRaw = (obj as Record<string, unknown>).technologies ?? obj.tech;
    const tech = Array.isArray(techRaw) ? (techRaw as unknown[]).filter((t): t is string => typeof t === "string") : [];

    facts.push({
      type: "http_endpoint",
      value: { url, status, server, title, tech },
      source: "httpx"
    });

    let probedPort: number | null = null;
    try {
      const u = new URL(url);
      probedPort = Number(u.port || (u.protocol === "https:" ? 443 : 80));
    } catch {
      probedPort = null;
    }
    const verifiesFp =
      probedPort !== null ? `open-port|${input.target.host}|tcp|${probedPort}` : undefined;

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
    } else if (status !== null && status >= 500) {
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

  const recs: ToolEnvelope["recommendations"] = [];
  if (facts.length > 0) {
    recs.push({ agent: "recon.spider", reason: "Discovered web endpoints — crawl them with katana", priority: 65 });
    recs.push({ agent: "recon.gobuster", reason: "Discovered web endpoints — brute-force common paths", priority: 60 });
    const https =
      mode === "context"
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

function quote(s: string) {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}
