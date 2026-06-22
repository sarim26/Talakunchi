import { ToolDefinition, ToolEnvelope, type ToolInput } from "../mcp/types.js";
import { remoteScript, requireRemoteTool, snippet } from "./shared.js";
import {
  buildOriginUrl,
  detectCdnVendor,
  emptyWebScanHints,
  httpxExtraFlags,
  isIpAddress,
  looksLikeCdnBlock,
  mergeWebScanHints,
  parseCertHostnames,
  resolveWebScanFromInput,
  rewriteUrlsForVhost,
  serializeWebScan,
  shellQuote,
  type WebScanHints
} from "./webTarget.js";

const HTTPX_BIN = "httpx-toolkit";

/**
 * recon.http_probe — httpx JSON lines from explicit URLs or service rows.
 *
 * When the target is an IP and the edge returns CDN 400 (e.g. AkamaiGHost),
 * discovers TLS cert SAN names and retries with vhost URL + `-ip <target>`.
 */
export const httpProbeTool: ToolDefinition = {
  name: "recon.http_probe",
  description:
    "Probe HTTP/HTTPS with httpx. For IP targets behind CDN/WAF, auto-discovers vhost from TLS cert and retries with Host/SNI routing.",
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
      description:
        "Full http(s) URLs on the target host, and/or path-only entries (e.g. /uploads/) expanded against `ports` and/or known web services"
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
    let webScan = resolveWebScanFromInput(host, input.target.vhost, input.context?.webScan);

    const fromArgsPorts = (args.ports ?? []).filter((p): p is number => typeof p === "number" && Number.isFinite(p)).map((p) => Math.floor(p));
    const expansionPorts = webCandidatePortsForProbe(input.context?.knownServices, fromArgsPorts);

    const fromUrls = buildProbeUrlsFromUrlsArg(args.urls, host, expansionPorts, webScan.vhost);
    if (fromUrls.length > 0) {
      return runHttpxWithVhostFallback(fromUrls, host, input, emit, fromUrls.length, "urls", webScan);
    }

    const fromServices = probeRowsFromServices(args.services, host);
    if (fromServices.length > 0) {
      const urls = fromServices.map((kp) => originUrlForProbe(host, kp.port, kp.scheme as "http" | "https", webScan));
      return runHttpxWithVhostFallback(urls, host, input, emit, fromServices.length, "services", webScan, fromServices);
    }

    const knownPorts = (input.context?.knownServices ?? [])
      .filter((s) => /^http|^https|^web/i.test(s.name ?? "") || [80, 443, 8080, 8443].includes(s.port))
      .map((s) => ({ port: s.port, scheme: (s.port === 443 || s.port === 8443 ? "https" : "http") as "http" | "https" }));

    for (const p of fromArgsPorts) {
      const scheme = p === 443 || p === 8443 ? "https" : "http";
      if (!knownPorts.some((kp) => kp.port === p)) knownPorts.push({ port: p, scheme: scheme as "http" | "https" });
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
          commandSummary: `Probe HTTP/HTTPS endpoints on ${host} with httpx and capture status, headers, and title.`,
          webScan: serializeWebScan(webScan)
        }
      };
    }

    const urls = knownPorts.map((kp) => originUrlForProbe(host, kp.port, kp.scheme, webScan));
    return runHttpxWithVhostFallback(urls, host, input, emit, knownPorts.length, "context", webScan, knownPorts);
  }
};

type ProbeRow = { port: number; scheme: "http" | "https" };

function originUrlForProbe(host: string, port: number, scheme: "http" | "https", webScan: WebScanHints): string {
  if (webScan.connectIp && webScan.vhost) return buildOriginUrl(webScan.vhost, port, scheme);
  return buildOriginUrl(host, port, scheme);
}

function webCandidatePortsForProbe(
  knownServices: Array<{ port: number; protocol: string; name?: string }> | undefined,
  explicitPorts: number[]
): number[] {
  const set = new Set<number>();
  for (const p of explicitPorts) {
    if (p >= 1 && p <= 65535) set.add(p);
  }
  for (const s of knownServices ?? []) {
    if (/^http|^https|^web/i.test(s.name ?? "") || [80, 443, 8080, 8443, 8000, 8888].includes(s.port)) {
      set.add(s.port);
    }
  }
  return [...set].sort((a, b) => a - b);
}

function tryAbsoluteProbeUrl(s: string, host: string, vhost: string | null): string | null {
  try {
    const parsed = new URL(s.trim());
    const allowed = parsed.hostname === host || (vhost ? parsed.hostname === vhost : false);
    if (!allowed) return null;
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
    return parsed.href;
  } catch {
    return null;
  }
}

function toPathForProbe(s: string): string | null {
  const t = s.trim();
  if (!t || t.length > 800) return null;
  if (/\s/.test(t)) return null;
  if (t.includes("..")) return null;
  if (/^https?:\/\//i.test(t)) return null;
  return t.startsWith("/") ? t : `/${t}`;
}

function buildProbeUrlsFromUrlsArg(urls: unknown, host: string, expansionPorts: number[], vhost: string | null): string[] {
  if (!Array.isArray(urls) || urls.length === 0) return [];
  const ports = expansionPorts.length > 0 ? expansionPorts : [80];
  const out: string[] = [];
  const seen = new Set<string>();
  const add = (href: string) => {
    if (seen.has(href)) return;
    seen.add(href);
    out.push(href);
  };

  for (const raw of urls) {
    if (typeof raw !== "string") continue;
    const s = raw.trim();
    if (!s) continue;

    const absolute = tryAbsoluteProbeUrl(s, host, vhost);
    if (absolute) {
      add(absolute);
      continue;
    }

    const path = toPathForProbe(s);
    if (!path) continue;
    for (const port of ports) {
      const scheme = port === 443 || port === 8443 ? "https" : "http";
      const base = buildOriginUrl(vhost ?? host, port, scheme);
      try {
        add(new URL(path, base).href);
      } catch {
        // skip
      }
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

type HttpxParseResult = {
  facts: ToolEnvelope["facts"];
  findings: ToolEnvelope["findings"];
  cdnDetected: boolean;
  cdnVendor: string | null;
  hasLive: boolean;
};

async function discoverCertHostnames(
  connectIp: string,
  signal?: AbortSignal,
  extraServernames: string[] = []
): Promise<string[]> {
  const names = new Set<string>();
  const snis = new Set<string>([connectIp]);
  for (const s of extraServernames) {
    const t = s.trim();
    if (t && !isIpAddress(t)) snis.add(t);
  }

  for (const sni of [...snis].slice(0, 12)) {
    const script = [
      `set +e`,
      `IP=${shellQuote(connectIp)}`,
      `SNI=${shellQuote(sni)}`,
      `openssl s_client -connect "$IP:443" -servername "$SNI" </dev/null 2>/dev/null | openssl x509 -noout -text 2>/dev/null || true`
    ].join("\n");
    const r = await remoteScript(script, signal);
    for (const n of parseCertHostnames(r.stdout)) names.add(n);
  }

  const noSniScript = [
    `set +e`,
    `IP=${shellQuote(connectIp)}`,
    `openssl s_client -connect "$IP:443" </dev/null 2>/dev/null | openssl x509 -noout -text 2>/dev/null || true`
  ].join("\n");
  const bare = await remoteScript(noSniScript, signal);
  for (const n of parseCertHostnames(bare.stdout)) names.add(n);

  return [...names];
}

async function runHttpxWithVhostFallback(
  urls: string[],
  host: string,
  input: ToolInput,
  emit: { log: (s: string) => void },
  probedCount: number,
  mode: "urls" | "services" | "context",
  webScan: WebScanHints,
  knownPorts?: ProbeRow[]
): Promise<ToolEnvelope> {
  let first = await runHttpxOnce(urls, host, input, emit, mode, webScan);

  const needsVhost =
    isIpAddress(host) &&
    !webScan.vhost &&
    (first.cdnDetected || !first.hasLive);

  if (needsVhost) {
    emit.log(`CDN/IP-direct probe inconclusive — discovering vhost from TLS cert on ${host}`);
    const candidates = new Set<string>();
    if (input.target.vhost?.trim()) candidates.add(input.target.vhost.trim());
    for (const d of input.context?.knownDomains ?? []) {
      if (typeof d === "string" && d.trim()) candidates.add(d.trim());
    }
    for (const n of await discoverCertHostnames(host, input.signal, input.context?.knownDomains ?? [])) candidates.add(n);

    for (const name of [...candidates].slice(0, 10)) {
      if (isIpAddress(name)) continue;
      const vhostUrls = rewriteUrlsForVhost(urls, name);
      const hints = mergeWebScanHints(webScan, {
        connectIp: host,
        vhost: name,
        cdnDetected: first.cdnDetected,
        cdnVendor: first.cdnVendor
      });
      emit.log(`Retrying httpx with vhost ${name} (connect ${host})`);
      const retry = await runHttpxOnce(vhostUrls, host, input, emit, mode, hints);
      if (retry.hasLive) {
        webScan = hints;
        first = retry;
        break;
      }
    }
  } else if (webScan.vhost && isIpAddress(host)) {
    webScan = mergeWebScanHints(webScan, { connectIp: host, cdnDetected: first.cdnDetected, cdnVendor: first.cdnVendor });
  }

  const recs: ToolEnvelope["recommendations"] = [];
  if (first.facts.length > 0) {
    const gobusterArgs: Record<string, unknown> = {};
    if (webScan.vhost) {
      gobusterArgs.http_targets = first.facts
        .map((f) => (f.value as { url?: string })?.url)
        .filter((u): u is string => typeof u === "string")
        .slice(0, 5);
    }
    recs.push({ agent: "recon.spider", reason: "Discovered web endpoints — crawl them with katana", priority: 65 });
    recs.push({
      agent: "recon.gobuster",
      reason: webScan.vhost
        ? `Discovered web endpoints via vhost ${webScan.vhost} — brute-force common paths`
        : "Discovered web endpoints — brute-force common paths",
      priority: 60,
      args: Object.keys(gobusterArgs).length ? gobusterArgs : undefined
    });
    const https =
      mode === "context"
        ? (knownPorts ?? []).some((kp) => kp.scheme === "https")
        : urls.some((u) => u.startsWith("https://"));
    if (https) {
      recs.push({ agent: "recon.tls_check", reason: "Verify TLS configuration", priority: 70 });
    }
    if (webScan.cdnDetected) {
      recs.push({ agent: "recon.waf_detect", reason: "CDN/WAF edge detected — fingerprint protection", priority: 55 });
    }
  }

  const extraFacts: ToolEnvelope["facts"] = [];
  if (webScan.vhost && isIpAddress(host)) {
    extraFacts.push({
      type: "virtual_host",
      value: { vhost: webScan.vhost, connectIp: host, cdnVendor: webScan.cdnVendor },
      source: "http_probe"
    });
  }

  return {
    status: first.facts.length > 0 ? "succeeded" : "partial",
    durationMs: first.durationMs,
    artifacts: first.artifacts,
    facts: [...first.facts, ...extraFacts],
    findings: first.findings,
    recommendations: recs,
    meta: {
      exitCode: first.exitCode,
      probed: probedCount,
      live: first.facts.length,
      resolutionMode: mode,
      vhostResolved: Boolean(webScan.vhost && isIpAddress(host)),
      webScan: serializeWebScan(webScan),
      commandSummary: webScan.vhost
        ? `Probe HTTP/S on ${host} using vhost ${webScan.vhost} (CDN-aware).`
        : `Probe ${probedCount} HTTP/HTTPS endpoint(s) on ${host} with httpx.`
    }
  };
}

async function runHttpxOnce(
  urls: string[],
  host: string,
  input: ToolInput,
  emit: { log: (s: string) => void },
  mode: string,
  webScan: WebScanHints
): Promise<
  HttpxParseResult & {
    durationMs?: number;
    exitCode: number | null;
    artifacts: ToolEnvelope["artifacts"];
  }
> {
  const presence = await requireRemoteTool(HTTPX_BIN, input.signal);
  if (presence.missing) {
    return {
      facts: [],
      findings: [],
      cdnDetected: false,
      cdnVendor: null,
      hasLive: false,
      exitCode: null,
      artifacts: { commands: [] }
    };
  }

  const extra = httpxExtraFlags(webScan);
  const urlArgs = urls.map((u) => shellQuote(u)).join(" ");
  const script = `printf '%s\\n' ${urlArgs} | ${HTTPX_BIN} -silent -json -title -status-code -web-server -tech-detect -follow-redirects -timeout 8 -no-color ${extra}`;

  emit.log(
    webScan.vhost && webScan.connectIp
      ? `Probing ${urls.length} URL(s) via vhost ${webScan.vhost} → ${webScan.connectIp}`
      : `Probing ${urls.length} HTTP/S endpoint(s) on ${host} (${mode})`
  );
  const r = await remoteScript(script, input.signal, (s) => emit.log(s));

  const parsed = parseHttpxStdout(r.stdout, input.target.host, webScan.vhost);
  return {
    ...parsed,
    durationMs: r.durationMs,
    exitCode: r.exitCode,
    artifacts: { commands: r.commands, stdoutSnippet: snippet(r.stdout), stderrSnippet: snippet(r.stderr) }
  };
}

function parseHttpxStdout(stdout: string, targetHost: string, vhost: string | null): HttpxParseResult {
  const facts: ToolEnvelope["facts"] = [];
  const findings: ToolEnvelope["findings"] = [];
  let cdnDetected = false;
  let cdnVendor: string | null = null;
  let hasLive = false;

  for (const line of stdout.split("\n")) {
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

    const vendor = detectCdnVendor(server);
    if (vendor) {
      cdnDetected = true;
      cdnVendor = vendor;
    }
    if (looksLikeCdnBlock(status, server)) {
      cdnDetected = true;
      cdnVendor = vendor ?? cdnVendor;
    }

    facts.push({
      type: "http_endpoint",
      value: { url, status, server, title, tech, vhost: vhost ?? undefined },
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
      probedPort !== null ? `open-port|${targetHost}|tcp|${probedPort}` : undefined;

    if (status !== null && status >= 200 && status < 400) {
      hasLive = true;
      findings.push({
        title: `Reachable web endpoint: ${url}`,
        severity: "info",
        evidence: `HTTP ${status}${server ? ` Server: ${server}` : ""}${tech.length ? ` Tech: ${tech.join(", ")}` : ""}${vhost ? ` (vhost ${vhost})` : ""}`,
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

  return { facts, findings, cdnDetected, cdnVendor, hasLive };
}
