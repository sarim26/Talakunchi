import net from "node:net";
import { isHostInScope } from "../scope.js";

/**
 * CDN / virtual-host aware web scanning.
 *
 * When the engagement target is an IP behind Akamai (or similar), probing
 * `http://<ip>/` often returns 400. Connect to the IP but present the
 * customer hostname via URL + `-ip` (httpx/gobuster) or `Host:` (ffuf).
 */
export type WebScanHints = {
  /** When set, TCP connects here while HTTP Host/SNI use `vhost`. */
  connectIp: string | null;
  /** Canonical HTTP hostname (Host header / URL host). */
  vhost: string | null;
  cdnDetected: boolean;
  cdnVendor: string | null;
};

/** Rules for accepting a discovered/configured HTTP hostname on this run. */
export type VhostAcceptPolicy = {
  targetHost: string;
  targetName?: string | null;
  configuredVhost?: string | null;
  knownDomains?: string[];
  scopeEntries?: string[];
  scopeEnforce?: boolean;
  cdnDetected: boolean;
};

function tokensFromTargetName(name: string | null | undefined): string[] {
  if (!name?.trim()) return [];
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .split(/\s+/)
    .filter((t) => t.length >= 3);
}

function hostnameRelatesToTargetName(hostname: string, targetName: string | null | undefined): boolean {
  const tokens = tokensFromTargetName(targetName);
  if (!tokens.length) return false;
  const h = normHost(hostname);
  return tokens.some((t) => h.includes(t));
}

/** True when the engagement target is an IP that is allowed by scope (or scope is open). */
export function isScopedIpEngagement(policy: VhostAcceptPolicy): boolean {
  if (!isIpAddress(policy.targetHost)) return false;
  if (!policy.scopeEnforce || !policy.scopeEntries?.length) return true;
  return isHostInScope(policy.targetHost, policy.scopeEntries);
}

/** Hostname matches a scope entry exactly or as a subdomain of a scoped domain. */
export function hostnameMatchesScopeEntry(hostname: string, entries: string[]): boolean {
  const h = normHost(hostname);
  for (const raw of entries) {
    const entry = normHost(raw);
    if (!entry || net.isIP(entry) !== 0) continue;
    if (h === entry) return true;
    if (h.endsWith(`.${entry}`)) return true;
  }
  return isHostInScope(hostname, entries);
}

/**
 * Whether a hostname may be used as vhost / http_targets for this engagement.
 *
 * For IP targets in scope behind CDN, TLS cert SANs on that IP identify the
 * customer's web hostname when that IP is in the engagement scope.
 */
export function acceptVhostCandidate(hostname: string, policy: VhostAcceptPolicy): boolean {
  const h = normHost(hostname);
  if (!h || isIpAddress(h)) return false;

  if (policy.configuredVhost && normHost(policy.configuredVhost) === h) return true;

  if (policy.knownDomains?.some((d) => normHost(d) === h)) return true;

  if (policy.scopeEnforce && policy.scopeEntries?.length) {
    if (hostnameMatchesScopeEntry(h, policy.scopeEntries)) return true;
    if (isHostInScope(h, policy.scopeEntries)) return true;
    // Scoped IP pentest: cert/vhost hostnames for that IP are in-scope web identities.
    if (policy.cdnDetected && isScopedIpEngagement(policy)) return true;
    return false;
  }

  if (normHost(policy.targetHost) === h) return true;

  if (hostnameRelatesToTargetName(h, policy.targetName)) return true;

  if (policy.cdnDetected && isScopedIpEngagement(policy)) return true;

  if (policy.cdnDetected) return false;

  return true;
}

export function vhostAcceptPolicyFromInput(
  targetHost: string,
  input: {
    target?: { vhost?: string; name?: string };
    context?: {
      knownDomains?: string[];
      scopeEntries?: string[];
      scopeEnforce?: boolean;
      webScan?: WebScanHints | null;
    };
  },
  cdnDetected: boolean
): VhostAcceptPolicy {
  return {
    targetHost,
    targetName: input.target?.name ?? null,
    configuredVhost: input.target?.vhost ?? null,
    knownDomains: input.context?.knownDomains ?? [],
    scopeEntries: input.context?.scopeEntries ?? [],
    scopeEnforce: input.context?.scopeEnforce ?? false,
    cdnDetected: cdnDetected || isIpAddress(targetHost)
  };
}

function acceptedVhost(hostname: string | null | undefined, policy: VhostAcceptPolicy): string | null {
  if (!hostname?.trim()) return null;
  return acceptVhostCandidate(hostname, policy) ? normHost(hostname) : null;
}

/** Prefer `www.` hostnames when multiple in-scope identities exist. */
function pickPreferredVhost(candidates: string[]): string | null {
  const uniq = [...new Set(candidates.map((c) => normHost(c)).filter(Boolean))];
  if (!uniq.length) return null;
  return uniq.find((h) => h.startsWith("www.")) ?? uniq[0];
}

/**
 * Resolve an HTTP hostname for CDN/IP targets when `webScan.vhost` is still empty.
 * Uses configured vhost, TLS/cert domains, discovered URLs, scope entries, and seeds.
 */
export function inferVhostForIpTarget(
  targetHost: string,
  webScan: WebScanHints,
  policy: VhostAcceptPolicy,
  opts?: {
    seeds?: string[];
    discoveredEndpoints?: Array<{ url: string }>;
  }
): string | null {
  if (!isIpAddress(targetHost)) return webScan.vhost;
  if (webScan.vhost) return webScan.vhost;

  const candidates: string[] = [];

  const configured = acceptedVhost(policy.configuredVhost, policy);
  if (configured) return configured;

  for (const d of policy.knownDomains ?? []) {
    const ok = acceptedVhost(d, policy);
    if (ok) candidates.push(ok);
  }

  for (const ep of opts?.discoveredEndpoints ?? []) {
    try {
      const ok = acceptedVhost(new URL(ep.url).hostname, policy);
      if (ok) candidates.push(ok);
    } catch {
      // ignore
    }
  }

  for (const raw of policy.scopeEntries ?? []) {
    const entry = raw.trim();
    if (!entry || entry.includes("/")) continue;
    if (net.isIP(entry) !== 0) continue;
    const ok = acceptedVhost(entry, policy);
    if (ok) candidates.push(ok);
  }

  for (const s of opts?.seeds ?? []) {
    try {
      const h = new URL(s).hostname;
      if (isIpAddress(h)) continue;
      const ok = acceptedVhost(h, policy);
      if (ok) candidates.push(ok);
    } catch {
      // ignore
    }
  }

  return pickPreferredVhost(candidates);
}

export function emptyWebScanHints(targetHost: string, configuredVhost?: string | null): WebScanHints {
  const connectIp = isIpAddress(targetHost) ? targetHost.trim() : null;
  const vhost =
    (configuredVhost && configuredVhost.trim()) || (isIpAddress(targetHost) ? null : targetHost.trim()) || null;
  return { connectIp, vhost, cdnDetected: false, cdnVendor: null };
}

export function mergeWebScanHints(base: WebScanHints, patch: Partial<WebScanHints>): WebScanHints {
  return {
    connectIp: patch.connectIp !== undefined ? patch.connectIp : base.connectIp,
    vhost: patch.vhost !== undefined ? patch.vhost : base.vhost,
    cdnDetected: patch.cdnDetected !== undefined ? patch.cdnDetected : base.cdnDetected,
    cdnVendor: patch.cdnVendor !== undefined ? patch.cdnVendor : base.cdnVendor
  };
}

/** True when the target IP is a CDN edge and web tools need a Host/vhost before crawling. */
export function requiresCdnVhost(targetHost: string, webScan: WebScanHints): boolean {
  return isIpAddress(targetHost) && webScan.cdnDetected && !webScan.vhost;
}

export function isIpAddress(host: string): boolean {
  return net.isIP(host.trim()) !== 0;
}

export function normHost(h: string): string {
  return h.trim().replace(/\.$/, "").toLowerCase();
}

function hostTrim(h: string): string {
  return h.trim().replace(/\.$/, "");
}

const CDN_VENDOR_PATTERNS: Array<{ re: RegExp; name: string }> = [
  { re: /akamai/i, name: "Akamai" },
  { re: /cloudflare/i, name: "Cloudflare" },
  { re: /cloudfront/i, name: "CloudFront" },
  { re: /fastly/i, name: "Fastly" },
  { re: /incapsula|imperva/i, name: "Imperva" },
  { re: /sucuri/i, name: "Sucuri" }
];

export function detectCdnVendor(server: string | null | undefined): string | null {
  if (!server) return null;
  for (const { re, name } of CDN_VENDOR_PATTERNS) {
    if (re.test(server)) return name;
  }
  return null;
}

export function looksLikeCdnBlock(status: number | null, server: string | null | undefined): boolean {
  const vendor = detectCdnVendor(server);
  if (!vendor) return false;
  return status === 400 || status === 403 || status === 503;
}

/** Hostname allowed for URLs on this run (target address or validated vhost). */
export function hostAllowed(
  urlHostname: string,
  targetHost: string,
  vhost: string | null,
  policy?: VhostAcceptPolicy | null
): boolean {
  const h = normHost(urlHostname);
  if (h === normHost(targetHost)) return true;
  if (vhost && h === normHost(vhost)) {
    if (policy && isIpAddress(targetHost) && isScopedIpEngagement(policy)) return true;
    if (policy) return acceptVhostCandidate(vhost, policy);
    return true;
  }
  return false;
}

export function buildOriginUrl(vhost: string, port: number, scheme: "http" | "https"): string {
  const def = scheme === "https" ? 443 : 80;
  const host = hostTrim(vhost);
  if (port === def) return `${scheme}://${host}/`;
  return `${scheme}://${host}:${port}/`;
}

/** Rewrite probe URLs to use vhost in the URL (for httpx `-ip` connect mode). */
export function rewriteUrlsForVhost(urls: string[], vhost: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const raw of urls) {
    try {
      const u = new URL(raw);
      const scheme = u.protocol === "https:" ? "https" : "http";
      const port = Number(u.port || (scheme === "https" ? 443 : 80));
      const base = buildOriginUrl(vhost, port, scheme);
      const next = new URL(u.pathname + u.search, base).href;
      if (seen.has(next)) continue;
      seen.add(next);
      out.push(next);
    } catch {
      // skip
    }
  }
  return out;
}

export function httpxExtraFlags(hints: WebScanHints): string {
  if (hints.connectIp && hints.vhost) return `-ip ${shellQuote(hints.connectIp)}`;
  return "";
}

/** Strip default ports (:80 / :443) so CLIs don't choke on explicit defaults. */
export function normalizeHttpUrl(url: string): string {
  try {
    const u = new URL(url);
    const port = Number(u.port || (u.protocol === "https:" ? 443 : 80));
    const def = u.protocol === "https:" ? 443 : 80;
    if (port === def) u.port = "";
    return u.href;
  } catch {
    return url;
  }
}

/**
 * For CDN/IP targets: keep path/scheme/port but connect to `connectIp`.
 * Pair with `cdnHostHeaderFlag()` — gobuster/katana do not support httpx's `-ip`.
 */
export function connectIpUrl(url: string, hints: WebScanHints): string {
  if (!hints.connectIp || !hints.vhost) return normalizeHttpUrl(url);
  try {
    const u = new URL(url);
    const port = Number(u.port || (u.protocol === "https:" ? 443 : 80));
    const def = u.protocol === "https:" ? 443 : 80;
    u.hostname = hints.connectIp;
    u.port = port === def ? "" : String(port);
    return u.href;
  } catch {
    return normalizeHttpUrl(url);
  }
}

/** `-H 'Host: …'` for tools that connect to an IP but must present a vhost (gobuster, ffuf, katana). */
export function cdnHostHeaderFlag(hints: WebScanHints): string {
  if (hints.connectIp && hints.vhost) return `-H ${shellQuote(`Host: ${hostTrim(hints.vhost)}`)}`;
  return "";
}

/** @deprecated Use {@link cdnHostHeaderFlag} — gobuster has no `-ip` flag. */
export function gobusterConnectFlag(hints: WebScanHints): string {
  return cdnHostHeaderFlag(hints);
}

/** @deprecated Use {@link connectIpUrl} + {@link cdnHostHeaderFlag}. */
export function gobusterBaseUrl(url: string, hints: WebScanHints): string {
  return connectIpUrl(url, hints);
}

export function ffufHostHeaderArgs(hints: WebScanHints): string {
  return cdnHostHeaderFlag(hints);
}

/** Parse CN + SAN DNS names from `openssl x509 -noout -text` output. */
export function parseCertHostnames(opensslText: string): string[] {
  const names = new Set<string>();
  const cn = /Subject:.*?CN\s*=\s*([^,\n/]+)/i.exec(opensslText);
  if (cn?.[1]) {
    const v = cleanHostname(cn[1]);
    if (v) names.add(v);
  }
  const sanBlock = /X509v3 Subject Alternative Name:\s*\n\s*([^\n]+(?:\n\s+[^\n]+)*)/i.exec(opensslText);
  if (sanBlock?.[1]) {
    const chunk = sanBlock[1].replace(/\n\s+/g, " ");
    for (const part of chunk.split(/,\s*/)) {
      const m = /^(?:DNS|dns):(.+)$/i.exec(part.trim());
      if (m?.[1]) {
        const v = cleanHostname(m[1]);
        if (v) names.add(v);
      }
    }
  }
  return [...names].filter((n) => !isIpAddress(n) && !n.startsWith("*."));
}

function cleanHostname(raw: string): string | null {
  let s = raw.trim().replace(/^DNS:/i, "");
  if (s.startsWith("*.")) return null;
  s = s.replace(/^\*\./, "").trim();
  if (!s || s.length > 253 || /\s/.test(s)) return null;
  if (!/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/i.test(s)) return null;
  return s.toLowerCase();
}

export function shellQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

export function resolveWebScanFromInput(
  targetHost: string,
  configuredVhost: string | null | undefined,
  contextWebScan?: WebScanHints | null
): WebScanHints {
  const base = emptyWebScanHints(targetHost, configuredVhost ?? null);
  if (!contextWebScan) return base;
  return mergeWebScanHints(base, {
    connectIp: contextWebScan.connectIp ?? base.connectIp,
    vhost: contextWebScan.vhost ?? base.vhost,
    cdnDetected: contextWebScan.cdnDetected,
    cdnVendor: contextWebScan.cdnVendor
  });
}

export function webScanFromEnvelopeMeta(meta: Record<string, unknown> | undefined): Partial<WebScanHints> | null {
  if (!meta?.webScan || typeof meta.webScan !== "object") return null;
  const w = meta.webScan as Record<string, unknown>;
  return {
    connectIp: typeof w.connectIp === "string" ? w.connectIp : null,
    vhost: typeof w.vhost === "string" ? w.vhost : null,
    cdnDetected: w.cdnDetected === true,
    cdnVendor: typeof w.cdnVendor === "string" ? w.cdnVendor : null
  };
}

export function ffufConnectUrl(fuzzUrl: string, hints: WebScanHints): string {
  if (!hints.connectIp || !hints.vhost) return fuzzUrl;
  try {
    const placeholder = "xFUZzx";
    const u = new URL(fuzzUrl.replace(/FUZZ/gi, placeholder));
    const scheme = u.protocol;
    const port = u.port ? Number(u.port) : scheme === "https:" ? 443 : 80;
    const path = u.pathname.replace(new RegExp(placeholder, "g"), "FUZZ") + u.search;
    const def = scheme === "https:" ? 443 : 80;
    if (port === def) return `${scheme}//${hints.connectIp}${path}`;
    return `${scheme}//${hints.connectIp}:${port}${path}`;
  } catch {
    return fuzzUrl;
  }
}

export function serializeWebScan(hints: WebScanHints): Record<string, unknown> {
  return {
    connectIp: hints.connectIp,
    vhost: hints.vhost,
    cdnDetected: hints.cdnDetected,
    cdnVendor: hints.cdnVendor
  };
}
