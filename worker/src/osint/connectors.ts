/**
 * Env-gated OSINT connectors.
 *
 * Each connector returns `null` (and the caller logs a no-op) when its API key
 * is not configured, so OSINT tools degrade gracefully in offline/dev setups.
 */
import { env } from "../env.js";

export type OsintHost = {
  ip: string;
  ports?: number[];
  hostnames?: string[];
  org?: string | null;
  os?: string | null;
  source: string;
};

export type PassiveDnsRecord = {
  hostname: string;
  ips: string[];
  source: string;
};

async function getJson(url: string, init: RequestInit | undefined, signal?: AbortSignal): Promise<any | null> {
  try {
    const res = await fetch(url, { ...init, signal });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

export function shodanEnabled(): boolean {
  return Boolean(env.SHODAN_API_KEY);
}

export async function shodanHost(ip: string, signal?: AbortSignal): Promise<OsintHost | null> {
  if (!env.SHODAN_API_KEY) return null;
  const data = await getJson(
    `https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${env.SHODAN_API_KEY}`,
    undefined,
    signal
  );
  if (!data) return null;
  return {
    ip,
    ports: Array.isArray(data.ports) ? data.ports.filter((p: unknown): p is number => typeof p === "number") : [],
    hostnames: Array.isArray(data.hostnames)
      ? data.hostnames.filter((h: unknown): h is string => typeof h === "string")
      : [],
    org: typeof data.org === "string" ? data.org : null,
    os: typeof data.os === "string" ? data.os : null,
    source: "shodan"
  };
}

export function censysEnabled(): boolean {
  return Boolean(env.CENSYS_API_ID && env.CENSYS_API_SECRET);
}

export async function censysHost(ip: string, signal?: AbortSignal): Promise<OsintHost | null> {
  if (!env.CENSYS_API_ID || !env.CENSYS_API_SECRET) return null;
  const auth = Buffer.from(`${env.CENSYS_API_ID}:${env.CENSYS_API_SECRET}`).toString("base64");
  const data = await getJson(
    `https://search.censys.io/api/v2/hosts/${encodeURIComponent(ip)}`,
    { headers: { authorization: `Basic ${auth}` } },
    signal
  );
  const result = data?.result;
  if (!result) return null;
  const services = Array.isArray(result.services) ? result.services : [];
  return {
    ip,
    ports: services.map((s: { port?: unknown }) => s.port).filter((p: unknown): p is number => typeof p === "number"),
    hostnames: Array.isArray(result.dns?.names)
      ? result.dns.names.filter((h: unknown): h is string => typeof h === "string")
      : [],
    org: typeof result.autonomous_system?.name === "string" ? result.autonomous_system.name : null,
    os: typeof result.operating_system?.product === "string" ? result.operating_system.product : null,
    source: "censys"
  };
}

export function securityTrailsEnabled(): boolean {
  return Boolean(env.SECURITYTRAILS_API_KEY);
}

export async function securityTrailsPassiveDns(
  hostname: string,
  signal?: AbortSignal
): Promise<PassiveDnsRecord[] | null> {
  if (!env.SECURITYTRAILS_API_KEY) return null;
  const data = await getJson(
    `https://api.securitytrails.com/v1/history/${encodeURIComponent(hostname)}/dns/a`,
    { headers: { apikey: env.SECURITYTRAILS_API_KEY } },
    signal
  );
  const records = data?.records;
  if (!Array.isArray(records)) return null;
  return records.slice(0, 25).map((rec: { values?: Array<{ ip?: string }> }) => ({
    hostname,
    ips: Array.isArray(rec.values)
      ? rec.values.map((v) => v.ip).filter((ip): ip is string => typeof ip === "string")
      : [],
    source: "securitytrails"
  }));
}

/** Names of connectors that currently have credentials configured. */
export function enabledConnectors(): string[] {
  const out: string[] = [];
  if (shodanEnabled()) out.push("shodan");
  if (censysEnabled()) out.push("censys");
  if (securityTrailsEnabled()) out.push("securitytrails");
  return out;
}

