  /**
 * Engagement scope enforcement.
 *
 * Scope entries may be exact IPv4 addresses, IPv4 CIDR ranges, or exact
 * hostnames (case-insensitive). When a scope list is provided and enforcement
 * is on, the orchestrator refuses to touch any target outside it.
 */
import net from "node:net";

export function parseScopeList(raw: string | undefined | null): string[] {
  if (!raw) return [];
  return raw
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function ipv4ToInt(ip: string): number | null {
  if (net.isIPv4(ip) !== true) return null;
  const parts = ip.split(".").map((p) => Number(p));
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return ((parts[0]! << 24) >>> 0) + (parts[1]! << 16) + (parts[2]! << 8) + parts[3]!;
}

function inCidr(ip: string, cidr: string): boolean {
  const [base, bitsRaw] = cidr.split("/");
  const bits = Number(bitsRaw);
  if (!base || !Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const ipInt = ipv4ToInt(ip);
  const baseInt = ipv4ToInt(base);
  if (ipInt === null || baseInt === null) return false;
  if (bits === 0) return true;
  const mask = (0xffffffff << (32 - bits)) >>> 0;
  return (ipInt & mask) === (baseInt & mask);
}

/** True when `host` is allowed by `entries`. An empty list means unrestricted. */
export function isHostInScope(host: string, entries: string[]): boolean {
  if (entries.length === 0) return true;
  const h = host.trim().toLowerCase();
  const hostIsIpv4 = net.isIPv4(host) === true;
  for (const raw of entries) {
    const entry = raw.trim();
    if (!entry) continue;
    if (entry.toLowerCase() === h) return true;
    if (!hostIsIpv4 && !entry.includes("/") && net.isIP(entry) === 0) {
      const e = entry.toLowerCase();
      if (h === e || h.endsWith(`.${e}`)) return true;
    }
    if (hostIsIpv4) {
      if (entry.includes("/")) {
        if (inCidr(host, entry)) return true;
      } else if (net.isIPv4(entry) === true && ipv4ToInt(entry) === ipv4ToInt(host)) {
        return true;
      }
    }
  }
  return false;
}

export type EngagementScopeInput = {
  targetAddress: string;
  targetVhost?: string | null;
  /** Per-target scope: IPs, CIDRs, hostnames allowed for this engagement. */
  targetScope?: string[] | null;
  envScope?: string | null;
  pipelineAllowedCidrs?: string[];
  pipelineEnforceScope?: boolean;
};

/**
 * Merge scope from target (primary), optional global env, and pipeline config.
 * Each target/run can define its own scope — nothing is hardcoded per customer.
 */
export function resolveEngagementScope(input: EngagementScopeInput): { enforce: boolean; entries: string[] } {
  const envEntries = parseScopeList(input.envScope);
  const targetScopeEntries = (input.targetScope ?? []).map((s) => s.trim()).filter(Boolean);
  const targetEntries = [
    input.targetAddress.trim(),
    ...(input.targetVhost?.trim() ? [input.targetVhost.trim()] : []),
    ...targetScopeEntries
  ].filter(Boolean);
  const pipelineEntries = (input.pipelineAllowedCidrs ?? []).map((s) => s.trim()).filter(Boolean);
  const entries = [...new Set([...targetEntries, ...envEntries, ...pipelineEntries])];
  const enforce =
    (targetScopeEntries.length > 0 || envEntries.length > 0 || input.pipelineEnforceScope === true) &&
    entries.length > 0;
  return { enforce, entries };
}
