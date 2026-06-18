import { ToolDefinition, ToolEnvelope, type Severity } from "../mcp/types.js";
import { loadCveHeuristics, type CompiledHeuristic } from "../cveDb/heuristics.js";
import { env } from "../env.js";

type OnlineCve = { id: string; summary?: string; severity?: Severity };

/**
 * Optional online CVE lookup. Disabled unless `CVE_FEED_URL` or `NVD_API_KEY`
 * is configured. Failures are swallowed (returns []) so offline enrichment is
 * never blocked by network issues.
 */
async function queryOnlineCves(banner: string, signal?: AbortSignal): Promise<OnlineCve[]> {
  const keyword = banner.trim();
  if (!keyword) return [];
  try {
    if (env.CVE_FEED_URL) {
      const url = `${env.CVE_FEED_URL}${env.CVE_FEED_URL.includes("?") ? "&" : "?"}keyword=${encodeURIComponent(keyword)}`;
      const res = await fetch(url, { signal });
      if (!res.ok) return [];
      const data = (await res.json()) as Array<Record<string, unknown>>;
      return (Array.isArray(data) ? data : [])
        .map((d) => ({
          id: String(d.id ?? d.cve ?? "").trim(),
          summary: typeof d.summary === "string" ? d.summary : undefined,
          severity: normalizeSeverity(d.severity)
        }))
        .filter((d) => d.id.length > 0)
        .slice(0, 10);
    }
    if (env.NVD_API_KEY) {
      const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(keyword)}&resultsPerPage=5`;
      const res = await fetch(url, { headers: { apiKey: env.NVD_API_KEY }, signal });
      if (!res.ok) return [];
      const data = (await res.json()) as { vulnerabilities?: Array<{ cve?: Record<string, unknown> }> };
      return (data.vulnerabilities ?? [])
        .map((v) => {
          const cve = (v.cve ?? {}) as Record<string, unknown>;
          const descs = (cve.descriptions ?? []) as Array<{ lang?: string; value?: string }>;
          const summary = descs.find((d) => d.lang === "en")?.value;
          return { id: String(cve.id ?? "").trim(), summary };
        })
        .filter((d) => d.id.length > 0)
        .slice(0, 5);
    }
  } catch {
    return [];
  }
  return [];
}

function normalizeSeverity(v: unknown): Severity | undefined {
  const s = String(v ?? "").toLowerCase();
  if (s === "critical" || s === "high" || s === "medium" || s === "low" || s === "info") return s;
  return undefined;
}

/**
 * recon.cve_enricher — pure enrichment, no scanning. Maps observed
 * (product, version) tuples to a small built-in heuristic set of
 * known-bad versions / families.
 *
 * This tool is intentionally offline at runtime: it reads a local feed
 * from `data/cve-heuristics.json` (or CVE_HEURISTICS_PATH) and falls back
 * to a small built-in set when the feed is missing/invalid.
 */
let heuristicsCache: { heuristics: CompiledHeuristic[]; source: string; path: string; error?: string } | null = null;
async function getHeuristics(): Promise<typeof heuristicsCache> {
  if (heuristicsCache) return heuristicsCache;
  const p = process.env.CVE_HEURISTICS_PATH;
  const r = await loadCveHeuristics({ path: p || undefined });
  heuristicsCache =
    r.source === "file"
      ? { heuristics: r.heuristics, source: "file", path: r.path }
      : { heuristics: r.heuristics, source: "default", path: r.path, error: r.error };
  return heuristicsCache;
}

export const cveEnricherTool: ToolDefinition = {
  name: "recon.cve_enricher",
  description: "Enrich detected services with a local CVE heuristics feed (offline at runtime; no remote scanning).",
  tags: ["recon", "enrichment"],
  requires: ["services"],
  defaultTimeoutMs: 60_000,
  handler: async (input): Promise<ToolEnvelope> => {
    const services = input.context?.knownServices ?? [];
    const cfg = await getHeuristics();
    const onlineEnabled = Boolean(env.CVE_FEED_URL || env.NVD_API_KEY);
    const findings: ToolEnvelope["findings"] = [];
    const facts: ToolEnvelope["facts"] = [];

    for (const svc of services) {
      const banner = [svc.product, svc.version, svc.name].filter(Boolean).join(" ").trim();
      // Always emit a normalization fact so the operator can see what the enricher considered.
      facts.push({
        type: "service_banner",
        value: { port: svc.port, protocol: svc.protocol, name: svc.name ?? null, product: svc.product ?? null, version: svc.version ?? null, banner },
        source: "enricher"
      });
      if (!banner) continue;
      for (const h of cfg?.heuristics ?? []) {
        if (h.match.test(banner)) {
          facts.push({ type: "cve_match", value: { port: svc.port, banner, cves: h.cves }, source: "heuristic" });
          findings.push({
            title: `Potentially vulnerable: ${banner} on port ${svc.port}`,
            severity: h.severity,
            port: svc.port,
            protocol: svc.protocol,
            evidence: `${h.description} — references: ${h.cves.join(", ")}`,
            fingerprint: `cve|${svc.port}|${h.cves.join(",")}`,
            // The exact version string in the banner is the evidence; no
            // second tool is needed for the CVE attribution itself.
            confidence: "high",
            requiresVerification: false,
            claimType: "cve_match"
          });
        }
      }

      if (onlineEnabled) {
        const online = await queryOnlineCves(banner, input.signal);
        for (const cve of online) {
          facts.push({ type: "cve_online", value: { port: svc.port, banner, id: cve.id }, source: env.CVE_FEED_URL ? "cve_feed" : "nvd" });
          findings.push({
            title: `${cve.id}: ${banner} on port ${svc.port}`,
            severity: cve.severity ?? "medium",
            port: svc.port,
            protocol: svc.protocol,
            evidence: cve.summary ? cve.summary.slice(0, 600) : `Online CVE feed matched ${cve.id} for banner "${banner}"`,
            fingerprint: `cve-online|${svc.port}|${cve.id}`,
            confidence: "medium",
            requiresVerification: true,
            claimType: "cve_online"
          });
        }
      }
    }

    return {
      status: services.length === 0 ? "skipped" : "succeeded",
      facts,
      findings,
      recommendations: [],
      artifacts: { commands: [] },
      meta: {
        cveFeed: { source: cfg?.source ?? "unknown", path: cfg?.path ?? null, error: cfg?.error ?? null, online: onlineEnabled },
        servicesScanned: services.length,
        matches: findings.length,
        commandSummary: `Enrich discovered services with a local CVE heuristics feed (offline at runtime; no remote scanning).`
      }
    };
  }
};
