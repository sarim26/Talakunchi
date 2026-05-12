import { ToolDefinition, ToolEnvelope } from "../mcp/types.js";
import { loadCveHeuristics, type CompiledHeuristic } from "../cveDb/heuristics.js";

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
  defaultTimeoutMs: 30_000,
  handler: async (input): Promise<ToolEnvelope> => {
    const services = input.context?.knownServices ?? [];
    const cfg = await getHeuristics();
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
    }

    return {
      status: services.length === 0 ? "skipped" : "succeeded",
      facts,
      findings,
      recommendations: [],
      artifacts: { commands: [] },
      meta: {
        cveFeed: { source: cfg?.source ?? "unknown", path: cfg?.path ?? null, error: cfg?.error ?? null },
        servicesScanned: services.length,
        matches: findings.length,
        commandSummary: `Enrich discovered services with a local CVE heuristics feed (offline at runtime; no remote scanning).`
      }
    };
  }
};
