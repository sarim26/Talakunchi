import { ToolDefinition, ToolEnvelope } from "../mcp/types.js";

/**
 * recon.cve_enricher — pure enrichment, no scanning. Maps observed
 * (product, version) tuples to a small built-in heuristic set of
 * known-bad versions / families. This is intentionally local-only;
 * a future iteration can wire it to an offline NVD mirror.
 */
const HEURISTICS: Array<{
  match: RegExp;
  cves: string[];
  severity: "info" | "low" | "medium" | "high" | "critical";
  description: string;
}> = [
  { match: /OpenSSH[_ ]?7\.[0-3]/i, cves: ["CVE-2016-10009", "CVE-2016-10010"], severity: "medium", description: "OpenSSH 7.0–7.3 has known agent-related issues" },
  { match: /Apache\/2\.4\.49/i, cves: ["CVE-2021-41773"], severity: "critical", description: "Apache 2.4.49 path traversal" },
  { match: /Apache\/2\.4\.50/i, cves: ["CVE-2021-42013"], severity: "critical", description: "Apache 2.4.50 path traversal (incomplete fix)" },
  { match: /nginx\/1\.(?:1[0-7]|[0-9])\b/i, cves: ["CVE-2019-9511"], severity: "medium", description: "Older nginx HTTP/2 DoS family" },
  { match: /Microsoft IIS httpd\/?\s*(?:6|7|7\.5)\b/i, cves: ["EOL"], severity: "high", description: "End-of-life IIS — patches no longer issued" },
  { match: /vsftpd 2\.3\.4/i, cves: ["CVE-2011-2523"], severity: "critical", description: "vsftpd 2.3.4 backdoor" },
  { match: /\bJetty\b.*\b8\./i, cves: ["EOL"], severity: "medium", description: "Older Jetty 8.x is end-of-life; review upgrade path" },
  { match: /\bProFTPD\b.*\b1\.3\.5\b/i, cves: ["CVE-2015-3306"], severity: "high", description: "ProFTPD 1.3.5 has known mod_copy file copy issues (context-dependent)" }
];

export const cveEnricherTool: ToolDefinition = {
  name: "recon.cve_enricher",
  description: "Enrich detected services with known-vulnerable software heuristics (no remote scanning).",
  tags: ["recon", "enrichment"],
  requires: ["services"],
  defaultTimeoutMs: 30_000,
  handler: async (input): Promise<ToolEnvelope> => {
    const services = input.context?.knownServices ?? [];
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
      for (const h of HEURISTICS) {
        if (h.match.test(banner)) {
          facts.push({ type: "cve_match", value: { port: svc.port, banner, cves: h.cves }, source: "heuristic" });
          findings.push({
            title: `Potentially vulnerable: ${banner} on port ${svc.port}`,
            severity: h.severity,
            port: svc.port,
            protocol: svc.protocol,
            evidence: `${h.description} — references: ${h.cves.join(", ")}`,
            fingerprint: `cve|${svc.port}|${h.cves.join(",")}`
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
        servicesScanned: services.length,
        matches: findings.length,
        commandSummary: `Enrich discovered services with local CVE/version heuristics (no remote scanning).`
      }
    };
  }
};
