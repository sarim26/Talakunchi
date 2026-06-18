/**
 * Lightweight heuristic mapping from recon findings to MITRE ATT&CK technique
 * IDs. This is intentionally coarse (recon-grade) — it tags findings by their
 * `claimType`, emitting tool, and title keywords so the report can group by
 * technique. Not a substitute for analyst review.
 */

type FindingLike = { title: string; claimType?: string };

const CLAIM_TYPE_TECHNIQUES: Record<string, string[]> = {
  open_port: ["T1046"], // Network Service Discovery
  service_reachable: ["T1046"],
  http_reachable: ["T1046"],
  ssh_reachable: ["T1046"],
  ssh_cve: ["T1190"], // Exploit Public-Facing Application
  ssh_weak_algorithm: ["T1040"], // Network Sniffing (weak crypto enables)
  cve_match: ["T1190"],
  cve_online: ["T1190"],
  nuclei_finding: ["T1190", "T1592"], // Gather Victim Host Information
  waf_detected: ["T1590"], // Gather Victim Network Information
  ftp_anonymous: ["T1078", "T1083"], // Valid Accounts / File and Directory Discovery
  smtp_open_relay: ["T1071"], // Application Layer Protocol
  smtp_commands: ["T1087"], // Account Discovery
  ldap_anonymous_bind: ["T1087", "T1018"], // Account / Remote System Discovery
  nfs_export: ["T1135"], // Network Share Discovery
  redis_unauthenticated: ["T1078", "T1213"], // Valid Accounts / Data from Information Repositories
  rdp_ntlm_info: ["T1592"],
  rdp_weak_security: ["T1021"], // Remote Services
  snmp_readable: ["T1602"], // Data from Configuration Repository (SNMP)
  db_banner: ["T1592"],
  osint_exposure: ["T1596"] // Search Open Technical Databases
};

const KEYWORD_TECHNIQUES: Array<{ re: RegExp; techniques: string[] }> = [
  { re: /anonymous|unauthenticated|no auth|null session/i, techniques: ["T1078"] },
  { re: /tls|ssl|certificate|cipher/i, techniques: ["T1040"] },
  { re: /share|export|smb|nfs/i, techniques: ["T1135"] },
  { re: /credential|password|login/i, techniques: ["T1110"] }, // Brute Force (indicative)
  { re: /cve-\d{4}-\d+/i, techniques: ["T1190"] }
];

/** Return de-duplicated MITRE technique IDs for a finding. */
export function mitreTechniquesFor(finding: FindingLike): string[] {
  const out = new Set<string>();
  if (finding.claimType && CLAIM_TYPE_TECHNIQUES[finding.claimType]) {
    for (const t of CLAIM_TYPE_TECHNIQUES[finding.claimType]!) out.add(t);
  }
  for (const k of KEYWORD_TECHNIQUES) {
    if (k.re.test(finding.title)) for (const t of k.techniques) out.add(t);
  }
  return [...out];
}
