import type { MCPServer } from "../mcp/server.js";
import type { ToolFinding } from "../mcp/types.js";

export type PendingVerification = {
  fingerprint: string;
  verifierTool: string;
  args?: Record<string, unknown>;
};

const WEB_PORTS = new Set([80, 443, 8080, 8443, 8000, 8888, 8081, 3000, 8008, 8181]);
const TLS_PORTS = new Set([443, 8443, 993, 995, 465, 636, 990, 989, 8989]);

/**
 * Map a finding that still requires verification to a verifier tool that can
 * independently corroborate it. Returns null when no verification is needed or
 * no suitable verifier is registered.
 *
 * Strategy (open-port claims only for now): prefer a protocol-appropriate tool
 * that emits `verifiesFingerprint` for the port (tls_check / http_probe), and
 * otherwise fall back to the thin `recon.port_recheck`.
 */
export function pickVerifierFor(
  finding: ToolFinding,
  server: MCPServer
): PendingVerification | null {
  if (!finding.fingerprint) return null;
  if (finding.requiresVerification === false) return null;
  if (finding.confidence === "high") return null;
  if (finding.claimType !== "open_port") return null;

  const port = finding.port ?? null;
  if (port == null) return null;
  const protocol = finding.protocol ?? "tcp";
  if (protocol !== "tcp") return null;

  if (TLS_PORTS.has(port) && server.has("recon.tls_check")) {
    return {
      fingerprint: finding.fingerprint,
      verifierTool: "recon.tls_check",
      args: { services: [{ port, protocol }] }
    };
  }
  if (WEB_PORTS.has(port) && server.has("recon.http_probe")) {
    return {
      fingerprint: finding.fingerprint,
      verifierTool: "recon.http_probe",
      args: { ports: [port] }
    };
  }
  if (server.has("recon.port_recheck")) {
    return {
      fingerprint: finding.fingerprint,
      verifierTool: "recon.port_recheck",
      args: { port }
    };
  }
  return null;
}
