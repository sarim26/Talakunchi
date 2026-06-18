import { ToolDefinition, ToolEnvelope } from "../mcp/types.js";
import { remoteRun, snippet } from "./shared.js";
import { parseNmapXml } from "../nmapScan.js";

/**
 * recon.port_recheck — thin verifier.
 *
 * Re-scans a single TCP port with nmap and, if it is still open, emits a
 * high-confidence corroboration keyed to `open-port|host|tcp|port` via
 * `verifiesFingerprint`. This promotes a previously single-tool open-port
 * claim to "confirmed" (Situation 1) without any new scanning breadth.
 */
export const portRecheckTool: ToolDefinition = {
  name: "recon.port_recheck",
  description: "Re-check a single TCP port with nmap to corroborate a prior open-port finding (verification only).",
  tags: ["recon", "verification"],
  requires: ["target"],
  defaultTimeoutMs: 3 * 60 * 1000,
  argSchema: {
    port: { type: "number", description: "TCP port to re-check on the target host" }
  },
  handler: async (input, emit): Promise<ToolEnvelope> => {
    const args = (input.args ?? {}) as Record<string, unknown>;
    const port = Number(args.port);
    if (!Number.isInteger(port) || port <= 0 || port > 65535) {
      return {
        status: "failed",
        error: "recon.port_recheck requires a valid `port` (1-65535).",
        artifacts: { commands: [] },
        facts: [],
        findings: [],
        recommendations: [],
        meta: {},
        durationMs: 0
      };
    }

    const host = input.target.host;
    const nmapArgs = ["-Pn", "--reason", "-sV", "--version-light", "-p", String(port), "-oX", "-", host];
    emit.log(`Re-checking ${host}:${port}/tcp with nmap (verification)`);

    const r = await remoteRun("nmap", nmapArgs, input.signal, (s) => emit.log(s));
    const parsed = parseNmapXml(r.stdout, host);
    const open =
      parsed?.services.some((s) => s.port === port && s.protocol === "tcp" && s.state === "open") ?? false;

    const fingerprint = `open-port|${host}|tcp|${port}`;
    const findings: ToolEnvelope["findings"] = open
      ? [
          {
            title: `Open port corroborated: ${port}/tcp`,
            severity: "info",
            port,
            protocol: "tcp",
            evidence: `nmap re-check confirms ${host}:${port}/tcp is open`,
            // Independent second observation of the same claim → confirms it.
            fingerprint: `port-recheck|${host}|tcp|${port}`,
            confidence: "high",
            requiresVerification: false,
            claimType: "open_port",
            verifiesFingerprint: fingerprint
          }
        ]
      : [];

    return {
      status: "succeeded",
      durationMs: r.durationMs,
      artifacts: { commands: [r.command], stdoutSnippet: snippet(r.stdout), stderrSnippet: snippet(r.stderr) },
      facts: [],
      findings,
      recommendations: [],
      meta: {
        exitCode: r.exitCode,
        port,
        open,
        commandSummary: `Re-check ${host}:${port}/tcp to corroborate an open-port claim.`
      }
    };
  }
};
