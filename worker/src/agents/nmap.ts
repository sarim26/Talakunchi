import { ToolDefinition, ToolEnvelope } from "../mcp/types.js";
import { remoteRun, snippet } from "./shared.js";
import { parseNmapXml } from "../nmapScan.js";

const DEFAULT_TOP_PORTS = 200;

/**
 * recon.nmap — port + light service detection.
 *
 * Phases supported via `args.profile`:
 *   "fast"      → -Pn -T4 --top-ports 200 -sV --version-light
 *   "targeted"  → uses args.ports
 *   "deep"      → -Pn -sV -O --version-all --top-ports 1000 (heavier)
 *   "full"      → -Pn -sV --version-light -p- (all TCP ports, heavier)
 */
export const nmapTool: ToolDefinition = {
  name: "recon.nmap",
  description: "Run an nmap scan to discover open ports and detect services on a target host.",
  tags: ["recon", "network"],
  requires: ["target"],
  defaultTimeoutMs: 15 * 60 * 1000,
  argSchema: {
    profile: { type: "string", enum: ["fast", "targeted", "deep", "full"], default: "deep" },
    ports: { type: "array", items: { type: "number" } },
    extraArgs: { type: "string", description: "Optional additional raw nmap flags (space-separated). Example: -sC -sV" }
  },
  handler: async (input, emit): Promise<ToolEnvelope> => {
    const profile = String((input.args as Record<string, unknown> | undefined)?.profile ?? "deep");
    const portsArg = (input.args as Record<string, unknown> | undefined)?.ports as number[] | undefined;
    const extraArgsRaw = String(((input.args as Record<string, unknown> | undefined)?.extraArgs as string | undefined) ?? "").trim();
    const extraArgs = extraArgsRaw ? extraArgsRaw.split(/\s+/).filter(Boolean) : [];

    const baseArgs = ["-Pn", "--reason", "--stats-every", "10s", "-oX", "-"];
    if (profile === "full") {
      baseArgs.push("-sV", "--version-light", "-p-");
    } else if (profile === "deep") {
      baseArgs.push("-sV", "--version-all", "--top-ports", "1000");
    } else if (profile === "targeted" && portsArg && portsArg.length > 0) {
      baseArgs.push("-sV", "--version-light", "-p", portsArg.join(","));
    } else {
      baseArgs.push("-T4", "-sV", "--version-light", "--top-ports", String(DEFAULT_TOP_PORTS));
    }

    // Append optional user-supplied flags at the end (before host).
    // This is intentionally simple: whitespace split, no quoting support.
    if (extraArgs.length) baseArgs.push(...extraArgs);

    baseArgs.push(input.target.host);
    emit.log(`Starting nmap (${profile}) on ${input.target.host}`);

    const r = await remoteRun("nmap", baseArgs, input.signal, (s) => emit.log(s));
    const parsed = parseNmapXml(r.stdout, input.target.host);
    if (!parsed) {
      return {
        status: "failed",
        error: "Failed to parse nmap XML output",
        artifacts: { commands: [r.command], stdoutSnippet: snippet(r.stdout), stderrSnippet: snippet(r.stderr) },
        facts: [],
        findings: [],
        recommendations: [],
        meta: { exitCode: r.exitCode, profile },
        durationMs: r.durationMs
      };
    }

    const openServices = parsed.services
      .filter((s) => s.state === "open")
      .map((s) => ({
        port: s.port,
        protocol: s.protocol,
        name: s.serviceName ?? "",
        product: s.product ?? "",
        version: s.version ?? "",
        banner: s.banner ?? ""
      }));

    for (const svc of openServices) emit.fact({ type: "service", value: svc, source: "nmap" });

    return {
      status: "succeeded",
      durationMs: r.durationMs,
      artifacts: { commands: [r.command], stdoutSnippet: snippet(r.stdout), stderrSnippet: snippet(r.stderr) },
      facts: openServices.map((svc) => ({ type: "service", value: svc, source: "nmap" })),
      findings: openServices.map((svc) => ({
        title: `Open service: ${svc.port}/${svc.protocol}${svc.name ? ` (${svc.name})` : ""}`,
        severity: severityForPort(svc.port),
        port: svc.port,
        protocol: svc.protocol,
        evidence: `Detected ${svc.name || "service"}${svc.product ? ` ${svc.product}` : ""}${svc.version ? ` ${svc.version}` : ""} on ${input.target.host}:${svc.port}/${svc.protocol}`,
        // Stable, normalised claim key so other tools (httpx, tls_check, etc.)
        // can corroborate the same open-port claim via verifiesFingerprint.
        fingerprint: `open-port|${input.target.host}|${svc.protocol}|${svc.port}`,
        // A single-tool open-port claim should be corroborated before we
        // treat it as confirmed (Situation 1).
        confidence: "medium",
        requiresVerification: true,
        claimType: "open_port"
      })),
      recommendations: [],
      meta: {
        exitCode: r.exitCode,
        profile,
        serviceCount: openServices.length,
        hostStatus: parsed.status,
        commandSummary: `Scan ${input.target.host} for open ports and service banners using nmap (${profile} profile).`
      }
    };
  }
};

function severityForPort(port: number): "info" | "low" | "medium" | "high" | "critical" {
  // This is an EXPOSURE severity for an open service (not a confirmed vuln).
  // Keep it policy-based (service classes) rather than ad-hoc single ports.

  // Remote admin / lateral movement enablers.
  if ([3389, 5985, 5986, 5900, 5901, 16992, 16993].includes(port)) return "medium";

  // SMB is often a big deal in internal networks.
  if ([445, 139].includes(port)) return "medium";

  // Databases / data stores exposed.
  if ([3306, 5432, 1433, 1521, 27017, 6379, 9200, 9300, 11211].includes(port)) return "medium";

  // Cleartext / legacy protocols (credential leakage risk).
  if ([21, 23, 25, 110, 143, 445, 139].includes(port)) return "medium";

  // Common web entry points.
  if ([80, 443, 8080, 8443, 8000].includes(port)) return "low";

  // SSH is common; exposure depends on environment.
  if ([22].includes(port)) return "low";

  return "info";
}
