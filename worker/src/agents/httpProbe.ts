import { ToolDefinition, ToolEnvelope } from "../mcp/types.js";
import { remoteScript, requireRemoteTool, snippet } from "./shared.js";

const HTTPX_BIN = "httpx-toolkit";

/**
 * recon.http_probe — JSON-native HTTP(S) probing using ProjectDiscovery's
 * httpx (Kali package: httpx-toolkit). Candidate URLs are fed on stdin via
 * `printf '%s\\n' … | httpx` and httpx emits one JSON object per live endpoint;
 * we parse those into
 * `http_endpoint` facts and `Reachable web endpoint:` findings.
 *
 * If `httpx-toolkit` is missing on the remote host we return a missing-tool
 * envelope so the orchestrator can auto-install it via system.tool_installer.
 */
export const httpProbeTool: ToolDefinition = {
  name: "recon.http_probe",
  description: "Probe HTTP/HTTPS endpoints on a target with httpx and capture status, title, server header and detected tech.",
  tags: ["recon", "web"],
  requires: ["services"],
  defaultTimeoutMs: 5 * 60 * 1000,
  argSchema: {
    ports: { type: "array", items: { type: "number" } }
  },
  handler: async (input, emit): Promise<ToolEnvelope> => {
    const knownPorts = (input.context?.knownServices ?? [])
      .filter((s) => /^http|^https|^web/i.test(s.name ?? "") || [80, 443, 8080, 8443].includes(s.port))
      .map((s) => ({ port: s.port, scheme: s.port === 443 || s.port === 8443 ? "https" : "http" }));

    const fromArgs = ((input.args as Record<string, unknown> | undefined)?.ports as number[] | undefined) ?? [];
    for (const p of fromArgs) {
      const scheme = p === 443 || p === 8443 ? "https" : "http";
      if (!knownPorts.some((kp) => kp.port === p)) knownPorts.push({ port: p, scheme });
    }

    if (knownPorts.length === 0) {
      return {
        status: "skipped",
        error: "No HTTP/HTTPS candidate ports in context",
        artifacts: { commands: [] },
        facts: [],
        findings: [],
        recommendations: [],
        meta: {
          commandSummary: `Probe HTTP/HTTPS endpoints on ${input.target.host} with httpx and capture status, headers, and title.`
        }
      };
    }

    const presence = await requireRemoteTool(HTTPX_BIN, input.signal);
    if (presence.missing) return presence.envelope;

    const host = input.target.host;
    // One pipeline so logs/artifacts show the real command (not a lone `} | httpx`).
    const urlArgs = knownPorts.map((kp) => quote(`${kp.scheme}://${host}:${kp.port}/`)).join(" ");
    const script = `printf '%s\\n' ${urlArgs} | ${HTTPX_BIN} -silent -json -title -status-code -web-server -tech-detect -follow-redirects -timeout 8 -no-color`;

    emit.log(`Probing ${knownPorts.length} HTTP/S endpoint(s) on ${host} via httpx`);
    const r = await remoteScript(script, input.signal, (s) => emit.log(s));

    const facts: ToolEnvelope["facts"] = [];
    const findings: ToolEnvelope["findings"] = [];

    for (const line of r.stdout.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed[0] !== "{") continue;
      let obj: Record<string, unknown>;
      try {
        obj = JSON.parse(trimmed) as Record<string, unknown>;
      } catch {
        continue;
      }

      const url = (obj.url as string) ?? (obj.input as string) ?? "";
      if (!url) continue;
      const statusRaw = (obj as Record<string, unknown>)["status-code"] ?? obj.status_code;
      const status =
        typeof statusRaw === "number"
          ? (statusRaw as number)
          : typeof statusRaw === "string" && Number.isFinite(Number(statusRaw))
            ? Number(statusRaw)
            : null;
      const server = typeof obj.webserver === "string" ? (obj.webserver as string) : null;
      const title = typeof obj.title === "string" ? (obj.title as string).slice(0, 200) : null;
      const techRaw = (obj as Record<string, unknown>).technologies ?? obj.tech;
      const tech = Array.isArray(techRaw) ? (techRaw as unknown[]).filter((t): t is string => typeof t === "string") : [];

      facts.push({
        type: "http_endpoint",
        value: { url, status, server, title, tech },
        source: "httpx"
      });

      // Pull the port we just probed back out of the URL so we can link this
      // back to nmap's open-port claim (Situation 1: gold-standard verifier).
      let probedPort: number | null = null;
      try {
        const u = new URL(url);
        probedPort = Number(u.port || (u.protocol === "https:" ? 443 : 80));
      } catch {
        probedPort = null;
      }
      const verifiesFp =
        probedPort !== null
          ? `open-port|${input.target.host}|tcp|${probedPort}`
          : undefined;

      if (status !== null && status >= 200 && status < 400) {
        findings.push({
          title: `Reachable web endpoint: ${url}`,
          severity: "info",
          evidence: `HTTP ${status}${server ? ` Server: ${server}` : ""}${tech.length ? ` Tech: ${tech.join(", ")}` : ""}`,
          fingerprint: `http|${url}`,
          // httpx independently spoke HTTP and got a response — definitive.
          confidence: "high",
          requiresVerification: false,
          claimType: "http_reachable",
          verifiesFingerprint: verifiesFp
        });
      } else if (status !== null && status >= 500) {
        findings.push({
          title: `Web endpoint returns ${status}: ${url}`,
          severity: "low",
          evidence: `HTTP ${status} from ${url}`,
          fingerprint: `http5xx|${url}`,
          confidence: "high",
          requiresVerification: false,
          claimType: "http_5xx",
          verifiesFingerprint: verifiesFp
        });
      }
    }

    const recs: ToolEnvelope["recommendations"] = [];
    if (facts.length > 0) {
      recs.push({ agent: "recon.spider", reason: "Discovered web endpoints — crawl them with katana", priority: 65 });
      recs.push({ agent: "recon.gobuster", reason: "Discovered web endpoints — brute-force common paths", priority: 60 });
      if (knownPorts.some((kp) => kp.scheme === "https")) {
        recs.push({ agent: "recon.tls_check", reason: "Verify TLS configuration", priority: 70 });
      }
    }

    return {
      status: facts.length > 0 ? "succeeded" : "partial",
      durationMs: r.durationMs,
      artifacts: { commands: r.commands, stdoutSnippet: snippet(r.stdout), stderrSnippet: snippet(r.stderr) },
      facts,
      findings,
      recommendations: recs,
      meta: {
        exitCode: r.exitCode,
        probed: knownPorts.length,
        live: facts.length,
        commandSummary: `Probe ${knownPorts.length} HTTP/HTTPS endpoint(s) on ${host} with httpx (JSON output) and emit live endpoints as facts.`
      }
    };
  }
};

function quote(s: string) {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}
