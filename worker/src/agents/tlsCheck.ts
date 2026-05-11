import { ToolDefinition, ToolEnvelope } from "../mcp/types.js";
import { remoteScript, requireRemoteTool, snippet } from "./shared.js";

const TESTSSL_BIN = "testssl.sh";

type TestsslSeverity = "OK" | "INFO" | "DEBUG" | "WARN" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

/**
 * recon.tls_check — JSON-native TLS posture check using testssl.sh.
 *
 * For each TLS port we run testssl.sh with --jsonfile-pretty, then read the
 * JSON result file. testssl emits an array of finding objects with a
 * standardized severity scale; we map LOW+ to our severities and emit the
 * cert details (subject/issuer/dates) as facts.
 */
export const tlsCheckTool: ToolDefinition = {
  name: "recon.tls_check",
  description: "Inspect TLS certificate, protocols and known vulnerabilities on TLS-enabled ports for the target host using testssl.sh.",
  tags: ["recon", "tls"],
  requires: ["tls_targets"],
  defaultTimeoutMs: 10 * 60 * 1000,
  handler: async (input, emit): Promise<ToolEnvelope> => {
    const tlsPorts = new Set<number>();
    for (const s of input.context?.knownServices ?? []) {
      if ([443, 8443, 993, 995, 465, 5986].includes(s.port) || /^https?$|tls/i.test(s.name ?? "")) {
        tlsPorts.add(s.port);
      }
    }
    const explicit = (input.args as Record<string, unknown> | undefined)?.ports as number[] | undefined;
    if (explicit) for (const p of explicit) tlsPorts.add(p);
    if (tlsPorts.size === 0) tlsPorts.add(443);

    const presence = await requireRemoteTool(TESTSSL_BIN, input.signal);
    if (presence.missing) return presence.envelope;

    const host = input.target.host;
    const portList = [...tlsPorts];

    const script = [
      `set +e`,
      `HOST=${quote(host)}`,
      `for PORT in ${portList.join(" ")}; do`,
      `  OUT="/tmp/_testssl_\${PORT}.json"`,
      `  rm -f "$OUT"`,
      `  echo "==== TESTSSL $PORT ===="`,
      `  ${TESTSSL_BIN} --jsonfile-pretty "$OUT" --warnings batch --color 0 --quiet "$HOST:$PORT" >/dev/null 2>&1 || true`,
      `  if [ -f "$OUT" ]; then`,
      `    cat "$OUT"`,
      `  else`,
      `    echo '{"_error":"no_output"}'`,
      `  fi`,
      `  echo`,
      `done`
    ].join("\n");

    emit.log(`testssl.sh on ${host} ports: ${portList.join(",")}`);
    const r = await remoteScript(script, input.signal, (s) => emit.log(s));

    const facts: ToolEnvelope["facts"] = [];
    const findings: ToolEnvelope["findings"] = [];

    const blocks = r.stdout.split(/^==== TESTSSL /m).slice(1);
    for (const block of blocks) {
      const portMatch = /^(\d+)\s+====/.exec(block);
      if (!portMatch) continue;
      const port = Number(portMatch[1]);
      const jsonStart = block.indexOf("[");
      const jsonEnd = block.lastIndexOf("]");
      if (jsonStart < 0 || jsonEnd <= jsonStart) continue;
      const jsonText = block.slice(jsonStart, jsonEnd + 1);

      let parsed: Array<Record<string, unknown>>;
      try {
        parsed = JSON.parse(jsonText) as Array<Record<string, unknown>>;
      } catch {
        continue;
      }

      const certSubject = pickFinding(parsed, ["cert_subject"]);
      const certIssuer = pickFinding(parsed, ["cert_caIssuers", "cert_issuer"]);
      const notBefore = pickFinding(parsed, ["cert_notBefore"]);
      const notAfter = pickFinding(parsed, ["cert_notAfter"]);

      facts.push({
        type: "tls_cert",
        value: {
          port,
          subject: certSubject,
          issuer: certIssuer,
          notBefore,
          notAfter
        },
        source: "testssl.sh"
      });

      for (const item of parsed) {
        const sev = String(item.severity ?? "INFO").toUpperCase() as TestsslSeverity;
        const mapped = mapSeverity(sev);
        if (!mapped) continue;
        const id = String(item.id ?? "tls_finding");
        const finding = String(item.finding ?? "").slice(0, 600);
        const cve = typeof item.cve === "string" ? item.cve : undefined;
        findings.push({
          title: `TLS ${id} on ${host}:${port}`,
          severity: mapped,
          port,
          protocol: "tcp",
          evidence: `${finding}${cve ? ` (CVE: ${cve})` : ""}`,
          fingerprint: `testssl|${host}|${port}|${id}`
        });
      }
    }

    return {
      status: "succeeded",
      durationMs: r.durationMs,
      artifacts: { commands: r.commands, stdoutSnippet: snippet(r.stdout), stderrSnippet: snippet(r.stderr) },
      facts,
      findings,
      recommendations: [],
      meta: {
        exitCode: r.exitCode,
        ports: portList,
        commandSummary: `Run testssl.sh JSON output against ${host} (ports: ${portList.join(",")}) and lift LOW+ findings into our severity scale.`
      }
    };
  }
};

function pickFinding(arr: Array<Record<string, unknown>>, ids: string[]): string | undefined {
  for (const id of ids) {
    const hit = arr.find((x) => String(x.id ?? "") === id);
    if (hit && typeof hit.finding === "string") return hit.finding as string;
  }
  return undefined;
}

function mapSeverity(s: TestsslSeverity): "low" | "medium" | "high" | "critical" | null {
  switch (s) {
    case "LOW":
    case "WARN":
      return "low";
    case "MEDIUM":
      return "medium";
    case "HIGH":
      return "high";
    case "CRITICAL":
      return "critical";
    default:
      return null;
  }
}

function quote(s: string) {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}
