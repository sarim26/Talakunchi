import { ToolDefinition, ToolEnvelope } from "../mcp/types.js";
import { remoteScript, requireRemoteTool, snippet } from "./shared.js";

const SSH_AUDIT_BIN = "ssh-audit";

/**
 * recon.ssh_enum — JSON-native SSH posture audit using `ssh-audit -j`.
 *
 * For each known SSH port we run ssh-audit and parse the JSON. We emit:
 *   - `ssh_banner` fact (banner.raw, software, protocol)
 *   - `ssh_kex` / `ssh_mac` / `ssh_enc` / `ssh_key` facts (algorithm lists)
 *   - findings derived from the `cves`, recommendations.critical and
 *     recommendations.warning sections.
 */
export const sshEnumTool: ToolDefinition = {
  name: "recon.ssh_enum",
  description: "Audit SSH banner, supported algorithms and known CVEs using ssh-audit (JSON output).",
  tags: ["recon", "ssh"],
  requires: ["services"],
  defaultTimeoutMs: 4 * 60 * 1000,
  handler: async (input, emit): Promise<ToolEnvelope> => {
    const sshPorts = (input.context?.knownServices ?? [])
      .filter((s) => s.port === 22 || /^ssh$/i.test(s.name ?? ""))
      .map((s) => s.port);
    if (sshPorts.length === 0) sshPorts.push(22);

    const presence = await requireRemoteTool(SSH_AUDIT_BIN, input.signal);
    if (presence.missing) return presence.envelope;

    const host = input.target.host;
    const script = [
      `set +e`,
      `HOST=${quote(host)}`,
      `for PORT in ${sshPorts.join(" ")}; do`,
      `  echo "==== SSHAUDIT $PORT ===="`,
      `  ${SSH_AUDIT_BIN} -j -p $PORT "$HOST" 2>/dev/null || true`,
      `  echo`,
      `done`
    ].join("\n");

    emit.log(`ssh-audit on ${host} ports: ${sshPorts.join(",")}`);
    const r = await remoteScript(script, input.signal, (s) => emit.log(s));

    const facts: ToolEnvelope["facts"] = [];
    const findings: ToolEnvelope["findings"] = [];

    const blocks = r.stdout.split(/^==== SSHAUDIT /m).slice(1);
    for (const block of blocks) {
      const portMatch = /^(\d+)\s+====/.exec(block);
      if (!portMatch) continue;
      const port = Number(portMatch[1]);

      const jsonStart = block.indexOf("{");
      const jsonEnd = block.lastIndexOf("}");
      if (jsonStart < 0 || jsonEnd <= jsonStart) continue;
      let obj: Record<string, unknown>;
      try {
        obj = JSON.parse(block.slice(jsonStart, jsonEnd + 1)) as Record<string, unknown>;
      } catch {
        continue;
      }

      const banner = (obj.banner ?? {}) as Record<string, unknown>;
      const raw = typeof banner.raw === "string" ? (banner.raw as string) : undefined;
      const software = typeof banner.software === "string" ? (banner.software as string) : undefined;
      const protocol = banner.protocol;

      facts.push({
        type: "ssh_banner",
        value: { port, raw: raw ?? null, software: software ?? null, protocol },
        source: "ssh-audit"
      });

      for (const key of ["kex", "key", "mac", "enc", "compression"] as const) {
        const list = obj[key];
        if (Array.isArray(list)) {
          facts.push({
            type: `ssh_${key}`,
            value: { port, count: list.length, algorithms: list.slice(0, 30) },
            source: "ssh-audit"
          });
        }
      }

      const cves = Array.isArray(obj.cves) ? (obj.cves as Array<Record<string, unknown>>) : [];
      for (const cve of cves) {
        const name = typeof cve.name === "string" ? cve.name : "CVE";
        const description = typeof cve.description === "string" ? cve.description : "";
        const cvssv2 = typeof cve.cvssv2 === "number" ? cve.cvssv2 : null;
        const severity: "info" | "low" | "medium" | "high" | "critical" =
          cvssv2 !== null && cvssv2 >= 9 ? "critical" : cvssv2 !== null && cvssv2 >= 7 ? "high" : cvssv2 !== null && cvssv2 >= 4 ? "medium" : "low";
        findings.push({
          title: `SSH ${name} on ${host}:${port}`,
          severity,
          port,
          protocol: "tcp",
          evidence: `${description}${cvssv2 !== null ? ` (CVSSv2: ${cvssv2})` : ""}`,
          fingerprint: `ssh-cve|${host}|${port}|${name}`
        });
      }

      const recsObj = (obj.recommendations ?? {}) as Record<string, unknown>;
      const critical = (recsObj.critical ?? {}) as Record<string, unknown>;
      const warning = (recsObj.warning ?? {}) as Record<string, unknown>;
      const issuesFound = collectIssues(critical).map((e) => ({ ...e, severity: "high" as const }));
      const warns = collectIssues(warning).map((e) => ({ ...e, severity: "medium" as const }));
      for (const e of [...issuesFound, ...warns]) {
        findings.push({
          title: `Weak/legacy SSH ${e.kind}: ${e.algorithm} on ${host}:${port}`,
          severity: e.severity,
          port,
          protocol: "tcp",
          evidence: `ssh-audit recommends removing ${e.kind} ${e.algorithm}`,
          fingerprint: `ssh-weak|${host}|${port}|${e.kind}|${e.algorithm}`
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
        ports: sshPorts,
        commandSummary: `Run ssh-audit -j on ${host} (ports: ${sshPorts.join(",")}) and lift CVEs / weak algorithms into findings.`
      }
    };
  }
};

function collectIssues(section: Record<string, unknown>): Array<{ kind: string; algorithm: string }> {
  const out: Array<{ kind: string; algorithm: string }> = [];
  for (const action of Object.keys(section)) {
    const block = section[action] as Record<string, unknown> | undefined;
    if (!block) continue;
    for (const kind of Object.keys(block)) {
      const list = block[kind];
      if (!Array.isArray(list)) continue;
      for (const item of list) {
        const algorithm = typeof item === "string" ? item : typeof (item as Record<string, unknown>)?.name === "string" ? String((item as Record<string, unknown>).name) : null;
        if (algorithm) out.push({ kind, algorithm });
      }
    }
  }
  return out;
}

function quote(s: string) {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}
