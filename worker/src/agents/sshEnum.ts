import { ToolDefinition, ToolEnvelope } from "../mcp/types.js";
import { remoteScript, snippet } from "./shared.js";

/**
 * recon.ssh_enum — banner + key exchange algorithms via nmap script. Read-only.
 */
export const sshEnumTool: ToolDefinition = {
  name: "recon.ssh_enum",
  description: "Capture SSH banner and offered algorithms for the target.",
  tags: ["recon", "ssh"],
  requires: ["services"],
  defaultTimeoutMs: 3 * 60 * 1000,
  handler: async (input, emit): Promise<ToolEnvelope> => {
    const sshPorts = (input.context?.knownServices ?? [])
      .filter((s) => s.port === 22 || /^ssh$/i.test(s.name ?? ""))
      .map((s) => s.port);
    if (sshPorts.length === 0) sshPorts.push(22);

    const host = input.target.host;
    const script = [
      `set +e`,
      `HOST=${quote(host)}`,
      `for PORT in ${sshPorts.join(" ")}; do`,
      `  echo "==== SSH $PORT ===="`,
      `  timeout 5 bash -c "exec 3<>/dev/tcp/$HOST/$PORT && head -n 1 <&3" 2>/dev/null || echo "BANNER_FAIL"`,
      `  timeout 30 nmap -Pn -p $PORT --script ssh2-enum-algos "$HOST" 2>&1 | tail -n 40 || true`,
      `done`
    ].join("\n");

    emit.log(`SSH enum for ${host}`);
    const r = await remoteScript(script, input.signal, (s) => emit.log(s));

    const facts: ToolEnvelope["facts"] = [];
    const findings: ToolEnvelope["findings"] = [];

    const blocks = r.stdout.split(/^==== SSH /m).slice(1);
    for (const block of blocks) {
      const port = Number(/^(\d+)\s+====/.exec(block)?.[1] ?? "22");
      const bannerMatch = /SSH-([\d.]+)-(\S+)/.exec(block);
      if (bannerMatch) {
        facts.push({ type: "ssh_banner", value: { port, version: bannerMatch[1], software: bannerMatch[2] }, source: "tcp_banner" });
      }
      const weak = block.match(/(?:diffie-hellman-group1-sha1|ssh-rsa|hmac-md5)/g);
      if (weak && weak.length > 0) {
        findings.push({
          title: `Weak SSH algorithms on ${host}:${port}`,
          severity: "medium",
          port,
          protocol: "tcp",
          evidence: `Detected: ${[...new Set(weak)].join(", ")}`,
          fingerprint: `ssh-weak|${host}|${port}`
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
        commandSummary: `Check SSH banner and supported algorithms on ${host} (ports: ${sshPorts.join(",")}).`
      }
    };
  }
};

function quote(s: string) {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}
