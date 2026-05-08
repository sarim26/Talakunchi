import { ToolDefinition, ToolEnvelope } from "../mcp/types.js";
import { remoteScript, snippet } from "./shared.js";

/**
 * recon.smb_enum — passive SMB enumeration: dialects, signing, anonymous shares.
 * Read-only, never authenticates with real creds.
 */
export const smbEnumTool: ToolDefinition = {
  name: "recon.smb_enum",
  description: "Enumerate SMB on the target: dialects, signing, anonymous share listing.",
  tags: ["recon", "smb"],
  requires: ["services"],
  defaultTimeoutMs: 4 * 60 * 1000,
  handler: async (input, emit): Promise<ToolEnvelope> => {
    const hasSmb = (input.context?.knownServices ?? []).some((s) => [139, 445].includes(s.port));
    if (!hasSmb) {
      return {
        status: "skipped",
        error: "No SMB ports in context",
        artifacts: { commands: [] },
        facts: [],
        findings: [],
        recommendations: [],
        meta: { commandSummary: `Enumerate SMB shares and signing posture on ${input.target.host} (anonymous / read-only).` }
      };
    }

    const host = input.target.host;
    const script = [
      `set +e`,
      `HOST=${quote(host)}`,
      `echo "== smbclient -L -N =="`,
      `timeout 20 smbclient -L "//$HOST" -N -g 2>&1 | head -n 80 || true`,
      `echo "== nmap smb-protocols =="`,
      `timeout 60 nmap -Pn -p 139,445 --script smb-protocols,smb-security-mode "$HOST" 2>&1 | tail -n 60 || true`
    ].join("\n");

    emit.log(`SMB enum for ${host}`);
    const r = await remoteScript(script, input.signal, (s) => emit.log(s));

    const findings: ToolEnvelope["findings"] = [];
    const facts: ToolEnvelope["facts"] = [];

    const sharesBlock = /== smbclient -L -N ==([\s\S]*?)(?:==|$)/.exec(r.stdout);
    if (sharesBlock) {
      const lines = sharesBlock[1].split("\n").filter((l) => /^Disk\||Sharename|^Share\|/.test(l));
      if (lines.length > 0) {
        facts.push({ type: "smb_shares", value: lines, source: "smbclient" });
        if (lines.some((l) => /Disk\|.*\|/i.test(l))) {
          findings.push({
            title: `SMB anonymous share enumeration succeeded on ${host}`,
            severity: "medium",
            port: 445,
            protocol: "tcp",
            evidence: lines.slice(0, 10).join("\n"),
            fingerprint: `smb-anon|${host}`
          });
        }
      }
    }

    if (/Message signing enabled but not required/i.test(r.stdout)) {
      findings.push({
        title: `SMB signing not required on ${host}`,
        severity: "medium",
        port: 445,
        protocol: "tcp",
        evidence: "Nmap smb-security-mode reports signing enabled but not required",
        fingerprint: `smb-signing|${host}`
      });
    }

    return {
      status: "succeeded",
      durationMs: r.durationMs,
      artifacts: { commands: r.commands, stdoutSnippet: snippet(r.stdout), stderrSnippet: snippet(r.stderr) },
      facts,
      findings,
      recommendations: [],
      meta: { exitCode: r.exitCode, commandSummary: `Enumerate SMB shares and signing posture on ${host} (anonymous / read-only).` }
    };
  }
};

function quote(s: string) {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}
