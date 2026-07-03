import { ToolDefinition, ToolEnvelope, ToolFinding } from "../mcp/types.js";
import { env } from "../env.js";
import { remoteScript, requireRemoteTool, snippet } from "./shared.js";
import { quoteShell, requireGatedExploitMode, runGatedApproval } from "./exploitGated.js";

const NXC_INSTALL = "apt-get update -y && apt-get install -y crackmapexec || pip3 install crackmapexec";

/** exploit.crackmapexec — gated SMB/Win checks via crackmapexec/netexec. */
export const crackmapexecTool: ToolDefinition = {
  name: "exploit.crackmapexec",
  description:
    "Gated SMB attack surface check (crackmapexec/nxc): auth test, share listing, password spray on discovered SMB. Requires approval.",
  tags: ["exploit", "smb", "credentials", "gated"],
  requires: ["services"],
  defaultTimeoutMs: 15 * 60 * 1000,
  argSchema: {
    username: { type: "string", description: "SMB username (or from hydra finding)" },
    password: { type: "string", description: "SMB password" },
    module: { type: "string", description: "smb | winrm (default smb)" },
    action: { type: "string", description: "shares | auth | spray (default shares)" }
  },
  handler: async (input, emit): Promise<ToolEnvelope> => {
    const blocked = requireGatedExploitMode("exploit.crackmapexec");
    if (blocked) return blocked;
    if (!env.CRACKMAPEXEC_ENABLED) {
      return {
        status: "skipped",
        error: "exploit.crackmapexec is disabled (set CRACKMAPEXEC_ENABLED=true).",
        artifacts: { commands: [] },
        facts: [],
        findings: [],
        recommendations: [],
        meta: {}
      };
    }

    const hasSmb = (input.context?.knownServices ?? []).some((s) =>
      [139, 445].includes(s.port) || /smb|netbios|microsoft-ds/i.test(s.name ?? "")
    );
    if (!hasSmb) {
      return {
        status: "skipped",
        error: "No SMB service (139/445) in context.",
        artifacts: { commands: [] },
        facts: [],
        findings: [],
        recommendations: [],
        meta: {}
      };
    }

    const nxc = await requireRemoteTool("crackmapexec", input.signal, { installCommand: NXC_INSTALL });
    let bin: string;
    if (!nxc.missing) {
      bin = "crackmapexec";
    } else {
      const netexec = await requireRemoteTool("nxc", input.signal, { installCommand: NXC_INSTALL });
      if (netexec.missing) return netexec.envelope;
      bin = "nxc";
    }

    const args = (input.args ?? {}) as { username?: string; password?: string; module?: string; action?: string };
    const username = args.username ?? env.HYDRA_USERNAME ?? "";
    const password = args.password ?? env.HYDRA_PASSWORD ?? "";
    const action = (args.action ?? "shares").toLowerCase();
    const proto = (args.module ?? "smb").toLowerCase() === "winrm" ? "winrm" : "smb";
    const host = input.target.host;

    let cmd = "";
    if (action === "auth" && username && password) {
      cmd = `${bin} ${proto} ${host} -u ${quoteShell(username)} -p ${quoteShell(password)}`;
    } else if (action === "spray" && username) {
      const passFile = env.HYDRA_PASSLIST?.trim();
      cmd = passFile
        ? `${bin} ${proto} ${host} -u ${quoteShell(username)} -p ${quoteShell(passFile)} --continue-on-success`
        : `${bin} ${proto} ${host} -u ${quoteShell(username)} -p ${quoteShell(password || "Password1")}`;
    } else {
      cmd = `${bin} ${proto} ${host} --shares`;
    }

    const planned = cmd.length > 200 ? `${cmd.slice(0, 197)}…` : cmd;
    const approval = await runGatedApproval({
      agentRunId: input.context?.runId,
      tool: "exploit.crackmapexec",
      command: planned,
      reasoning: input.intent ?? `SMB exploitation check (${action}) on ${host}`,
      impact: "high",
      args: { host, action, proto, username: username || null },
      signal: input.signal,
      emitLog: (s) => emit.log(s)
    });
    if (!approval.approved) return approval.envelope;

    const script = `set +e\n${cmd} 2>&1`;
    const r = await remoteScript(script, input.signal, (s) => emit.log(s));
    const out = r.stdout + r.stderr;

    const findings: ToolFinding[] = [];
    const facts: ToolEnvelope["facts"] = [{ type: "nxc_output", value: { host, snippet: snippet(out, 600) }, source: "crackmapexec" }];

    if (/\[+\].*Pwn3d!|\[+\].*STATUS_LOGON_SUCCESS|administrator/i.test(out)) {
      findings.push({
        title: `SMB authentication success on ${host}`,
        severity: "critical",
        port: 445,
        protocol: "tcp",
        evidence: snippet(out, 500),
        fingerprint: `nxc-auth|${host}|${username}`,
        confidence: "high",
        requiresVerification: false,
        claimType: "weak_credentials"
      });
    }
    if (/READ|WRITE|IPC\$|ADMIN\$/i.test(out) && findings.length === 0) {
      findings.push({
        title: `SMB shares enumerated on ${host}`,
        severity: "high",
        port: 445,
        protocol: "tcp",
        evidence: snippet(out, 400),
        fingerprint: `nxc-shares|${host}`,
        confidence: "medium",
        requiresVerification: false,
        claimType: "smb_shares"
      });
    }

    const recommendations: ToolEnvelope["recommendations"] = [];
    if (findings.some((f) => f.claimType === "weak_credentials")) {
      recommendations.push({
        agent: "postex.session_recon",
        reason: "Valid SMB/Windows credentials — run gated SSH session recon if SSH is open",
        priority: 90
      });
    }

    return {
      status: "succeeded",
      facts,
      findings,
      recommendations,
      artifacts: { commands: [planned], stdoutSnippet: snippet(out, 2000) },
      meta: { approvalId: approval.approvalId, action, commandSummary: planned }
    };
  }
};
