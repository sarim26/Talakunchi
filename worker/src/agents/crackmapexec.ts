import { ToolDefinition, ToolEnvelope, ToolFinding } from "../mcp/types.js";
import { env } from "../env.js";
import { remoteScript, requireRemoteTool, snippet } from "./shared.js";
import { quoteShell, requireGatedExploitMode, runGatedApproval } from "./exploitGated.js";
import { resolveCredSource } from "../credSource.js";

const NXC_INSTALL =
  "apt-get update -y && (apt-get install -y netexec || apt-get install -y crackmapexec || pip3 install netexec)";

/** Hard wall-clock for the remote nxc process (seconds). NetExec `--timeout` alone is not enough when TCP/SMB hangs. */
const NXC_WALL_SECS = 45;

/** exploit.crackmapexec — gated SMB/Win checks via NetExec (nxc); crackmapexec as legacy fallback. */
export const crackmapexecTool: ToolDefinition = {
  name: "exploit.crackmapexec",
  description:
    "Gated SMB attack surface check via NetExec (nxc) / legacy crackmapexec: share listing, auth test, or spray. Requires approval.",
  tags: ["exploit", "smb", "credentials", "gated"],
  requires: ["services"],
  defaultTimeoutMs: 2 * 60 * 1000,
  argSchema: {
    username: { type: "string", description: "SMB username or path to user wordlist for spray" },
    password: { type: "string", description: "SMB password or path to password wordlist for spray" },
    userlist: { type: "string", description: "Absolute path to username wordlist on Kali (spray)" },
    passlist: { type: "string", description: "Absolute path to password wordlist on Kali (spray)" },
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

    // Prefer NetExec (nxc); fall back to legacy crackmapexec.
    const netexec = await requireRemoteTool("nxc", input.signal, { installCommand: NXC_INSTALL });
    let bin: string;
    if (!netexec.missing) {
      bin = "nxc";
    } else {
      const cme = await requireRemoteTool("crackmapexec", input.signal, { installCommand: NXC_INSTALL });
      if (cme.missing) return cme.envelope;
      bin = "crackmapexec";
    }

    const args = (input.args ?? {}) as {
      username?: string;
      password?: string;
      userlist?: string;
      passlist?: string;
      module?: string;
      action?: string;
    };
    const action = (args.action ?? "shares").toLowerCase();
    const proto = (args.module ?? "smb").toLowerCase() === "winrm" ? "winrm" : "smb";
    const host = input.target.host;

    let username = args.username?.trim() ?? "";
    let password = args.password?.trim() ?? "";

    if (action === "auth" || action === "spray") {
      const credResolved = await resolveCredSource({
        args,
        engagement: input.context?.engagementCreds,
        signal: input.signal,
        emitLog: (s) => emit.log(s)
      });
      if (!credResolved.source && action === "auth") {
        return {
          status: "skipped",
          error: credResolved.error ?? "auth/spray requires credentials or wordlists configured for this engagement.",
          artifacts: { commands: [] },
          facts: [],
          findings: [],
          recommendations: [],
          meta: credResolved.meta ?? {}
        };
      }
      if (credResolved.source) {
        if ("username" in credResolved.source && credResolved.source.username) username = credResolved.source.username;
        if ("password" in credResolved.source && credResolved.source.password) password = credResolved.source.password;
        if ("userList" in credResolved.source && credResolved.source.userList) username = credResolved.source.userList;
        if ("passwordList" in credResolved.source && credResolved.source.passwordList) password = credResolved.source.passwordList;
      }
    }

    // Protocol + host first (most reliable across nxc versions). Put timeouts
    // after. --no-progress avoids Rich UI oddities over SSH. Wrap with GNU
    // timeout because nxc can still hang forever on unreachable SMB.
    const connTimeout = Math.max(5, Math.min(30, NXC_WALL_SECS - 5));
    const common = `${bin} ${proto} ${quoteShell(host)} --no-progress --timeout ${connTimeout}`;
    let inner = "";
    if (action === "auth" && username && password) {
      inner = `${common} -u ${quoteShell(username)} -p ${quoteShell(password)}`.replace(/\s+/g, " ").trim();
    } else if (action === "spray" && username) {
      inner =
        `${common} -u ${quoteShell(username)} -p ${quoteShell(password || "Password1")} --continue-on-success`
          .replace(/\s+/g, " ")
          .trim();
    } else if (action === "spray") {
      return {
        status: "skipped",
        error: "spray requires username or userlist configured for this engagement.",
        artifacts: { commands: [] },
        facts: [],
        findings: [],
        recommendations: [],
        meta: {}
      };
    } else {
      // Null session first — Metasploitable / many Linux Samba boxes need this for --shares.
      inner = `${common} -u '' -p '' --shares`.replace(/\s+/g, " ").trim();
    }

    const cmd = `timeout -k 5 ${NXC_WALL_SECS}s ${inner}`;
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

    const script = `set +e\n${cmd} 2>&1\nEC=$?\necho "NXC_EXIT=$EC"`;
    const r = await remoteScript(script, input.signal, (s) => emit.log(s));
    const out = r.stdout + r.stderr;
    const wallTimedOut = /NXC_EXIT=124\b/.test(out) || r.aborted === true;

    const findings: ToolFinding[] = [];
    const facts: ToolEnvelope["facts"] = [
      {
        type: "nxc_output",
        value: {
          host,
          action,
          wallTimedOut,
          snippet: snippet(out, 600)
        },
        source: "crackmapexec"
      }
    ];

    if (wallTimedOut) {
      return {
        status: "failed",
        error:
          `NetExec did not finish within ${NXC_WALL_SECS}s (likely unreachable SMB or hung NetBIOS). ` +
          `Check Kali can reach ${host}:445 (nc -zv ${host} 445).`,
        facts,
        findings: [],
        recommendations: [],
        artifacts: { commands: [planned], stdoutSnippet: snippet(out, 2000) },
        meta: { approvalId: approval.approvalId, action, wallTimedOut: true, commandSummary: planned }
      };
    }

    // NetExec exits 0 with an empty target list — treat as failure (not success).
    if (/against\s+0\s+targets/i.test(out) && !/\[\*].*SMB|READ|WRITE|IPC\$/i.test(out)) {
      return {
        status: "failed",
        error:
          `NetExec parsed 0 targets for ${host} (CLI/version quirk or host not accepted). ` +
          `Retry with guest null session or confirm: nxc smb ${host} -u '' -p '' --shares`,
        facts,
        findings: [],
        recommendations: [
          {
            agent: "recon.smb_enum",
            reason: "NetExec returned 0 targets — fall back to enum4linux-ng / smbclient",
            priority: 70
          }
        ],
        artifacts: { commands: [planned], stdoutSnippet: snippet(out, 2000) },
        meta: { approvalId: approval.approvalId, action, zeroTargets: true, commandSummary: planned }
      };
    }

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
