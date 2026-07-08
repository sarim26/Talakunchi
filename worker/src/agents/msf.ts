import { ToolDefinition, ToolEnvelope, ToolFinding } from "../mcp/types.js";
import { env } from "../env.js";
import { remoteScript, requireRemoteTool, snippet } from "./shared.js";
import { isLhostAllowed } from "../approvals.js";
import {
  matchMsfModuleForService,
  msfAllowAllModules,
  parseMsfModuleAllowlist,
  quoteShell,
  requireGatedExploitMode,
  runGatedApproval
} from "./exploitGated.js";

const MSF_INSTALL =
  "apt-get update -y && apt-get install -y metasploit-framework";

/**
 * exploit.msf_module — gated Metasploit module runner (allow-listed modules only).
 */
export const msfModuleTool: ToolDefinition = {
  name: "exploit.msf_module",
  description:
    "Gated Metasploit module execution (check or run) against a discovered service. Module must be in MSF_MODULE_ALLOWLIST. Requires approval.",
  tags: ["exploit", "rce", "gated"],
  requires: ["services"],
  defaultTimeoutMs: 15 * 60 * 1000,
  argSchema: {
    module: { type: "string", description: "Metasploit module path e.g. exploit/unix/ftp/vsftpd_234_backdoor" },
    rhost: { type: "string", description: "Target host (defaults to engagement target)" },
    rport: { type: "number", description: "Target port" },
    lhost: { type: "string", description: "Listener host for reverse payloads (must be in EXPLOIT_LHOST_ALLOWLIST)" },
    lport: { type: "number", default: 4444 },
    action: { type: "string", description: "check or run (default: check first)" }
  },
  handler: async (input, emit): Promise<ToolEnvelope> => {
    const blocked = requireGatedExploitMode("exploit.msf_module");
    if (blocked) return blocked;
    if (!env.MSF_ENABLED) {
      return {
        status: "skipped",
        error: "exploit.msf_module is disabled (set MSF_ENABLED=true).",
        artifacts: { commands: [] },
        facts: [],
        findings: [],
        recommendations: [],
        meta: {}
      };
    }

    const args = (input.args ?? {}) as {
      module?: string;
      rhost?: string;
      rport?: number;
      lhost?: string;
      lport?: number;
      action?: string;
    };

    const allowAll = msfAllowAllModules();
    const allow = allowAll ? null : new Set(parseMsfModuleAllowlist());
    let module = args.module?.trim() ?? "";
    let rport = Number(args.rport ?? 0);

    if (!module) {
      for (const svc of input.context?.knownServices ?? []) {
        const m = matchMsfModuleForService(svc);
        if (m) {
          module = m;
          rport = svc.port;
          break;
        }
      }
    }

    if (!module || (!allowAll && !allow?.has(module))) {
      return {
        status: "skipped",
        error: module
          ? `MSF module "${module}" is not in MSF_MODULE_ALLOWLIST.`
          : `No matching MSF module for discovered services. Allowed: ${[...(allow ?? new Set())].slice(0, 8).join(", ")}…`,
        artifacts: { commands: [] },
        facts: [],
        findings: [],
        recommendations: [],
        meta: { allowedModules: allow ? [...allow] : ["*"] }
      };
    }

    const rhost = (args.rhost ?? input.target.host).trim();
    if (!rport) {
      const svc = (input.context?.knownServices ?? []).find((s) => matchMsfModuleForService(s) === module);
      rport = svc?.port ?? 0;
    }
    if (!rport) {
      return {
        status: "skipped",
        error: "Could not determine RPORT for MSF module. Pass rport in args.",
        artifacts: { commands: [] },
        facts: [],
        findings: [],
        recommendations: [],
        meta: { module }
      };
    }

    const lhost = args.lhost?.trim() || env.EXPLOIT_LHOST_ALLOWLIST.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean)[0] || "";
    if (lhost && !isLhostAllowed(lhost)) {
      return {
        status: "skipped",
        error: `lhost "${lhost}" is not in EXPLOIT_LHOST_ALLOWLIST.`,
        artifacts: { commands: [] },
        facts: [],
        findings: [],
        recommendations: [],
        meta: {}
      };
    }

    const action = (args.action ?? "check").toLowerCase() === "run" ? "run" : "check";
    const lport = Number(args.lport ?? 4444);
    const presence = await requireRemoteTool("msfconsole", input.signal, { installCommand: MSF_INSTALL });
    if (presence.missing) return presence.envelope;

    const planned = `msf ${action} ${module} RHOST=${rhost} RPORT=${rport}${lhost ? ` LHOST=${lhost}` : ""}`;
    const approval = await runGatedApproval({
      agentRunId: input.context?.runId,
      tool: "exploit.msf_module",
      command: planned,
      reasoning: input.intent ?? `Metasploit ${action} for ${module}`,
      impact: action === "run" ? "high" : "medium",
      args: { module, rhost, rport, lhost, lport, action },
      signal: input.signal,
      emitLog: (s) => emit.log(s)
    });
    if (!approval.approved) return approval.envelope;

    const msfLines = [
      `use ${module}`,
      `set RHOST ${rhost}`,
      `set RPORT ${rport}`
    ];
    if (lhost) {
      msfLines.push(`set LHOST ${lhost}`, `set LPORT ${lport}`);
    }
    msfLines.push(action, "exit");

    const script = [
      "set +e",
      `msfconsole -q -x ${quoteShell(msfLines.join("; "))} 2>&1`
    ].join("\n");

    emit.log(`[msf] ${action} ${module}`);
    const r = await remoteScript(script, input.signal, (s) => emit.log(s));
    const out = r.stdout + r.stderr;

    const findings: ToolFinding[] = [];
    const facts: ToolEnvelope["facts"] = [
      { type: "msf_result", value: { module, action, rhost, rport, snippet: snippet(out, 800) }, source: "msf" }
    ];

    const vulnerable =
      /Vulnerable|is vulnerable|Exploit completed|Command shell session|Meterpreter session/i.test(out);
    const checkPositive = action === "check" && /The target is vulnerable|appears to be vulnerable/i.test(out);

    if (vulnerable || checkPositive) {
      findings.push({
        title: `MSF ${action}: ${module} on ${rhost}:${rport}`,
        severity: "critical",
        port: rport,
        protocol: "tcp",
        evidence: snippet(out, 600),
        fingerprint: `msf|${module}|${rhost}|${rport}`,
        confidence: "high",
        requiresVerification: false,
        claimType: "rce"
      });
      if (action === "check") {
        return {
          status: "succeeded",
          facts,
          findings,
          recommendations: [
            {
              agent: "exploit.msf_module",
              reason: `Target vulnerable to ${module} — re-run with action=run after approval`,
              priority: 95,
              args: { module, rhost, rport, lhost, lport, action: "run" }
            }
          ],
          artifacts: { commands: [planned], stdoutSnippet: snippet(out, 2000) },
          meta: { approvalId: approval.approvalId, module, action, vulnerable: true }
        };
      }
    }

    return {
      status: "succeeded",
      facts,
      findings,
      recommendations: [],
      artifacts: { commands: [planned], stdoutSnippet: snippet(out, 2000) },
      meta: { approvalId: approval.approvalId, module, action, exitCode: r.exitCode }
    };
  }
};
