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
    "Gated Metasploit module execution (check or run) against a discovered service. Module must be in MSF_MODULE_ALLOWLIST. Requires approval; action=run additionally requires explicit sensitiveOk=true.",
  tags: ["exploit", "rce", "gated"],
  requires: ["services"],
  defaultTimeoutMs: 15 * 60 * 1000,
  argSchema: {
    module: { type: "string", description: "Metasploit module path e.g. exploit/unix/ftp/vsftpd_234_backdoor" },
    rhost: { type: "string", description: "Target host (defaults to engagement target)" },
    rport: { type: "number", description: "Target port" },
    lhost: { type: "string", description: "Listener host for reverse payloads (must be in EXPLOIT_LHOST_ALLOWLIST)" },
    lport: { type: "number", default: 4444 },
    action: { type: "string", description: "check or run (default: check first)" },
    sensitiveOk: {
      type: "boolean",
      description:
        "Must be true to allow action=run (payload execution / session risk). Default false. Keep checks as default for safety."
    }
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
      sensitiveOk?: boolean;
    };

    const allowAll = msfAllowAllModules();
    const allow = allowAll ? null : new Set(parseMsfModuleAllowlist());
    // LLMs often invent `exploits/` (plural) or fake Windows paths.
    let module = (args.module?.trim() ?? "").replace(/^exploits\//i, "exploit/");
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

    const knownPorts = new Set((input.context?.knownServices ?? []).map((s) => s.port));
    if (knownPorts.size > 0 && !knownPorts.has(rport)) {
      return {
        status: "skipped",
        error: `RPORT ${rport} is not among discovered open ports (${[...knownPorts].join(", ")}). Refuse hallucinated services (e.g. NetSupport :5555).`,
        artifacts: { commands: [] },
        facts: [],
        findings: [],
        recommendations: [
          {
            agent: "exploit.msf_search",
            reason: "Search Metasploit for modules matching discovered services (ftp/ssh/samba/http), not invented ports",
            priority: 88,
            args: { query: "proftpd OR samba OR vsftpd" }
          }
        ],
        meta: { module, rport, knownPorts: [...knownPorts] }
      };
    }

    const svcBlob = (input.context?.knownServices ?? [])
      .map((s) => `${s.name ?? ""} ${s.product ?? ""} ${s.version ?? ""}`)
      .join(" ")
      .toLowerCase();
    const looksLinux =
      /ubuntu|debian|samba|proftpd|openssh|linux|unix|apache httpd|mysql/i.test(svcBlob) ||
      (input.context?.knownServices ?? []).some((s) => /samba|proftpd|openssh/i.test(`${s.product ?? ""} ${s.name ?? ""}`));
    if (looksLinux && /\/windows\//i.test(module)) {
      return {
        status: "skipped",
        error: `Refusing Windows MSF module "${module}" against Linux-looking services (Samba/ProFTPD/OpenSSH). Use exploit.msf_search for unix/linux modules.`,
        artifacts: { commands: [] },
        facts: [],
        findings: [],
        recommendations: [
          {
            agent: "exploit.msf_search",
            reason: "Find Linux/Unix modules matching discovered services",
            priority: 90,
            args: { query: "proftpd OR samba OR vsftpd" }
          }
        ],
        meta: { module, rport }
      };
    }

    // LHOST = YOUR attacker/Kali IP (listener), NEVER the Metasploitable target IP.
    // Auto-detect Kali IP when allowed/unset; ignore hallucinated IPs for check actions.
    let actionWanted = (args.action ?? "check").toLowerCase() === "run" ? "run" : "check";
    // Auxiliary modules don't implement `check` — use `run`.
    if (module.startsWith("auxiliary/") && actionWanted === "check") actionWanted = "run";

    const sensitiveOk = Boolean(args.sensitiveOk);
    if (actionWanted === "run" && !sensitiveOk) {
      return {
        status: "skipped",
        error:
          "exploit.msf_module action=run requires explicit sensitiveOk=true (company-safe gating). " +
          "Run action=check first, then re-run with sensitiveOk=true if the operator approves exploitation.",
        artifacts: { commands: [] },
        facts: [
          {
            type: "msf_policy",
            value: { blockedAction: "run", reason: "sensitiveOk_required" },
            source: "msf"
          }
        ],
        findings: [],
        recommendations: [
          {
            agent: "exploit.msf_module",
            reason: "If the operator wants to actually exploit, re-run with sensitiveOk=true.",
            priority: 95,
            args: { module, rhost: (args.rhost ?? input.target.host).trim(), rport, action: "run", sensitiveOk: true }
          }
        ],
        meta: { module, action: actionWanted }
      };
    }

    const lport = Number(args.lport ?? 4444);
    const presence = await requireRemoteTool("msfconsole", input.signal, { installCommand: MSF_INSTALL });
    if (presence.missing) return presence.envelope;

    let lhost = args.lhost?.trim() || "";
    if (actionWanted === "check") {
      // Checks don't need reverse listeners — drop bad LHOST so we don't skip.
      lhost = "";
    } else {
      const allowlist = env.EXPLOIT_LHOST_ALLOWLIST.split(/[\s,]+/)
        .map((s) => s.trim())
        .filter(Boolean);
      if (!lhost || (allowlist.length > 0 && !isLhostAllowed(lhost))) {
        // Prefer configured allowlist; else detect Kali's address that can reach RHOST.
        if (allowlist.length > 0) {
          lhost = allowlist[0]!;
        } else {
          lhost = await detectKaliLhost(rhost, input.signal);
        }
      }
      if (lhost && !isLhostAllowed(lhost) && allowlist.length > 0) {
        return {
          status: "skipped",
          error: `lhost "${lhost}" is not in EXPLOIT_LHOST_ALLOWLIST.`,
          artifacts: { commands: [] },
          facts: [],
          findings: [],
          recommendations: [
            {
              agent: "exploit.msf_search",
              reason: "Fix LHOST allowlist, then search for a valid module for this service",
              priority: 80,
              args: { query: "proftpd" }
            }
          ],
          meta: {}
        };
      }
      // If allowlist empty, allow detected Kali IP automatically (lab convenience).
    }

    const action = actionWanted;
    const planned = `msf ${action} ${module} RHOST=${rhost} RPORT=${rport}${lhost ? ` LHOST=${lhost}` : ""}`;
    const approval = await runGatedApproval({
      agentRunId: input.context?.runId,
      tool: "exploit.msf_module",
      command: planned,
      reasoning: input.intent ?? `Metasploit ${action} for ${module}`,
      impact: action === "run" ? "high" : "medium",
      args: { module, rhost, rport, lhost, lport, action, sensitiveOk },
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

    const moduleMissing = /Failed to load module|No results from search/i.test(out);
    const checkUnsupported = /Unknown command: check/i.test(out);
    if (moduleMissing) {
      facts.push({
        type: "msf_module_missing",
        value: { module, hint: "Run exploit.msf_search for a real path on this Kali" },
        source: "msf"
      });
      return {
        status: "succeeded",
        facts,
        findings: [],
        recommendations: [
          {
            agent: "exploit.msf_search",
            reason: `Module "${module}" is not installed/named incorrectly on Kali — search for alternatives`,
            priority: 90,
            args: { query: module.split("/").pop() || "proftpd" }
          }
        ],
        artifacts: { commands: [planned], stdoutSnippet: snippet(out, 2000) },
        meta: { approvalId: approval.approvalId, module, action, moduleMissing: true }
      };
    }

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

    facts.push({
      type: "msf_summary",
      value: {
        result: "no_vuln_confirmed",
        module,
        action,
        checkUnsupported,
        notes: checkUnsupported ? ["module_does_not_support_check"] : []
      },
      source: "msf"
    });

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

/** Pick a non-loopback IPv4 on Kali that can reach the RHOST (best-effort). */
async function detectKaliLhost(rhost: string, signal?: AbortSignal): Promise<string> {
  const script = [
    "set +e",
    `# Prefer the source IP Kali would use to talk to RHOST`,
    `IP=$(ip -4 route get ${quoteShell(rhost)} 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')`,
    `if [ -z "$IP" ]; then IP=$(hostname -I 2>/dev/null | awk '{print $1}'); fi`,
    `echo "LHOST_DETECTED=$IP"`
  ].join("\n");
  try {
    const r = await remoteScript(script, signal);
    const m = /LHOST_DETECTED=([0-9.]+)/.exec(r.stdout);
    return m?.[1]?.trim() || "";
  } catch {
    return "";
  }
}
