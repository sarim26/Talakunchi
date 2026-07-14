import { ToolDefinition, ToolEnvelope, ToolFinding } from "../mcp/types.js";
import { env } from "../env.js";
import { requireRemoteTool } from "./shared.js";
import { hydraFromNmapServices } from "../hydraScan.js";
import { requestApproval, waitForApproval } from "../approvals.js";
import { resolveCredSource } from "../credSource.js";

/**
 * recon.hydra — gated credential check.
 *
 * Wordlists come from (in order): per-target fields → HYDRA_* env →
 * Pipeline allowedWordlists → tool args (LLM junk like 3bb router lists ignored).
 */
export const hydraTool: ToolDefinition = {
  name: "recon.hydra",
  description:
    "Gated online credential check (hydra) against discovered auth services. " +
    "Uses engagement wordlists (target fields, env, or pipeline config). Requires approval.",
  tags: ["exploit", "credentials", "gated"],
  requires: ["services"],
  defaultTimeoutMs: 20 * 60 * 1000,
  argSchema: {
    services: { type: "array", description: "nmap-style services rows to target (ssh/ftp/rdp/smb/db/...)" },
    stopOnFirstFind: { type: "boolean", default: true },
    username: { type: "string", description: "Single username (optional)" },
    password: { type: "string", description: "Single password (optional)" },
    userlist: { type: "string", description: "Absolute path to username wordlist on Kali tools host" },
    passlist: { type: "string", description: "Absolute path to password wordlist on Kali tools host" }
  },
  handler: async (input, emit): Promise<ToolEnvelope> => {
    if (env.RECON_MODE !== "gated_exploit" || !env.HYDRA_ENABLED) {
      return {
        status: "skipped",
        error: "recon.hydra is disabled (requires RECON_MODE=gated_exploit and HYDRA_ENABLED=true).",
        artifacts: { commands: [] },
        facts: [],
        findings: [],
        recommendations: [],
        meta: {}
      };
    }

    const credResolved = await resolveCredSource({
      args: input.args,
      engagement: input.context?.engagementCreds,
      signal: input.signal,
      emitLog: (s) => emit.log(s)
    });
    if (!credResolved.source) {
      return {
        status: "failed",
        error: credResolved.error ?? "No hydra credentials configured for this engagement.",
        artifacts: { commands: [] },
        facts: [],
        findings: [],
        recommendations: [],
        meta: credResolved.meta ?? {}
      };
    }
    const credSource = credResolved.source;

    const services = (input.context?.knownServices ?? []).map((s) => ({ port: s.port, serviceName: s.name }));
    const attackable = services.filter((s) => isAttackable(s.serviceName));
    if (attackable.length === 0) {
      return {
        status: "skipped",
        error: "No hydra-supported auth services in context (ssh/ftp/rdp/smb/mysql/mssql/postgres/smtp/...).",
        artifacts: { commands: [] },
        facts: [],
        findings: [],
        recommendations: [],
        meta: { services }
      };
    }

    const presence = await requireRemoteTool("hydra", input.signal);
    if (presence.missing) return presence.envelope;

    const plannedCommand = `hydra against ${input.target.host} services: ${attackable.map((s) => `${s.serviceName ?? "?"}:${s.port}`).join(", ")}`;
    emit.log(`Requesting approval for: ${plannedCommand}`);
    const approvalId = await requestApproval({
      agentRunId: input.context?.runId ?? null,
      tool: "recon.hydra",
      command: plannedCommand,
      reasoning: input.intent ?? "Online credential check on discovered auth services",
      impact: "high",
      args: { services: attackable, host: input.target.host, credMode: credResolved.meta?.credMode }
    });

    const decision = await waitForApproval(approvalId, input.signal);
    if (decision !== "approved") {
      return {
        status: "skipped",
        error: `recon.hydra not approved (status=${decision}). Approve the pending command in the Pipeline approval queue and re-run.`,
        artifacts: { commands: [] },
        facts: [],
        findings: [],
        recommendations: [],
        meta: { approvalId, decision, plannedCommand }
      };
    }

    emit.log(`Approved (id=${approvalId}); running hydra`);
    const stopOnFirstFind = (input.args as { stopOnFirstFind?: boolean } | undefined)?.stopOnFirstFind !== false;
    try {
      const results = await hydraFromNmapServices(input.target.host, attackable, credSource, {
        stopOnFirstFind,
        threads: env.HYDRA_THREADS,
        onOutput: (s) => emit.log(s),
        signal: input.signal
      });

      const findings: ToolFinding[] = [];
      const facts: ToolEnvelope["facts"] = [];
      let rawAll = "";
      for (const r of results) {
        rawAll += r.raw;
        for (const cred of r.credentials) {
          facts.push({ type: "credential", value: { host: cred.host, port: cred.port, service: cred.service, username: cred.username }, source: "hydra" });
          findings.push({
            title: `Weak credentials on ${cred.service} ${cred.host}:${cred.port}`,
            severity: "critical",
            port: cred.port,
            protocol: "tcp",
            evidence: `hydra found valid login: ${cred.username}:**** on ${cred.service}`,
            fingerprint: `weak-cred|${cred.host}|${cred.port}|${cred.username}`,
            confidence: "high",
            requiresVerification: false,
            claimType: "weak_credentials"
          });
        }
      }

      return {
        status: "succeeded",
        facts: [
          ...facts,
          ...(findings.length === 0
            ? [
                {
                  type: "hydra_summary" as const,
                  value: {
                    host: input.target.host,
                    services: attackable.map((s) => `${s.serviceName}:${s.port}`),
                    credentialsFound: 0,
                    credMode: credResolved.meta?.credMode,
                    userList: credResolved.meta?.userList ?? null,
                    passList: credResolved.meta?.passList ?? null
                  },
                  source: "hydra"
                }
              ]
            : [])
        ],
        findings,
        recommendations: [],
        artifacts: { commands: [plannedCommand], stdoutSnippet: rawAll.slice(0, 1500) },
        meta: { approvalId, attacked: attackable, credentialsFound: findings.length, commandSummary: plannedCommand, ...credResolved.meta }
      };
    } catch (e) {
      return {
        status: "failed",
        error: (e as Error).message,
        artifacts: { commands: [plannedCommand] },
        facts: [],
        findings: [],
        recommendations: [],
        meta: { approvalId, attacked: attackable, plannedCommand, ...credResolved.meta }
      };
    }
  }
};

function isAttackable(serviceName?: string): boolean {
  const n = (serviceName ?? "").toLowerCase();
  return /ssh|ftp|rdp|microsoft-rdp|microsoft-ds|netbios-ssn|smb|mysql|ms-sql-s|postgresql|smtp|imap|pop3|telnet|vnc/.test(n);
}
