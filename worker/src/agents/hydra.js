import { env } from "../env.js";
import { requireRemoteTool } from "./shared.js";
import { hydraFromNmapServices } from "../hydraScan.js";
import { requestApproval, waitForApproval } from "../approvals.js";
/**
 * recon.hydra — gated credential check.
 *
 * Only registered in `RECON_MODE=gated_exploit` with `HYDRA_ENABLED=true`, and
 * every run still requires an approved command_approvals row. Credentials and
 * wordlists come from the HYDRA_* env settings.
 */
export const hydraTool = {
    name: "recon.hydra",
    description: "Gated online credential check (hydra) against discovered auth services. Requires approval before running.",
    tags: ["exploit", "credentials", "gated"],
    requires: ["services"],
    defaultTimeoutMs: 20 * 60 * 1000,
    argSchema: {
        services: { type: "array", description: "nmap-style services rows to target (ssh/ftp/rdp/smb/db/...)" },
        stopOnFirstFind: { type: "boolean", default: true }
    },
    handler: async (input, emit) => {
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
        const credSource = buildCredSource();
        if (!credSource) {
            return {
                status: "skipped",
                error: "No hydra credentials configured. Set HYDRA_USERNAME/HYDRA_PASSWORD or HYDRA_USERLIST/HYDRA_PASSLIST.",
                artifacts: { commands: [] },
                facts: [],
                findings: [],
                recommendations: [],
                meta: {}
            };
        }
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
        if (presence.missing)
            return presence.envelope;
        const plannedCommand = `hydra against ${input.target.host} services: ${attackable.map((s) => `${s.serviceName ?? "?"}:${s.port}`).join(", ")}`;
        emit.log(`Requesting approval for: ${plannedCommand}`);
        const approvalId = await requestApproval({
            agentRunId: input.context?.runId ?? null,
            tool: "recon.hydra",
            command: plannedCommand,
            reasoning: input.intent ?? "Online credential check on discovered auth services",
            impact: "high",
            args: { services: attackable, host: input.target.host }
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
        const stopOnFirstFind = input.args?.stopOnFirstFind !== false;
        const results = await hydraFromNmapServices(input.target.host, attackable, credSource, {
            stopOnFirstFind,
            threads: env.HYDRA_THREADS,
            onOutput: (s) => emit.log(s),
            signal: input.signal
        });
        const findings = [];
        const facts = [];
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
            facts,
            findings,
            recommendations: [],
            artifacts: { commands: [plannedCommand], stdoutSnippet: rawAll.slice(0, 1500) },
            meta: { approvalId, attacked: attackable, credentialsFound: findings.length, commandSummary: plannedCommand }
        };
    }
};
function isAttackable(serviceName) {
    const n = (serviceName ?? "").toLowerCase();
    return /ssh|ftp|rdp|microsoft-rdp|microsoft-ds|netbios-ssn|smb|mysql|ms-sql-s|postgresql|smtp|imap|pop3|telnet|vnc/.test(n);
}
function buildCredSource() {
    const hasUser = Boolean(env.HYDRA_USERNAME);
    const hasUserList = Boolean(env.HYDRA_USERLIST);
    const hasPass = Boolean(env.HYDRA_PASSWORD);
    const hasPassList = Boolean(env.HYDRA_PASSLIST);
    if (!(hasUser || hasUserList) || !(hasPass || hasPassList))
        return null;
    const user = hasUserList ? { userList: env.HYDRA_USERLIST } : { username: env.HYDRA_USERNAME };
    const pass = hasPassList ? { passwordList: env.HYDRA_PASSLIST } : { password: env.HYDRA_PASSWORD };
    return { ...user, ...pass };
}
