import { env } from "../env.js";
import { remoteScript, requireRemoteTool, snippet } from "./shared.js";
import { requestApproval, waitForApproval, isLhostAllowed } from "../approvals.js";
function quote(s) {
    return `'${s.replace(/'/g, `'\\''`)}'`;
}
/**
 * postex.session_recon — read-only post-exploitation enumeration over an
 * authenticated SSH session to the target.
 *
 * Strictly gated: requires RECON_MODE=gated_exploit, valid credentials (args or
 * HYDRA_* env), an approved command_approvals row, and a fixed read-only command
 * set (no writes, no privilege changes). Discovered network interfaces are fed
 * back to recon via a recommendation, closing the loop to Phase 2.
 */
const READONLY_BATCH = "id; uname -a; hostname; (ip -o addr 2>/dev/null || ifconfig -a 2>/dev/null)";
export const postexSessionReconTool = {
    name: "postex.session_recon",
    description: "Read-only post-exploitation enumeration (id/uname/interfaces) over an approved SSH session. Gated + approval-required.",
    tags: ["postex", "gated"],
    requires: ["target"],
    defaultTimeoutMs: 8 * 60 * 1000,
    argSchema: {
        username: { type: "string", description: "SSH username (defaults to HYDRA_USERNAME)" },
        password: { type: "string", description: "SSH password (defaults to HYDRA_PASSWORD)" },
        port: { type: "number", default: 22 },
        lhost: { type: "string", description: "Optional listener host; must be in EXPLOIT_LHOST_ALLOWLIST when set" }
    },
    handler: async (input, emit) => {
        if (env.RECON_MODE !== "gated_exploit") {
            return skipped("postex.session_recon requires RECON_MODE=gated_exploit.");
        }
        const args = (input.args ?? {});
        if (!isLhostAllowed(args.lhost)) {
            return skipped(`lhost "${args.lhost}" is not in EXPLOIT_LHOST_ALLOWLIST.`);
        }
        const username = args.username ?? env.HYDRA_USERNAME;
        const password = args.password ?? env.HYDRA_PASSWORD;
        if (!username || !password) {
            return skipped("No SSH credentials available (pass username/password or set HYDRA_USERNAME/HYDRA_PASSWORD).");
        }
        const presence = await requireRemoteTool("sshpass", input.signal, { installCommand: "apt-get install -y sshpass" });
        if (presence.missing)
            return presence.envelope;
        const host = input.target.host;
        const port = Number(args.port ?? 22);
        const planned = `ssh ${username}@${host}:${port} -> read-only: ${READONLY_BATCH}`;
        emit.log(`Requesting approval for post-ex session recon: ${planned}`);
        const approvalId = await requestApproval({
            agentRunId: input.context?.runId ?? null,
            tool: "postex.session_recon",
            command: planned,
            reasoning: input.intent ?? "Read-only post-exploitation enumeration over SSH",
            impact: "high",
            args: { host, port, username }
        });
        const decision = await waitForApproval(approvalId, input.signal);
        if (decision !== "approved") {
            return skipped(`postex.session_recon not approved (status=${decision}). Approve in the Pipeline queue and re-run.`, { approvalId, decision });
        }
        // sshpass + ssh to the target, running only the fixed read-only batch.
        const script = [
            "set +e",
            `sshpass -p ${quote(password)} ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p ${port} ${quote(`${username}@${host}`)} ${quote(READONLY_BATCH)}`
        ].join("\n");
        emit.log(`Approved (id=${approvalId}); running read-only session recon on ${host}`);
        const r = await remoteScript(script, input.signal, (s) => emit.log(s));
        const facts = [{ type: "postex_session", value: { host, username, output: snippet(r.stdout, 1200) }, source: "postex" }];
        const findings = [
            {
                title: `Authenticated SSH session established on ${host}`,
                severity: "high",
                port,
                protocol: "tcp",
                evidence: snippet(r.stdout, 600),
                fingerprint: `postex-session|${host}|${username}`,
                confidence: "high",
                requiresVerification: false,
                claimType: "postex_session"
            }
        ];
        // Feed loop: extract internal IPs/interfaces and recommend looping back to recon.
        const internalIps = extractIps(r.stdout).filter((ip) => ip !== host);
        const recommendations = [];
        if (internalIps.length > 0) {
            facts.push({ type: "postex_interfaces", value: { host, internalIps }, source: "postex" });
            recommendations.push({
                agent: "recon.nmap",
                reason: `Post-ex discovered internal interfaces (${internalIps.slice(0, 5).join(", ")}); loop back to recon for lateral surface.`,
                priority: 40
            });
        }
        return {
            status: "succeeded",
            durationMs: r.durationMs,
            artifacts: { commands: [planned], stdoutSnippet: snippet(r.stdout) },
            facts,
            findings,
            recommendations,
            meta: { approvalId, host, internalIps, commandSummary: planned }
        };
    }
};
function extractIps(stdout) {
    const out = new Set();
    const re = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;
    let m;
    while ((m = re.exec(stdout)) !== null) {
        const ip = m[1];
        if (ip !== "127.0.0.1" && ip !== "0.0.0.0")
            out.add(ip);
    }
    return [...out];
}
function skipped(error, meta = {}) {
    return { status: "skipped", error, artifacts: { commands: [] }, facts: [], findings: [], recommendations: [], meta };
}
export const postexTools = [postexSessionReconTool];
