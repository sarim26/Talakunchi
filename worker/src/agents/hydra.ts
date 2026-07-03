import { ToolDefinition, ToolEnvelope, ToolFinding } from "../mcp/types.js";
import { env } from "../env.js";
import { remoteScript, requireRemoteTool } from "./shared.js";
import { getWordlistCatalog } from "./wordlists.js";
import { shellQuote } from "./webTarget.js";
import { hydraFromNmapServices, type HydraCredSource } from "../hydraScan.js";
import { requestApproval, waitForApproval } from "../approvals.js";

/**
 * recon.hydra — gated credential check.
 *
 * Only registered in `RECON_MODE=gated_exploit` with `HYDRA_ENABLED=true`, and
 * every run still requires an approved command_approvals row. Credentials and
 * wordlists come from the HYDRA_* env settings.
 */
export const hydraTool: ToolDefinition = {
  name: "recon.hydra",
  description: "Gated online credential check (hydra) against discovered auth services. Requires approval before running.",
  tags: ["exploit", "credentials", "gated"],
  requires: ["services"],
  defaultTimeoutMs: 20 * 60 * 1000,
  argSchema: {
    services: { type: "array", description: "nmap-style services rows to target (ssh/ftp/rdp/smb/db/...)" },
    stopOnFirstFind: { type: "boolean", default: true }
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

    const credResolved = await resolveCredSource(input.signal, (s) => emit.log(s));
    if (!credResolved.source) {
      return {
        status: "failed",
        error: credResolved.error ?? "No hydra credentials configured.",
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
        facts,
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

function buildCredSource(): HydraCredSource | null {
  const hasUser = Boolean(env.HYDRA_USERNAME?.trim());
  const hasUserList = Boolean(env.HYDRA_USERLIST?.trim());
  const hasPass = Boolean(env.HYDRA_PASSWORD?.trim());
  const hasPassList = Boolean(env.HYDRA_PASSLIST?.trim());
  if (!(hasUser || hasUserList) || !(hasPass || hasPassList)) return null;
  const user = hasUserList ? { userList: env.HYDRA_USERLIST!.trim() } : { username: env.HYDRA_USERNAME!.trim() };
  const pass = hasPassList ? { passwordList: env.HYDRA_PASSLIST!.trim() } : { password: env.HYDRA_PASSWORD!.trim() };
  return { ...user, ...pass } as HydraCredSource;
}

async function remoteFileExists(path: string, signal?: AbortSignal): Promise<boolean> {
  const script = `test -f ${shellQuote(path)} && echo FILE_OK || echo FILE_MISSING`;
  const r = await remoteScript(script, signal);
  return /FILE_OK/.test(r.stdout);
}

async function resolveCredSource(
  signal?: AbortSignal,
  emitLog?: (s: string) => void
): Promise<{
  source: HydraCredSource | null;
  error?: string;
  meta?: Record<string, unknown>;
}> {
  const hasUser = Boolean(env.HYDRA_USERNAME?.trim());
  const hasPass = Boolean(env.HYDRA_PASSWORD?.trim());
  if (hasUser && hasPass) {
    return {
      source: { username: env.HYDRA_USERNAME!.trim(), password: env.HYDRA_PASSWORD!.trim() },
      meta: { credMode: "single" }
    };
  }

  const catalog = await getWordlistCatalog({ signal });
  const tried: string[] = [];

  const pickList = async (envPath: string | undefined, fallback: string | null, label: string): Promise<string | null> => {
    if (envPath?.trim()) {
      tried.push(envPath.trim());
      if (await remoteFileExists(envPath.trim(), signal)) return envPath.trim();
      emitLog?.(`[hydra] ${label} not found on SSH host: ${envPath.trim()}`);
    }
    if (fallback) {
      tried.push(fallback);
      if (await remoteFileExists(fallback, signal)) {
        emitLog?.(`[hydra] using SecLists default ${label}: ${fallback}`);
        return fallback;
      }
    }
    return null;
  };

  const userList = await pickList(env.HYDRA_USERLIST, catalog.defaults.usernames, "userlist");
  const passList = await pickList(env.HYDRA_PASSLIST, catalog.defaults.passwords, "passlist");

  if (hasUser && passList) {
    return {
      source: { username: env.HYDRA_USERNAME!.trim(), passwordList: passList },
      meta: { credMode: "user+passlist", userList: null, passList }
    };
  }
  if (userList && hasPass) {
    return {
      source: { userList, password: env.HYDRA_PASSWORD!.trim() },
      meta: { credMode: "userlist+pass", userList, passList: null }
    };
  }
  if (userList && passList) {
    return {
      source: { userList, passwordList: passList },
      meta: { credMode: "lists", userList, passList }
    };
  }

  const configured = buildCredSource();
  if (configured) {
    return {
      source: null,
      error:
        `Hydra credential files missing on the SSH tools host. Tried: ${tried.join(", ") || "(none)"}. ` +
        `Set HYDRA_USERLIST/HYDRA_PASSLIST to paths under ${catalog.root} on Kali, or HYDRA_USERNAME/HYDRA_PASSWORD for a single cred pair.`,
      meta: { tried, catalogRoot: catalog.root, catalogDefaults: catalog.defaults }
    };
  }

  return {
    source: null,
    error: "No hydra credentials configured. Set HYDRA_USERNAME/HYDRA_PASSWORD or HYDRA_USERLIST/HYDRA_PASSLIST.",
    meta: { catalogRoot: catalog.root }
  };
}
