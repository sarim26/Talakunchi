import { ToolDefinition, ToolEnvelope } from "../mcp/types.js";
import { env } from "../env.js";
import { remoteScript, requireRemoteTool, snippet } from "./shared.js";
import { requireGatedExploitMode, runGatedApproval, quoteShell } from "./exploitGated.js";

const MSF_INSTALL = "apt-get update -y && apt-get install -y metasploit-framework";

/** Parse module paths from `msfconsole search` table output (handles leading index column). */
export function parseMsfSearchModules(stdout: string): string[] {
  const names = new Set<string>();
  const re = /(?:^|\s)((?:auxiliary|exploit|post|encoder|payload|nop|evasion)\/[a-z0-9_\/\-]+)/gi;
  for (const line of stdout.split(/\r?\n/)) {
    const t = line.trim();
    if (!t || /^(Matching Modules|No results from search|Interact with)/i.test(t)) continue;
    if (/\\_\s/.test(t)) continue;
    let m: RegExpExecArray | null;
    while ((m = re.exec(line)) !== null) {
      const path = m[1]!.toLowerCase();
      if (path.includes("target:")) continue;
      names.add(m[1]!);
    }
  }
  return [...names];
}

/** Prefer real exploit modules relevant to the search keyword. */
export function pickBestMsfExploitModule(modules: string[], query: string): string | null {
  const q = query.toLowerCase();
  const exploits = modules.filter((m) => m.startsWith("exploit/"));
  const pool = exploits.length > 0 ? exploits : modules;

  if (q.includes("proftpd") || q.includes("proftp")) {
    return (
      pool.find((m) => /modcopy/i.test(m)) ??
      pool.find((m) => /133c|backdoor/i.test(m)) ??
      pool.find((m) => /proftp/i.test(m)) ??
      null
    );
  }
  if (q.includes("vsftpd")) {
    return pool.find((m) => /vsftpd/i.test(m)) ?? null;
  }
  if (q.includes("samba")) {
    return pool.find((m) => /samba|pipename/i.test(m)) ?? null;
  }
  if (q.includes("distcc")) {
    return pool.find((m) => /distcc/i.test(m)) ?? null;
  }
  return pool[0] ?? null;
}

/**
 * exploit.msf_search — query Metasploit module database on Kali.
 */
export const msfSearchTool: ToolDefinition = {
  name: "exploit.msf_search",
  description: "Search Metasploit modules on the Kali tools host (read-only). Requires approval.",
  tags: ["exploit", "gated", "msf"],
  requires: ["services"],
  defaultTimeoutMs: 6 * 60 * 1000,
  argSchema: {
    query: { type: "string", description: "Search query, e.g. proftpd, samba, vsftpd, distcc" },
    limit: { type: "number", default: 25 }
  },
  handler: async (input, emit): Promise<ToolEnvelope> => {
    const blocked = requireGatedExploitMode("exploit.msf_search");
    if (blocked) return blocked;
    if (!env.MSF_ENABLED) {
      return {
        status: "skipped",
        error: "exploit.msf_search is disabled (set MSF_ENABLED=true).",
        artifacts: { commands: [] },
        facts: [],
        findings: [],
        recommendations: [],
        meta: {}
      };
    }

    const args = (input.args ?? {}) as { query?: string; limit?: number };
    const q = String(args.query ?? "").trim();
    if (!q) {
      return {
        status: "skipped",
        error: "Missing args.query for exploit.msf_search.",
        artifacts: { commands: [] },
        facts: [],
        findings: [],
        recommendations: [],
        meta: {}
      };
    }

    const presence = await requireRemoteTool("msfconsole", input.signal, { installCommand: MSF_INSTALL });
    if (presence.missing) return presence.envelope;

    const planned = `msf search ${q}`;
    const approval = await runGatedApproval({
      agentRunId: input.context?.runId,
      tool: "exploit.msf_search",
      command: planned,
      reasoning: input.intent ?? `Search Metasploit for "${q}"`,
      impact: "low",
      args: { query: q },
      signal: input.signal,
      emitLog: (s) => emit.log(s)
    });
    if (!approval.approved) return approval.envelope;

    const script = [
      "set +e",
      `Q=${quoteShell(q)}`,
      `msfconsole -q -x "search $Q; exit" 2>&1 || true`
    ].join("\n");

    emit.log(`[msf] search ${q}`);
    const r = await remoteScript(script, input.signal, (s) => emit.log(s));
    const out = r.stdout + r.stderr;

    const all = parseMsfSearchModules(out);
    const limit = Math.min(100, Math.max(1, Number(args.limit ?? 25)));
    const list = all.slice(0, limit);
    const best = pickBestMsfExploitModule(all, q);

    const rport =
      Number((input.args as { rport?: number })?.rport ?? 0) ||
      (input.context?.knownServices ?? []).find((s) => s.port === 21 || /ftp/i.test(s.name ?? ""))?.port ||
      0;

    const recommendations: ToolEnvelope["recommendations"] = [];
    if (best) {
      recommendations.push({
        agent: "exploit.msf_module",
        reason: `MSF search "${q}" found ${best} — run check then run if vulnerable`,
        priority: 92,
        args: {
          module: best,
          rhost: input.target.host,
          rport: rport || undefined,
          action: "check"
        }
      });
    }

    return {
      status: "succeeded",
      artifacts: { commands: [planned], stdoutSnippet: snippet(out, 2000) },
      facts: [
        {
          type: "msf_search",
          value: { query: q, modules: list, bestModule: best, totalParsed: all.length },
          source: "msf"
        }
      ],
      findings: [],
      recommendations,
      meta: { approvalId: approval.approvalId, parsed: all.length, bestModule: best }
    };
  }
};
