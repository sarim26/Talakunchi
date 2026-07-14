/**
 * Execution command writer.
 *
 * After the prompter has produced a specialist-facing instruction string,
 * this module asks an LLM to translate that prose into the structured
 * `args` payload that the already-selected MCP tool understands (per its
 * `argSchema`). It does NOT pick the tool — the manager already did that.
 *
 * Pipeline position:
 *   manager → prompter → executionCommandWriter → server.invoke(tool, args)
 *
 * Contracts:
 *   - Input: chosen tool definition, prompter text, manager intent + args,
 *            run context (target, ports, services, endpoints, wordlists).
 *   - Output: a sanitized record of args plus metadata for telemetry. Manager
 *            args take precedence on conflict; the writer fills missing keys.
 *   - Failure: returns the manager args unchanged with `source: "manager"`
 *              so the orchestrator can still invoke the tool.
 */
import { z } from "zod";
import { env } from "../env.js";
import { chatJSON } from "../llm/ollama.js";
import type { TargetCtx, ToolDefinition, ToolFinding } from "../mcp/types.js";
import { isWordlistAllowed, type WordlistCatalog } from "./wordlists.js";
import { isAllowedWordlistPath, isJunkPasswordWordlist } from "../credSource.js";
import { acceptVhostCandidate, hostnameMatchesScopeEntry, isIpAddress, isScopedIpEngagement, normHost, type WebScanHints, vhostAcceptPolicyFromInput } from "./webTarget.js";

export type ExecutionWriterContext = {
  target: TargetCtx;
  knownPorts: number[];
  knownServices: Array<{ port: number; protocol: string; name?: string; product?: string; version?: string }>;
  discoveredEndpoints: Array<{ url: string; method?: string; status?: number | null; sourceTool?: string }>;
  priorFindings: ToolFinding[];
  wordlistCatalog?: WordlistCatalog;
  webScan?: WebScanHints | null;
  scopeEntries?: string[];
  scopeEnforce?: boolean;
};

function urlHostAllowed(hostname: string, ctx: ExecutionWriterContext): boolean {
  const h = normHost(hostname);
  if (h === normHost(ctx.target.host)) return true;
  const policy = vhostAcceptPolicyFromInput(ctx.target.host, {
    target: { vhost: ctx.target.vhost, name: ctx.target.name },
    context: {
      knownDomains: [],
      scopeEntries: ctx.scopeEntries,
      scopeEnforce: ctx.scopeEnforce,
      webScan: ctx.webScan
    }
  }, ctx.webScan?.cdnDetected ?? false);
  if (isIpAddress(ctx.target.host) && isScopedIpEngagement(policy) && ctx.webScan?.vhost && h === normHost(ctx.webScan.vhost))
    return true;
  if (ctx.scopeEnforce && ctx.scopeEntries?.length && hostnameMatchesScopeEntry(h, ctx.scopeEntries)) return true;
  return acceptVhostCandidate(hostname, policy);
}

export type ExecutionWriterInput = {
  tool: ToolDefinition;
  prompterText: string;
  intentGoal: string;
  managerArgs?: Record<string, unknown>;
  context: ExecutionWriterContext;
  signal?: AbortSignal;
};

export type ExecutionWriterResult = {
  finalArgs: Record<string, unknown>;
  /** The raw args the LLM produced (before merge), for telemetry. */
  draftArgs: Record<string, unknown>;
  /** Where the final args came from. */
  source: "llm" | "manager" | "merged";
  /** Short diagnostic for telemetry (parse errors, fallback reasons). */
  diag?: string;
  modelUsed: string;
};

const DraftSchema = z.object({
  args: z.record(z.string(), z.any()).default({}),
  rationale: z.string().optional()
});

/**
 * Merge writer-drafted args with manager-provided args.
 * Manager wins on conflict — but only after both sides are sanitized
 * (so placeholder hosts like 10.10.10.10 cannot survive from the manager).
 */
function mergeArgs(
  managerArgs: Record<string, unknown> | undefined,
  draftArgs: Record<string, unknown>
): { merged: Record<string, unknown>; source: "manager" | "merged" } {
  const base = { ...(managerArgs ?? {}) };
  let touched = false;
  for (const [k, v] of Object.entries(draftArgs)) {
    if (v === undefined || v === null) continue;
    if (Object.prototype.hasOwnProperty.call(base, k)) continue;
    base[k] = v;
    touched = true;
  }
  return { merged: base, source: touched ? "merged" : "manager" };
}

/** Rewrite obvious LLM placeholder hosts to the engagement target. */
function rewritePlaceholderHost(urlStr: string, targetHost: string): string | null {
  try {
    const u = new URL(urlStr.trim());
    const h = u.hostname.toLowerCase();
    const placeholders = new Set([
      "10.10.10.10",
      "10.0.0.1",
      "192.168.0.1",
      "192.168.1.1",
      "127.0.0.1",
      "localhost",
      "example.com",
      "example.org",
      "target",
      "victim",
      "host"
    ]);
    if (placeholders.has(h) || /^xxx+\./i.test(h)) {
      u.hostname = targetHost;
      return u.href;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Strip any obviously-bogus keys the LLM might invent (e.g. URLs that don't
 * point at this run's target host, wordlists outside the SecLists catalog).
 * Specialists already do their own validation, but trimming here keeps the
 * telemetry honest and avoids burning a tool turn on garbage.
 */
function sanitizeDraft(
  tool: ToolDefinition,
  draft: Record<string, unknown>,
  ctx: ExecutionWriterContext
): { cleaned: Record<string, unknown>; dropped: string[] } {
  const cleaned: Record<string, unknown> = {};
  const dropped: string[] = [];
  const allowedKeys = new Set(Object.keys(tool.argSchema ?? {}));

  for (const [k, v] of Object.entries(draft)) {
    if (allowedKeys.size > 0 && !allowedKeys.has(k)) {
      dropped.push(`${k} (not in argSchema)`);
      continue;
    }
    if (k === "http_targets" && Array.isArray(v)) {
      const ok: string[] = [];
      for (const item of v) {
        if (typeof item !== "string") continue;
        const rewritten = rewritePlaceholderHost(item, ctx.target.host);
        const candidate = rewritten ?? item.trim();
        try {
          const u = new URL(candidate);
          if (!urlHostAllowed(u.hostname, ctx)) {
            dropped.push(`http_targets item (host ${u.hostname} != target ${ctx.target.host})`);
            continue;
          }
          if (u.protocol !== "http:" && u.protocol !== "https:") continue;
          ok.push(u.href);
        } catch {
          dropped.push("http_targets item (invalid URL)");
        }
      }
      if (ok.length) cleaned[k] = ok;
      continue;
    }
    if (k === "urls" && Array.isArray(v)) {
      const ok: string[] = [];
      for (const item of v) {
        if (typeof item !== "string") continue;
        const t = item.trim();
        if (!t) continue;
        if (/^https?:\/\//i.test(t)) {
          const rewritten = rewritePlaceholderHost(t, ctx.target.host);
          const candidate = rewritten ?? t;
          try {
            const u = new URL(candidate);
            if (!urlHostAllowed(u.hostname, ctx)) {
              dropped.push(`urls item (host ${u.hostname} != target ${ctx.target.host})`);
              continue;
            }
            if (u.protocol !== "http:" && u.protocol !== "https:") continue;
            ok.push(u.href);
          } catch {
            dropped.push("urls item (invalid URL)");
          }
          continue;
        }
        if (t.length > 800 || /\s/.test(t) || t.includes("..")) {
          dropped.push("urls item (unsafe or invalid path)");
          continue;
        }
        ok.push(t.startsWith("/") ? t : `/${t}`);
      }
      if (ok.length) cleaned[k] = ok;
      continue;
    }
    if ((k === "url" || k === "targetUrl") && typeof v === "string") {
      const rewritten = rewritePlaceholderHost(v, ctx.target.host);
      const candidate = rewritten ?? v.trim();
      try {
        const u = new URL(candidate);
        if (!urlHostAllowed(u.hostname, ctx)) {
          dropped.push(`${k} (host ${u.hostname} != target ${ctx.target.host})`);
          continue;
        }
        if (u.protocol !== "http:" && u.protocol !== "https:") {
          dropped.push(`${k} (non-http URL)`);
          continue;
        }
        cleaned[k] = u.href;
        if (rewritten) dropped.push(`${k} (rewrote placeholder host → ${ctx.target.host})`);
      } catch {
        dropped.push(`${k} (invalid URL)`);
      }
      continue;
    }
    if (k === "services" && Array.isArray(v)) {
      const out: Record<string, unknown>[] = [];
      for (const item of v) {
        if (!item || typeof item !== "object") continue;
        const o = item as Record<string, unknown>;
        const port = Number(o.port);
        if (!Number.isFinite(port) || port < 1 || port > 65535) continue;
        out.push({
          port,
          ...(typeof o.protocol === "string" ? { protocol: o.protocol } : {}),
          ...(typeof o.name === "string" ? { name: o.name } : {}),
          ...(typeof o.product === "string" ? { product: o.product } : {}),
          ...(typeof o.version === "string" ? { version: o.version } : {})
        });
      }
      if (out.length) cleaned[k] = out;
      continue;
    }
    if ((k === "wordlist" || k === "userlist" || k === "passlist") && typeof v === "string") {
      const ok =
        (ctx.wordlistCatalog && isWordlistAllowed(ctx.wordlistCatalog, v)) || isAllowedWordlistPath(v);
      if (!ok) {
        dropped.push(`${k} (not under allowed wordlist roots)`);
        continue;
      }
      if ((k === "passlist" || k === "wordlist") && isJunkPasswordWordlist(v)) {
        dropped.push(`${k} (vendor/router junk list — e.g. 3bb)`);
        continue;
      }
    }
    cleaned[k] = v;
  }
  return { cleaned, dropped };
}

export async function draftExecutionPayload(input: ExecutionWriterInput): Promise<ExecutionWriterResult> {
  const { tool, prompterText, intentGoal, managerArgs, context, signal } = input;
  const model = env.executionWriterModel;

  const wordlistHints = (() => {
    const cat = context.wordlistCatalog;
    if (!cat?.rootExists) return null;
    const top = (list: { path: string; label: string }[], n = 5) =>
      list.slice(0, n).map((e) => ({ path: e.path, label: e.label }));
    return {
      root: cat.root,
      defaults: cat.defaults,
      webContent: top(cat.byCategory["discovery-web-content"]),
      dnsSubdomains: top(cat.byCategory["discovery-dns"])
    };
  })();

  const schemaKeys = Object.keys(tool.argSchema ?? {});
  const maxTokens = Math.min(2048, 450 + schemaKeys.length * 90);

  const systemMsg = [
    "You are EXECUTION_COMMAND_WRITER for an autonomous penetration-testing pipeline.",
    "The MANAGER has already chosen the tool. The PROMPTER has produced an instruction.",
    "Your only job is to translate that instruction into a JSON `args` object that the chosen tool can execute.",
    "You do NOT output shell commands; each tool maps validated args to its CLI (e.g. katana flags from depth, http_targets, etc.).",
    "",
    "Hard rules:",
    "- Return ONLY a JSON object, no markdown fences, no commentary.",
    `- Tool: ${tool.name}.`,
    `- Tool description: ${tool.description}`,
    `- Tool argSchema (use ONLY these keys): ${JSON.stringify(tool.argSchema ?? {}, null, 0)}`,
    `- Target host MUST equal: ${context.target.host}. Full URLs must use this host; \`urls\` may also use path-only strings (e.g. /uploads/) expanded per args.ports / context.`,
    context.webScan?.vhost
      ? `- CDN/vhost mode: URLs may also use the resolved vhost hostname (${context.webScan.vhost}). Tools connect to ${context.webScan.connectIp ?? context.target.host} with Host: ${context.webScan.vhost}.`
      : "",
    "- If a wordlist is needed, use an absolute path from the SecLists catalog or from engagement wordlist roots on Kali.",
    "- For recon.hydra / exploit.crackmapexec: omit userlist/passlist when engagementCreds or env lists exist. Never use SecLists router defaults (3bb_default-passwords, Default-Credentials/Routers/*).",
    "- Do not invent unknown keys. Omit fields you are unsure about (defaults will apply).",
    "- Do not include a 'tool' or 'name' field; just args.",
    "",
    'Schema: { "args": { ... per argSchema ... }, "rationale": "<one-line why>" }'
  ].join("\n");

  const userMsg = JSON.stringify(
    {
      intentGoal,
      prompterInstruction: prompterText.slice(0, 4000),
      managerArgs: managerArgs ?? {},
      target: { host: context.target.host, ip: context.target.ip ?? null },
      knownPorts: context.knownPorts.slice(0, 40),
      knownServices: context.knownServices.slice(0, 30),
      discoveredEndpoints: context.discoveredEndpoints.slice(-15).map((e) => ({
        url: e.url,
        method: e.method ?? "GET",
        status: e.status ?? null
      })),
      webScan: context.webScan
        ? {
            connectIp: context.webScan.connectIp,
            vhost: context.webScan.vhost,
            cdnDetected: context.webScan.cdnDetected
          }
        : null,
      wordlists: wordlistHints
    },
    null,
    2
  );

  const fallback = (diag: string): ExecutionWriterResult => {
    const { cleaned, dropped } = sanitizeDraft(tool, managerArgs ?? {}, context);
    return {
      finalArgs: cleaned,
      draftArgs: {},
      source: "manager",
      diag: dropped.length ? `${diag}; sanitized manager: ${dropped.join("; ")}` : diag,
      modelUsed: model
    };
  };

  let raw = "";
  try {
    const r = await chatJSON<unknown>({
      model,
      messages: [
        { role: "system", content: systemMsg },
        { role: "user", content: userMsg }
      ],
      temperature: 0.2,
      maxTokens,
      signal
    });
    raw = r.raw ?? "";
    if (r.value === null) {
      return fallback(`No JSON from execution writer (raw len ${raw.length})`);
    }
    const parsed = DraftSchema.safeParse(r.value);
    if (!parsed.success) {
      const msg = parsed.error.errors.slice(0, 4).map((e) => `${e.path.join(".")}: ${e.message}`).join("; ");
      return fallback(`Schema mismatch: ${msg}`);
    }
    const draftSan = sanitizeDraft(tool, parsed.data.args, context);
    const mgrSan = sanitizeDraft(tool, managerArgs ?? {}, context);
    const { merged, source } = mergeArgs(mgrSan.cleaned, draftSan.cleaned);
    const dropped = [...mgrSan.dropped, ...draftSan.dropped];
    return {
      finalArgs: merged,
      draftArgs: parsed.data.args,
      source: source === "manager" && Object.keys(draftSan.cleaned).length > 0 ? "merged" : source,
      diag: dropped.length > 0 ? `Dropped: ${dropped.join("; ")}` : undefined,
      modelUsed: model
    };
  } catch (e) {
    return fallback(`Ollama error: ${(e as Error).message}`);
  }
}

/** True when the tool declares structured `argSchema` keys (execution writer fills args from prompter text). */
export function shouldUseExecutionWriter(tool: ToolDefinition): boolean {
  return Object.keys(tool.argSchema ?? {}).length > 0;
}
