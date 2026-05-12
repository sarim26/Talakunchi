import { z } from "zod";
import { env } from "../env.js";
import { chatJSON } from "../llm/ollama.js";
import type { ToolEnvelope, ToolFact } from "../mcp/types.js";

const LlmFindingSchema = z.object({
  title: z.string().min(1),
  severity: z.enum(["info", "low", "medium", "high", "critical"]),
  evidence: z.string().min(1),
  fingerprint: z.string().optional()
});

const LlmOutputSchema = z.object({
  findings: z.array(LlmFindingSchema).max(80)
});

export type WebObservation = {
  url: string;
  httpStatus: number | null;
  method?: string | null;
  responseBytes?: number | null;
};

/**
 * Turn `web_path` / `web_url` facts into security findings using the specialist
 * stack LLM (no static keyword lists). Facts remain the source of truth; this
 * only proposes operator-facing findings.
 */
export async function findingsFromWebFactsLlm(opts: {
  tool: string;
  targetHost: string;
  facts: ToolFact[];
  signal?: AbortSignal;
  /** Max observations sent to the model (prioritized). Default 140. */
  maxObservations?: number;
  emitLog?: (s: string) => void;
}): Promise<{
  findings: ToolEnvelope["findings"];
  meta: { modelUsed: string; sentCount: number; inputCount: number; diag?: string };
}> {
  const observations = extractObservations(opts.facts);
  if (observations.length === 0) {
    return { findings: [], meta: { modelUsed: env.webFindingsModel, sentCount: 0, inputCount: 0 } };
  }

  const maxSend = Math.min(opts.maxObservations ?? 140, 200);
  const prioritized = prioritizeObservations(observations).slice(0, maxSend);
  const model = env.webFindingsModel;

  const system = [
    "You are a senior application security analyst reviewing reconnaissance output.",
    "You will receive JSON: an array of HTTP observations (url, httpStatus, optional method/responseBytes) from an automated scanner.",
    "",
    "Task: decide which observations warrant formal security FINDINGS for an enterprise report.",
    "",
    "Rules:",
    "- Output ONLY valid JSON matching: { \"findings\": [ ... ] }.",
    "- Do NOT include markdown fences or commentary outside JSON.",
    "- Do NOT invent URLs, ports, products, or CVEs — only use observations from the input.",
    "- Do NOT provide exploitation steps or payloads.",
    "- Skip noise: generic 200 OK on '/', favicon.ico, robots.txt alone, etc., unless clearly sensitive.",
    "- Observations with null httpStatus are often historical (e.g. Wayback) — still surface notable admin/API paths as informational clues when appropriate.",
    "- Prefer: auth misconfigs (403 on sensitive files), directory listings, admin/login panels, debug/test endpoints,",
    "  source/config backup paths, server-status, graphql/swagger exposure, redirects to sensitive areas, etc.",
    "- severity: use \"info\" for minor; escalate only when impact is clear from the path/status alone.",
    "- Cap at 50 findings; merge duplicates (same URL).",
    "",
    "Each finding object:",
    "- title: short imperative label",
    "- severity: info | low | medium | high | critical",
    "- evidence: one line including URL and HTTP status (and size if present)",
    "- fingerprint: stable id, e.g. \"llm-web|<tool>|<url>|<status>\""
  ].join("\n");

  const user = JSON.stringify(
    {
      tool: opts.tool,
      targetHost: opts.targetHost,
      observations: prioritized
    },
    null,
    2
  );

  try {
    const r = await chatJSON<unknown>({
      model,
      messages: [
        { role: "system", content: system },
        { role: "user", content: user }
      ],
      temperature: 0.15,
      maxTokens: 3600,
      signal: opts.signal
    });

    if (r.value === null) {
      opts.emitLog?.(`[web-findings-llm] no JSON from model (raw len ${r.raw?.length ?? 0})`);
      return {
        findings: [],
        meta: {
          modelUsed: model,
          sentCount: prioritized.length,
          inputCount: observations.length,
          diag: "LLM returned no parseable JSON for web findings"
        }
      };
    }

    const parsed = LlmOutputSchema.safeParse(r.value);
    if (!parsed.success) {
      opts.emitLog?.(`[web-findings-llm] schema mismatch: ${parsed.error.message}`);
      return {
        findings: [],
        meta: {
          modelUsed: model,
          sentCount: prioritized.length,
          inputCount: observations.length,
          diag: parsed.error.issues.slice(0, 3).map((e) => `${e.path.join(".")}: ${e.message}`).join("; ")
        }
      };
    }

    const urlPool = prioritized.map((o) => o.url);
    const out: ToolEnvelope["findings"] = [];
    const seenFp = new Set<string>();

    for (const f of parsed.data.findings) {
      const matchedUrl = longestUrlContainedIn(f.evidence, urlPool);
      if (!matchedUrl) continue;

      const fp =
        f.fingerprint?.trim() ||
        `llm-web|${opts.tool}|${matchedUrl}|${f.severity}`;
      if (seenFp.has(fp)) continue;
      seenFp.add(fp);

      out.push({
        title: f.title,
        severity: f.severity,
        evidence: f.evidence,
        fingerprint: fp,
        confidence: "medium",
        requiresVerification: true,
        claimType: "web_path_llm"
      });
    }

    return {
      findings: out,
      meta: { modelUsed: model, sentCount: prioritized.length, inputCount: observations.length }
    };
  } catch (e) {
    opts.emitLog?.(`[web-findings-llm] ${(e as Error).message}`);
    return {
      findings: [],
      meta: {
        modelUsed: model,
        sentCount: prioritized.length,
        inputCount: observations.length,
        diag: (e as Error).message
      }
    };
  }
}

function extractObservations(facts: ToolFact[]): WebObservation[] {
  const out: WebObservation[] = [];
  for (const f of facts) {
    if (f.type !== "web_path" && f.type !== "web_url") continue;
    const v = (f.value ?? {}) as Record<string, unknown>;
    const url = typeof v.url === "string" ? v.url.trim() : "";
    if (!url) continue;
    const httpStatus =
      typeof v.status === "number"
        ? (v.status as number)
        : v.status === null || v.status === undefined
          ? null
          : Number(v.status);
    const method = typeof v.method === "string" ? v.method : null;
    const responseBytes = typeof v.length === "number" ? v.length : null;
    out.push({
      url,
      httpStatus: Number.isFinite(httpStatus as number) ? (httpStatus as number) : null,
      method,
      responseBytes
    });
  }
  return dedupeObservations(out);
}

function longestUrlContainedIn(evidence: string, urls: string[]): string | null {
  let best: string | null = null;
  for (const u of urls) {
    if (!evidence.includes(u)) continue;
    if (!best || u.length > best.length) best = u;
  }
  return best;
}

function dedupeObservations(rows: WebObservation[]): WebObservation[] {
  const m = new Map<string, WebObservation>();
  for (const r of rows) {
    const k = `${r.url}|${r.httpStatus ?? "null"}|${r.method ?? ""}`;
    if (!m.has(k)) m.set(k, r);
  }
  return [...m.values()];
}

function statusRank(s: number | null): number {
  if (s === null) return 50;
  if (s === 403 || s === 401) return 0;
  if (s >= 500) return 1;
  if (s === 405 || s === 400) return 2;
  if (s === 200) return 3;
  if (s === 301 || s === 302 || s === 307 || s === 308) return 4;
  if (s === 204) return 8;
  return 6;
}

function prioritizeObservations(rows: WebObservation[]): WebObservation[] {
  return [...rows].sort((a, b) => {
    const ra = statusRank(a.httpStatus);
    const rb = statusRank(b.httpStatus);
    if (ra !== rb) return ra - rb;
    return b.url.length - a.url.length;
  });
}
