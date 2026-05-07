/**
 * API-side Ollama client.
 *
 * Used by the /api/findings/:id/explain endpoint (formerly Gemini-backed).
 * Same JSON-mode pattern as the worker client; no streaming required for
 * single-shot summaries.
 */
import { env } from "../env.js";

export type ExplainInput = {
  title: string;
  severity: string;
  targetName: string;
  targetAddress: string;
  service: null | { port: number; protocol: string; name: string | null };
  evidenceRedacted: string;
};

export type ExplainOutput = {
  summary: string;
  whyItMatters: string;
  remediation: string[];
  verification: string[];
  suggestedSeverity?: "info" | "low" | "medium" | "high" | "critical";
};

function ollamaBase() {
  return (env.OLLAMA_URL || "http://localhost:11434").replace(/\/+$/, "");
}

function safeParseJson<T>(text: string): T | null {
  if (!text) return null;
  const cleaned = text
    .replace(/^```(?:json)?\s*/i, "")
    .replace(/```$/i, "")
    .trim();
  try {
    return JSON.parse(cleaned) as T;
  } catch {
    const a = cleaned.indexOf("{");
    const b = cleaned.lastIndexOf("}");
    if (a >= 0 && b > a) {
      try {
        return JSON.parse(cleaned.slice(a, b + 1)) as T;
      } catch {
        return null;
      }
    }
    return null;
  }
}

export async function explainWithOllama(input: ExplainInput): Promise<ExplainOutput> {
  const system = [
    "You are assisting an internal security team. Summarise the finding and provide remediation guidance.",
    "Constraints:",
    "- Do NOT provide exploitation steps, payloads, or instructions to break into systems.",
    "- Use only the provided data; do not invent ports, products, or versions.",
    "- Keep it concise and actionable.",
    "",
    "Return ONLY a JSON object of this shape:",
    "{",
    '  "summary": string,',
    '  "whyItMatters": string,',
    '  "remediation": string[],',
    '  "verification": string[],',
    '  "suggestedSeverity": "info" | "low" | "medium" | "high" | "critical" (optional)',
    "}"
  ].join("\n");

  const user = `Finding data:\n${JSON.stringify(input, null, 2)}`;

  const body = {
    model: env.OLLAMA_EXPLAIN_MODEL,
    messages: [
      { role: "system", content: system },
      { role: "user", content: user }
    ],
    format: "json",
    stream: false,
    options: { temperature: 0.2, num_predict: 700 }
  };

  let res: Response;
  try {
    res = await fetch(`${ollamaBase()}/api/chat`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body)
    });
  } catch (err) {
    throw new Error(`Ollama request failed (${ollamaBase()}): ${(err as Error).message}`);
  }
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`Ollama HTTP ${res.status}: ${text || res.statusText}`);
  }
  const data = (await res.json()) as { message?: { content?: string }; response?: string };
  const content = String(data.message?.content ?? data.response ?? "").trim();
  const parsed = safeParseJson<{
    summary?: unknown;
    whyItMatters?: unknown;
    remediation?: unknown;
    verification?: unknown;
    suggestedSeverity?: unknown;
  }>(content);

  if (!parsed) {
    return {
      summary: content.slice(0, 600) || "AI returned no parseable summary.",
      whyItMatters: "AI returned non-JSON output; review the summary and verify against evidence.",
      remediation: ["Review service exposure and apply least-privilege network access.", "Patch and harden configuration."],
      verification: ["Re-run the scan and confirm the finding no longer appears."]
    };
  }
  return {
    summary: String(parsed.summary ?? ""),
    whyItMatters: String(parsed.whyItMatters ?? ""),
    remediation: Array.isArray(parsed.remediation) ? (parsed.remediation as unknown[]).map(String) : [],
    verification: Array.isArray(parsed.verification) ? (parsed.verification as unknown[]).map(String) : [],
    suggestedSeverity:
      typeof parsed.suggestedSeverity === "string" && ["info", "low", "medium", "high", "critical"].includes(parsed.suggestedSeverity)
        ? (parsed.suggestedSeverity as ExplainOutput["suggestedSeverity"])
        : undefined
  };
}

export async function listOllamaModels(): Promise<string[]> {
  const res = await fetch(`${ollamaBase()}/api/tags`);
  if (!res.ok) throw new Error(`Ollama tags HTTP ${res.status}`);
  const data = (await res.json()) as { models?: Array<{ name?: string }> };
  return (data.models ?? []).map((m) => m.name ?? "").filter(Boolean);
}

/* ------------------------------------------------------------------ *
 *  Run-level (scan-level) summary
 * ------------------------------------------------------------------ */

export type RunSummaryInput = {
  target: { name: string; address: string };
  status: string;
  steps: number;
  invocationCount: number;
  findingCount: number;
  serviceCount: number;
  /** Top tools that ran during the scan (for "what we did" section). */
  toolsUsed: Array<{ tool: string; status: string; durationMs: number | null; commandSnippet: string | null }>;
  /** Compact list of services discovered. */
  services: Array<{ port: number; protocol: string; name?: string | null; product?: string | null; version?: string | null }>;
  /** Subset of findings, sorted by severity desc. */
  findings: Array<{ title: string; severity: string; evidence?: string | null }>;
  /** Manager decisions trace (compact). */
  decisions: Array<{ step: number; tool?: string; intent?: string; reasoning?: string; reason?: string }>;
};

export type RunSummaryOutput = {
  overallRisk: "info" | "low" | "medium" | "high" | "critical";
  headline: string;
  keyExposures: string[];
  prioritizedFixes: Array<{ priority: "p0" | "p1" | "p2"; recommendation: string }>;
  whatWeDid: string[];
  verificationSteps: string[];
};

export async function summariseAgentRunWithOllama(input: RunSummaryInput): Promise<RunSummaryOutput> {
  const system = [
    "You are an autonomous penetration testing assistant generating a SCAN-LEVEL executive summary.",
    "Audience: a security analyst / engineering lead. Be terse, factual, and actionable.",
    "Constraints:",
    "- Do NOT provide exploitation steps, payloads, or attacker tradecraft.",
    "- Only use the data the operator hands you. Do not fabricate ports, products, versions, or vulnerabilities.",
    "- Treat unknowns as unknowns.",
    "",
    "Return ONLY a single JSON object with this exact shape:",
    "{",
    '  "overallRisk": "info" | "low" | "medium" | "high" | "critical",',
    '  "headline": string,',
    '  "keyExposures": string[],',
    '  "prioritizedFixes": [{ "priority": "p0" | "p1" | "p2", "recommendation": string }, ...],',
    '  "whatWeDid": string[],',
    '  "verificationSteps": string[]',
    "}"
  ].join("\n");

  const compact = {
    target: input.target,
    status: input.status,
    steps: input.steps,
    counts: {
      invocations: input.invocationCount,
      findings: input.findingCount,
      services: input.serviceCount
    },
    services: input.services.slice(0, 40),
    findings: input.findings.slice(0, 60),
    toolsUsed: input.toolsUsed.slice(0, 30),
    decisions: input.decisions.slice(-30)
  };
  const user = `Scan data:\n${JSON.stringify(compact, null, 2)}`;

  const body = {
    model: env.OLLAMA_EXPLAIN_MODEL,
    messages: [
      { role: "system", content: system },
      { role: "user", content: user }
    ],
    format: "json",
    stream: false,
    options: { temperature: 0.2, num_predict: 1100 }
  };

  let res: Response;
  try {
    res = await fetch(`${ollamaBase()}/api/chat`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body)
    });
  } catch (err) {
    throw new Error(`Ollama request failed (${ollamaBase()}): ${(err as Error).message}`);
  }
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`Ollama HTTP ${res.status}: ${text || res.statusText}`);
  }
  const data = (await res.json()) as { message?: { content?: string }; response?: string };
  const content = String(data.message?.content ?? data.response ?? "").trim();
  const parsed = safeParseJson<Record<string, unknown>>(content);

  const fallbackHeadline = `${input.target.name || input.target.address}: ${input.findingCount} findings across ${input.serviceCount} services in ${input.invocationCount} agent steps.`;

  if (!parsed) {
    return {
      overallRisk: pickOverallRisk(input.findings),
      headline: fallbackHeadline,
      keyExposures: input.findings.slice(0, 5).map((f) => `${f.severity.toUpperCase()}: ${f.title}`),
      prioritizedFixes: [
        { priority: "p1", recommendation: "Patch and harden services flagged with high/critical findings." },
        { priority: "p2", recommendation: "Review network exposure of all listening services." }
      ],
      whatWeDid: input.toolsUsed.slice(0, 8).map((t) => `${t.tool} (${t.status})`),
      verificationSteps: ["Re-run the agentic recon and confirm findings disappear or are downgraded."]
    };
  }

  const sev = ["info", "low", "medium", "high", "critical"];
  const risk = sev.includes(String(parsed.overallRisk))
    ? (String(parsed.overallRisk) as RunSummaryOutput["overallRisk"])
    : pickOverallRisk(input.findings);

  const fixes = Array.isArray(parsed.prioritizedFixes)
    ? (parsed.prioritizedFixes as unknown[]).map((f) => {
        const o = (f && typeof f === "object" ? f : {}) as Record<string, unknown>;
        const pr = ["p0", "p1", "p2"].includes(String(o.priority)) ? (String(o.priority) as "p0" | "p1" | "p2") : "p2";
        return { priority: pr, recommendation: String(o.recommendation ?? "") };
      })
    : [];

  return {
    overallRisk: risk,
    headline: String(parsed.headline ?? fallbackHeadline),
    keyExposures: Array.isArray(parsed.keyExposures) ? (parsed.keyExposures as unknown[]).map(String) : [],
    prioritizedFixes: fixes,
    whatWeDid: Array.isArray(parsed.whatWeDid) ? (parsed.whatWeDid as unknown[]).map(String) : [],
    verificationSteps: Array.isArray(parsed.verificationSteps) ? (parsed.verificationSteps as unknown[]).map(String) : []
  };
}

function pickOverallRisk(findings: Array<{ severity: string }>): RunSummaryOutput["overallRisk"] {
  const order = ["critical", "high", "medium", "low", "info"] as const;
  for (const lvl of order) if (findings.some((f) => f.severity === lvl)) return lvl;
  return "info";
}
