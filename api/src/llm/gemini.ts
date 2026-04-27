import { GoogleGenerativeAI } from "@google/generative-ai";

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

export type SurfaceInput = {
  targetName: string;
  targetAddress: string;
  services: Array<{
    port: number;
    protocol: string;
    serviceName: string | null;
    product: string | null;
    version: string | null;
  }>;
};

export type SurfaceOutput = {
  summary: string;
  keyRisks: string[];
  topExposures: Array<{ port: number; protocol: string; risk: "low" | "medium" | "high" | "critical"; reason: string }>;
  remediation: string[];
  verification: string[];
};

export async function explainWithGemini(opts: {
  apiKey: string;
  model: string;
  input: ExplainInput;
}): Promise<ExplainOutput> {
  const client = new GoogleGenerativeAI(opts.apiKey);
  const candidates = [
    opts.model,
    // Some environments require fully qualified names.
    opts.model.startsWith("models/") ? opts.model : `models/${opts.model}`
  ];

  const prompt = [
    "You are assisting an internal security team. Summarize the finding and provide remediation guidance.",
    "Constraints:",
    "- Do NOT provide exploitation steps, payloads, or instructions to break into systems.",
    "- Use only the provided data; do not invent ports, products, or versions.",
    "- Keep it concise and actionable.",
    "",
    "Return STRICT JSON with this shape:",
    "{",
    '  "summary": string,',
    '  "whyItMatters": string,',
    '  "remediation": string[],',
    '  "verification": string[],',
    '  "suggestedSeverity": "info" | "low" | "medium" | "high" | "critical" (optional)',
    "}",
    "",
    "Finding data:",
    JSON.stringify(opts.input, null, 2)
  ].join("\n");

  let lastErr: unknown = null;
  let text: string | null = null;
  for (const m of candidates) {
    try {
      const model = client.getGenerativeModel({
        model: m,
        generationConfig: {
          temperature: 0.2,
          maxOutputTokens: 600
        }
      });
      const resp = await model.generateContent(prompt);
      text = resp.response.text();
      break;
    } catch (e) {
      lastErr = e;
    }
  }
  if (!text) {
    throw lastErr instanceof Error ? lastErr : new Error(String(lastErr));
  }

  // Extract JSON robustly (model sometimes wraps in ```json ... ```).
  const jsonText = text
    .replace(/```json\s*/i, "```")
    .replace(/```/g, "")
    .trim();

  let parsed: any;
  try {
    parsed = JSON.parse(jsonText);
  } catch {
    // Fallback: return a safe plain mapping.
    return {
      summary: text.slice(0, 600),
      whyItMatters: "AI returned non-JSON output; review the summary and verify against evidence.",
      remediation: ["Review service exposure and apply least-privilege network access.", "Patch and harden configuration."],
      verification: ["Re-run the scan and confirm the finding no longer appears."]
    };
  }

  return {
    summary: String(parsed.summary ?? ""),
    whyItMatters: String(parsed.whyItMatters ?? ""),
    remediation: Array.isArray(parsed.remediation) ? parsed.remediation.map(String) : [],
    verification: Array.isArray(parsed.verification) ? parsed.verification.map(String) : [],
    suggestedSeverity: ["info", "low", "medium", "high", "critical"].includes(parsed.suggestedSeverity)
      ? parsed.suggestedSeverity
      : undefined
  };
}

export async function summarizeSurfaceWithGemini(opts: {
  apiKey: string;
  model: string;
  input: SurfaceInput;
}): Promise<SurfaceOutput> {
  const client = new GoogleGenerativeAI(opts.apiKey);
  const candidates = [
    opts.model,
    opts.model.startsWith("models/") ? opts.model : `models/${opts.model}`
  ];

  const prompt = [
    "You are assisting an internal security team. Summarize the exposed attack surface from open ports/services.",
    "Constraints:",
    "- Do NOT provide exploitation steps, payloads, or instructions to break into systems.",
    "- Use only the provided data; do not invent services or ports.",
    "- Keep it concise and actionable for remediation planning.",
    "",
    "Return STRICT JSON with this shape:",
    "{",
    '  "summary": string,',
    '  "keyRisks": string[],',
    '  "topExposures": [{ "port": number, "protocol": string, "risk": "low"|"medium"|"high"|"critical", "reason": string }],',
    '  "remediation": string[],',
    '  "verification": string[]',
    "}",
    "",
    "Surface data:",
    JSON.stringify(opts.input, null, 2)
  ].join("\n");

  let lastErr: unknown = null;
  let text: string | null = null;
  for (const m of candidates) {
    try {
      const model = client.getGenerativeModel({
        model: m,
        generationConfig: { temperature: 0.2, maxOutputTokens: 700 }
      });
      const resp = await model.generateContent(prompt);
      text = resp.response.text();
      break;
    } catch (e) {
      lastErr = e;
    }
  }
  if (!text) throw lastErr instanceof Error ? lastErr : new Error(String(lastErr));

  const jsonText = text.replace(/```json\s*/i, "```").replace(/```/g, "").trim();
  let parsed: any;
  try {
    parsed = JSON.parse(jsonText);
  } catch {
    return {
      summary: text.slice(0, 800),
      keyRisks: ["AI returned non-JSON output; review manually."],
      topExposures: [],
      remediation: ["Restrict exposure to required subnets only.", "Patch/harden services."],
      verification: ["Re-run the scan and confirm exposure is reduced."]
    };
  }

  const top = Array.isArray(parsed.topExposures) ? parsed.topExposures : [];
  return {
    summary: String(parsed.summary ?? ""),
    keyRisks: Array.isArray(parsed.keyRisks) ? parsed.keyRisks.map(String) : [],
    topExposures: top
      .map((x: any) => ({
        port: Number(x.port),
        protocol: String(x.protocol),
        risk: ["low", "medium", "high", "critical"].includes(x.risk) ? x.risk : "low",
        reason: String(x.reason ?? "")
      }))
      .filter((x: any) => Number.isFinite(x.port) && x.protocol),
    remediation: Array.isArray(parsed.remediation) ? parsed.remediation.map(String) : [],
    verification: Array.isArray(parsed.verification) ? parsed.verification.map(String) : []
  };
}

