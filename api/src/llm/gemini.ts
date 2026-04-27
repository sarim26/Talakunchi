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

