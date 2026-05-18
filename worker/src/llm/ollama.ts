/**
 * Minimal Ollama client used by the MCP recon system.
 *
 * Models are selected per-role (manager/specialist/prompter) by the caller.
 * Two surface methods:
 *  - chat()         streaming-free chat completion (string out)
 *  - chatJSON<T>()  chat completion that demands a JSON object reply
 */
import { env } from "../env.js";

export type ChatRole = "system" | "user" | "assistant";
export type ChatMessage = { role: ChatRole; content: string };

export type ChatOptions = {
  model: string;
  messages: ChatMessage[];
  /** 0..1; lower = more deterministic (default 0.2). */
  temperature?: number;
  /** Force JSON mode where supported (Ollama supports format="json"). */
  json?: boolean;
  /** Hard cap on output tokens (best-effort; Ollama uses num_predict). */
  maxTokens?: number;
  /** Abort signal */
  signal?: AbortSignal;
};

export type ChatResponse = {
  model: string;
  content: string;
  /** True if the request used Ollama's JSON mode. */
  json: boolean;
  /** Total round-trip in ms (client side). */
  elapsedMs: number;
};

const DEFAULT_BASE = "http://localhost:11434";

function ollamaBaseUrl(): string {
  return (env.OLLAMA_URL || DEFAULT_BASE).replace(/\/+$/, "");
}

export async function chat(opts: ChatOptions): Promise<ChatResponse> {
  const start = Date.now();
  const body = {
    model: opts.model,
    messages: opts.messages,
    stream: false,
    format: opts.json ? "json" : undefined,
    options: {
      temperature: opts.temperature ?? 0.2,
      num_predict: opts.maxTokens ?? 1024,
      num_ctx: 8192
    }
  };

  let res: Response;
  try {
    res = await fetch(`${ollamaBaseUrl()}/api/chat`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: opts.signal
    });
  } catch (err) {
    throw new Error(`Ollama request failed (${ollamaBaseUrl()}): ${(err as Error).message}`);
  }

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`Ollama HTTP ${res.status}: ${text || res.statusText}`);
  }

  const data = (await res.json()) as { message?: { content?: string }; response?: string };
  const content = String(data.message?.content ?? data.response ?? "").trim();
  return {
    model: opts.model,
    content,
    json: Boolean(opts.json),
    elapsedMs: Date.now() - start
  };
}

/** Tries to parse model output as JSON. Strips ```json fences if present. */
export function safeParseJson<T = unknown>(text: string): T | null {
  if (!text) return null;
  const cleaned = text
    .replace(/^```(?:json)?\s*/i, "")
    .replace(/```$/i, "")
    .trim();

  try {
    return JSON.parse(cleaned) as T;
  } catch {
    const first = cleaned.indexOf("{");
    const last = cleaned.lastIndexOf("}");
    if (first >= 0 && last > first) {
      try {
        return JSON.parse(cleaned.slice(first, last + 1)) as T;
      } catch {
        return null;
      }
    }
    return null;
  }
}

export async function chatJSON<T = unknown>(opts: ChatOptions): Promise<{ value: T | null; raw: string; elapsedMs: number; model: string }> {
  const r = await chat({ ...opts, json: true });
  const parsed = safeParseJson<T>(r.content);
  return { value: parsed, raw: r.content, elapsedMs: r.elapsedMs, model: r.model };
}

/** Health check — returns model list available on the local Ollama. */
export async function listModels(signal?: AbortSignal): Promise<string[]> {
  const res = await fetch(`${ollamaBaseUrl()}/api/tags`, { signal });
  if (!res.ok) throw new Error(`Ollama tags HTTP ${res.status}`);
  const data = (await res.json()) as { models?: Array<{ name?: string }> };
  return (data.models ?? []).map((m) => m.name ?? "").filter(Boolean);
}
