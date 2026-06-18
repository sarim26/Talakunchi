/**
 * Minimal Ollama client used by the MCP recon system.
 *
 * Models are selected per-role (manager/specialist/prompter) by the caller.
 * Two surface methods:
 *  - chat()         streaming-free chat completion (string out)
 *  - chatJSON<T>()  chat completion that demands a JSON object reply
 */
import { env } from "../env.js";
const DEFAULT_BASE = "http://localhost:11434";
function ollamaBaseUrl() {
    return (env.OLLAMA_URL || DEFAULT_BASE).replace(/\/+$/, "");
}
export async function chat(opts) {
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
    let res;
    try {
        res = await fetch(`${ollamaBaseUrl()}/api/chat`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify(body),
            signal: opts.signal
        });
    }
    catch (err) {
        throw new Error(`Ollama request failed (${ollamaBaseUrl()}): ${err.message}`);
    }
    if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new Error(`Ollama HTTP ${res.status}: ${text || res.statusText}`);
    }
    const data = (await res.json());
    const content = String(data.message?.content ?? data.response ?? "").trim();
    return {
        model: opts.model,
        content,
        json: Boolean(opts.json),
        elapsedMs: Date.now() - start
    };
}
/**
 * Strip reasoning-model wrappers before JSON parsing.
 *
 * Reasoning models (DeepSeek-R1, Qwen "thinking" variants, etc.) emit a
 * `<think>...</think>` (or `<reasoning>...</reasoning>`) block before the
 * actual answer. Ollama's `format:"json"` mode does not always suppress it,
 * so we remove it here to keep `safeParseJson` robust.
 */
export function stripModelReasoning(text) {
    if (!text)
        return "";
    return text
        .replace(/[\s\S]*?<\/think>/gi, "")
        .replace(/<reasoning>[\s\S]*?<\/reasoning>/gi, "")
        .trim();
}
/** Tries to parse model output as JSON. Strips reasoning blocks and ```json fences if present. */
export function safeParseJson(text) {
    if (!text)
        return null;
    const cleaned = stripModelReasoning(text)
        .replace(/^```(?:json)?\s*/i, "")
        .replace(/```$/i, "")
        .trim();
    try {
        return JSON.parse(cleaned);
    }
    catch {
        const first = cleaned.indexOf("{");
        const last = cleaned.lastIndexOf("}");
        if (first >= 0 && last > first) {
            try {
                return JSON.parse(cleaned.slice(first, last + 1));
            }
            catch {
                return null;
            }
        }
        return null;
    }
}
export async function chatJSON(opts) {
    const r = await chat({ ...opts, json: true });
    const parsed = safeParseJson(r.content);
    return { value: parsed, raw: r.content, elapsedMs: r.elapsedMs, model: r.model };
}
/** Health check — returns model list available on the local Ollama. */
export async function listModels(signal) {
    const res = await fetch(`${ollamaBaseUrl()}/api/tags`, { signal });
    if (!res.ok)
        throw new Error(`Ollama tags HTTP ${res.status}`);
    const data = (await res.json());
    return (data.models ?? []).map((m) => m.name ?? "").filter(Boolean);
}
