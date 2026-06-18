/**
 * In-process MCP server.
 *
 * Exposes a registry of tools and a typed `invoke()` that the manager (or a
 * future remote MCP client) can call. Every invocation is wrapped in
 * timeout + error capture and emits structured events through the supplied
 * sink so the live monitor UI can show what is happening.
 */
import { ToolEnvelopeSchema } from "./types.js";
export class MCPServer {
    tools = new Map();
    register(def) {
        if (this.tools.has(def.name)) {
            throw new Error(`MCP tool already registered: ${def.name}`);
        }
        this.tools.set(def.name, def);
    }
    list() {
        return [...this.tools.values()];
    }
    manifest() {
        return this.list().map((t) => ({
            name: t.name,
            description: t.description,
            tags: t.tags,
            requires: t.requires
        }));
    }
    /** Compact tool list for planner LLMs (avoids huge prompts from long descriptions). */
    manifestCompact() {
        return this.list().map((t) => ({
            name: t.name,
            requires: t.requires,
            tags: t.tags,
            summary: t.description.length > 110 ? `${t.description.slice(0, 107)}…` : t.description
        }));
    }
    has(name) {
        return this.tools.has(name);
    }
    /**
     * Invoke a tool with full lifecycle accounting.
     * Always returns a valid envelope (never throws to the caller).
     */
    async invoke(name, input, sink) {
        const tool = this.tools.get(name);
        const start = Date.now();
        const invocationId = await sink.invocationStarted({ name, intent: input.intent, args: input.args });
        if (!tool) {
            const envelope = ToolEnvelopeSchema.parse({
                status: "failed",
                error: `Unknown tool: ${name}`,
                artifacts: { commands: [] }
            });
            await sink.invocationFinished(invocationId, envelope);
            return { invocationId, envelope };
        }
        const timeoutMs = input.timeoutMs ?? tool.defaultTimeoutMs ?? 120_000;
        const ac = new AbortController();
        const tid = setTimeout(() => ac.abort(), timeoutMs);
        if (input.signal) {
            if (input.signal.aborted)
                ac.abort();
            else
                input.signal.addEventListener("abort", () => ac.abort(), { once: true });
        }
        let envelope;
        try {
            const callInput = { ...input, signal: ac.signal };
            const raw = await tool.handler(callInput, {
                log: (msg) => {
                    void sink.invocationLog(String(invocationId), msg.endsWith("\n") ? msg : `${msg}\n`);
                },
                fact: (fact) => {
                    void sink.invocationFact(String(invocationId), fact);
                }
            });
            envelope = ToolEnvelopeSchema.parse({
                ...raw,
                durationMs: raw.durationMs ?? Date.now() - start
            });
        }
        catch (err) {
            const aborted = err?.name === "AbortError" || /aborted/i.test(err?.message ?? "");
            envelope = ToolEnvelopeSchema.parse({
                status: aborted ? "failed" : "failed",
                error: aborted ? `Tool timed out after ${timeoutMs}ms` : err?.message ?? String(err),
                durationMs: Date.now() - start,
                artifacts: { commands: [] }
            });
        }
        finally {
            clearTimeout(tid);
        }
        await sink.invocationFinished(invocationId, envelope);
        return { invocationId, envelope };
    }
}
export function createMCPServer() {
    return new MCPServer();
}
