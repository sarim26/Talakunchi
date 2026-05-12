/**
 * In-process MCP server.
 *
 * Exposes a registry of tools and a typed `invoke()` that the manager (or a
 * future remote MCP client) can call. Every invocation is wrapped in
 * timeout + error capture and emits structured events through the supplied
 * sink so the live monitor UI can show what is happening.
 */
import { ToolDefinition, ToolEnvelope, ToolEnvelopeSchema, ToolInput } from "./types.js";

export type AgentEventSink = {
  invocationStarted: (input: { name: string; intent?: string; args?: unknown }) => Promise<string> | string;
  invocationLog: (invocationId: string, line: string) => Promise<void> | void;
  invocationFact: (invocationId: string, fact: { type: string; value: unknown; source?: string }) => Promise<void> | void;
  invocationFinished: (invocationId: string, envelope: ToolEnvelope) => Promise<void> | void;
};

export class MCPServer {
  private readonly tools = new Map<string, ToolDefinition>();

  register(def: ToolDefinition) {
    if (this.tools.has(def.name)) {
      throw new Error(`MCP tool already registered: ${def.name}`);
    }
    this.tools.set(def.name, def);
  }

  list(): ToolDefinition[] {
    return [...this.tools.values()];
  }

  manifest(): Array<{ name: string; description: string; tags?: string[]; requires?: string[] }> {
    return this.list().map((t) => ({
      name: t.name,
      description: t.description,
      tags: t.tags,
      requires: t.requires
    }));
  }

  /** Compact tool list for planner LLMs (avoids huge prompts from long descriptions). */
  manifestCompact(): Array<{ name: string; requires?: string[]; tags?: string[]; summary: string }> {
    return this.list().map((t) => ({
      name: t.name,
      requires: t.requires,
      tags: t.tags,
      summary: t.description.length > 110 ? `${t.description.slice(0, 107)}…` : t.description
    }));
  }

  has(name: string) {
    return this.tools.has(name);
  }

  /**
   * Invoke a tool with full lifecycle accounting.
   * Always returns a valid envelope (never throws to the caller).
   */
  async invoke(name: string, input: ToolInput, sink: AgentEventSink): Promise<{ invocationId: string; envelope: ToolEnvelope }> {
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
      if (input.signal.aborted) ac.abort();
      else input.signal.addEventListener("abort", () => ac.abort(), { once: true });
    }

    let envelope: ToolEnvelope;
    try {
      const callInput: ToolInput = { ...input, signal: ac.signal };
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
    } catch (err) {
      const aborted = (err as Error)?.name === "AbortError" || /aborted/i.test((err as Error)?.message ?? "");
      envelope = ToolEnvelopeSchema.parse({
        status: aborted ? "failed" : "failed",
        error: aborted ? `Tool timed out after ${timeoutMs}ms` : (err as Error)?.message ?? String(err),
        durationMs: Date.now() - start,
        artifacts: { commands: [] }
      });
    } finally {
      clearTimeout(tid);
    }

    await sink.invocationFinished(invocationId, envelope);
    return { invocationId, envelope };
  }
}

export function createMCPServer(): MCPServer {
  return new MCPServer();
}
