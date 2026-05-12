/**
 * Local MCP-style types.
 *
 * We use an in-process MCP server because all specialist agents run inside the
 * worker container and execute tools over the existing SSH bastion. The shapes
 * mirror the real MCP tool contract (name + JSON Schema + handler) so that
 * specialists can later be split into separate MCP servers without rewriting
 * the manager.
 */
import { z } from "zod";

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export const TargetCtxSchema = z.object({
  targetId: z.string().uuid(),
  host: z.string().min(1),
  ip: z.string().optional()
});
export type TargetCtx = z.infer<typeof TargetCtxSchema>;

export const ToolFactSchema = z.object({
  type: z.string(),
  value: z.union([z.string(), z.number(), z.boolean(), z.record(z.string(), z.any()), z.array(z.any())]),
  source: z.string().optional()
});
export type ToolFact = z.infer<typeof ToolFactSchema>;

export const ToolFindingSchema = z.object({
  title: z.string().min(1),
  severity: z.enum(["info", "low", "medium", "high", "critical"]),
  port: z.number().int().nullable().optional(),
  protocol: z.string().nullable().optional(),
  evidence: z.string().default(""),
  fingerprint: z.string().optional(),
  /**
   * Confidence the emitting tool has in the claim itself.
   * - "high"   = output is intrinsically definitive (e.g. cert returned, banner returned)
   * - "medium" = default; benefits from a second tool corroborating it
   * - "low"    = inferred/heuristic, prefer to verify before reporting upward
   */
  confidence: z.enum(["low", "medium", "high"]).optional(),
  /**
   * If false, this finding is considered confirmed immediately
   * (Situation 2: inherently high-confidence). Defaults to true when
   * confidence is not "high".
   */
  requiresVerification: z.boolean().optional(),
  /**
   * When set, this finding corroborates another finding identified by its
   * fingerprint (Situation 1: gold-standard verification). The orchestrator
   * uses this to promote the original finding to "confirmed".
   */
  verifiesFingerprint: z.string().optional(),
  /** Optional normalised claim key (e.g. "open_port", "http_reachable"). */
  claimType: z.string().optional()
});
export type ToolFinding = z.infer<typeof ToolFindingSchema>;

export const ToolRecommendationSchema = z.object({
  agent: z.string(),
  reason: z.string(),
  priority: z.number().int().min(0).max(100).default(50),
  intent: z.string().optional(),
  /**
   * Optional structured args the recommendation wants the next invocation to use.
   * The manager forwards these through to the next ManagerDecision so that, for
   * example, `system.tool_installer` knows which tool it should install.
   */
  args: z.record(z.string(), z.any()).optional()
});
export type ToolRecommendation = z.infer<typeof ToolRecommendationSchema>;

export const ToolEnvelopeSchema = z.object({
  status: z.enum(["succeeded", "failed", "partial", "skipped"]),
  durationMs: z.number().int().nonnegative().optional(),
  facts: z.array(ToolFactSchema).default([]),
  findings: z.array(ToolFindingSchema).default([]),
  recommendations: z.array(ToolRecommendationSchema).default([]),
  artifacts: z
    .object({
      commands: z.array(z.string()).default([]),
      stdoutSnippet: z.string().optional(),
      stderrSnippet: z.string().optional()
    })
    .default({ commands: [] }),
  meta: z.record(z.string(), z.any()).default({}),
  error: z.string().optional()
});
export type ToolEnvelope = z.infer<typeof ToolEnvelopeSchema>;

export type ToolInput = {
  /** Target this invocation is bound to. */
  target: TargetCtx;
  /** Caller-provided English instruction (from the prompter). */
  intent?: string;
  /** Free-form, structured arguments understood by the specific tool. */
  args?: Record<string, unknown>;
  /** Manager-supplied facts accumulated so far. */
  context?: {
    knownPorts?: number[];
    knownServices?: Array<{ port: number; protocol: string; name?: string; product?: string; version?: string }>;
    knownDomains?: string[];
    priorFindings?: ToolFinding[];
    /** URLs accumulated by the orchestrator for planners and web tools. */
    discoveredEndpoints?: Array<{ url: string; method?: string; status?: number | null; sourceTool?: string }>;
    /** Optional last remote shell outcome (reserved for future tools). */
    lastKaliShell?: {
      exitCode: number | null;
      commandPreview?: string;
      stdoutSnippet?: string;
      stderrSnippet?: string;
    };
    runId: string;
    invocationId: string;
  };
  /** Hard cap; tool implementations should respect this. */
  timeoutMs?: number;
  signal?: AbortSignal;
};

export type ToolHandler = (input: ToolInput, emit: ToolEmitter) => Promise<ToolEnvelope>;

export type ToolEmitter = {
  /** Append a streaming log line for the live monitor. */
  log: (msg: string) => void;
  /** Add an in-progress fact (e.g. "found service" mid-scan). */
  fact: (fact: ToolFact) => void;
};

export type ToolDefinition = {
  /** Stable id, e.g. "recon.nmap" (also used as MCP tool name). */
  name: string;
  /** Short human description used by the manager + UI. */
  description: string;
  /** JSON-schema-like documentation for `args` (informational only). */
  argSchema?: Record<string, unknown>;
  /** Hint to the manager about preconditions ("requires services" etc.). */
  requires?: Array<"target" | "services" | "domains" | "http_targets" | "tls_targets">;
  /** Default per-call timeout. */
  defaultTimeoutMs?: number;
  /** Capability tags for grouping in UI. */
  tags?: string[];
  handler: ToolHandler;
};

export type ToolRegistration = {
  definition: ToolDefinition;
};
