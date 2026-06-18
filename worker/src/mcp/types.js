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
export const TargetCtxSchema = z.object({
    targetId: z.string().uuid(),
    host: z.string().min(1),
    ip: z.string().optional()
});
export const ToolFactSchema = z.object({
    type: z.string(),
    value: z.union([z.string(), z.number(), z.boolean(), z.record(z.string(), z.any()), z.array(z.any())]),
    source: z.string().optional()
});
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
