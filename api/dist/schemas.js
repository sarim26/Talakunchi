import { z } from "zod";
export const CreateTargetSchema = z.object({
    name: z.string().min(1),
    address: z.string().min(1),
    tags: z.array(z.string()).optional().default([]),
    owner: z.string().optional()
});
export const CreateScanSchema = z.object({
    targetId: z.string().uuid(),
    profile: z.string().optional().default("network_surface_safe"),
    requestedBy: z.string().optional().default("demo")
});
export const UpdateFindingSchema = z.object({
    status: z
        .enum([
        "open",
        "triaged",
        "in_progress",
        "fixed",
        "verified",
        "false_positive",
        "accepted_risk"
    ])
        .optional(),
    severity: z.enum(["info", "low", "medium", "high", "critical"]).optional()
});
export const PipelineConfigSchema = z.object({
    maxConcurrentScans: z.coerce.number().int().positive().max(100).default(2),
    requestRatePerMinute: z.coerce.number().int().positive().max(5000).default(120),
    safeMode: z.coerce.boolean().default(true),
    requireHumanApproval: z.coerce.boolean().default(false),
    auditEnabled: z.coerce.boolean().default(true),
    allowedWordlists: z.array(z.string()).default([])
});
