import { z } from "zod";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://localhost:8080";

async function http<T>(path: string, init?: RequestInit, schema?: z.ZodType<T>): Promise<T> {
  const method = (init?.method ?? "GET").toUpperCase();
  const needsBody = method === "POST" || method === "PUT" || method === "PATCH";
  const body = init?.body ?? (needsBody ? "{}" : undefined);
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    method,
    body,
    headers: {
      ...(body !== undefined ? { "content-type": "application/json" } : {}),
      ...(init?.headers ?? {})
    }
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`API ${res.status}: ${text || res.statusText}`);
  }
  const json = (await res.json()) as unknown;
  return schema ? schema.parse(json) : (json as T);
}

export const TargetSchema = z.object({
  id: z.string().uuid(),
  name: z.string(),
  address: z.string(),
  vhost: z.string().nullable().optional(),
  scope: z.array(z.string()).default([]),
  tags: z.array(z.string()),
  owner: z.string().nullable().optional(),
  hydraUserlist: z.string().nullable().optional(),
  hydraPasslist: z.string().nullable().optional(),
  hydraUsername: z.string().nullable().optional(),
  hydraPassword: z.string().nullable().optional(),
  createdAt: z.string().or(z.date())
});
export type Target = z.infer<typeof TargetSchema>;

export const ScanRunSchema = z.object({
  id: z.string().uuid(),
  targetId: z.string().uuid(),
  target: z.object({ name: z.string(), address: z.string() }),
  profile: z.string(),
  status: z.string(),
  cancelRequested: z.boolean().optional(),
  requestedBy: z.string().nullable().optional(),
  startedAt: z.any().optional().nullable(),
  finishedAt: z.any().optional().nullable(),
  createdAt: z.any()
});
export type ScanRun = z.infer<typeof ScanRunSchema>;

export const ScanRunDetailSchema = ScanRunSchema.extend({
  steps: z.array(
    z.object({
      id: z.string().uuid(),
      name: z.string(),
      status: z.string(),
      startedAt: z.any().optional().nullable(),
      finishedAt: z.any().optional().nullable(),
      log: z.string(),
      createdAt: z.any()
    })
  )
});
export type ScanRunDetail = z.infer<typeof ScanRunDetailSchema>;

export const VerificationAttemptSchema = z.object({
  tool: z.string(),
  outcome: z.string(),
  at: z.any(),
  invocationId: z.string().uuid().nullable().optional()
});
export type VerificationAttempt = z.infer<typeof VerificationAttemptSchema>;

export const FindingVerificationSchema = z.object({
  status: z.enum(["confirmed", "unverified", "pending"]),
  confirmedByTools: z.array(z.string()),
  attempts: z.array(VerificationAttemptSchema),
  confidence: z.enum(["low", "medium", "high"]).optional(),
  claimType: z.string().nullable().optional()
});
export type FindingVerification = z.infer<typeof FindingVerificationSchema>;

export const FindingSchema = z.object({
  id: z.string().uuid(),
  title: z.string(),
  severity: z.enum(["info", "low", "medium", "high", "critical"]),
  status: z.string(),
  evidenceRedacted: z.string(),
  firstSeenAt: z.any(),
  lastSeenAt: z.any(),
  target: z.object({ id: z.string().uuid(), name: z.string(), address: z.string() }),
  service: z
    .object({ port: z.number(), protocol: z.string(), name: z.string().nullable() })
    .nullable(),
  verification: FindingVerificationSchema.optional()
});
export type Finding = z.infer<typeof FindingSchema>;

export const FindingEvidenceSchema = z.object({
  id: z.string().uuid(),
  fingerprint: z.string(),
  title: z.string(),
  severity: z.string(),
  claimType: z.string().nullable().optional(),
  verification: FindingVerificationSchema,
  evidence: z.array(
    z.object({
      tool: z.string(),
      status: z.string(),
      evidence: z.string(),
      createdAt: z.any(),
      invocationId: z.string().uuid().nullable().optional()
    })
  )
});
export type FindingEvidenceDetail = z.infer<typeof FindingEvidenceSchema>;

export const ServiceSchema = z.object({
  id: z.string().uuid(),
  targetId: z.string().uuid(),
  port: z.number(),
  protocol: z.string(),
  serviceName: z.string().nullable(),
  product: z.string().nullable(),
  version: z.string().nullable(),
  banner: z.string().nullable(),
  firstSeenAt: z.any(),
  lastSeenAt: z.any()
});
export type Service = z.infer<typeof ServiceSchema>;

export const PipelineConfigSchema = z.object({
  maxConcurrentScans: z.number(),
  requestRatePerMinute: z.number(),
  auditEnabled: z.boolean(),
  allowedWordlists: z.array(z.string()),
  allowedCidrs: z.array(z.string()),
  enforceScope: z.boolean(),
  maxConcurrentAgentRuns: z.number()
});
export type PipelineConfig = z.infer<typeof PipelineConfigSchema>;

export const AuditEventSchema = z.object({
  id: z.string().uuid(),
  actor: z.string(),
  action: z.string(),
  target: z.string().nullable().optional(),
  payload: z.any(),
  createdAt: z.any()
});
export type AuditEvent = z.infer<typeof AuditEventSchema>;

export const ReconAssetSchema = z.object({
  id: z.string().uuid(),
  targetId: z.string().uuid(),
  assetType: z.string(),
  value: z.string(),
  source: z.string(),
  confidence: z.number(),
  metadata: z.any(),
  firstSeenAt: z.any(),
  lastSeenAt: z.any()
});
export type ReconAsset = z.infer<typeof ReconAssetSchema>;

export const ScanMessageSchema = z.object({
  id: z.string().uuid(),
  role: z.enum(["user", "assistant", "system"]),
  content: z.string(),
  createdAt: z.any()
});
export type ScanMessage = z.infer<typeof ScanMessageSchema>;

export async function listTargets() {
  return http("/api/targets", undefined, z.array(TargetSchema));
}

export async function createTarget(input: {
  name: string;
  address: string;
  vhost?: string;
  scope?: string[];
  tags?: string[];
  owner?: string;
  hydraUserlist?: string;
  hydraPasslist?: string;
  hydraUsername?: string;
  hydraPassword?: string;
}) {
  return http("/api/targets", { method: "POST", body: JSON.stringify(input) }, TargetSchema);
}

export async function createScan(input: { targetId: string; profile?: string; requestedBy?: string }) {
  return http(
    "/api/scans",
    { method: "POST", body: JSON.stringify(input) },
    z.object({
      id: z.string().uuid(),
      targetId: z.string().uuid(),
      profile: z.string(),
      status: z.string()
    })
  );
}

export async function listScans() {
  return http("/api/scans", undefined, z.array(ScanRunSchema));
}

export async function getScan(id: string) {
  return http(`/api/scans/${id}`, undefined, ScanRunDetailSchema);
}

export async function listFindings(params?: { targetId?: string; severity?: string; status?: string; verification?: string }) {
  const qp = new URLSearchParams();
  if (params?.targetId) qp.set("targetId", params.targetId);
  if (params?.severity) qp.set("severity", params.severity);
  if (params?.status) qp.set("status", params.status);
  if (params?.verification) qp.set("verification", params.verification);
  const qs = qp.toString() ? `?${qp.toString()}` : "";
  return http(`/api/findings${qs}`, undefined, z.array(FindingSchema));
}

export async function getFindingEvidence(id: string) {
  return http(`/api/findings/${id}/evidence`, undefined, FindingEvidenceSchema);
}

export async function listServices(targetId: string) {
  const qp = new URLSearchParams();
  qp.set("targetId", targetId);
  return http(`/api/services?${qp.toString()}`, undefined, z.array(ServiceSchema));
}

export async function updateFinding(id: string, input: { status?: string; severity?: string }) {
  return http(
    `/api/findings/${id}`,
    { method: "PATCH", body: JSON.stringify(input) },
    z.object({ id: z.string().uuid(), status: z.string(), severity: z.string().optional() })
  );
}

export async function explainFinding(id: string) {
  return http(
    `/api/findings/${id}/explain`,
    { method: "POST", body: "{}" },
    z.object({
      mode: z.string(),
      summary: z.string(),
      whyItMatters: z.string(),
      remediation: z.array(z.string()),
      verification: z.array(z.string()),
      suggestedSeverity: z.enum(["info", "low", "medium", "high", "critical"]).optional()
    })
  );
}

export async function cancelScan(scanRunId: string) {
  return http(
    `/api/scans/${scanRunId}/cancel`,
    { method: "POST", body: "{}" },
    z.object({ ok: z.boolean() })
  );
}

export async function listScanMessages(scanRunId: string) {
  return http(`/api/scans/${scanRunId}/messages`, undefined, z.array(ScanMessageSchema));
}

export async function postScanMessage(input: { scanRunId: string; content: string; resume?: boolean }) {
  return http(
    `/api/scans/${input.scanRunId}/messages`,
    { method: "POST", body: JSON.stringify({ role: "user", content: input.content, resume: input.resume ?? false }) },
    ScanMessageSchema
  );
}

export async function resumeScan(scanRunId: string, note?: string) {
  return http(
    `/api/scans/${scanRunId}/resume`,
    { method: "POST", body: JSON.stringify({ note: note?.trim() || undefined }) },
    z.object({ ok: z.boolean() })
  );
}

export async function requestReset() {
  return http(
    "/api/admin/reset/request",
    { method: "POST", body: "{}" },
    z.object({ code: z.string(), expiresInSeconds: z.number() })
  );
}

export async function confirmReset(code: string) {
  return http(
    "/api/admin/reset/confirm",
    { method: "POST", body: JSON.stringify({ code }) },
    z.object({ ok: z.boolean() })
  );
}

export async function getGraphForTarget(targetId: string) {
  return http(
    `/api/graph/target/${targetId}`,
    undefined,
    z.object({
      target: z.any().nullable(),
      services: z.array(z.any()),
      findings: z.array(z.any()),
      nodes: z.array(z.any()).optional(),
      edges: z
        .array(
          z.object({
            id: z.string(),
            source: z.string(),
            target: z.string()
          })
        )
        .optional()
        .default([])
    })
  );
}

export async function getPipelineConfig() {
  return http("/api/pipeline/config", undefined, PipelineConfigSchema);
}

export async function updatePipelineConfig(input: PipelineConfig) {
  return http("/api/pipeline/config", { method: "PUT", body: JSON.stringify(input) }, PipelineConfigSchema);
}

export async function listAuditEvents(limit = 50) {
  return http(`/api/audit-events?limit=${limit}`, undefined, z.array(AuditEventSchema));
}

export const CommandApprovalSchema = z.object({
  id: z.string().uuid(),
  scanRunId: z.string().uuid().nullable().optional(),
  agentRunId: z.string().uuid().nullable().optional(),
  tool: z.string().nullable().optional(),
  command: z.string(),
  reasoning: z.string().nullable().optional(),
  impact: z.string(),
  status: z.string(),
  decidedBy: z.string().nullable().optional(),
  args: z.any().optional(),
  createdAt: z.any(),
  decidedAt: z.any().nullable().optional()
});
export type CommandApproval = z.infer<typeof CommandApprovalSchema>;

export async function listCommandApprovals(status = "pending") {
  return http(`/api/command-approvals?status=${encodeURIComponent(status)}`, undefined, z.array(CommandApprovalSchema));
}

export async function approveCommand(id: string) {
  return http(`/api/command-approvals/${id}/approve`, { method: "POST" }, z.object({ id: z.string(), status: z.string() }));
}

export async function rejectCommand(id: string) {
  return http(`/api/command-approvals/${id}/reject`, { method: "POST" }, z.object({ id: z.string(), status: z.string() }));
}

export async function listReconAssets(targetId: string) {
  const qp = new URLSearchParams();
  qp.set("targetId", targetId);
  return http(`/api/recon-assets?${qp.toString()}`, undefined, z.array(ReconAssetSchema));
}

// --- Agentic Recon (MCP) ---

export const AgentToolSchema = z.object({
  name: z.string(),
  description: z.string(),
  tags: z.array(z.string()).optional()
});
export type AgentTool = z.infer<typeof AgentToolSchema>;

export const AgentRunSchema = z.object({
  id: z.string().uuid(),
  targetId: z.string().uuid(),
  target: z.object({ id: z.string().uuid(), name: z.string(), address: z.string() }),
  status: z.string(),
  managerModel: z.string(),
  specialistModel: z.string(),
  prompterModel: z.string(),
  maxSteps: z.number(),
  stepsTaken: z.number(),
  invocationCount: z.number(),
  findingCount: z.number(),
  serviceCount: z.number(),
  phase: z.enum(["recon", "exploit"]),
  notes: z.string().nullable().optional(),
  startedAt: z.any().nullable().optional(),
  finishedAt: z.any().nullable().optional(),
  createdAt: z.any()
});
export type AgentRun = z.infer<typeof AgentRunSchema>;

export const AgentInvocationSchema = z.object({
  id: z.string().uuid(),
  tool: z.string(),
  intent: z.string().nullable(),
  args: z.record(z.string(), z.any()),
  status: z.string(),
  envelope: z.any().nullable().optional(),
  log: z.string(),
  startedAt: z.any(),
  finishedAt: z.any().nullable().optional()
});
export type AgentInvocation = z.infer<typeof AgentInvocationSchema>;

export const AgentEventSchema = z.object({
  id: z.string().uuid(),
  invocationId: z.string().uuid().nullable(),
  kind: z.string(),
  payload: z.any(),
  createdAt: z.any()
});
export type AgentEvent = z.infer<typeof AgentEventSchema>;

export async function listAgentTools() {
  return http("/api/agent-tools", undefined, z.array(AgentToolSchema));
}

export async function startAgentRun(input: {
  targetId: string;
  maxSteps?: number;
  notes?: string;
  phase?: "recon" | "exploit";
  initialNmap?: { profile?: "fast" | "targeted" | "deep" | "full"; ports?: number[]; extraArgs?: string };
}) {
  return http(
    "/api/agent-runs",
    { method: "POST", body: JSON.stringify(input) },
    z.object({ id: z.string().uuid(), status: z.string(), phase: z.enum(["recon", "exploit"]).optional() })
  );
}

export async function listAgentRuns(params?: { targetId?: string; limit?: number }) {
  const qp = new URLSearchParams();
  if (params?.targetId) qp.set("targetId", params.targetId);
  if (params?.limit) qp.set("limit", String(params.limit));
  const qs = qp.toString() ? `?${qp.toString()}` : "";
  return http(`/api/agent-runs${qs}`, undefined, z.array(AgentRunSchema));
}

export async function cancelAgentRun(id: string) {
  return http(`/api/agent-runs/${id}/cancel`, { method: "POST", body: "{}" }, z.object({ ok: z.boolean() }));
}

export async function startExploitPhase(id: string, maxSteps = 8) {
  return http(
    `/api/agent-runs/${id}/start-exploit`,
    { method: "POST", body: JSON.stringify({ maxSteps }) },
    z.object({ id: z.string().uuid(), status: z.string(), phase: z.literal("exploit") })
  );
}

export async function restartReconPhase(id: string, maxSteps = 20) {
  return http(
    `/api/agent-runs/${id}/restart-recon`,
    { method: "POST", body: JSON.stringify({ maxSteps }) },
    z.object({ id: z.string().uuid(), status: z.string(), phase: z.literal("recon") })
  );
}

export async function restartExploitPhase(id: string, maxSteps = 8) {
  return http(
    `/api/agent-runs/${id}/restart-exploit`,
    { method: "POST", body: JSON.stringify({ maxSteps }) },
    z.object({ id: z.string().uuid(), status: z.string(), phase: z.literal("exploit") })
  );
}

export async function getAgentRun(id: string) {
  return http(`/api/agent-runs/${id}`, undefined, AgentRunSchema);
}

export async function getAgentRunInvocations(id: string) {
  return http(`/api/agent-runs/${id}/invocations`, undefined, z.array(AgentInvocationSchema));
}

export async function getAgentRunEvents(id: string, since?: string) {
  const qp = new URLSearchParams();
  if (since) qp.set("since", since);
  const qs = qp.toString() ? `?${qp.toString()}` : "";
  return http(`/api/agent-runs/${id}/events${qs}`, undefined, z.array(AgentEventSchema));
}

export const AgentRunSummarySchema = z.object({
  mode: z.string(),
  run: z.object({ id: z.string().uuid(), status: z.string() }).optional(),
  overallRisk: z.enum(["info", "low", "medium", "high", "critical"]),
  headline: z.string(),
  keyExposures: z.array(z.string()),
  prioritizedFixes: z.array(
    z.object({
      priority: z.enum(["p0", "p1", "p2"]),
      recommendation: z.string()
    })
  ),
  whatWeDid: z.array(z.string()),
  verificationSteps: z.array(z.string()),
  error: z.string().optional()
});
export type AgentRunSummary = z.infer<typeof AgentRunSummarySchema>;

export async function explainAgentRun(id: string) {
  return http(`/api/agent-runs/${id}/explain`, { method: "POST", body: "{}" }, AgentRunSummarySchema);
}

export const AgentRunReportSchema = z.object({
  mode: z.string(),
  run: z.object({ id: z.string().uuid(), status: z.string() }).optional(),
  title: z.string(),
  markdown: z.string(),
  error: z.string().optional()
});
export type AgentRunReport = z.infer<typeof AgentRunReportSchema>;

export async function getAgentRunReport(id: string) {
  return http(`/api/agent-runs/${id}/report`, { method: "POST", body: "{}" }, AgentRunReportSchema);
}

