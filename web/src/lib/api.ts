import { z } from "zod";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://localhost:8080";

async function http<T>(path: string, init?: RequestInit, schema?: z.ZodType<T>): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      "content-type": "application/json",
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
  tags: z.array(z.string()),
  owner: z.string().nullable().optional(),
  createdAt: z.string().or(z.date())
});
export type Target = z.infer<typeof TargetSchema>;

export const ScanRunSchema = z.object({
  id: z.string().uuid(),
  targetId: z.string().uuid(),
  target: z.object({ name: z.string(), address: z.string() }),
  profile: z.string(),
  status: z.string(),
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
    .nullable()
});
export type Finding = z.infer<typeof FindingSchema>;

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
  allowedWordlists: z.array(z.string())
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

export async function listTargets() {
  return http("/api/targets", undefined, z.array(TargetSchema));
}

export async function createTarget(input: { name: string; address: string; tags?: string[]; owner?: string }) {
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

export async function listFindings(params?: { targetId?: string; severity?: string; status?: string }) {
  const qp = new URLSearchParams();
  if (params?.targetId) qp.set("targetId", params.targetId);
  if (params?.severity) qp.set("severity", params.severity);
  if (params?.status) qp.set("status", params.status);
  const qs = qp.toString() ? `?${qp.toString()}` : "";
  return http(`/api/findings${qs}`, undefined, z.array(FindingSchema));
}

export async function listServices(targetId: string) {
  const qp = new URLSearchParams();
  qp.set("targetId", targetId);
  return http(`/api/services?${qp.toString()}`, undefined, z.array(ServiceSchema));
}

export async function explainSurface(targetId: string) {
  return http(
    `/api/targets/${targetId}/explain-surface`,
    { method: "POST", body: "{}" },
    z.object({
      mode: z.string(),
      summary: z.string(),
      keyRisks: z.array(z.string()),
      topExposures: z.array(
        z.object({
          port: z.number(),
          protocol: z.string(),
          risk: z.enum(["low", "medium", "high", "critical"]),
          reason: z.string()
        })
      ),
      remediation: z.array(z.string()),
      verification: z.array(z.string())
    })
  );
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
      target: z.any(),
      services: z.array(z.any()),
      findings: z.array(z.any()),
      nodes: z.array(z.any()).optional(),
      edges: z.array(
        z.object({
          id: z.string(),
          source: z.string(),
          target: z.string()
        })
      )
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

export async function listReconAssets(targetId: string) {
  const qp = new URLSearchParams();
  qp.set("targetId", targetId);
  return http(`/api/recon-assets?${qp.toString()}`, undefined, z.array(ReconAssetSchema));
}

export async function createExploitRun(input: { scanRunId?: string; targetId?: string; requestedBy?: string }) {
  return http(
    "/api/exploit-runs",
    { method: "POST", body: JSON.stringify(input) },
    z.object({ scanRunId: z.string().uuid(), status: z.string() })
  );
}

