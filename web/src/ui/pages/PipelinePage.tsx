import React from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Divider,
  MenuItem,
  Select,
  Stack,
  Switch,
  Tab,
  TextField,
  Tabs,
  Typography
} from "@mui/material";
import {
  AgentEvent,
  AgentInvocation,
  AgentRun,
  approveCommand,
  cancelAgentRun,
  cancelScan,
  getAgentRun,
  getAgentRunEvents,
  getAgentRunInvocations,
  getPipelineConfig,
  listAgentRuns,
  listAuditEvents,
  listCommandApprovals,
  listFindings,
  listReconAssets,
  listScans,
  listServices,
  listTargets,
  rejectCommand,
  updatePipelineConfig
} from "../../lib/api";

type PipelinePhase = {
  id: number;
  title: string;
  goal: string;
  modules: string[];
  controls: string[];
};

const WORKFLOW_STAGES: PipelinePhase[] = [
  {
    id: 1,
    title: "Scoping & Configuration",
    goal: "Define rates, credentials source, and engagement guardrails.",
    modules: ["scope validator", "audit logger", "rate limiter", "target policy"],
    controls: ["hard abort out-of-scope", "audit log enabled"]
  },
  {
    id: 2,
    title: "Reconnaissance",
    goal: "Build an asset inventory using passive and light active discovery.",
    modules: ["dns enum", "osint connectors", "host discovery", "waf/cdn detect"],
    controls: ["non-destructive mode", "bounded probes", "target-driven scope"]
  },
  {
    id: 3,
    title: "Scanning & Enumeration",
    goal: "Enumerate services/versions and correlate exposure into prioritized findings.",
    modules: ["nmap scan", "cve correlator", "nuclei/openvas hooks", "web crawler"],
    controls: ["service state tracking", "version collection", "priority scoring queue"]
  },
  {
    id: 4,
    title: "Exploitation",
    goal: "Run controlled exploit and credential paths based on ranking.",
    modules: ["hydra", "metasploit", "web exploit adapters"],
    controls: ["rank-based execution", "human approval gate", "job timeout/kill"]
  },
  {
    id: 5,
    title: "Post-Exploitation",
    goal: "Gather session intel and feed discovered assets back into recon.",
    modules: ["privesc checks", "credential harvesting", "lateral discovery"],
    controls: ["session-scoped actions", "loopback to phase 2", "evidence logging"]
  },
  {
    id: 6,
    title: "Reporting",
    goal: "Produce deduplicated, actionable reports and downstream integrations.",
    modules: ["dedupe engine", "report renderer", "mitre mapper", "ticket pushers"],
    controls: ["cvss+context ranking", "remediation guidance", "sync with overview"]
  }
];

export function PipelinePage() {
  const qc = useQueryClient();
  const [activePhase, setActivePhase] = React.useState(0);
  const [targetId, setTargetId] = React.useState("");
  const [draftWordlists, setDraftWordlists] = React.useState("");
  const [draftCidrs, setDraftCidrs] = React.useState("");
  const targetsQ = useQuery({ queryKey: ["targets"], queryFn: listTargets, refetchInterval: 5000 });
  const runsQ = useQuery({ queryKey: ["runs"], queryFn: listScans, refetchInterval: 5000 });
  const findingsQ = useQuery({ queryKey: ["findings", targetId], queryFn: () => listFindings({ targetId: targetId || undefined }), refetchInterval: 5000 });
  const servicesQ = useQuery({
    queryKey: ["services", targetId],
    queryFn: () => listServices(targetId),
    enabled: Boolean(targetId),
    refetchInterval: 5000
  });
  const reconQ = useQuery({
    queryKey: ["recon-assets", targetId],
    queryFn: () => listReconAssets(targetId),
    enabled: Boolean(targetId),
    refetchInterval: 5000
  });
  const pipelineQ = useQuery({ queryKey: ["pipeline-config"], queryFn: getPipelineConfig, refetchInterval: 5000 });
  const auditQ = useQuery({ queryKey: ["audit-events"], queryFn: () => listAuditEvents(12), refetchInterval: 5000 });
  const approvalsQ = useQuery({ queryKey: ["command-approvals"], queryFn: () => listCommandApprovals("pending"), refetchInterval: 4000 });
  const approveM = useMutation({
    mutationFn: approveCommand,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["command-approvals"] })
  });
  const rejectM = useMutation({
    mutationFn: rejectCommand,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["command-approvals"] })
  });
  const cancelScanM = useMutation({
    mutationFn: cancelScan,
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["runs"] });
      await qc.invalidateQueries({ queryKey: ["audit-events"] });
    }
  });

  const saveM = useMutation({
    mutationFn: updatePipelineConfig,
    onSuccess: async (updated) => {
      setConfig(updated);
      await qc.invalidateQueries({ queryKey: ["pipeline-config"] });
      await qc.invalidateQueries({ queryKey: ["audit-events"] });
    }
  });

  const [config, setConfig] = React.useState<null | Awaited<ReturnType<typeof getPipelineConfig>>>(null);
  React.useEffect(() => {
    if (!pipelineQ.data) return;
    setConfig(pipelineQ.data);
    setDraftWordlists(pipelineQ.data.allowedWordlists.join("\n"));
    setDraftCidrs((pipelineQ.data.allowedCidrs ?? []).join("\n"));
  }, [pipelineQ.data]);

  const stage = WORKFLOW_STAGES[activePhase];
  const findings = findingsQ.data ?? [];
  const services = servicesQ.data ?? [];
  const runs = runsQ.data ?? [];
  const openRuns = runs.filter((r) => r.status === "queued" || r.status === "running").length;
  const weakCredFindings = findings.filter((f) => f.title.toLowerCase().includes("credential")).length;
  const saveConfig = async () => {
    if (!config) return;
    const next = {
      ...config,
      allowedWordlists: draftWordlists
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean),
      allowedCidrs: draftCidrs
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean)
    };
    await saveM.mutateAsync(next);
  };

  return (
    <Box>
      <Typography variant="h5" gutterBottom>
        Offensive Pipeline
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Six workflow stages for scoped recon, scanning, exploitation, post-exploitation, and reporting.
      </Typography>

      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Stack direction={{ xs: "column", md: "row" }} spacing={2} alignItems="center">
            <Select value={targetId} onChange={(e) => setTargetId(String(e.target.value))} displayEmpty fullWidth>
              <MenuItem value="">All targets</MenuItem>
              {(targetsQ.data ?? []).map((t) => (
                <MenuItem key={t.id} value={t.id}>
                  {t.name} ({t.address})
                </MenuItem>
              ))}
            </Select>
            <Chip label={`Targets: ${targetsQ.data?.length ?? 0}`} />
            <Chip label={`Runs active: ${openRuns}`} color={openRuns ? "warning" : "default"} />
            <Chip label={`Findings: ${findings.length}`} color={findings.length ? "error" : "default"} />
            <Chip label={`Open ports: ${services.length}`} />
            <Chip label={`Weak creds: ${weakCredFindings}`} color={weakCredFindings ? "error" : "default"} />
          </Stack>
        </CardContent>
      </Card>

      {targetsQ.isError || runsQ.isError || findingsQ.isError || servicesQ.isError || pipelineQ.isError || auditQ.isError || reconQ.isError ? (
        <Alert severity="error" sx={{ mb: 2 }}>
          Failed to load one or more pipeline data sources.
        </Alert>
      ) : null}

      <Card>
        <CardContent>
          <Tabs
            value={activePhase}
            onChange={(_evt, value) => setActivePhase(value)}
            variant="scrollable"
            scrollButtons="auto"
          >
            {WORKFLOW_STAGES.map((p) => (
              <Tab key={p.id} label={`Stage ${p.id}`} />
            ))}
          </Tabs>
          <Divider sx={{ my: 2 }} />

          {stage.id === 1 ? (
            <Box sx={{ mb: 2 }}>
              <Typography variant="subtitle2" sx={{ mb: 1 }}>
                Workflow Runtime Controls
              </Typography>
              {config ? (
                <Stack spacing={2}>
                  <Stack direction={{ xs: "column", md: "row" }} spacing={2}>
                    <TextField
                      label="Max concurrent scans"
                      type="number"
                      value={config.maxConcurrentScans}
                      onChange={(e) => setConfig({ ...config, maxConcurrentScans: Number(e.target.value) || 1 })}
                      fullWidth
                    />
                    <TextField
                      label="Request rate / minute"
                      type="number"
                      value={config.requestRatePerMinute}
                      onChange={(e) => setConfig({ ...config, requestRatePerMinute: Number(e.target.value) || 1 })}
                      fullWidth
                    />
                    <TextField
                      label="Max concurrent agent runs"
                      type="number"
                      value={config.maxConcurrentAgentRuns}
                      onChange={(e) => setConfig({ ...config, maxConcurrentAgentRuns: Number(e.target.value) || 1 })}
                      fullWidth
                    />
                  </Stack>
                  <TextField
                    label="Allowed wordlists (one path per line)"
                    multiline
                    minRows={3}
                    value={draftWordlists}
                    onChange={(e) => setDraftWordlists(e.target.value)}
                    fullWidth
                  />
                  <TextField
                    label="Engagement scope — IPs / CIDRs / hostnames (one per line)"
                    multiline
                    minRows={3}
                    value={draftCidrs}
                    onChange={(e) => setDraftCidrs(e.target.value)}
                    helperText="When enforcement is on, recon runs against targets outside this list are aborted."
                    fullWidth
                  />

                  <Stack direction={{ xs: "column", md: "row" }} spacing={2}>
                    <Stack direction="row" spacing={1} alignItems="center">
                      <Switch checked={config.enforceScope} onChange={(_e, checked) => setConfig({ ...config, enforceScope: checked })} />
                      <Typography variant="body2">Enforce scope</Typography>
                    </Stack>

                    <Stack direction="row" spacing={1} alignItems="center">
                      <Switch checked={config.auditEnabled} onChange={(_e, checked) => setConfig({ ...config, auditEnabled: checked })} />
                      <Typography variant="body2">Audit logging</Typography>
                    </Stack>
                  </Stack>
                  <Box>
                    <Button variant="contained" onClick={saveConfig} disabled={saveM.isPending}>
                      Save Workflow Configuration
                    </Button>
                  </Box>
                </Stack>
              ) : (
                <Typography variant="body2" color="text.secondary">
                  Loading pipeline configuration...
                </Typography>
              )}
            </Box>
          ) : null}

          {stage.id === 1 ? (
            <Box sx={{ mb: 2 }}>
              <Typography variant="subtitle2" sx={{ mb: 1 }}>
                Active Scan Runs
              </Typography>
              {runs.filter((r) => r.status === "queued" || r.status === "running").length ? (
                <Stack spacing={1}>
                  {runs
                    .filter((r) => r.status === "queued" || r.status === "running")
                    .slice(0, 8)
                    .map((r) => {
                      const canCancel = !(r.cancelRequested ?? false);
                      return (
                        <Box key={r.id} sx={{ p: 1.25, border: "1px solid", borderColor: "divider", borderRadius: 1 }}>
                          <Stack direction={{ xs: "column", md: "row" }} spacing={1} alignItems={{ md: "center" }} justifyContent="space-between">
                            <Stack spacing={0.25}>
                              <Typography variant="body2">
                                <strong>{r.target.name}</strong> ({r.target.address}) · {r.profile}
                              </Typography>
                              <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
                                <Chip size="small" label={r.status} />
                                {r.cancelRequested ? <Chip size="small" color="warning" label="cancel requested" /> : null}
                                <Chip size="small" variant="outlined" label={r.id.slice(0, 8)} />
                              </Stack>
                            </Stack>
                            <Stack direction="row" spacing={1} alignItems="center">
                              <Button
                                size="small"
                                variant="outlined"
                                color="error"
                                disabled={!canCancel || cancelScanM.isPending}
                                onClick={() => cancelScanM.mutate(r.id)}
                              >
                                Stop scan
                              </Button>
                            </Stack>
                          </Stack>
                        </Box>
                      );
                    })}
                </Stack>
              ) : (
                <Typography variant="body2" color="text.secondary">
                  No active scans right now.
                </Typography>
              )}
            </Box>
          ) : null}

          {stage.id === 2 ? (
            <Box sx={{ mb: 2 }}>
              <Typography variant="subtitle2" sx={{ mb: 1 }}>
                Reconnaissance Assets
              </Typography>
              {!targetId ? (
                <Typography variant="body2" color="text.secondary">
                  Select a target above to view recon inventory.
                </Typography>
              ) : (
                <Stack spacing={1}>
                  {(reconQ.data ?? []).length ? (
                    (reconQ.data ?? []).slice(0, 20).map((a) => (
                      <Box key={a.id} sx={{ p: 1, border: "1px solid", borderColor: "divider", borderRadius: 1 }}>
                        <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
                          <Chip size="small" label={a.assetType} />
                          <Chip size="small" label={a.source} variant="outlined" />
                          <Chip size="small" label={`confidence ${a.confidence}`} />
                          <Typography variant="body2">{a.value}</Typography>
                        </Stack>
                      </Box>
                    ))
                  ) : (
                    <Typography variant="body2" color="text.secondary">
                      No recon assets yet. Run a scan to populate this stage.
                    </Typography>
                  )}
                </Stack>
              )}
            </Box>
          ) : null}

          {stage.id === 4 ? (
            <Box sx={{ mb: 2 }}>
              <Typography variant="subtitle2" sx={{ mb: 1 }}>
                Command Approval Queue
              </Typography>
              {(approvalsQ.data ?? []).length ? (
                <Stack spacing={1}>
                  {(approvalsQ.data ?? []).map((a) => (
                    <Box key={a.id} sx={{ p: 1.5, border: "1px solid", borderColor: "divider", borderRadius: 1 }}>
                      <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap sx={{ mb: 0.5 }}>
                        <Chip size="small" color="warning" label={a.impact} />
                        {a.tool ? <Chip size="small" variant="outlined" label={a.tool} /> : null}
                      </Stack>
                      <Typography variant="body2" sx={{ fontFamily: "monospace", mb: 0.5 }}>{a.command}</Typography>
                      {a.reasoning ? (
                        <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>{a.reasoning}</Typography>
                      ) : null}
                      <Stack direction="row" spacing={1}>
                        <Button size="small" variant="contained" color="success" disabled={approveM.isPending} onClick={() => approveM.mutate(a.id)}>
                          Approve
                        </Button>
                        <Button size="small" variant="outlined" color="error" disabled={rejectM.isPending} onClick={() => rejectM.mutate(a.id)}>
                          Reject
                        </Button>
                      </Stack>
                    </Box>
                  ))}
                </Stack>
              ) : (
                <Typography variant="body2" color="text.secondary">
                  No pending approvals. Gated exploit/hydra commands awaiting human sign-off appear here.
                </Typography>
              )}
            </Box>
          ) : null}

          <Typography variant="h6">{`Stage ${stage.id} - ${stage.title}`}</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, mb: 2 }}>
            {stage.goal}
          </Typography>

          <Box
            sx={{
              display: "grid",
              gridTemplateColumns: { xs: "1fr", md: "1fr 1fr" },
              gap: 2
            }}
          >
            <Card variant="outlined">
              <CardContent>
                <Typography variant="subtitle2" sx={{ mb: 1 }}>
                  Modules
                </Typography>
                <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                  {stage.modules.map((m) => (
                    <Chip key={m} label={m} size="small" />
                  ))}
                </Stack>
              </CardContent>
            </Card>

            <Card variant="outlined">
              <CardContent>
                <Typography variant="subtitle2" sx={{ mb: 1 }}>
                  Controls & Gates
                </Typography>
                <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                  {stage.controls.map((c) => (
                    <Chip key={c} label={c} size="small" color="primary" variant="outlined" />
                  ))}
                </Stack>
              </CardContent>
            </Card>
          </Box>

          {stage.id === 1 ? (
            <>
              <Divider sx={{ my: 2 }} />
              <Typography variant="subtitle2" sx={{ mb: 1 }}>
                Recent Audit Events
              </Typography>
              {/* Audit + agent telemetry sit on Stage 1 because that's the
                  operator-control stage; the AI commentary lives here so the
                  human-in-the-loop can see exactly what the agents ran. */}
              <Stack spacing={1}>
                {(auditQ.data ?? []).map((e) => (
                  <Box key={e.id} sx={{ p: 1, border: "1px solid", borderColor: "divider", borderRadius: 1 }}>
                    <Typography variant="body2">
                      {e.actor} - {e.action}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {new Date(e.createdAt).toLocaleString()} {e.target ? `- ${e.target}` : ""}
                    </Typography>
                  </Box>
                ))}
              </Stack>

              <Divider sx={{ my: 2 }} />
              <LatestAgentTelemetry targetId={targetId} />
            </>
          ) : null}
        </CardContent>
      </Card>
    </Box>
  );
}

/**
 * Compact telemetry surface — shows what the latest Agentic Recon run is
 * doing right now: manager decisions, tool invocations, the actual command
 * that ran, and a stdout/stderr snippet. Operator can deep-link into the
 * full Agentic Recon page for more.
 */
function LatestAgentTelemetry(props: { targetId: string }) {
  const runsQ = useQuery({
    queryKey: ["agent-runs-latest", props.targetId || "any"],
    queryFn: () => listAgentRuns({ targetId: props.targetId || undefined, limit: 1 }),
    refetchInterval: 4000
  });
  const latest: AgentRun | undefined = runsQ.data?.[0];
  const qc = useQueryClient();
  const cancelAgentM = useMutation({
    mutationFn: cancelAgentRun,
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["agent-runs-latest"] });
      await qc.invalidateQueries({ queryKey: ["audit-events"] });
    }
  });

  const runQ = useQuery({
    queryKey: ["pipeline-agent-run", latest?.id],
    queryFn: () => getAgentRun(latest!.id),
    enabled: Boolean(latest),
    refetchInterval: 3000
  });
  const invocationsQ = useQuery({
    queryKey: ["pipeline-agent-run-invocations", latest?.id],
    queryFn: () => getAgentRunInvocations(latest!.id),
    enabled: Boolean(latest),
    refetchInterval: 3000
  });
  const eventsQ = useQuery({
    queryKey: ["pipeline-agent-run-events", latest?.id],
    queryFn: () => getAgentRunEvents(latest!.id),
    enabled: Boolean(latest),
    refetchInterval: 3000
  });

  if (!latest) {
    return (
      <Box>
        <Typography variant="subtitle2" sx={{ mb: 1 }}>
          Agent telemetry
        </Typography>
        <Typography variant="body2" color="text.secondary">
          No agentic recon runs yet.{" "}
          <Link to="/agents">Start one in Agentic Recon →</Link>
        </Typography>
      </Box>
    );
  }

  const run = runQ.data ?? latest;
  const invocations: AgentInvocation[] = invocationsQ.data ?? [];
  const decisionEvents: AgentEvent[] = (eventsQ.data ?? []).filter((e) => e.kind === "manager.decision");

  return (
    <Box>
      <Stack direction={{ xs: "column", md: "row" }} spacing={1} alignItems={{ md: "center" }} justifyContent="space-between" sx={{ mb: 1 }}>
        <Typography variant="subtitle2">
          Agent telemetry — latest run on {run.target.name}
        </Typography>
        <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
          <Chip size="small" label={run.status} />
          <Chip size="small" label={`steps ${run.stepsTaken}/${run.maxSteps}`} variant="outlined" />
          <Chip size="small" label={`tools ${run.invocationCount}`} variant="outlined" />
          <Chip
            size="small"
            label={`findings ${run.findingCount}`}
            variant="outlined"
            color={run.findingCount ? "warning" : "default"}
          />
          {(run.status === "queued" || run.status === "running") ? (
            <Button size="small" color="error" variant="outlined" disabled={cancelAgentM.isPending} onClick={() => cancelAgentM.mutate(run.id)}>
              Stop agent run
            </Button>
          ) : null}
          <Button size="small" component={Link} to="/agents">Open Agentic Recon</Button>
        </Stack>
      </Stack>

      <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", md: "1fr 1fr" }, gap: 2 }}>
        <Card variant="outlined">
          <CardContent>
            <Typography variant="caption" color="text.secondary">Recent manager decisions</Typography>
            {decisionEvents.length === 0 ? (
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>No decisions yet.</Typography>
            ) : (
              <Stack spacing={0.75} sx={{ mt: 1 }}>
                {decisionEvents.slice(-5).map((e) => {
                  const p = (e.payload ?? {}) as { step?: number; decision?: { action?: string; tool?: string; intentGoal?: string; reason?: string; reasoning?: string } };
                  const d = p.decision ?? {};
                  return (
                    <Box key={e.id} sx={{ p: 0.75, border: "1px dashed", borderColor: "divider", borderRadius: 1 }}>
                      <Typography variant="body2">
                        <strong>step {p.step ?? "?"}</strong> · {d.action ?? "?"}{d.tool ? ` → ${d.tool}` : ""}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {d.intentGoal ?? d.reason ?? d.reasoning ?? ""}
                      </Typography>
                    </Box>
                  );
                })}
              </Stack>
            )}
          </CardContent>
        </Card>

        <Card variant="outlined">
          <CardContent>
            <Typography variant="caption" color="text.secondary">Specialist invocations (commands & status)</Typography>
            {invocations.length === 0 ? (
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>No invocations yet.</Typography>
            ) : (
              <Stack spacing={0.75} sx={{ mt: 1 }}>
                {invocations.slice(-6).map((inv) => {
                  const env = (inv.envelope ?? {}) as {
                    artifacts?: { commands?: string[]; stdoutSnippet?: string; stderrSnippet?: string };
                    durationMs?: number;
                    error?: string;
                  };
                  const cmd = env.artifacts?.commands?.[0];
                  return (
                    <Box key={inv.id} sx={{ p: 0.75, border: "1px solid", borderColor: "divider", borderRadius: 1 }}>
                      <Stack direction="row" justifyContent="space-between" alignItems="center" spacing={1}>
                        <Typography variant="body2" sx={{ fontWeight: 600 }}>{inv.tool}</Typography>
                        <Chip size="small" label={inv.status} />
                      </Stack>
                      {cmd ? (
                        <Box sx={{ p: 0.75, bgcolor: "grey.100", borderRadius: 1, mt: 0.5, maxHeight: 80, overflow: "auto" }}>
                          <Typography variant="caption" component="pre" sx={{ m: 0, whiteSpace: "pre-wrap", wordBreak: "break-word", fontFamily: "monospace" }}>
                            $ {cmd}
                          </Typography>
                        </Box>
                      ) : null}
                      {env.error ? (
                        <Typography variant="caption" color="error" sx={{ display: "block", mt: 0.5 }}>
                          err: {env.error}
                        </Typography>
                      ) : null}
                    </Box>
                  );
                })}
              </Stack>
            )}
          </CardContent>
        </Card>
      </Box>
    </Box>
  );
}
