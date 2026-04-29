import React from "react";
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
  createExploitRun,
  getPipelineConfig,
  listAuditEvents,
  listFindings,
  listReconAssets,
  listScans,
  listServices,
  listTargets,
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
  const saveM = useMutation({
    mutationFn: updatePipelineConfig,
    onSuccess: async (updated) => {
      setConfig(updated);
      await qc.invalidateQueries({ queryKey: ["pipeline-config"] });
      await qc.invalidateQueries({ queryKey: ["audit-events"] });
    }
  });

  const exploitM = useMutation({
    mutationFn: (input: { scanRunId?: string; targetId?: string }) => createExploitRun(input),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["audit-events"] });
      await qc.invalidateQueries({ queryKey: ["runs"] });
    }
  });

  const [config, setConfig] = React.useState<null | Awaited<ReturnType<typeof getPipelineConfig>>>(null);
  React.useEffect(() => {
    if (!pipelineQ.data) return;
    setConfig(pipelineQ.data);
    setDraftWordlists(pipelineQ.data.allowedWordlists.join("\n"));
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
                  </Stack>
                  <TextField
                    label="Allowed wordlists (one path per line)"
                    multiline
                    minRows={3}
                    value={draftWordlists}
                    onChange={(e) => setDraftWordlists(e.target.value)}
                    fullWidth
                  />

                  <Stack direction={{ xs: "column", md: "row" }} spacing={2}>
                    <Stack direction="row" spacing={1} alignItems="center">
                    </Stack>
                    <Stack direction="row" spacing={1} alignItems="center">
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

          {stage.id === 4 ? (() => {
            const targetRuns = runs.filter((r) => !targetId || r.targetId === targetId);
            const succeeded = targetRuns.filter((r) => r.status === "succeeded");
            const latestSucceeded = succeeded[0];
            const exploitEvents = (auditQ.data ?? []).filter((e) =>
              e.action.startsWith("agent.exploit.") || e.action.startsWith("exploit.")
            );
            return (
              <Box sx={{ mb: 2 }}>
                <Typography variant="subtitle2" sx={{ mb: 1 }}>
                  AI Exploitation Control
                </Typography>
                <Stack spacing={2}>
                  <Stack direction={{ xs: "column", md: "row" }} spacing={2} alignItems={{ md: "center" }}>
                    <Chip
                      label={
                        latestSucceeded
                          ? `Latest scan: ${latestSucceeded.target.name} - ${new Date(
                              (latestSucceeded.finishedAt ?? latestSucceeded.createdAt) as string
                            ).toLocaleString()}`
                          : targetId
                          ? "No succeeded scans for this target yet"
                          : "Pick a target above (or run any scan) to enable manual exploitation"
                      }
                      color={latestSucceeded ? "success" : "default"}
                      variant="outlined"
                    />
                    <Button
                      variant="contained"
                      color="warning"
                      disabled={(!latestSucceeded && !targetId) || exploitM.isPending}
                      onClick={() =>
                        exploitM.mutate(
                          latestSucceeded ? { scanRunId: latestSucceeded.id } : { targetId: targetId || undefined }
                        )
                      }
                    >
                      {exploitM.isPending ? "Queueing..." : "Launch AI Exploitation"}
                    </Button>
                  </Stack>
                  <Typography variant="caption" color="text.secondary">
                    Auto-trigger after a successful scan is controlled by the worker env flag EXPLOIT_ENABLED. The
                    AI agent will pick exploit/credential modules (hydra, medusa, ncrack, msfconsole, sqlmap...),
                    install missing tools on demand, and stop after at most 15 commands. Reverse-shell payloads are
                    pinned to the worker host - no external callbacks.
                  </Typography>
                  {exploitM.isError ? (
                    <Alert severity="error">
                      {exploitM.error instanceof Error ? exploitM.error.message : String(exploitM.error)}
                    </Alert>
                  ) : null}
                  {exploitM.isSuccess ? (
                    <Alert severity="success">
                      Exploitation queued for scan {exploitM.data?.scanRunId.slice(0, 8)}... - watch the scan run
                      page for the "AI Exploitation" step log.
                    </Alert>
                  ) : null}

                  <Divider />
                  <Typography variant="subtitle2">Recent Exploitation Audit Events</Typography>
                  {exploitEvents.length === 0 ? (
                    <Typography variant="body2" color="text.secondary">
                      No exploitation activity yet. Launch a run above (or wait for the next scan to auto-trigger).
                    </Typography>
                  ) : (
                    <Stack spacing={1}>
                      {exploitEvents.slice(0, 10).map((e) => (
                        <Box
                          key={e.id}
                          sx={{ p: 1, border: "1px solid", borderColor: "divider", borderRadius: 1 }}
                        >
                          <Typography variant="body2">
                            {e.actor} - {e.action}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            {new Date(e.createdAt).toLocaleString()} {e.target ? `- ${e.target}` : ""}
                          </Typography>
                          {e.payload && Object.keys(e.payload).length > 0 ? (
                            <Typography
                              variant="caption"
                              color="text.secondary"
                              component="pre"
                              sx={{ m: 0, mt: 0.5, whiteSpace: "pre-wrap", wordBreak: "break-all" }}
                            >
                              {JSON.stringify(e.payload, null, 2)}
                            </Typography>
                          ) : null}
                        </Box>
                      ))}
                    </Stack>
                  )}
                </Stack>
              </Box>
            );
          })() : null}

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
            </>
          ) : null}
        </CardContent>
      </Card>
    </Box>
  );
}
