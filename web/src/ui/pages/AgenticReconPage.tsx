import React from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  IconButton,
  LinearProgress,
  MenuItem,
  Select,
  Stack,
  TextField,
  Tooltip,
  Typography
} from "@mui/material";
import {
  AgentEvent,
  AgentInvocation,
  AgentRun,
  AgentRunSummary,
  AgentRunReport,
  AgentTool,
  explainAgentRun,
  getAgentRunReport,
  getAgentRun,
  getAgentRunEvents,
  getAgentRunInvocations,
  listAgentRuns,
  listAgentTools,
  listTargets,
  startAgentRun
} from "../../lib/api";
import { jsPDF } from "jspdf";

const STATUS_COLOR: Record<string, "default" | "primary" | "success" | "warning" | "error"> = {
  queued: "default",
  running: "primary",
  succeeded: "success",
  failed: "error"
};

const RISK_COLOR: Record<string, "default" | "info" | "warning" | "error" | "success"> = {
  info: "info",
  low: "success",
  medium: "warning",
  high: "error",
  critical: "error"
};

function StatusChip(props: { status: string }) {
  const color = STATUS_COLOR[props.status] ?? "default";
  return <Chip size="small" label={props.status} color={color} />;
}

export function AgenticReconPage() {
  const qc = useQueryClient();
  const [sp] = useSearchParams();
  const [targetId, setTargetId] = React.useState("");
  const [selectedRunId, setSelectedRunId] = React.useState<string | null>(null);
  const [maxSteps, setMaxSteps] = React.useState(20);
  const [notes, setNotes] = React.useState("");
  const [initialNmapProfile, setInitialNmapProfile] = React.useState<"fast" | "targeted" | "deep" | "full">("deep");
  const [initialNmapPorts, setInitialNmapPorts] = React.useState<string>("");
  const [initialNmapExtraArgs, setInitialNmapExtraArgs] = React.useState<string>("");
  React.useEffect(() => {
    const runId = sp.get("runId");
    if (runId && runId !== selectedRunId) setSelectedRunId(runId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sp]);

  const targetsQ = useQuery({ queryKey: ["targets"], queryFn: listTargets });
  const toolsQ = useQuery({ queryKey: ["agent-tools"], queryFn: listAgentTools });
  const runsQ = useQuery({
    queryKey: ["agent-runs"],
    queryFn: () => listAgentRuns({ limit: 25 }),
    refetchInterval: 3000
  });

  const startM = useMutation({
    mutationFn: () =>
      startAgentRun({
        targetId,
        maxSteps,
        notes: notes.trim() || undefined,
        initialNmap: {
          profile: initialNmapProfile,
          ports:
            initialNmapProfile === "targeted"
              ? initialNmapPorts
                  .split(/[,\s]+/)
                  .map((s) => Number(s.trim()))
                  .filter((n) => Number.isInteger(n) && n > 0 && n <= 65535)
              : undefined,
          extraArgs: initialNmapExtraArgs.trim() || undefined
        }
      }),
    onSuccess: async (created) => {
      setSelectedRunId(created.id);
      setNotes("");
      await qc.invalidateQueries({ queryKey: ["agent-runs"] });
    }
  });

  const runQ = useQuery({
    queryKey: ["agent-run", selectedRunId],
    queryFn: () => getAgentRun(selectedRunId as string),
    enabled: Boolean(selectedRunId),
    refetchInterval: 2500
  });
  const invocationsQ = useQuery({
    queryKey: ["agent-run-invocations", selectedRunId],
    queryFn: () => getAgentRunInvocations(selectedRunId as string),
    enabled: Boolean(selectedRunId),
    refetchInterval: 2500
  });
  const eventsQ = useQuery({
    queryKey: ["agent-run-events", selectedRunId],
    queryFn: () => getAgentRunEvents(selectedRunId as string),
    enabled: Boolean(selectedRunId),
    refetchInterval: 2000
  });

  const run = runQ.data ?? null;

  return (
    <Box>
      <Typography variant="h5" gutterBottom>
        Agentic Recon (MCP)
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        A manager LLM sequences specialised local agents over an MCP framework. The
        prompter translates manager intents into agent-specific instructions; specialists run nmap, gobuster,
        DNS, TLS, SMB, SSH and CVE enrichment over the SSH bastion. All telemetry streams below in real time.
      </Typography>

      <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", md: "minmax(0,1fr) minmax(0,2fr)" }, gap: 2 }}>
        <Stack spacing={2}>
          <Card>
            <CardContent>
              <Typography variant="subtitle1" gutterBottom>
                Launch a recon run
              </Typography>
              <Stack spacing={2}>
                <Select value={targetId} onChange={(e) => setTargetId(String(e.target.value))} displayEmpty fullWidth>
                  <MenuItem value="" disabled>
                    Select target
                  </MenuItem>
                  {(targetsQ.data ?? []).map((t) => (
                    <MenuItem key={t.id} value={t.id}>
                      {t.name} ({t.address})
                    </MenuItem>
                  ))}
                </Select>
                <TextField
                  label="Max steps"
                  type="number"
                  value={maxSteps}
                  onChange={(e) => setMaxSteps(Math.max(1, Math.min(60, Number(e.target.value) || 1)))}
                  size="small"
                />
                <TextField
                  label="Notes (optional)"
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  size="small"
                />
                <Divider />
                <Typography variant="subtitle2">Initial Nmap scan (step 1)</Typography>
                <Select
                  value={initialNmapProfile}
                  onChange={(e) => setInitialNmapProfile(e.target.value as any)}
                  size="small"
                  fullWidth
                >
                  <MenuItem value="fast">fast (top ports 200, -sV)</MenuItem>
                  <MenuItem value="deep">deep (top ports 1000, --version-all)</MenuItem>
                  <MenuItem value="full">full (-p-)</MenuItem>
                  <MenuItem value="targeted">targeted (custom ports)</MenuItem>
                </Select>
                {initialNmapProfile === "targeted" ? (
                  <TextField
                    label="Target ports (comma/space separated)"
                    placeholder="22,80,443,445"
                    value={initialNmapPorts}
                    onChange={(e) => setInitialNmapPorts(e.target.value)}
                    size="small"
                  />
                ) : null}
                <TextField
                  label="Extra nmap args (optional)"
                  placeholder="-sC -sV"
                  value={initialNmapExtraArgs}
                  onChange={(e) => setInitialNmapExtraArgs(e.target.value)}
                  size="small"
                />
                <Button
                  variant="contained"
                  disabled={!targetId || startM.isPending}
                  onClick={() => startM.mutate()}
                >
                  {startM.isPending ? "Queueing…" : "Start Agentic Recon"}
                </Button>
                {startM.isError ? (
                  <Alert severity="error">{(startM.error as Error)?.message ?? "Failed to start"}</Alert>
                ) : null}
              </Stack>
            </CardContent>
          </Card>

          <Card>
            <CardContent>
              <Typography variant="subtitle1" gutterBottom>
                Available specialist agents
              </Typography>
              {toolsQ.isLoading ? (
                <Typography variant="body2" color="text.secondary">Loading…</Typography>
              ) : (
                <Stack spacing={1}>
                  {(toolsQ.data ?? []).map((t: AgentTool) => (
                    <Box key={t.name} sx={{ p: 1, border: "1px solid", borderColor: "divider", borderRadius: 1 }}>
                      <Typography variant="body2" sx={{ fontWeight: 600 }}>{t.name}</Typography>
                      <Typography variant="caption" color="text.secondary">{t.description}</Typography>
                      {t.tags?.length ? (
                        <Stack direction="row" spacing={0.5} sx={{ mt: 0.5 }}>
                          {t.tags.map((tag) => <Chip key={tag} size="small" label={tag} variant="outlined" />)}
                        </Stack>
                      ) : null}
                    </Box>
                  ))}
                </Stack>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardContent>
              <Typography variant="subtitle1" gutterBottom>
                Recent runs
              </Typography>
              {runsQ.isLoading ? (
                <Typography variant="body2" color="text.secondary">Loading…</Typography>
              ) : (
                <Stack spacing={1}>
                  {(runsQ.data ?? []).map((r: AgentRun) => (
                    <Box
                      key={r.id}
                      onClick={() => setSelectedRunId(r.id)}
                      sx={{
                        p: 1,
                        border: "1px solid",
                        borderColor: selectedRunId === r.id ? "primary.main" : "divider",
                        borderRadius: 1,
                        cursor: "pointer"
                      }}
                    >
                      <Stack direction="row" justifyContent="space-between" alignItems="center">
                        <Typography variant="body2" sx={{ fontWeight: 600 }}>
                          {r.target.name}
                        </Typography>
                        <StatusChip status={r.status} />
                      </Stack>
                      <Typography variant="caption" color="text.secondary">
                        {new Date(r.createdAt).toLocaleString()}
                      </Typography>
                      <Stack direction="row" spacing={1} sx={{ mt: 0.5 }} flexWrap="wrap" useFlexGap>
                        <Chip size="small" label={`steps ${r.stepsTaken}/${r.maxSteps}`} variant="outlined" />
                        <Chip size="small" label={`tools ${r.invocationCount}`} variant="outlined" />
                        <Chip
                          size="small"
                          label={`findings ${r.findingCount}`}
                          variant="outlined"
                          color={r.findingCount ? "warning" : "default"}
                        />
                      </Stack>
                    </Box>
                  ))}
                  {(runsQ.data ?? []).length === 0 ? (
                    <Typography variant="body2" color="text.secondary">No runs yet.</Typography>
                  ) : null}
                </Stack>
              )}
            </CardContent>
          </Card>
        </Stack>

        <RunMonitor
          run={run}
          invocations={invocationsQ.data ?? []}
          events={eventsQ.data ?? []}
        />
      </Box>
    </Box>
  );
}

function RunMonitor(props: { run: AgentRun | null; invocations: AgentInvocation[]; events: AgentEvent[] }) {
  const { run, invocations, events } = props;
  const [openInvocation, setOpenInvocation] = React.useState<string | null>(null);
  const [summaryOpen, setSummaryOpen] = React.useState(false);
  const [summary, setSummary] = React.useState<AgentRunSummary | null>(null);
  const [summaryError, setSummaryError] = React.useState<string | null>(null);
  const [reportOpen, setReportOpen] = React.useState(false);
  const [report, setReport] = React.useState<AgentRunReport | null>(null);
  const [reportError, setReportError] = React.useState<string | null>(null);

  const summaryM = useMutation({
    mutationFn: (id: string) => explainAgentRun(id),
    onMutate: () => {
      setSummary(null);
      setSummaryError(null);
      setSummaryOpen(true);
    },
    onSuccess: (data) => setSummary(data),
    onError: (err) => setSummaryError((err as Error)?.message ?? "Failed to generate summary")
  });

  const reportM = useMutation({
    mutationFn: (id: string) => getAgentRunReport(id),
    onMutate: () => {
      setReport(null);
      setReportError(null);
      setReportOpen(true);
    },
    onSuccess: (data) => setReport(data),
    onError: (err) => setReportError((err as Error)?.message ?? "Failed to generate report")
  });

  if (!run) {
    return (
      <Card>
        <CardContent>
          <Typography variant="body2" color="text.secondary">
            Select a run on the left or start a new Agentic Recon.
          </Typography>
        </CardContent>
      </Card>
    );
  }

  const decisionEvents = events.filter((e) => e.kind === "manager.decision");
  const promptEvents = events.filter((e) => e.kind === "prompter.output");
  const writerEvents = events.filter((e) => e.kind === "execution_writer.output");
  const wordlistEvent = events.find((e) => e.kind === "wordlist.catalog");
  const failureEvents = events.filter((e) => e.kind === "agent.failure");
  const finishedCount = invocations.filter((i) => ["succeeded", "failed", "skipped"].includes(i.status)).length;
  const progress = run.maxSteps > 0 ? Math.min(100, Math.round((run.stepsTaken / run.maxSteps) * 100)) : 0;
  const summaryAvailable = run.status === "succeeded" || run.status === "failed";

  const latestDecision = (decisionEvents[decisionEvents.length - 1]?.payload ?? {}) as {
    snapshot?: {
      pendingVerifications?: number;
      discoveredEndpoints?: number;
      services?: number;
      findings?: number;
      knownPorts?: number[];
    };
  };
  const latestSnapshot = latestDecision.snapshot ?? null;

  return (
    <Stack spacing={2}>
      <Card>
        <CardContent>
          <Stack direction={{ xs: "column", md: "row" }} spacing={2} alignItems={{ md: "center" }} justifyContent="space-between">
            <Box>
              <Typography variant="subtitle1">
                {run.target.name} <Typography component="span" color="text.secondary">({run.target.address})</Typography>
              </Typography>
              <Typography variant="caption" color="text.secondary">
                Manager: {run.managerModel || "qwen3:8b"} · Arg writer: {run.specialistModel || "qwen3:8b"} · Prompter: {run.prompterModel || "qwen3:8b"}
              </Typography>
            </Box>
            <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
              <StatusChip status={run.status} />
              <Chip size="small" label={`${finishedCount}/${invocations.length} agents finished`} variant="outlined" />
              <Tooltip title={summaryAvailable ? "Generate one AI summary for this whole scan" : "Available once the run finishes"}>
                <span>
                  <Button
                    size="small"
                    variant="contained"
                    color="secondary"
                    disabled={!summaryAvailable || summaryM.isPending}
                    onClick={() => summaryM.mutate(run.id)}
                  >
                    {summaryM.isPending ? "Summarising…" : "AI Summary"}
                  </Button>
                </span>
              </Tooltip>
              <Tooltip title={summaryAvailable ? "Generate a detailed AI report + PDF export" : "Available once the run finishes"}>
                <span>
                  <Button
                    size="small"
                    variant="contained"
                    color="error"
                    disabled={!summaryAvailable || reportM.isPending}
                    onClick={() => reportM.mutate(run.id)}
                  >
                    {reportM.isPending ? "Generating…" : "Detailed AI report"}
                  </Button>
                </span>
              </Tooltip>
              <Button size="small" component={Link} to={`/graph`}>Open graph</Button>
            </Stack>
          </Stack>
          <Box sx={{ mt: 2 }}>
            <LinearProgress
              variant="determinate"
              value={progress}
              color={run.status === "failed" ? "error" : run.status === "succeeded" ? "success" : "primary"}
            />
            <Typography variant="caption" color="text.secondary">
              Step {run.stepsTaken} / {run.maxSteps} · {run.findingCount} findings · {run.serviceCount} services
            </Typography>
          </Box>
        </CardContent>
      </Card>

      <RunContextCard latestSnapshot={latestSnapshot} />

      {wordlistEvent ? <WordlistCatalogCard event={wordlistEvent} /> : null}

      {failureEvents.length ? <FailureCard events={failureEvents} /> : null}

      <Card>
        <CardContent>
          <Typography variant="subtitle1" gutterBottom>
            Manager decisions
          </Typography>
          {decisionEvents.length === 0 ? (
            <Typography variant="body2" color="text.secondary">No decisions yet.</Typography>
          ) : (
            <Stack spacing={1}>
              {decisionEvents.slice(-12).map((e) => {
                const p = (e.payload ?? {}) as {
                  step?: number;
                  decision?: { action?: string; tool?: string; intentGoal?: string; reason?: string; reasoning?: string; args?: Record<string, unknown> };
                };
                const d = p.decision ?? {};
                return (
                  <Box key={e.id} sx={{ p: 1, border: "1px dashed", borderColor: "divider", borderRadius: 1 }}>
                    <Typography variant="body2">
                      <strong>Step {p.step ?? "?"}</strong> · {d.action ?? "?"}{d.tool ? ` → ${d.tool}` : ""}
                    </Typography>
                    {d.intentGoal ? <Typography variant="caption" color="text.secondary">Intent: {d.intentGoal}</Typography> : null}
                    {d.reason || d.reasoning ? (
                      <Typography variant="caption" sx={{ display: "block" }} color="text.secondary">
                        {d.reason ?? d.reasoning}
                      </Typography>
                    ) : null}
                    {d.args && Object.keys(d.args).length ? (
                      <Typography variant="caption" sx={{ display: "block", color: "text.secondary", fontFamily: "monospace" }}>
                        args: {JSON.stringify(d.args)}
                      </Typography>
                    ) : null}
                  </Box>
                );
              })}
            </Stack>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardContent>
          <Typography variant="subtitle1" gutterBottom>
            Specialist invocations
          </Typography>
          {invocations.length === 0 ? (
            <Typography variant="body2" color="text.secondary">No specialist agents have run yet.</Typography>
          ) : (
            <Stack spacing={1}>
              {invocations.map((inv) => (
                <InvocationCard
                  key={inv.id}
                  inv={inv}
                  open={openInvocation === inv.id}
                  onToggle={() => setOpenInvocation((cur) => (cur === inv.id ? null : inv.id))}
                />
              ))}
            </Stack>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardContent>
          <Typography variant="subtitle1" gutterBottom>
            Execution writer (structured args)
          </Typography>
          {writerEvents.length === 0 ? (
            <Typography variant="body2" color="text.secondary">
              No execution-writer events yet (tools without argSchema skip this step).
            </Typography>
          ) : (
            <Stack spacing={1}>
              {writerEvents.slice(-8).map((e) => {
                const p = (e.payload ?? {}) as {
                  step?: number;
                  tool?: string;
                  source?: string;
                  model?: string;
                  draftArgs?: Record<string, unknown>;
                  finalArgs?: Record<string, unknown>;
                  diag?: string | null;
                };
                return (
                  <Box key={e.id} sx={{ p: 1, border: "1px solid", borderColor: "divider", borderRadius: 1 }}>
                    <Typography variant="caption" color="text.secondary">
                      step {p.step ?? "?"} · {p.tool ?? "?"} · source: {p.source ?? "?"} · model: {p.model ?? "?"}
                    </Typography>
                    {p.diag ? (
                      <Typography variant="caption" sx={{ display: "block" }} color="warning.main">
                        {p.diag}
                      </Typography>
                    ) : null}
                    <Typography variant="caption" sx={{ display: "block", mt: 0.5 }} color="text.secondary">
                      final args
                    </Typography>
                    <Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: "0.8rem", whiteSpace: "pre-wrap" }}>
                      {JSON.stringify(p.finalArgs ?? {}, null, 2)}
                    </Typography>
                  </Box>
                );
              })}
            </Stack>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardContent>
          <Typography variant="subtitle1" gutterBottom>
            Prompter outputs
          </Typography>
          {promptEvents.length === 0 ? (
            <Typography variant="body2" color="text.secondary">No prompts generated yet.</Typography>
          ) : (
            <Stack spacing={1}>
              {promptEvents.slice(-6).map((e) => {
                const p = (e.payload ?? {}) as { step?: number; tool?: string; prompt?: string };
                return (
                  <Box key={e.id} sx={{ p: 1, border: "1px dotted", borderColor: "divider", borderRadius: 1 }}>
                    <Typography variant="caption" color="text.secondary">
                      step {p.step ?? "?"} · {p.tool ?? "?"}
                    </Typography>
                    <Typography variant="body2" sx={{ whiteSpace: "pre-wrap" }}>
                      {p.prompt ?? ""}
                    </Typography>
                  </Box>
                );
              })}
            </Stack>
          )}
        </CardContent>
      </Card>

      <SummaryDialog
        open={summaryOpen}
        onClose={() => setSummaryOpen(false)}
        loading={summaryM.isPending}
        summary={summary}
        error={summaryError}
      />

      <ReportDialog
        open={reportOpen}
        onClose={() => setReportOpen(false)}
        loading={reportM.isPending}
        report={report}
        error={reportError}
        onDownloadPdf={() => {
          const title = report?.title || `Security recon report`;
          const md = report?.markdown || "";
          const doc = new jsPDF({ unit: "pt", format: "a4" });
          const margin = 40;
          const pageWidth = doc.internal.pageSize.getWidth();
          const maxWidth = pageWidth - margin * 2;
          const text = toPlainText(md);
          doc.setFont("helvetica", "normal");
          doc.setFontSize(11);
          const lines = doc.splitTextToSize(text, maxWidth);
          let y = margin;
          for (const line of lines) {
            if (y > doc.internal.pageSize.getHeight() - margin) {
              doc.addPage();
              y = margin;
            }
            doc.text(line, margin, y);
            y += 14;
          }
          doc.save(safeFilename(`${title}.pdf`));
        }}
      />
    </Stack>
  );
}

/* ------------------------------------------------------------------ *
 *  Sub-components
 * ------------------------------------------------------------------ */

function InvocationCard(props: { inv: AgentInvocation; open: boolean; onToggle: () => void }) {
  const { inv, open, onToggle } = props;
  const env = (inv.envelope ?? {}) as {
    facts?: unknown[];
    findings?: Array<{ title: string; severity: string; evidence?: string }>;
    durationMs?: number;
    error?: string;
    artifacts?: { commands?: string[]; stdoutSnippet?: string; stderrSnippet?: string };
    meta?: Record<string, unknown>;
  };
  const cmds = env.artifacts?.commands ?? [];
  const webPaths = Array.isArray(env.facts)
    ? (env.facts as Array<{ type?: string; value?: any }>).filter((f) => f?.type === "web_path").slice(0, 40)
    : [];
  const commandSummary = typeof env.meta?.commandSummary === "string" ? env.meta.commandSummary : null;
  const argsKeys = Object.keys(inv.args ?? {});

  return (
    <Box sx={{ p: 1, border: "1px solid", borderColor: "divider", borderRadius: 1 }}>
      <Stack direction="row" spacing={1} alignItems="center" justifyContent="space-between">
        <Box sx={{ minWidth: 0 }}>
          <Typography variant="body2" sx={{ fontWeight: 600 }}>{inv.tool}</Typography>
          {inv.intent ? (
            <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
              {inv.intent.slice(0, 200)}
            </Typography>
          ) : null}
        </Box>
        <Stack direction="row" spacing={1} alignItems="center">
          <StatusChip status={inv.status} />
          <Tooltip title={open ? "Hide details" : "Show details"}>
            <IconButton size="small" onClick={onToggle}>
              {open ? "−" : "+"}
            </IconButton>
          </Tooltip>
        </Stack>
      </Stack>
      <Stack direction="row" spacing={1} sx={{ mt: 0.5 }} flexWrap="wrap" useFlexGap>
        <Chip size="small" label={`facts ${(env.facts ?? []).length}`} variant="outlined" />
        <Chip
          size="small"
          label={`findings ${(env.findings ?? []).length}`}
          variant="outlined"
          color={(env.findings ?? []).length ? "warning" : "default"}
        />
        {typeof env.durationMs === "number" ? (
          <Chip size="small" label={`${Math.round(env.durationMs / 1000)}s`} variant="outlined" />
        ) : null}
        {cmds.length ? <Chip size="small" label={`${cmds.length} cmd`} variant="outlined" /> : null}
        {argsKeys.length ? <Chip size="small" label={`args: ${argsKeys.join(",")}`} variant="outlined" /> : null}
        {env.error ? (
          <Chip size="small" label={`err: ${String(env.error).slice(0, 60)}`} color="error" variant="outlined" />
        ) : null}
      </Stack>

      {open ? (
        <>
          <Divider sx={{ my: 1 }} />

          {argsKeys.length ? (
            <>
              <Typography variant="caption" color="text.secondary">Args</Typography>
              <Box sx={mono(120)}>
                <Typography variant="caption" component="pre" sx={preSx}>
                  {JSON.stringify(inv.args, null, 2)}
                </Typography>
              </Box>
            </>
          ) : null}

          {cmds.length ? (
            <>
              <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: "block" }}>
                Commands run on tools host
              </Typography>
              <Box sx={mono(160)}>
                <Typography variant="caption" component="pre" sx={preSx}>
                  {cmds.join("\n")}
                </Typography>
              </Box>
            </>
          ) : null}

          {commandSummary ? (
            <>
              <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: "block" }}>
                What this did (simple English)
              </Typography>
              <Alert severity="info" sx={{ mt: 0.5 }}>
                {commandSummary}
              </Alert>
            </>
          ) : null}

          {env.artifacts?.stdoutSnippet ? (
            <>
              <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: "block" }}>
                stdout (snippet)
              </Typography>
              <Box sx={mono(220)}>
                <Typography variant="caption" component="pre" sx={preSx}>
                  {env.artifacts.stdoutSnippet}
                </Typography>
              </Box>
            </>
          ) : null}

          {env.artifacts?.stderrSnippet ? (
            <>
              <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: "block" }}>
                stderr (snippet)
              </Typography>
              <Box sx={mono(160)}>
                <Typography variant="caption" component="pre" sx={preSx}>
                  {env.artifacts.stderrSnippet}
                </Typography>
              </Box>
            </>
          ) : null}

          <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: "block" }}>Live log</Typography>
          <Box sx={mono(280)}>
            <Typography variant="caption" component="pre" sx={preSx}>
              {inv.log || "(no output yet)"}
            </Typography>
          </Box>

          {env.findings?.length ? (
            <>
              <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: "block" }}>Findings</Typography>
              <Stack spacing={0.5} sx={{ mt: 0.5 }}>
                {env.findings.map((f, i) => (
                  <Box key={i} sx={{ p: 0.5 }}>
                    <Typography variant="body2"><strong>[{f.severity?.toUpperCase()}]</strong> {f.title}</Typography>
                    {f.evidence ? <Typography variant="caption" color="text.secondary">{f.evidence.slice(0, 240)}</Typography> : null}
                  </Box>
                ))}
              </Stack>
            </>
          ) : null}

          {webPaths.length ? (
            <>
              <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: "block" }}>
                Web paths discovered
              </Typography>
              <Box sx={mono(180)}>
                <Typography variant="caption" component="pre" sx={preSx}>
                  {webPaths
                    .map((p) => {
                      const u = String(p?.value?.url ?? "");
                      const s = p?.value?.status != null ? `HTTP ${String(p.value.status)}` : "";
                      return `${s}  ${u}`.trim();
                    })
                    .filter(Boolean)
                    .join("\n")}
                </Typography>
              </Box>
            </>
          ) : null}
        </>
      ) : null}
    </Box>
  );
}

function RunContextCard(props: {
  latestSnapshot: {
    pendingVerifications?: number;
    discoveredEndpoints?: number;
    services?: number;
    findings?: number;
    knownPorts?: number[];
  } | null;
}) {
  const { latestSnapshot } = props;
  return (
    <Card>
      <CardContent>
        <Stack direction={{ xs: "column", md: "row" }} alignItems={{ md: "center" }} justifyContent="space-between" spacing={1}>
          <Typography variant="subtitle1">Run context</Typography>
          <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
            {typeof latestSnapshot?.services === "number" ? (
              <Chip size="small" label={`services: ${latestSnapshot.services}`} variant="outlined" />
            ) : null}
            {typeof latestSnapshot?.findings === "number" ? (
              <Chip size="small" label={`findings: ${latestSnapshot.findings}`} variant="outlined" />
            ) : null}
            {typeof latestSnapshot?.discoveredEndpoints === "number" ? (
              <Chip size="small" label={`endpoints: ${latestSnapshot.discoveredEndpoints}`} variant="outlined" />
            ) : null}
            {typeof latestSnapshot?.pendingVerifications === "number" ? (
              <Chip
                size="small"
                label={`pending verifications: ${latestSnapshot.pendingVerifications}`}
                color={latestSnapshot.pendingVerifications > 0 ? "warning" : "default"}
                variant="outlined"
              />
            ) : null}
          </Stack>
        </Stack>
        <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
          The manager LLM picks one tool per step; the worker runs it over SSH. No fixed phase ordering.
        </Typography>
      </CardContent>
    </Card>
  );
}

function WordlistCatalogCard(props: { event: AgentEvent }) {
  const p = (props.event.payload ?? {}) as {
    root?: string;
    rootExists?: boolean;
    totalEntries?: number;
    defaults?: { webContent?: string | null; dnsSubdomains?: string | null; passwords?: string | null; usernames?: string | null } | null;
  };
  return (
    <Card>
      <CardContent>
        <Typography variant="subtitle1" gutterBottom>
          Wordlist catalog (SecLists)
        </Typography>
        {p.rootExists ? (
          <>
            <Typography variant="caption" color="text.secondary">
              Root: <code>{p.root}</code> · {p.totalEntries ?? 0} usable wordlists detected.
            </Typography>
            <Stack direction="row" spacing={1} sx={{ mt: 1 }} flexWrap="wrap" useFlexGap>
              {p.defaults?.webContent ? <Chip size="small" label={`web → ${shortPath(p.defaults.webContent)}`} variant="outlined" /> : null}
              {p.defaults?.dnsSubdomains ? <Chip size="small" label={`dns → ${shortPath(p.defaults.dnsSubdomains)}`} variant="outlined" /> : null}
              {p.defaults?.passwords ? <Chip size="small" label={`pwd → ${shortPath(p.defaults.passwords)}`} variant="outlined" /> : null}
              {p.defaults?.usernames ? <Chip size="small" label={`user → ${shortPath(p.defaults.usernames)}`} variant="outlined" /> : null}
            </Stack>
            <Typography variant="caption" sx={{ display: "block", mt: 1 }} color="text.secondary">
              The manager picks the actual wordlist per invocation; defaults shown above are used when no choice is made.
            </Typography>
          </>
        ) : (
          <Alert severity="warning">
            SecLists root <code>{p.root}</code> is missing on the SSH host. Install SecLists to enable agent-selected wordlists.
          </Alert>
        )}
      </CardContent>
    </Card>
  );
}

function FailureCard(props: { events: AgentEvent[] }) {
  const items = props.events
    .slice(-8)
    .map((e) => {
      const p = (e.payload ?? {}) as {
        step?: number;
        tool?: string;
        attempt?: number;
        error?: string;
        stdoutSnippet?: string;
        stderrSnippet?: string;
        args?: Record<string, unknown>;
      };
      return { id: e.id, createdAt: e.createdAt, ...p };
    })
    .reverse();

  return (
    <Card>
      <CardContent>
        <Stack direction={{ xs: "column", md: "row" }} alignItems={{ md: "center" }} justifyContent="space-between" spacing={1}>
          <Typography variant="subtitle1">Failures & recovery</Typography>
          <Typography variant="caption" color="text.secondary">
            The manager sees these snippets and may retry safely (bounded) or choose an alternate tool.
          </Typography>
        </Stack>
        <Divider sx={{ my: 2 }} />
        <Stack spacing={1}>
          {items.map((f) => (
            <Box key={f.id} sx={{ p: 1, border: "1px solid", borderColor: "divider", borderRadius: 1 }}>
              <Stack direction="row" spacing={1} alignItems="center" justifyContent="space-between" flexWrap="wrap" useFlexGap>
                <Typography variant="body2" sx={{ fontWeight: 600 }}>
                  {f.tool ?? "unknown-tool"}
                </Typography>
                <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
                  {typeof f.step === "number" ? <Chip size="small" label={`step ${f.step}`} variant="outlined" /> : null}
                  {typeof f.attempt === "number" ? <Chip size="small" label={`attempt ${f.attempt + 1}`} variant="outlined" /> : null}
                  <Chip size="small" label="failed" color="error" />
                </Stack>
              </Stack>
              {f.error ? (
                <Alert severity="error" sx={{ mt: 1 }}>
                  {f.error}
                </Alert>
              ) : null}
              {f.args && Object.keys(f.args).length ? (
                <>
                  <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: "block" }}>
                    args
                  </Typography>
                  <Box sx={mono(140)}>
                    <Typography variant="caption" component="pre" sx={preSx}>
                      {JSON.stringify(f.args, null, 2)}
                    </Typography>
                  </Box>
                </>
              ) : null}
              {f.stdoutSnippet ? (
                <>
                  <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: "block" }}>
                    stdout (snippet)
                  </Typography>
                  <Box sx={mono(180)}>
                    <Typography variant="caption" component="pre" sx={preSx}>
                      {f.stdoutSnippet}
                    </Typography>
                  </Box>
                </>
              ) : null}
              {f.stderrSnippet ? (
                <>
                  <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: "block" }}>
                    stderr (snippet)
                  </Typography>
                  <Box sx={mono(180)}>
                    <Typography variant="caption" component="pre" sx={preSx}>
                      {f.stderrSnippet}
                    </Typography>
                  </Box>
                </>
              ) : null}
            </Box>
          ))}
        </Stack>
      </CardContent>
    </Card>
  );
}

function SummaryDialog(props: {
  open: boolean;
  onClose: () => void;
  loading: boolean;
  summary: AgentRunSummary | null;
  error: string | null;
}) {
  const { open, onClose, loading, summary, error } = props;
  const friendlyError = React.useMemo(() => {
    if (!error) return null;
    // React-query errors can include the whole JSON response blob; keep just the actionable part.
    const m = /Ollama HTTP \d+:\s*(.*)$/s.exec(error);
    if (m?.[1]) return `Ollama error: ${m[1].slice(0, 240)}`;
    if (/API 502/i.test(error) && /Ollama/i.test(error)) return "AI summary failed (Ollama). Check Ollama RAM/model availability, then retry.";
    return error.length > 260 ? `${error.slice(0, 260)}…` : error;
  }, [error]);
  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>AI Summary (whole scan)</DialogTitle>
      <DialogContent>
        {loading ? (
          <Stack alignItems="center" spacing={1} sx={{ py: 4 }}>
            <CircularProgress size={28} />
            <Typography variant="caption" color="text.secondary">
              Asking the local LLM to summarise the run…
            </Typography>
          </Stack>
        ) : null}

        {friendlyError ? <Alert severity="error" sx={{ mb: 2 }}>{friendlyError}</Alert> : null}

        {summary ? (
          <Stack spacing={2} sx={{ mt: 1 }}>
            <Stack direction="row" spacing={1} alignItems="center">
              <Chip size="small" label={`risk: ${summary.overallRisk}`} color={RISK_COLOR[summary.overallRisk] ?? "default"} />
              <Chip size="small" label={`mode: ${summary.mode}`} variant="outlined" />
            </Stack>
            <Typography variant="h6">{summary.headline}</Typography>

            {summary.error ? <Alert severity="warning">{summary.error}</Alert> : null}

            <Section title="Key exposures" items={summary.keyExposures} />

            <Box>
              <Typography variant="subtitle2">Prioritized fixes</Typography>
              <ul style={{ margin: 0, paddingLeft: 18 }}>
                {summary.prioritizedFixes.map((f, i) => (
                  <li key={i}>
                    <Typography variant="body2">
                      <strong>{f.priority.toUpperCase()}:</strong> {f.recommendation}
                    </Typography>
                  </li>
                ))}
                {summary.prioritizedFixes.length === 0 ? (
                  <Typography variant="body2" color="text.secondary">No fixes proposed.</Typography>
                ) : null}
              </ul>
            </Box>

            <Section title="What we did" items={summary.whatWeDid} />
            <Section title="Verification steps" items={summary.verificationSteps} />
          </Stack>
        ) : null}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Close</Button>
      </DialogActions>
    </Dialog>
  );
}

function Section(props: { title: string; items: string[] }) {
  return (
    <Box>
      <Typography variant="subtitle2">{props.title}</Typography>
      <ul style={{ margin: 0, paddingLeft: 18 }}>
        {props.items.map((s, i) => (
          <li key={i}>
            <Typography variant="body2">{s}</Typography>
          </li>
        ))}
        {props.items.length === 0 ? (
          <Typography variant="body2" color="text.secondary">—</Typography>
        ) : null}
      </ul>
    </Box>
  );
}

function ReportDialog(props: {
  open: boolean;
  onClose: () => void;
  loading: boolean;
  report: AgentRunReport | null;
  error: string | null;
  onDownloadPdf: () => void;
}) {
  const { open, onClose, loading, report, error, onDownloadPdf } = props;
  const friendlyError = React.useMemo(() => {
    if (!error) return null;
    const m = /Ollama HTTP \d+:\s*(.*)$/s.exec(error);
    if (m?.[1]) return `Ollama error: ${m[1].slice(0, 240)}`;
    if (/API 502/i.test(error) && /Ollama/i.test(error)) return "Detailed report failed (Ollama). Check Ollama RAM/model availability, then retry.";
    return error.length > 260 ? `${error.slice(0, 260)}…` : error;
  }, [error]);

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>Detailed AI report</DialogTitle>
      <DialogContent>
        {loading ? (
          <Stack alignItems="center" spacing={1} sx={{ py: 4 }}>
            <CircularProgress size={28} />
            <Typography variant="caption" color="text.secondary">
              Asking the local LLM to generate a detailed markdown report…
            </Typography>
          </Stack>
        ) : null}

        {friendlyError ? <Alert severity="error" sx={{ mb: 2 }}>{friendlyError}</Alert> : null}

        {report?.error ? <Alert severity="warning" sx={{ mb: 2 }}>{report.error}</Alert> : null}

        {report ? (
          <Box sx={mono(520)}>
            <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
              {report.title} · mode: {report.mode}
            </Typography>
            <Typography variant="caption" component="pre" sx={preSx}>
              {report.markdown}
            </Typography>
          </Box>
        ) : null}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Close</Button>
        <Button
          variant="contained"
          color="error"
          disabled={!report?.markdown}
          onClick={onDownloadPdf}
        >
          Download PDF
        </Button>
      </DialogActions>
    </Dialog>
  );
}

/* ------------------------------------------------------------------ *
 *  Helpers
 * ------------------------------------------------------------------ */

const preSx = { m: 0, whiteSpace: "pre-wrap" as const, wordBreak: "break-word" as const, fontFamily: "monospace" };

function mono(maxHeight: number) {
  return {
    p: 1,
    mt: 0.5,
    bgcolor: "grey.100",
    borderRadius: 1,
    maxHeight,
    overflow: "auto" as const
  };
}

function shortPath(p: string): string {
  if (!p) return "";
  if (p.length < 60) return p;
  const parts = p.split("/");
  return `…/${parts.slice(-3).join("/")}`;
}

function toPlainText(markdown: string): string {
  // Minimal markdown → text conversion for PDF export.
  // Keep headings and bullets readable without pulling in a full renderer.
  return markdown
    .replace(/\r\n/g, "\n")
    .replace(/```[\s\S]*?```/g, (m) => m.replace(/```/g, "")) // keep code, drop fences
    .replace(/#+\s*/g, "") // drop heading hashes
    .replace(/\*\*(.*?)\*\*/g, "$1")
    .replace(/`([^`]+)`/g, "$1")
    .replace(/\[(.*?)\]\((.*?)\)/g, "$1 ($2)")
    .trim();
}

function safeFilename(name: string): string {
  return name.replace(/[<>:\"/\\|?*\u0000-\u001F]+/g, "_").slice(0, 180);
}
