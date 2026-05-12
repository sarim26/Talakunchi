import React from "react";
import { useQuery } from "@tanstack/react-query";
import { Alert, Box, Card, CardContent, Chip, Divider, Stack, Typography } from "@mui/material";
import { AgentEvent, AgentInvocation, AgentRun, getAgentRun, getAgentRunEvents, getAgentRunInvocations, listAgentRuns } from "../../lib/api";

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

export function BackendPage() {
  const [selectedRunId, setSelectedRunId] = React.useState<string | null>(null);

  const runsQ = useQuery({
    queryKey: ["agent-runs", "backend"],
    queryFn: () => listAgentRuns({ limit: 500 }),
    refetchInterval: 5000
  });

  const runQ = useQuery({
    queryKey: ["agent-run", "backend", selectedRunId],
    queryFn: () => getAgentRun(selectedRunId as string),
    enabled: Boolean(selectedRunId),
    refetchInterval: 4000
  });
  const invocationsQ = useQuery({
    queryKey: ["agent-run-invocations", "backend", selectedRunId],
    queryFn: () => getAgentRunInvocations(selectedRunId as string),
    enabled: Boolean(selectedRunId),
    refetchInterval: 4000
  });
  const eventsQ = useQuery({
    queryKey: ["agent-run-events", "backend", selectedRunId],
    queryFn: () => getAgentRunEvents(selectedRunId as string),
    enabled: Boolean(selectedRunId),
    refetchInterval: 4000
  });

  const runs = runsQ.data ?? [];
  const run = runQ.data ?? null;
  const invocations = invocationsQ.data ?? [];
  const events = eventsQ.data ?? [];

  const decisionEvents = events.filter((e) => e.kind === "manager.decision");
  const promptEvents = events.filter((e) => e.kind === "prompter.output");
  const writerEvents = events.filter((e) => e.kind === "execution_writer.output");

  return (
    <Box>
      <Typography variant="h5" gutterBottom>
        Backend
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Raw run telemetry for debugging: all runs + per-run manager decisions, prompter output, execution-writer output, and the full raw bundle.
      </Typography>

      <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", md: "minmax(0,1fr) minmax(0,2fr)" }, gap: 2 }}>
        <Card>
          <CardContent>
            <Typography variant="subtitle1" gutterBottom>
              All runs
            </Typography>
            {runsQ.isError ? <Alert severity="error">{(runsQ.error as Error).message}</Alert> : null}
            <Box sx={mono(560)}>
              <Stack spacing={0.75}>
                {runs.map((r: AgentRun) => (
                  <Box
                    key={r.id}
                    onClick={() => setSelectedRunId(r.id)}
                    sx={{
                      p: 1,
                      border: "1px solid",
                      borderColor: selectedRunId === r.id ? "error.main" : "divider",
                      borderRadius: 1,
                      cursor: "pointer"
                    }}
                  >
                    <Stack direction="row" justifyContent="space-between" alignItems="center" spacing={1}>
                      <Typography variant="caption" sx={{ fontWeight: 700, minWidth: 0 }}>
                        {r.target.name} <span style={{ fontWeight: 400, opacity: 0.7 }}>({r.target.address})</span>
                      </Typography>
                      <Chip size="small" label={r.status} variant="outlined" />
                    </Stack>
                    <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                      {new Date(r.createdAt).toLocaleString()} · steps {r.stepsTaken}/{r.maxSteps} · invocations {r.invocationCount} · findings {r.findingCount}
                    </Typography>
                  </Box>
                ))}
                {runs.length === 0 && !runsQ.isLoading ? (
                  <Typography variant="body2" color="text.secondary">
                    No runs yet.
                  </Typography>
                ) : null}
              </Stack>
            </Box>
          </CardContent>
        </Card>

        <Stack spacing={2} sx={{ minWidth: 0 }}>
          <Card>
            <CardContent>
              <Typography variant="subtitle1" gutterBottom>
                Selected run
              </Typography>
              {!selectedRunId ? (
                <Typography variant="body2" color="text.secondary">
                  Select a run on the left.
                </Typography>
              ) : (
                <>
                  <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                    <Chip size="small" label={`runId: ${selectedRunId}`} variant="outlined" />
                    {run ? <Chip size="small" label={`status: ${run.status}`} variant="outlined" /> : null}
                    <Chip size="small" label={`events: ${events.length}`} variant="outlined" />
                    <Chip size="small" label={`invocations: ${invocations.length}`} variant="outlined" />
                  </Stack>
                  {runQ.isError ? <Alert severity="error" sx={{ mt: 1 }}>{(runQ.error as Error).message}</Alert> : null}
                  {eventsQ.isError ? <Alert severity="error" sx={{ mt: 1 }}>{(eventsQ.error as Error).message}</Alert> : null}
                  {invocationsQ.isError ? <Alert severity="error" sx={{ mt: 1 }}>{(invocationsQ.error as Error).message}</Alert> : null}
                </>
              )}
            </CardContent>
          </Card>

          <RawSection title="Manager decisions (all)" items={decisionEvents} />
          <RawSection title="Execution writer outputs (all)" items={writerEvents} />
          <RawSection title="Prompter outputs (all)" items={promptEvents} />

          <Card>
            <CardContent>
              <Typography variant="subtitle1" gutterBottom>
                Raw backend bundle
              </Typography>
              <Divider sx={{ mb: 1 }} />
              <Box sx={mono(520)}>
                <Typography component="pre" variant="caption" sx={preSx}>
                  {JSON.stringify({ run, invocations, events }, null, 2)}
                </Typography>
              </Box>
            </CardContent>
          </Card>
        </Stack>
      </Box>
    </Box>
  );
}

function RawSection(props: { title: string; items: AgentEvent[] }) {
  const { title, items } = props;
  return (
    <Card>
      <CardContent>
        <Typography variant="subtitle1" gutterBottom>
          {title}
        </Typography>
        {items.length === 0 ? (
          <Typography variant="body2" color="text.secondary">
            — none —
          </Typography>
        ) : (
          <Box sx={mono(280)}>
            <Typography component="pre" variant="caption" sx={preSx}>
              {items.map((e) => JSON.stringify({ createdAt: e.createdAt, kind: e.kind, payload: e.payload }, null, 2)).join("\n\n")}
            </Typography>
          </Box>
        )}
      </CardContent>
    </Card>
  );
}

