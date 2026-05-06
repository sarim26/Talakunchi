import { useMutation, useQuery } from "@tanstack/react-query";
import { Alert, Box, Button, Card, CardContent, Chip, Divider, Stack, TextField, Typography } from "@mui/material";
import { useParams } from "react-router-dom";
import { cancelScan, getScan, listScanMessages, postScanMessage, resumeScan } from "../../lib/api";
import { useMemo, useState } from "react";

export function RunDetailPage() {
  const { id } = useParams();
  const [draft, setDraft] = useState("");

  const cancelM = useMutation({
    mutationFn: async () => {
      if (!id) throw new Error("Missing scan id");
      return cancelScan(id);
    }
  });

  const runQ = useQuery({
    queryKey: ["run", id],
    queryFn: () => getScan(id!),
    enabled: Boolean(id),
    refetchInterval: 1000
  });

  const msgsQ = useQuery({
    queryKey: ["run", id, "messages"],
    queryFn: () => listScanMessages(id!),
    enabled: Boolean(id),
    refetchInterval: 1500
  });

  const canResume = useMemo(() => {
    const status = runQ.data?.status;
    return Boolean(status && status !== "running" && status !== "queued");
  }, [runQ.data?.status]);

  const sendM = useMutation({
    mutationFn: async (vars: { content: string; resume?: boolean }) => {
      if (!id) throw new Error("Missing scan id");
      return postScanMessage({ scanRunId: id, content: vars.content, resume: vars.resume });
    }
  });

  const resumeM = useMutation({
    mutationFn: async (note?: string) => {
      if (!id) throw new Error("Missing scan id");
      return resumeScan(id, note);
    }
  });

  if (runQ.isLoading) return <Typography>Loading…</Typography>;
  if (runQ.isError) return <Alert severity="error">Failed to load run.</Alert>;

  const run = runQ.data!;

  return (
    <Box>
      <Typography variant="h5" gutterBottom>
        Run details
      </Typography>

      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Typography variant="subtitle1">
            {run.target.name} <Typography component="span" color="text.secondary">({run.target.address})</Typography>
          </Typography>
          <Stack direction="row" spacing={1} sx={{ mt: 1 }} alignItems="center">
            <Chip label={`profile: ${run.profile}`} />
            <Chip label={`status: ${run.status}`} color={run.status === "succeeded" ? "success" : "default"} />
            {run.status === "running" ? (
              <Button
                variant="contained"
                color="error"
                size="small"
                disabled={cancelM.isPending}
                onClick={async () => {
                  await cancelM.mutateAsync();
                  await runQ.refetch();
                }}
              >
                Stop scan
              </Button>
            ) : null}
          </Stack>
          {cancelM.isError ? <Alert severity="error" sx={{ mt: 2 }}>{`${cancelM.error}`}</Alert> : null}
        </CardContent>
      </Card>

      <Card>
        <CardContent>
          <Typography variant="subtitle1">Steps</Typography>
          <Divider sx={{ my: 2 }} />

          <Stack spacing={2}>
            {run.steps.map((s) => (
              <Card key={s.id} variant="outlined">
                <CardContent>
                  <Stack direction="row" spacing={1} alignItems="center" justifyContent="space-between">
                    <Typography variant="body1">{s.name}</Typography>
                    <Chip label={s.status} />
                  </Stack>
                  {s.log ? (
                    <Box
                      component="pre"
                      sx={{
                        mt: 1,
                        p: 1,
                        borderRadius: 1,
                        bgcolor: "grey.100",
                        overflowX: "auto",
                        fontSize: 12
                      }}
                    >
                      {s.log}
                    </Box>
                  ) : null}
                </CardContent>
              </Card>
            ))}
          </Stack>
        </CardContent>
      </Card>

      <Card sx={{ mt: 2 }}>
        <CardContent>
          <Stack direction="row" alignItems="center" justifyContent="space-between" spacing={2}>
            <Typography variant="subtitle1">Chat (per run)</Typography>
            <Button
              size="small"
              variant="outlined"
              disabled={!canResume || resumeM.isPending}
              onClick={async () => {
                await resumeM.mutateAsync(draft.trim() || undefined);
                setDraft("");
                await runQ.refetch();
              }}
            >
              Resume scan
            </Button>
          </Stack>

          <Divider sx={{ my: 2 }} />

          {msgsQ.isError ? <Alert severity="error">Failed to load messages.</Alert> : null}

          <Box
            sx={{
              border: "1px solid",
              borderColor: "divider",
              borderRadius: 1,
              p: 1,
              bgcolor: "grey.50",
              height: 220,
              overflowY: "auto",
              fontSize: 13
            }}
          >
            <Stack spacing={1}>
              {(msgsQ.data ?? []).map((m) => (
                <Box key={m.id}>
                  <Typography variant="caption" color="text.secondary">
                    {m.role}
                  </Typography>
                  <Typography variant="body2" sx={{ whiteSpace: "pre-wrap" }}>
                    {m.content}
                  </Typography>
                </Box>
              ))}
              {(msgsQ.data ?? []).length === 0 ? (
                <Typography variant="body2" color="text.secondary">
                  No messages yet. Write “continue scanning” or ask for a specific next step.
                </Typography>
              ) : null}
            </Stack>
          </Box>

          <Stack direction="row" spacing={1} sx={{ mt: 2 }}>
            <TextField
              fullWidth
              size="small"
              placeholder='e.g. "Continue scanning from where you left off. Focus on web ports."'
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={async (e) => {
                if (e.key !== "Enter" || e.shiftKey) return;
                e.preventDefault();
                const content = draft.trim();
                if (!content) return;
                await sendM.mutateAsync({ content, resume: canResume });
                setDraft("");
                await msgsQ.refetch();
                await runQ.refetch();
              }}
            />
            <Button
              variant="contained"
              disabled={sendM.isPending || !draft.trim()}
              onClick={async () => {
                const content = draft.trim();
                if (!content) return;
                await sendM.mutateAsync({ content, resume: canResume });
                setDraft("");
                await msgsQ.refetch();
                await runQ.refetch();
              }}
            >
              Send{canResume ? " & resume" : ""}
            </Button>
          </Stack>

          {sendM.isError ? <Alert severity="error" sx={{ mt: 2 }}>{`${sendM.error}`}</Alert> : null}
          {resumeM.isError ? <Alert severity="error" sx={{ mt: 2 }}>{`${resumeM.error}`}</Alert> : null}
        </CardContent>
      </Card>
    </Box>
  );
}

