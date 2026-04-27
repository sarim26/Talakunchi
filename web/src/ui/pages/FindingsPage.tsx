import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Dialog,
  DialogContent,
  DialogTitle,
  Divider,
  MenuItem,
  Select,
  Stack,
  Typography
} from "@mui/material";
import { explainFinding, listFindings, listTargets, updateFinding } from "../../lib/api";

export function FindingsPage() {
  const qc = useQueryClient();
  const targetsQ = useQuery({ queryKey: ["targets"], queryFn: listTargets });
  const [targetId, setTargetId] = useState<string>("");
  const findingsQ = useQuery({
    queryKey: ["findings", targetId],
    queryFn: () => listFindings(targetId ? { targetId } : undefined),
    refetchInterval: 2000
  });

  const [dialogOpen, setDialogOpen] = useState(false);
  const [explainData, setExplainData] = useState<null | {
    summary: string;
    whyItMatters: string;
    remediation: string[];
    verification: string[];
    suggestedSeverity?: "info" | "low" | "medium" | "high" | "critical";
  }>(null);
  const [explainError, setExplainError] = useState<string | null>(null);
  const [explainedFindingId, setExplainedFindingId] = useState<string | null>(null);

  const statusM = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) => updateFinding(id, { status }),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["findings"], exact: false });
    }
  });

  const explainM = useMutation({
    mutationFn: (id: string) => explainFinding(id),
    onMutate: async () => {
      setExplainError(null);
      setExplainData(null);
      setExplainedFindingId(null);
      setDialogOpen(true);
    },
    onSuccess: (data) => {
      setExplainData(data);
    },
    onError: (e) => {
      setExplainError(String(e));
    }
  });

  const applySeverityM = useMutation({
    mutationFn: ({ id, severity }: { id: string; severity: string }) => updateFinding(id, { severity }),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["findings"], exact: false });
    }
  });

  const findings = findingsQ.data ?? [];

  const bySeverity = useMemo(() => {
    const m = new Map<string, number>();
    for (const f of findings) m.set(f.severity, (m.get(f.severity) ?? 0) + 1);
    return m;
  }, [findings]);

  return (
    <Box>
      <Typography variant="h5" gutterBottom>
        Findings
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
            <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
              {(["critical", "high", "medium", "low", "info"] as const).map((s) => (
                <Chip key={s} label={`${s}: ${bySeverity.get(s) ?? 0}`} />
              ))}
            </Stack>
          </Stack>
        </CardContent>
      </Card>

      {findingsQ.isError ? <Alert severity="error">Failed to load findings.</Alert> : null}

      <Card>
        <CardContent>
          <Typography variant="subtitle1">Latest findings</Typography>
          <Divider sx={{ my: 2 }} />

          {findings.length ? (
            <Stack spacing={1}>
              {findings.map((f) => (
                <Box key={f.id} sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                  <Box sx={{ flexGrow: 1 }}>
                    <Typography variant="body1">{f.title}</Typography>
                    <Typography variant="body2" color="text.secondary">
                      {f.target.name} · {f.service ? `${f.service.port}/${f.service.protocol}` : "n/a"} ·{" "}
                      {f.severity}
                    </Typography>
                  </Box>
                  <Select
                    size="small"
                    value={f.status}
                    onChange={(e) => statusM.mutate({ id: f.id, status: String(e.target.value) })}
                  >
                    {["open", "triaged", "in_progress", "fixed", "verified", "false_positive", "accepted_risk"].map(
                      (s) => (
                        <MenuItem key={s} value={s}>
                          {s}
                        </MenuItem>
                      )
                    )}
                  </Select>
                  <Button
                    variant="outlined"
                    size="small"
                    onClick={() => {
                      setExplainedFindingId(f.id);
                      explainM.mutate(f.id);
                    }}
                  >
                    Explain (AI)
                  </Button>
                </Box>
              ))}
            </Stack>
          ) : (
            <Typography variant="body2" color="text.secondary">
              No findings yet. Run a scan to generate prototype data.
            </Typography>
          )}
        </CardContent>
      </Card>

      <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>AI explanation</DialogTitle>
        <DialogContent>
          {explainError ? <Alert severity="error">{explainError}</Alert> : null}
          {explainM.isPending ? <Typography>Generating…</Typography> : null}
          {explainData ? (
            <Stack spacing={2} sx={{ mt: 1 }}>
              {explainData.suggestedSeverity && explainedFindingId ? (
                <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                  <Alert severity="info" sx={{ flexGrow: 1 }}>
                    Suggested severity: <b>{explainData.suggestedSeverity}</b>
                  </Alert>
                  <Button
                    variant="contained"
                    disabled={applySeverityM.isPending}
                    onClick={() =>
                      applySeverityM.mutate({
                        id: explainedFindingId,
                        severity: explainData.suggestedSeverity!
                      })
                    }
                  >
                    Apply
                  </Button>
                </Box>
              ) : null}
              <Box>
                <Typography variant="subtitle2">Summary</Typography>
                <Typography variant="body2">{explainData.summary}</Typography>
              </Box>
              <Box>
                <Typography variant="subtitle2">Why it matters</Typography>
                <Typography variant="body2">{explainData.whyItMatters}</Typography>
              </Box>
              <Box>
                <Typography variant="subtitle2">Recommended remediation</Typography>
                <ul>
                  {explainData.remediation.map((r, i) => (
                    <li key={i}>
                      <Typography variant="body2">{r}</Typography>
                    </li>
                  ))}
                </ul>
              </Box>
              <Box>
                <Typography variant="subtitle2">Verification</Typography>
                <ul>
                  {explainData.verification.map((r, i) => (
                    <li key={i}>
                      <Typography variant="body2">{r}</Typography>
                    </li>
                  ))}
                </ul>
              </Box>
            </Stack>
          ) : null}
        </DialogContent>
      </Dialog>
    </Box>
  );
}

