import { useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  Alert,
  Box,
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
import { explainFinding, listFindings, listTargets } from "../../lib/api";

export function FindingsPage() {
  const targetsQ = useQuery({ queryKey: ["targets"], queryFn: listTargets });
  const [targetId, setTargetId] = useState<string>("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const findingsQ = useQuery({
    queryKey: ["findings", targetId, severityFilter, statusFilter],
    queryFn: () =>
      listFindings({
        targetId: targetId || undefined,
        severity: severityFilter === "all" ? undefined : severityFilter,
        status: statusFilter === "all" ? undefined : statusFilter
      }),
    refetchInterval: 2000
  });

  const [dialogOpen, setDialogOpen] = useState(false);
  const [explainData, setExplainData] = useState<null | {
    summary: string;
    whyItMatters: string;
    remediation: string[];
    verification: string[];
  }>(null);
  const [explainError, setExplainError] = useState<string | null>(null);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);

  const explainM = useMutation({
    mutationFn: (fId: string) => explainFinding(fId),
    onMutate: async () => {
      setExplainError(null);
      setExplainData(null);
      setDialogOpen(true);
    },
    onSuccess: (data) => {
      setExplainData(data);
    },
    onError: (e) => {
      setExplainError(String(e));
    }
  });
  const findings = findingsQ.data ?? [];

  const bySeverity = useMemo(() => {
    const m = new Map<string, number>();
    for (const finding of findings) {
      m.set(finding.severity, (m.get(finding.severity) ?? 0) + 1);
    }
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
              <MenuItem value="">All findings</MenuItem>
              {(targetsQ.data ?? []).map((t) => (
                <MenuItem key={t.id} value={t.id}>
                  {t.name} ({t.address})
                </MenuItem>
              ))}
            </Select>
            <Select value={severityFilter} onChange={(e) => setSeverityFilter(String(e.target.value))} fullWidth>
              <MenuItem value="all">All severities</MenuItem>
              {(["critical", "high", "medium", "low", "info"] as const).map((s) => (
                <MenuItem key={s} value={s}>
                  {s}
                </MenuItem>
              ))}
            </Select>
            <Select value={statusFilter} onChange={(e) => setStatusFilter(String(e.target.value))} fullWidth>
              <MenuItem value="all">All statuses</MenuItem>
              {(["open", "triaged", "in_progress", "fixed", "verified", "false_positive", "accepted_risk"] as const).map((s) => (
                <MenuItem key={s} value={s}>
                  {s}
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
          <Typography variant="subtitle1">Results</Typography>
          <Divider sx={{ my: 2 }} />

          {findings.length ? (
            <Stack spacing={1}>
              {findings.map((f) => (
                <Box key={f.id} sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                  <Box sx={{ flexGrow: 1 }}>
                    <Typography variant="body1">
                      {f.title}
                    </Typography>
                    <Stack direction="row" spacing={1} sx={{ mt: 0.5 }}>
                      <Chip size="small" label={f.severity} />
                      <Chip size="small" label={f.status} />
                      <Chip size="small" label={`${f.target.name} (${f.target.address})`} />
                      {f.service ? <Chip size="small" label={`${f.service.port}/${f.service.protocol}`} /> : null}
                    </Stack>
                    <Typography variant="body2" color="text.secondary" sx={{ mt: 0.8 }}>
                      {f.evidenceRedacted}
                    </Typography>
                  </Box>
                  <Box>
                    <Chip
                      clickable
                      color="primary"
                      label="Explain AI"
                      onClick={() => {
                        setSelectedFindingId(f.id);
                        explainM.mutate(f.id);
                      }}
                    />
                  </Box>
                </Box>
              ))}
            </Stack>
          ) : (
            <Typography variant="body2" color="text.secondary">
              No findings match the current filters.
            </Typography>
          )}
        </CardContent>
      </Card>

      <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>AI finding explanation</DialogTitle>
        <DialogContent>
          {explainError ? <Alert severity="error">{explainError}</Alert> : null}
          {explainM.isPending ? <Typography>Generating…</Typography> : null}
          {explainData ? (
            <Stack spacing={2} sx={{ mt: 1 }}>
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
          {!explainData && !explainM.isPending && selectedFindingId ? (
            <Typography variant="body2" color="text.secondary">
              Unable to generate explanation for this finding.
            </Typography>
          ) : null}
        </DialogContent>
      </Dialog>
    </Box>
  );
}

