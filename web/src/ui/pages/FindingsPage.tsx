import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Alert,
  Box,
  Card,
  CardContent,
  Chip,
  Divider,
  MenuItem,
  Select,
  Stack,
  Typography
} from "@mui/material";
import { listFindings, listTargets } from "../../lib/api";

/**
 * Findings list. Per-finding "Explain AI" was intentionally removed —
 * AI summarisation now happens once per agentic-recon run from the
 * Agentic Recon page (one summary covering the whole scan).
 */
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

      <Alert severity="info" sx={{ mb: 2 }}>
        AI explanations are now generated once per run from the <strong>Agentic Recon</strong> page (one summary covering the whole scan).
      </Alert>

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
                    <Typography variant="body1">{f.title}</Typography>
                    <Stack direction="row" spacing={1} sx={{ mt: 0.5 }} flexWrap="wrap" useFlexGap>
                      <Chip size="small" label={f.severity} />
                      <Chip size="small" label={f.status} />
                      <Chip size="small" label={`${f.target.name} (${f.target.address})`} />
                      {f.service ? <Chip size="small" label={`${f.service.port}/${f.service.protocol}`} /> : null}
                    </Stack>
                    <Typography variant="body2" color="text.secondary" sx={{ mt: 0.8 }}>
                      {f.evidenceRedacted}
                    </Typography>
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
    </Box>
  );
}
