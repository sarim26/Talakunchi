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
import { explainSurface, listServices, listTargets } from "../../lib/api";

export function FindingsPage() {
  const targetsQ = useQuery({ queryKey: ["targets"], queryFn: listTargets });
  const [targetId, setTargetId] = useState<string>("");
  const servicesQ = useQuery({
    queryKey: ["services", targetId],
    queryFn: () => listServices(targetId),
    enabled: Boolean(targetId),
    refetchInterval: 2000
  });

  const [dialogOpen, setDialogOpen] = useState(false);
  const [explainData, setExplainData] = useState<null | {
    summary: string;
    keyRisks: string[];
    topExposures: Array<{ port: number; protocol: string; risk: "low" | "medium" | "high" | "critical"; reason: string }>;
    remediation: string[];
    verification: string[];
  }>(null);
  const [explainError, setExplainError] = useState<string | null>(null);

  const explainM = useMutation({
    mutationFn: (tId: string) => explainSurface(tId),
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
  const services = servicesQ.data ?? [];

  const bySeverity = useMemo(() => {
    const m = new Map<string, number>();
    // Surface view doesn't store severity counts per-port; keep chips but show counts from AI later.
    return m;
  }, []);

  return (
    <Box>
      <Typography variant="h5" gutterBottom>
        Surface summary
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
            <Button
              variant="contained"
              disabled={!targetId || explainM.isPending}
              onClick={() => explainM.mutate(targetId)}
            >
              Explain with AI
            </Button>
          </Stack>
        </CardContent>
      </Card>

      {servicesQ.isError ? <Alert severity="error">Failed to load services.</Alert> : null}

      <Card>
        <CardContent>
          <Typography variant="subtitle1">Open ports & services</Typography>
          <Divider sx={{ my: 2 }} />

          {services.length ? (
            <Stack spacing={1}>
              {services.map((s) => (
                <Box key={s.id} sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                  <Box sx={{ flexGrow: 1 }}>
                    <Typography variant="body1">
                      {s.port}/{s.protocol}{" "}
                      <Typography component="span" color="text.secondary">
                        {s.serviceName ?? "unknown"} {s.product ?? ""} {s.version ?? ""}
                      </Typography>
                    </Typography>
                    {s.banner ? (
                      <Typography variant="body2" color="text.secondary">
                        {s.banner}
                      </Typography>
                    ) : null}
                  </Box>
                </Box>
              ))}
            </Stack>
          ) : (
            <Typography variant="body2" color="text.secondary">
              Select a target and run a scan to populate services.
            </Typography>
          )}
        </CardContent>
      </Card>

      <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>AI summary (all open ports)</DialogTitle>
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
                <Typography variant="subtitle2">Key risks</Typography>
                <ul>
                  {explainData.keyRisks.map((r, i) => (
                    <li key={i}>
                      <Typography variant="body2">{r}</Typography>
                    </li>
                  ))}
                </ul>
              </Box>
              <Box>
                <Typography variant="subtitle2">Top exposures</Typography>
                <ul>
                  {explainData.topExposures.map((x, i) => (
                    <li key={i}>
                      <Typography variant="body2">
                        {x.port}/{x.protocol} — <b>{x.risk}</b> — {x.reason}
                      </Typography>
                    </li>
                  ))}
                </ul>
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

