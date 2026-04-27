import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Stack,
  TextField,
  Typography
} from "@mui/material";
import { confirmReset, listFindings, listScans, listTargets, requestReset } from "../../lib/api";

export function OverviewPage() {
  const qc = useQueryClient();
  const targetsQ = useQuery({ queryKey: ["targets"], queryFn: listTargets });
  const runsQ = useQuery({ queryKey: ["runs"], queryFn: listScans, refetchInterval: 2000 });
  const findingsQ = useQuery({ queryKey: ["findings"], queryFn: () => listFindings(), refetchInterval: 2000 });
  const [resetOpen, setResetOpen] = React.useState(false);
  const [resetCode, setResetCode] = React.useState<string | null>(null);
  const [typed, setTyped] = React.useState("");

  const requestM = useMutation({
    mutationFn: requestReset,
    onSuccess: (d) => {
      setResetCode(d.code);
    }
  });

  const confirmM = useMutation({
    mutationFn: (code: string) => confirmReset(code),
    onSuccess: async () => {
      setResetOpen(false);
      setResetCode(null);
      setTyped("");
      await qc.invalidateQueries();
    }
  });

  if (targetsQ.isError || runsQ.isError || findingsQ.isError) {
    return <Alert severity="error">Failed to load overview data.</Alert>;
  }

  const findings = findingsQ.data ?? [];
  const bySeverity = findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, {});

  return (
    <Box>
      <Typography variant="h5" gutterBottom>
        Overview
      </Typography>

      <Box
        sx={{
          display: "grid",
          gridTemplateColumns: { xs: "1fr", md: "repeat(3, 1fr)" },
          gap: 2
        }}
      >
        <Box>
          <Card>
            <CardContent>
              <Typography variant="overline">Targets</Typography>
              <Typography variant="h4">{targetsQ.data?.length ?? 0}</Typography>
            </CardContent>
          </Card>
        </Box>
        <Box>
          <Card>
            <CardContent>
              <Typography variant="overline">Recent runs</Typography>
              <Typography variant="h4">{runsQ.data?.length ?? 0}</Typography>
            </CardContent>
          </Card>
        </Box>
        <Box>
          <Card>
            <CardContent>
              <Typography variant="overline">Open findings</Typography>
              <Typography variant="h4">{findings.length}</Typography>
            </CardContent>
          </Card>
        </Box>

        <Box sx={{ gridColumn: { xs: "1 / -1", md: "1 / -1" } }}>
          <Card>
            <CardContent>
              <Typography variant="subtitle1" gutterBottom>
                Findings by severity
              </Typography>
              <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                {(["critical", "high", "medium", "low", "info"] as const).map((s) => (
                  <Chip key={s} label={`${s}: ${bySeverity[s] ?? 0}`} />
                ))}
              </Stack>
              <Typography variant="body2" sx={{ mt: 2, color: "text.secondary" }}>
                This is prototype data. Scans run in mock mode until you add your real `10.x.x.x` target.
              </Typography>

              <Box sx={{ mt: 2 }}>
                <Button
                  variant="outlined"
                  color="error"
                  onClick={() => {
                    setResetOpen(true);
                    requestM.mutate();
                  }}
                >
                  Reset demo database
                </Button>
              </Box>
            </CardContent>
          </Card>
        </Box>
      </Box>

      <Dialog open={resetOpen} onClose={() => setResetOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Reset demo database</DialogTitle>
        <DialogContent>
          <Alert severity="warning" sx={{ mb: 2 }}>
            This permanently deletes all targets, runs, services, and findings from Postgres and clears Neo4j.
          </Alert>
          {requestM.isError ? <Alert severity="error">{`${requestM.error}`}</Alert> : null}
          <Typography variant="body2" sx={{ mb: 1 }}>
            Type the confirmation code to proceed:
          </Typography>
          <Typography variant="h6" sx={{ letterSpacing: 2, mb: 2 }}>
            {resetCode ?? "…"}
          </Typography>
          <TextField
            label="Confirmation code"
            value={typed}
            onChange={(e) => setTyped(e.target.value)}
            fullWidth
          />
          {confirmM.isError ? <Alert severity="error" sx={{ mt: 2 }}>{`${confirmM.error}`}</Alert> : null}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setResetOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            color="error"
            disabled={!resetCode || typed.trim().toUpperCase() !== resetCode || confirmM.isPending}
            onClick={() => confirmM.mutate(typed.trim().toUpperCase())}
          >
            Delete everything
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

import React from "react";

