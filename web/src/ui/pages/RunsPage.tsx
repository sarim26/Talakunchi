import React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Divider,
  MenuItem,
  Select,
  Stack,
  Typography
} from "@mui/material";
import { Link } from "react-router-dom";
import { createScan, listScans, listTargets } from "../../lib/api";

export function RunsPage() {
  const qc = useQueryClient();
  const targetsQ = useQuery({ queryKey: ["targets"], queryFn: listTargets });
  const runsQ = useQuery({ queryKey: ["runs"], queryFn: listScans, refetchInterval: 2000 });
  const [selectedTargetId, setSelectedTargetId] = React.useState<string>("");

  const scanM = useMutation({
    mutationFn: createScan,
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["runs"] });
    }
  });

  const targets = targetsQ.data ?? [];
  const runs = runsQ.data ?? [];

  return (
    <Box>
      <Typography variant="h5" gutterBottom>
        Scan runs
      </Typography>

      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Typography variant="subtitle1" gutterBottom>
            Start a scan (mock mode for now)
          </Typography>
          {targetsQ.isError ? <Alert severity="error">Failed to load targets.</Alert> : null}
          <Stack direction={{ xs: "column", md: "row" }} spacing={2} alignItems="center">
            <Select
              value={selectedTargetId}
              onChange={(e) => setSelectedTargetId(String(e.target.value))}
              displayEmpty
              fullWidth
            >
              <MenuItem value="" disabled>
                Select target
              </MenuItem>
              {targets.map((t) => (
                <MenuItem key={t.id} value={t.id}>
                  {t.name} ({t.address})
                </MenuItem>
              ))}
            </Select>
            <Button
              variant="contained"
              disabled={!selectedTargetId || scanM.isPending}
              onClick={() => scanM.mutate({ targetId: selectedTargetId, profile: "network_surface_safe" })}
              sx={{ minWidth: 150 }}
            >
              Run scan
            </Button>
          </Stack>
          {scanM.isError ? <Alert severity="error" sx={{ mt: 2 }}>{`${scanM.error}`}</Alert> : null}
        </CardContent>
      </Card>

      <Card>
        <CardContent>
          <Typography variant="subtitle1">Recent runs</Typography>
          <Divider sx={{ my: 2 }} />

          {runsQ.isError ? <Alert severity="error">Failed to load runs.</Alert> : null}
          {runs.length ? (
            <Stack spacing={1}>
              {runs.map((r) => (
                <Box key={r.id} sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                  <Box sx={{ flexGrow: 1 }}>
                    <Typography variant="body1">
                      <Link to={`/runs/${r.id}`}>{r.target.name}</Link>
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {r.profile} · {r.status}
                    </Typography>
                  </Box>
                  <Button component={Link} to={`/runs/${r.id}`} size="small">
                    View
                  </Button>
                </Box>
              ))}
            </Stack>
          ) : (
            <Typography variant="body2" color="text.secondary">
              No runs yet. Add a target and run your first scan.
            </Typography>
          )}
        </CardContent>
      </Card>
    </Box>
  );
}

