import { useQuery } from "@tanstack/react-query";
import { Alert, Box, Card, CardContent, Chip, Stack, Typography } from "@mui/material";
import { listFindings, listScans, listTargets } from "../../lib/api";

export function OverviewPage() {
  const targetsQ = useQuery({ queryKey: ["targets"], queryFn: listTargets });
  const runsQ = useQuery({ queryKey: ["runs"], queryFn: listScans, refetchInterval: 2000 });
  const findingsQ = useQuery({ queryKey: ["findings"], queryFn: () => listFindings(), refetchInterval: 2000 });

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
            </CardContent>
          </Card>
        </Box>
      </Box>
    </Box>
  );
}

