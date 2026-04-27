import { useMutation, useQuery } from "@tanstack/react-query";
import { Alert, Box, Button, Card, CardContent, Chip, Divider, Stack, Typography } from "@mui/material";
import { useParams } from "react-router-dom";
import { cancelScan, getScan } from "../../lib/api";

export function RunDetailPage() {
  const { id } = useParams();

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
    </Box>
  );
}

