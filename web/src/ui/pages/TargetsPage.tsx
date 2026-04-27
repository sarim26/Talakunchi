import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Divider,
  Stack,
  TextField,
  Typography
} from "@mui/material";
import { createTarget, listTargets } from "../../lib/api";

export function TargetsPage() {
  const qc = useQueryClient();
  const targetsQ = useQuery({ queryKey: ["targets"], queryFn: listTargets });
  const [name, setName] = useState("WIN-LAB-01");
  const [address, setAddress] = useState("10.0.0.10");
  const [tags, setTags] = useState("lab,staging");

  const createM = useMutation({
    mutationFn: createTarget,
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["targets"] });
    }
  });

  const tagList = useMemo(
    () =>
      tags
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean),
    [tags]
  );

  return (
    <Box>
      <Typography variant="h5" gutterBottom>
        Targets
      </Typography>

      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Typography variant="subtitle1" gutterBottom>
            Add target
          </Typography>
          <Stack direction={{ xs: "column", md: "row" }} spacing={2}>
            <TextField label="Name" value={name} onChange={(e) => setName(e.target.value)} fullWidth />
            <TextField
              label="IP/Hostname"
              value={address}
              onChange={(e) => setAddress(e.target.value)}
              fullWidth
            />
            <TextField
              label="Tags (comma separated)"
              value={tags}
              onChange={(e) => setTags(e.target.value)}
              fullWidth
            />
            <Button
              variant="contained"
              onClick={() => createM.mutate({ name, address, tags: tagList })}
              disabled={createM.isPending}
              sx={{ minWidth: 150 }}
            >
              Add
            </Button>
          </Stack>
          {createM.isError ? <Alert severity="error" sx={{ mt: 2 }}>{`${createM.error}`}</Alert> : null}
        </CardContent>
      </Card>

      <Card>
        <CardContent>
          <Typography variant="subtitle1">Registered targets</Typography>
          <Divider sx={{ my: 2 }} />

          {targetsQ.isError ? <Alert severity="error">Failed to load targets.</Alert> : null}
          {targetsQ.data?.length ? (
            <Stack spacing={1}>
              {targetsQ.data.map((t) => (
                <Box key={t.id} sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                  <Box sx={{ flexGrow: 1 }}>
                    <Typography variant="body1">{t.name}</Typography>
                    <Typography variant="body2" color="text.secondary">
                      {t.address}
                    </Typography>
                  </Box>
                  <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                    {t.tags.map((tag) => (
                      <Chip key={tag} label={tag} size="small" />
                    ))}
                  </Stack>
                </Box>
              ))}
            </Stack>
          ) : (
            <Typography variant="body2" color="text.secondary">
              No targets yet. Add your lab machine to get started.
            </Typography>
          )}
        </CardContent>
      </Card>
    </Box>
  );
}

