import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Alert, Box, Card, CardContent, MenuItem, Select, Stack, Typography } from "@mui/material";
import ReactFlow, { Background, Controls, Edge, Node } from "reactflow";
import "reactflow/dist/style.css";
import { getGraphForTarget, listTargets } from "../../lib/api";

export function GraphPage() {
  const targetsQ = useQuery({ queryKey: ["targets"], queryFn: listTargets });
  const [targetId, setTargetId] = useState<string>("");

  const graphQ = useQuery({
    queryKey: ["graph", targetId],
    queryFn: () => getGraphForTarget(targetId),
    enabled: Boolean(targetId),
    refetchInterval: 2000
  });

  const { nodes, edges } = useMemo(() => {
    if (!graphQ.data) return { nodes: [] as Node[], edges: [] as Edge[] };
    const t = graphQ.data.target;
    const services = graphQ.data.services ?? [];
    const findings = graphQ.data.findings ?? [];
    const apiEdges = (graphQ.data as any).edges ?? [];

    const nodes: Node[] = [];
    const edges: Edge[] = [];

    nodes.push({
      id: `target:${t.id}`,
      data: { label: `${t.name}\n${t.address}` },
      position: { x: 0, y: 0 },
      style: { border: "1px solid #1976d2", padding: 10, borderRadius: 8 }
    });

    services.forEach((s: any, idx: number) => {
      nodes.push({
        id: `service:${s.id}`,
        data: { label: `${s.port}/${s.protocol}\n${s.name || "service"}` },
        position: { x: -300 + (idx % 3) * 300, y: 160 + Math.floor(idx / 3) * 120 },
        style: { border: "1px solid #6d4c41", padding: 10, borderRadius: 8 }
      });
    });

    findings.forEach((f: any, idx: number) => {
      nodes.push({
        id: `finding:${f.id}`,
        data: { label: `${(f.severity || "").toUpperCase()}\n${f.title}` },
        position: { x: 380, y: 160 + idx * 90 },
        style: { border: "1px solid #d32f2f", padding: 10, borderRadius: 8, maxWidth: 280 }
      });
    });

    apiEdges.forEach((e: any) => {
      if (!e?.source || !e?.target) return;
      edges.push({ id: e.id ?? `${e.source}->${e.target}`, source: e.source, target: e.target });
    });

    return { nodes, edges };
  }, [graphQ.data]);

  return (
    <Box>
      <Typography variant="h5" gutterBottom>
        Attack surface graph (Neo4j)
      </Typography>

      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Stack direction={{ xs: "column", md: "row" }} spacing={2} alignItems="center">
            <Select value={targetId} onChange={(e) => setTargetId(String(e.target.value))} displayEmpty fullWidth>
              <MenuItem value="" disabled>
                Select target
              </MenuItem>
              {(targetsQ.data ?? []).map((t) => (
                <MenuItem key={t.id} value={t.id}>
                  {t.name} ({t.address})
                </MenuItem>
              ))}
            </Select>
            <Typography variant="body2" color="text.secondary">
              Choose a target to render graph nodes/edges.
            </Typography>
          </Stack>
        </CardContent>
      </Card>

      {graphQ.isError ? <Alert severity="error">Failed to load graph.</Alert> : null}

      <Box sx={{ height: 560, border: "1px solid", borderColor: "divider", borderRadius: 2 }}>
        <ReactFlow nodes={nodes} edges={edges} fitView>
          <Background />
          <Controls />
        </ReactFlow>
      </Box>
    </Box>
  );
}

