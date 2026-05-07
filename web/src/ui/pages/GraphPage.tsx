import React, { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Alert, Box, Card, CardContent, Chip, MenuItem, Select, Stack, Typography } from "@mui/material";
import ReactFlow, {
  Background,
  Controls,
  type Edge,
  Handle,
  MarkerType,
  MiniMap,
  type Node,
  type NodeProps,
  Position
} from "reactflow";
import "reactflow/dist/style.css";
import { getGraphForTarget, listTargets } from "../../lib/api";

const SEVERITY_STROKE: Record<string, string> = {
  critical: "#880e4f",
  high: "#c62828",
  medium: "#ef6c00",
  low: "#f9a825",
  info: "#546e7a"
};

/**
 * Custom node. Critical: ReactFlow only draws edges between nodes that
 * expose <Handle> components. Without these, the graph renders only nodes.
 * We expose both a left "target" handle (incoming edges) and a right "source"
 * handle (outgoing edges) on every node, plus matching top/bottom handles so
 * edges look natural regardless of layout direction.
 */
function GraphEntityNode(props: NodeProps) {
  const { data, selected } = props;
  const d = data as { label?: string; kind?: string; severity?: string };
  const sevKey = typeof d.severity === "string" ? d.severity.toLowerCase() : "";
  const stroke =
    d.kind === "Finding" ? SEVERITY_STROKE[sevKey] ?? "#b71c1c" : d.kind === "Service" ? "#6d4c41" : "#1565c0";
  const bg =
    d.kind === "Target" ? "rgba(21, 101, 192, 0.06)" : d.kind === "Service" ? "rgba(109, 76, 65, 0.06)" : "rgba(183, 28, 28, 0.04)";

  const handleStyle = { width: 8, height: 8, background: stroke, border: `1px solid ${stroke}` } as const;

  return (
    <div
      style={{
        border: `2px solid ${stroke}`,
        borderRadius: 10,
        padding: "10px 12px",
        minWidth: 140,
        maxWidth: 280,
        background: bg,
        boxShadow: selected ? `0 0 0 2px ${stroke}` : "0 1px 3px rgba(0,0,0,0.12)",
        fontSize: 12,
        lineHeight: 1.35,
        whiteSpace: "pre-wrap",
        wordBreak: "break-word",
        position: "relative"
      }}
    >
      {/* Edges enter on the left/top, leave on the right/bottom. */}
      <Handle type="target" position={Position.Left} style={handleStyle} isConnectable={false} />
      <Handle type="target" position={Position.Top} style={handleStyle} isConnectable={false} />
      <Handle type="source" position={Position.Right} style={handleStyle} isConnectable={false} />
      <Handle type="source" position={Position.Bottom} style={handleStyle} isConnectable={false} />
      {d.label ?? ""}
    </div>
  );
}

const nodeTypes = { graphEntity: GraphEntityNode };

function layoutGraphNodes(
  apiNodes: Array<{ id: string; kind?: string; data?: Record<string, unknown> }>
): Node[] {
  let si = 0;
  let fi = 0;
  return apiNodes.map((n) => {
    const kind = n.kind ?? "";
    let position = { x: 0, y: 0 };
    if (kind === "Target") position = { x: 380, y: 32 };
    else if (kind === "Service") {
      position = { x: 48 + (si % 3) * 260, y: 220 + Math.floor(si / 3) * 130 };
      si += 1;
    } else if (kind === "Finding") {
      position = { x: 820, y: 48 + fi * 96 };
      fi += 1;
    }

    const data = n.data ?? {};
    const severity = typeof data.severity === "string" ? data.severity : undefined;
    const label = typeof data.label === "string" ? data.label : String(data.title ?? n.id);

    return {
      id: n.id,
      type: "graphEntity",
      position,
      data: { label, kind, severity }
    };
  });
}

function styleEdges(edges: Edge[]): Edge[] {
  return edges.map((e) => {
    const isTargetFinding = e.source.startsWith("target:") && e.target.startsWith("finding:");
    const isSvcFinding = e.source.startsWith("service:") && e.target.startsWith("finding:");
    const stroke = isTargetFinding ? "#ad1457" : isSvcFinding ? "#d84315" : "#78909c";
    return {
      ...e,
      markerEnd: { type: MarkerType.ArrowClosed, width: 18, height: 18, color: stroke },
      style: { stroke, strokeWidth: isTargetFinding ? 2 : 1.5 },
      animated: isSvcFinding || isTargetFinding
    };
  });
}

export function GraphPage() {
  const targetsQ = useQuery({ queryKey: ["targets"], queryFn: listTargets });
  const [targetId, setTargetId] = useState<string>("");

  const graphQ = useQuery({
    queryKey: ["graph", targetId],
    queryFn: () => getGraphForTarget(targetId),
    enabled: Boolean(targetId),
    refetchInterval: 4000
  });

  const { nodes, edges } = useMemo(() => {
    if (!graphQ.data?.target) return { nodes: [] as Node[], edges: [] as Edge[] };
    const apiNodes = graphQ.data.nodes as Array<{ id: string; kind?: string; data?: Record<string, unknown> }> | undefined;
    const rawEdges = (graphQ.data.edges ?? []) as Array<{ id: string; source: string; target: string }>;

    if (apiNodes?.length) {
      return {
        nodes: layoutGraphNodes(apiNodes),
        edges: styleEdges(rawEdges.map((e) => ({ id: e.id, source: e.source, target: e.target })))
      };
    }

    const t = graphQ.data.target as { id: string; name: string; address: string };
    const services = graphQ.data.services ?? [];
    const findings = graphQ.data.findings ?? [];

    const built: Array<{ id: string; kind?: string; data?: Record<string, unknown> }> = [
      {
        id: `target:${t.id}`,
        kind: "Target",
        data: { label: `${t.name}\n${t.address}`, severity: undefined }
      },
      ...services.map((s: Record<string, unknown>) => ({
        id: `service:${String(s.id)}`,
        kind: "Service",
        data: {
          label: `${s.port}/${s.protocol}\n${s.name || "service"}`,
          severity: undefined
        }
      })),
      ...findings.map((f: Record<string, unknown>) => ({
        id: `finding:${String(f.id)}`,
        kind: "Finding",
        data: {
          label: `${String(f.severity || "").toUpperCase()}\n${String(f.title || "")}`,
          severity: f.severity
        }
      }))
    ];

    return {
      nodes: layoutGraphNodes(built),
      edges: styleEdges(rawEdges.map((e) => ({ id: e.id, source: e.source, target: e.target })))
    };
  }, [graphQ.data]);

  const counts = graphQ.data
    ? {
        services: graphQ.data.services?.length ?? 0,
        findings: graphQ.data.findings?.length ?? 0,
        edges: graphQ.data.edges?.length ?? 0
      }
    : null;

  return (
    <Box>
      <Typography variant="h5" gutterBottom>
        Attack surface graph
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Live view of the target, discovered services, and findings synced from Postgres into Neo4j after each scan or agent
        run.
      </Typography>

      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Stack direction={{ xs: "column", md: "row" }} spacing={2} alignItems={{ md: "center" }} flexWrap="wrap" useFlexGap>
            <Select value={targetId} onChange={(e) => setTargetId(String(e.target.value))} displayEmpty fullWidth sx={{ maxWidth: { md: 420 } }}>
              <MenuItem value="" disabled>
                Select target
              </MenuItem>
              {(targetsQ.data ?? []).map((t) => (
                <MenuItem key={t.id} value={t.id}>
                  {t.name} ({t.address})
                </MenuItem>
              ))}
            </Select>
            {counts ? (
              <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                <Chip size="small" label={`Services: ${counts.services}`} variant="outlined" />
                <Chip size="small" label={`Findings: ${counts.findings}`} variant="outlined" color={counts.findings ? "warning" : "default"} />
                <Chip size="small" label={`Edges: ${counts.edges}`} variant="outlined" />
              </Stack>
            ) : (
              <Typography variant="body2" color="text.secondary">
                Choose a target to load graph data from Neo4j.
              </Typography>
            )}
          </Stack>
        </CardContent>
      </Card>

      {targetId && graphQ.isError ? (
        <Alert severity="error" sx={{ mb: 2 }}>
          Failed to load graph — check Neo4j is reachable and the API&apos;s Neo4j env matches the worker.
        </Alert>
      ) : null}

      {targetId && graphQ.data && graphQ.data.target == null && graphQ.data.findings?.length === 0 && graphQ.data.services?.length === 0 ? (
        <Alert severity="info" sx={{ mb: 2 }}>
          No Neo4j graph for this target yet. Complete a pipeline scan or agent run against this target — the worker will rebuild
          the graph afterward.
        </Alert>
      ) : null}

      <PaperFlowSurface
        key={`${targetId}-${nodes.length}-${edges.length}`}
        nodes={nodes}
        edges={edges}
        empty={Boolean(targetId) && !graphQ.isFetching && nodes.length === 0}
      />
    </Box>
  );
}

function PaperFlowSurface(props: { nodes: Node[]; edges: Edge[]; empty: boolean }) {
  const { nodes, edges, empty } = props;

  return (
    <Card variant="outlined" sx={{ borderRadius: 2, overflow: "hidden", bgcolor: "grey.50" }}>
      <Box sx={{ height: 620, width: "100%", position: "relative" }}>
        {empty ? (
          <Stack alignItems="center" justifyContent="center" sx={{ height: "100%", color: "text.secondary", px: 2 }}>
            <Typography variant="body1" align="center">
              No nodes to render. Select another target or run a scan after picking a valid target above.
            </Typography>
          </Stack>
        ) : (
          <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView fitViewOptions={{ padding: 0.2 }}>
            <Background gap={14} />
            <Controls />
            <MiniMap
              nodeStrokeWidth={2}
              zoomable
              pannable
              style={{ borderRadius: 8, overflow: "hidden", border: "1px solid #e0e0e0" }}
            />
          </ReactFlow>
        )}
      </Box>
      <Typography variant="caption" color="text.secondary" sx={{ display: "block", px: 2, py: 1 }}>
        Gray arrows: Target → Service. Orange: Service → Finding. Magenta: Target → Finding (no linked service row).
      </Typography>
    </Card>
  );
}
