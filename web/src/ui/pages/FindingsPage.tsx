import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Collapse,
  Divider,
  MenuItem,
  Select,
  Stack,
  Tooltip,
  Typography
} from "@mui/material";
import { getFindingEvidence, listFindings, listTargets, type Finding, type FindingVerification } from "../../lib/api";

/**
 * Findings list. Verification badges (Confirmed / Pending / Unverified)
 * surface the Layer-1 corroboration model: a finding is only "confirmed"
 * once it has been corroborated by a second tool (Situation 1) or emitted
 * with intrinsically high confidence (Situation 2).
 */
export function FindingsPage() {
  const targetsQ = useQuery({ queryKey: ["targets"], queryFn: listTargets });
  const [targetId, setTargetId] = useState<string>("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [verificationFilter, setVerificationFilter] = useState<string>("all");
  const [expanded, setExpanded] = useState<string | null>(null);

  const findingsQ = useQuery({
    queryKey: ["findings", targetId, severityFilter, statusFilter, verificationFilter],
    queryFn: () =>
      listFindings({
        targetId: targetId || undefined,
        severity: severityFilter === "all" ? undefined : severityFilter,
        status: statusFilter === "all" ? undefined : statusFilter,
        verification: verificationFilter === "all" ? undefined : verificationFilter
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

  const byVerification = useMemo(() => {
    const m = { confirmed: 0, unverified: 0, pending: 0 } as Record<"confirmed" | "unverified" | "pending", number>;
    for (const f of findings) {
      const v = f.verification?.status ?? "pending";
      m[v] = (m[v] ?? 0) + 1;
    }
    return m;
  }, [findings]);

  return (
    <Box>
      <Typography variant="h5" gutterBottom>
        Findings
      </Typography>

      <Alert severity="info" sx={{ mb: 2 }}>
        Findings are <strong>Confirmed</strong> when corroborated by a second tool or emitted with intrinsically high
        confidence. <strong>Unverified</strong> means a verifier ran but did not corroborate it. <strong>Pending</strong>{" "}
        means verification has not yet been attempted.
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
            <Select value={verificationFilter} onChange={(e) => setVerificationFilter(String(e.target.value))} fullWidth>
              <MenuItem value="all">All verification</MenuItem>
              <MenuItem value="confirmed">Confirmed</MenuItem>
              <MenuItem value="pending">Pending</MenuItem>
              <MenuItem value="unverified">Unverified</MenuItem>
            </Select>
          </Stack>
          <Stack direction="row" spacing={1} sx={{ mt: 2 }} flexWrap="wrap" useFlexGap>
            {(["critical", "high", "medium", "low", "info"] as const).map((s) => (
              <Chip key={s} size="small" label={`${s}: ${bySeverity.get(s) ?? 0}`} />
            ))}
            <Chip size="small" label={`Confirmed: ${byVerification.confirmed}`} color="success" />
            <Chip size="small" label={`Pending: ${byVerification.pending}`} color="default" />
            <Chip size="small" label={`Unverified: ${byVerification.unverified}`} color="warning" />
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
                <FindingRow
                  key={f.id}
                  finding={f}
                  isOpen={expanded === f.id}
                  onToggle={() => setExpanded((cur) => (cur === f.id ? null : f.id))}
                />
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

function FindingRow(props: { finding: Finding; isOpen: boolean; onToggle: () => void }) {
  const { finding, isOpen, onToggle } = props;
  return (
    <Box sx={{ display: "flex", flexDirection: "column", gap: 0.5, border: "1px solid", borderColor: "divider", borderRadius: 1, p: 1 }}>
      <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
        <Box sx={{ flexGrow: 1, minWidth: 0 }}>
          <Typography variant="body1">{finding.title}</Typography>
          <Stack direction="row" spacing={1} sx={{ mt: 0.5 }} flexWrap="wrap" useFlexGap>
            <Chip size="small" label={finding.severity} />
            <Chip size="small" label={finding.status} />
            <Chip size="small" label={`${finding.target.name} (${finding.target.address})`} />
            {finding.service ? <Chip size="small" label={`${finding.service.port}/${finding.service.protocol}`} /> : null}
            <VerificationBadge verification={finding.verification} />
          </Stack>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.8 }}>
            {finding.evidenceRedacted}
          </Typography>
        </Box>
        <Button size="small" onClick={onToggle}>
          {isOpen ? "Hide evidence" : "Evidence chain"}
        </Button>
      </Box>
      <Collapse in={isOpen} unmountOnExit>
        <EvidencePanel findingId={finding.id} />
      </Collapse>
    </Box>
  );
}

export function VerificationBadge(props: { verification?: FindingVerification }) {
  const v = props.verification;
  if (!v) return <Chip size="small" label="pending" color="default" variant="outlined" />;
  const color = v.status === "confirmed" ? "success" : v.status === "unverified" ? "warning" : "default";
  const tools = v.confirmedByTools.length ? ` · ${v.confirmedByTools.join(" + ")}` : "";
  return (
    <Tooltip
      title={
        v.status === "confirmed"
          ? `Confirmed by: ${v.confirmedByTools.join(", ") || "high-confidence tool"}`
          : v.status === "unverified"
            ? "Verifier ran but did not corroborate this finding"
            : "Verification has not yet been attempted"
      }
    >
      <Chip
        size="small"
        label={`${v.status}${tools}`}
        color={color as any}
        variant={v.status === "confirmed" ? "filled" : "outlined"}
      />
    </Tooltip>
  );
}

function EvidencePanel(props: { findingId: string }) {
  const q = useQuery({
    queryKey: ["finding-evidence", props.findingId],
    queryFn: () => getFindingEvidence(props.findingId),
    staleTime: 2000
  });
  if (q.isLoading) return <Typography variant="caption" color="text.secondary" sx={{ mt: 1 }}>Loading evidence…</Typography>;
  if (q.isError || !q.data) return <Alert severity="error" sx={{ mt: 1 }}>Failed to load evidence.</Alert>;
  const ev = q.data;
  return (
    <Box sx={{ mt: 1.5, p: 1, bgcolor: "grey.50", borderRadius: 1 }}>
      <Typography variant="caption" color="text.secondary">
        Fingerprint: <code>{ev.fingerprint}</code> · Confidence: {ev.verification.confidence}
        {ev.claimType ? ` · Claim: ${ev.claimType}` : ""}
      </Typography>
      <Box sx={{ mt: 1 }}>
        <Typography variant="subtitle2">Verification chain</Typography>
        {ev.evidence.length === 0 ? (
          <Typography variant="caption" color="text.secondary">No evidence recorded yet.</Typography>
        ) : (
          <Stack spacing={0.5} sx={{ mt: 0.5 }}>
            {ev.evidence.map((row, i) => (
              <Box key={i} sx={{ display: "flex", gap: 1, alignItems: "flex-start" }}>
                <Chip
                  size="small"
                  label={row.tool}
                  color={
                    row.status === "observed"
                      ? "success"
                      : row.status === "verifier_no_response" || row.status === "verifier_failed"
                        ? "warning"
                        : "default"
                  }
                  variant="outlined"
                />
                <Box sx={{ minWidth: 0 }}>
                  <Typography variant="caption" color="text.secondary">
                    {row.status} · {new Date(row.createdAt as any).toLocaleTimeString()}
                  </Typography>
                  <Typography variant="body2" sx={{ wordBreak: "break-word" }}>
                    {row.evidence || "—"}
                  </Typography>
                </Box>
              </Box>
            ))}
          </Stack>
        )}
      </Box>
    </Box>
  );
}
