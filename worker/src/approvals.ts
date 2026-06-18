/**
 * Human-in-the-loop command approvals (Phase 9 gating).
 *
 * Destructive/exploit actions insert a `pending` row and then poll until an
 * operator approves/rejects it (via the API) or a bounded timeout elapses.
 * Nothing runs without an `approved` row.
 */
import { setTimeout as sleep } from "node:timers/promises";
import { withClient } from "./db.js";
import { env } from "./env.js";

export type ApprovalStatus = "pending" | "approved" | "rejected" | "timeout";

export async function requestApproval(input: {
  agentRunId?: string | null;
  scanRunId?: string | null;
  tool: string;
  command: string;
  reasoning?: string;
  impact?: "low" | "medium" | "high";
  args?: Record<string, unknown>;
}): Promise<string> {
  return withClient(async (c) => {
    const res = await c.query(
      `insert into command_approvals (scan_run_id, agent_run_id, tool, command, reasoning, impact, status, args, created_at)
       values ($1, $2, $3, $4, $5, $6, 'pending', $7::jsonb, now())
       returning id`,
      [
        input.scanRunId ?? null,
        input.agentRunId ?? null,
        input.tool,
        input.command,
        input.reasoning ?? null,
        input.impact ?? "high",
        JSON.stringify(input.args ?? {})
      ]
    );
    return String(res.rows[0].id);
  });
}

export async function getApprovalStatus(id: string): Promise<ApprovalStatus> {
  return withClient(async (c) => {
    const res = await c.query(`select status from command_approvals where id = $1`, [id]);
    const s = res.rows[0]?.status;
    return s === "approved" || s === "rejected" ? s : "pending";
  });
}

/** Poll until approved/rejected or `APPROVAL_WAIT_MS` elapses. */
export async function waitForApproval(id: string, signal?: AbortSignal): Promise<ApprovalStatus> {
  const deadline = Date.now() + env.APPROVAL_WAIT_MS;
  const pollMs = 3000;
  for (;;) {
    if (signal?.aborted) return "timeout";
    const status = await getApprovalStatus(id);
    if (status === "approved" || status === "rejected") return status;
    if (Date.now() >= deadline) return "timeout";
    await sleep(Math.min(pollMs, Math.max(0, deadline - Date.now())));
  }
}

/** True when `command` starts with one of the configured allowlist prefixes. */
export function isCommandAllowlisted(command: string): boolean {
  const entries = env.EXPLOIT_COMMAND_ALLOWLIST.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean);
  if (entries.length === 0) return false;
  const cmd = command.trim();
  return entries.some((prefix) => cmd.startsWith(prefix));
}

/** True when `lhost` is empty (nothing to check) or present in EXPLOIT_LHOST_ALLOWLIST. */
export function isLhostAllowed(lhost: string | undefined | null): boolean {
  const v = (lhost ?? "").trim();
  if (!v) return true;
  const entries = env.EXPLOIT_LHOST_ALLOWLIST.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
  return entries.includes(v);
}
