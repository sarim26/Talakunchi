/**
 * Shared helpers for specialist agents:
 *  - executing tool commands over the SSH bastion
 *  - parsing nmap-like outputs
 *  - normalising service rows
 *  - presence-checking remote CLI tools so the orchestrator can auto-install
 *    missing dependencies via `system.tool_installer`
 */
import { spawnBashScriptOverSsh, spawnWithRemotePolicy } from "../remoteExec.js";
import type { ToolEnvelope } from "../mcp/types.js";

export type SpecialistContextSummary = {
  host: string;
  ip?: string;
  knownPorts: number[];
  knownServices: Array<{ port: number; protocol: string; name?: string; product?: string; version?: string }>;
  knownDomains: string[];
};

export function summariseContext(input: {
  host: string;
  ip?: string;
  knownPorts?: number[];
  knownServices?: Array<{ port: number; protocol: string; name?: string; product?: string; version?: string }>;
  knownDomains?: string[];
}): SpecialistContextSummary {
  return {
    host: input.host,
    ip: input.ip,
    knownPorts: input.knownPorts ?? [],
    knownServices: input.knownServices ?? [],
    knownDomains: input.knownDomains ?? []
  };
}

export type RemoteRunResult = {
  exitCode: number | null;
  stdout: string;
  stderr: string;
  command: string;
  /**
   * Command lines that actually ran (best-effort). Prefer this over `command`
   * when populating `envelope.artifacts.commands[]`.
   */
  commands: string[];
  durationMs: number;
  /** Set when the invocation was aborted (tool timeout) but partial stdout/stderr was kept. */
  aborted?: boolean;
};

/** Runs a single program (with args) over SSH. Returns stdout/stderr. */
export async function remoteRun(
  program: string,
  args: string[],
  signal?: AbortSignal,
  onLog?: (s: string) => void
): Promise<RemoteRunResult> {
  const start = Date.now();
  const cmd = `${program} ${args.join(" ")}`;
  onLog?.(`$ ${cmd}\n`);
  const r = await spawnWithRemotePolicy(program, args, {
    signal,
    onStdout: (s) => onLog?.(s),
    onStderr: (s) => onLog?.(s)
  });
  return {
    exitCode: r.exitCode,
    stdout: r.stdout,
    stderr: r.stderr,
    command: cmd,
    commands: [cmd],
    durationMs: Date.now() - start,
    aborted: r.aborted
  };
}

/** Runs an entire bash script over SSH (multi-line, pipes, redirection allowed). */
export async function remoteScript(
  script: string,
  signal?: AbortSignal,
  onLog?: (s: string) => void
): Promise<RemoteRunResult> {
  const start = Date.now();
  const extracted = extractCommandsFromScript(script);
  for (const c of extracted) onLog?.(`$ ${c}\n`);
  if (extracted.length === 0) {
    onLog?.(`$ bash <<EOF\n${script.split("\n").slice(0, 8).join("\n")}\n...EOF\n`);
  }
  const r = await spawnBashScriptOverSsh(script, {
    signal,
    onStdout: (s) => onLog?.(s),
    onStderr: (s) => onLog?.(s)
  });
  return {
    exitCode: r.exitCode,
    stdout: r.stdout,
    stderr: r.stderr,
    command: extracted[0] ?? "bash <<inline>>",
    commands: extracted,
    durationMs: Date.now() - start,
    aborted: r.aborted
  };
}

export function snippet(s: string, max = 1500) {
  if (!s) return "";
  if (s.length <= max) return s;
  return `${s.slice(0, max)}\n...[truncated ${s.length - max} chars]`;
}

export function uniqStrings(arr: string[]) {
  return [...new Set(arr.map((s) => s.trim()).filter(Boolean))];
}

export function safeNumber(v: unknown, fallback = 0): number {
  const n = typeof v === "string" ? Number(v) : (v as number);
  return Number.isFinite(n) ? n : fallback;
}

/**
 * Result of a remote tool presence check. When `missing` is true, agents should
 * return `envelope` directly so the orchestrator can detect the missing-tool
 * signal (`meta.missingTool`) and auto-install it via `system.tool_installer`.
 */
export type ToolPresenceCheck =
  | { missing: false }
  | { missing: true; envelope: ToolEnvelope }
  /** SSH/presence probe failed — do NOT treat as "install missing package". */
  | { missing: true; checkFailed: true; envelope: ToolEnvelope };

/**
 * Check whether a CLI binary is installed on the remote tools host.
 * Distinguishes true "not installed" from SSH flakes / timeouts so we don't
 * burn steps apt-installing nmap that already ran successfully this session.
 */
export async function requireRemoteTool(
  toolName: string,
  signal?: AbortSignal,
  opts?: { installCommand?: string; knownPresent?: string[] }
): Promise<ToolPresenceCheck> {
  const safe = toolName.replace(/[^a-zA-Z0-9_.\-]/g, "");
  if (!safe) {
    return { missing: true, envelope: missingToolEnvelope(toolName, "Invalid tool name") };
  }

  if (opts?.knownPresent?.some((t) => t === safe || t.endsWith(`/${safe}`))) {
    return { missing: false };
  }

  // Short wall-clock for presence only — never inherit a 6–25 min tool timeout.
  const ac = new AbortController();
  const tid = setTimeout(() => ac.abort(), 20_000);
  const onParentAbort = () => ac.abort();
  if (signal) {
    if (signal.aborted) ac.abort();
    else signal.addEventListener("abort", onParentAbort, { once: true });
  }

  try {
    // Login-ish PATH + common locations; match PRESENT anywhere (stdout/stderr).
    const script = [
      "set +e",
      "export PATH=\"$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$HOME/go/bin:$HOME/.local/bin\"",
      `if command -v ${safe} >/dev/null 2>&1 || [ -x "/usr/bin/${safe}" ] || [ -x "/usr/local/bin/${safe}" ]; then`,
      `  echo TK_TOOL_PRESENT=${safe}`,
      "else",
      `  echo TK_TOOL_MISSING=${safe}`,
      "fi"
    ].join("\n");

    const r = await remoteScript(script, ac.signal);
    const blob = `${r.stdout}\n${r.stderr}`;

    if (r.aborted || ac.signal.aborted) {
      return {
        missing: true,
        checkFailed: true,
        envelope: presenceCheckFailedEnvelope(toolName, "SSH/presence check timed out or aborted")
      };
    }

    if (blob.includes(`TK_TOOL_PRESENT=${safe}`)) return { missing: false };

    if (blob.includes(`TK_TOOL_MISSING=${safe}`)) {
      return { missing: true, envelope: missingToolEnvelope(toolName, undefined, opts?.installCommand) };
    }

    // Empty/garbage output = transport problem, not a missing package.
    return {
      missing: true,
      checkFailed: true,
      envelope: presenceCheckFailedEnvelope(
        toolName,
        `SSH presence check returned no clear result (exit=${r.exitCode ?? "?"}). Not treating as missing.`
      )
    };
  } catch (e) {
    return {
      missing: true,
      checkFailed: true,
      envelope: presenceCheckFailedEnvelope(toolName, (e as Error).message ?? String(e))
    };
  } finally {
    clearTimeout(tid);
    signal?.removeEventListener("abort", onParentAbort);
  }
}

export function presenceCheckFailedEnvelope(toolName: string, reason: string): ToolEnvelope {
  return {
    status: "failed",
    error: `Could not verify '${toolName}' on remote host (${reason}). SSH may be flaky — retry the specialist; do not apt-install if it already worked this run.`,
    facts: [],
    findings: [],
    recommendations: [
      {
        agent: toolName.startsWith("recon.") || toolName.startsWith("exploit.") ? toolName : "recon.nmap",
        reason: `Presence check failed for ${toolName} — retry after SSH settles`,
        priority: 70
      }
    ],
    artifacts: { commands: [`command -v ${toolName}`] },
    meta: { presenceCheckFailed: true, tool: toolName }
  };
}

/**
 * Build a uniform `failed` envelope that signals to the orchestrator that the
 * given tool is missing on the remote host. The orchestrator looks for
 * `meta.missingTool` and queues the installer.
 */
export function missingToolEnvelope(toolName: string, reason?: string, installCommand?: string): ToolEnvelope {
  const hint = typeof installCommand === "string" ? installCommand.trim() : "";
  const meta: Record<string, unknown> = { missingTool: toolName };
  if (hint) meta.missingToolInstallCommand = hint;
  return {
    status: "failed",
    error: `Missing tool on remote host: ${toolName}${reason ? ` (${reason})` : ""}`,
    facts: [],
    findings: [],
    recommendations: [],
    artifacts: { commands: [`command -v ${toolName}`] },
    meta
  };
}

function extractCommandsFromScript(script: string): string[] {
  const lines = script
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);

  const cmds: string[] = [];
  const skip = new Set(["then", "do", "fi", "done", "else", "elif", "function", "{", "}", ";;"]);
  const skipStarts = [
    "set ",
    "set -",
    "export ",
    "#",
    "if ",
    "for ",
    "while ",
    "case ",
    "HOST=",
    "URL=",
    "WORDLIST=",
    "IP=",
    "ROOT=",
    "SCHEME=",
    "PORT=",
    "ENTRY="
  ];

  for (const l of lines) {
    const bare = l.replace(/;$/, "");
    if (!bare) continue;
    if (skip.has(bare)) continue;
    if (skipStarts.some((p) => bare.startsWith(p))) continue;
    // Keep echo lines only when they are being used as section headers.
    if (bare.startsWith("echo ") && !/====|==/.test(bare)) continue;
    cmds.push(bare);
  }

  // Avoid huge lists.
  return cmds.slice(0, 40);
}
