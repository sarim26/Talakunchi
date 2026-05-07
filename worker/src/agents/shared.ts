/**
 * Shared helpers for specialist agents:
 *  - executing tool commands over the SSH bastion
 *  - parsing nmap-like outputs
 *  - normalising service rows
 */
import { spawnBashScriptOverSsh, spawnWithRemotePolicy } from "../remoteExec.js";

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
    durationMs: Date.now() - start
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
    durationMs: Date.now() - start
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
