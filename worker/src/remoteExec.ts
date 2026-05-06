import { spawn } from "node:child_process";
import { env } from "./env.js";

/**
 * Every spawned tool/shell runs as: ssh user@host <program> [args…] (via sshpass when using a password).
 * The worker container only runs Node; it does not run nmap/hydra/msf or agent bash locally.
 */
function buildSshArgv(program: string, programArgs: string[]): { exe: string; argv: string[] } {
  const host = env.REMOTE_SSH_HOST.trim();
  const user = env.REMOTE_SSH_USER.trim();
  const dest = `${user}@${host}`;

  const sshLong: string[] = [
    "-o",
    `StrictHostKeyChecking=${env.REMOTE_SSH_STRICT_HOST_KEY_CHECKING}`,
    "-o",
    "UserKnownHostsFile=/tmp/talakunchi_worker_known_hosts",
    "-p",
    String(env.REMOTE_SSH_PORT)
  ];

  if (env.REMOTE_SSH_IDENTITY_FILE?.trim()) {
    sshLong.push("-i", env.REMOTE_SSH_IDENTITY_FILE.trim(), "-o", "BatchMode=yes");
  } else if (!env.REMOTE_SSH_PASSWORD) {
    sshLong.push("-o", "BatchMode=yes");
  }

  const sshArgs = [...sshLong, dest, program, ...programArgs];

  if (env.REMOTE_SSH_PASSWORD) {
    return { exe: "sshpass", argv: ["-p", env.REMOTE_SSH_PASSWORD, "ssh", ...sshArgs] };
  }

  return { exe: "ssh", argv: sshArgs };
}

/** Remote: program + args after `ssh user@host`. */
export function resolveSpawnArgv(program: string, programArgs: string[]): { exe: string; argv: string[] } {
  return buildSshArgv(program, programArgs);
}

export type RemoteSpawnCallbacks = {
  onStdout?: (chunk: string) => void;
  onStderr?: (chunk: string) => void;
  signal?: AbortSignal;
};

/**
 * Remote bash script runner (robust): runs `bash -s` on the SSH host and streams the script over stdin.
 * This avoids quoting/base64 pitfalls with ssh remote command parsing.
 */
export function spawnBashScriptOverSsh(
  bashScript: string,
  opts?: RemoteSpawnCallbacks
): Promise<{ stdout: string; stderr: string; exitCode: number | null }> {
  const { exe, argv } = buildSshArgv("/bin/bash", ["-o", "xtrace", "-o", "verbose", "-s"]);

  return new Promise((resolve, reject) => {
    const child = spawn(exe, argv, { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    let settled = false;
    const settle = (fn: () => void) => {
      if (settled) return;
      settled = true;
      fn();
    };

    const onAbort = () => {
      try { child.kill("SIGKILL"); } catch { /* noop */ }
      settle(() => reject(new Error("aborted")));
    };

    const sig = opts?.signal;
    if (sig) {
      if (sig.aborted) return void onAbort();
      sig.addEventListener("abort", onAbort, { once: true });
    }

    child.stdout.on("data", (d: Buffer) => {
      const s = d.toString("utf8");
      stdout += s;
      opts?.onStdout?.(s);
    });
    child.stderr.on("data", (d: Buffer) => {
      const s = d.toString("utf8");
      stderr += s;
      opts?.onStderr?.(s);
    });
    child.on("error", (err) => settle(() => reject(err)));
    child.on("close", (code) => {
      sig?.removeEventListener("abort", onAbort);
      settle(() => resolve({ stdout, stderr, exitCode: code }));
    });

    child.stdin.on("error", () => { /* EPIPE/ECONNRESET when child is killed early */ });
    try {
      child.stdin.write(bashScript, "utf8", () => {
        try { child.stdin.end(); } catch { /* noop */ }
      });
    } catch { /* synchronous write error: close/error handlers settle */ }
  });
}

export function spawnWithRemotePolicy(
  program: string,
  programArgs: string[],
  opts?: RemoteSpawnCallbacks
): Promise<{ stdout: string; stderr: string; exitCode: number | null }> {
  const { exe, argv } = resolveSpawnArgv(program, programArgs);

  return new Promise((resolve, reject) => {
    const child = spawn(exe, argv, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    let settled = false;
    const settle = (fn: () => void) => {
      if (settled) return;
      settled = true;
      fn();
    };

    const onAbort = () => {
      try { child.kill("SIGKILL"); } catch { /* noop */ }
      settle(() => reject(new Error("aborted")));
    };

    const sig = opts?.signal;
    if (sig) {
      if (sig.aborted) return void onAbort();
      sig.addEventListener("abort", onAbort, { once: true });
    }

    child.stdout.on("data", (d: Buffer) => {
      const s = d.toString("utf8");
      stdout += s;
      opts?.onStdout?.(s);
    });
    child.stderr.on("data", (d: Buffer) => {
      const s = d.toString("utf8");
      stderr += s;
      opts?.onStderr?.(s);
    });
    child.on("error", (err) => settle(() => reject(err)));
    child.on("close", (code) => {
      sig?.removeEventListener("abort", onAbort);
      settle(() => resolve({ stdout, stderr, exitCode: code }));
    });
  });
}
