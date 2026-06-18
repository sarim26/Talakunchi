/**
 * Shared helpers for specialist agents:
 *  - executing tool commands over the SSH bastion
 *  - parsing nmap-like outputs
 *  - normalising service rows
 *  - presence-checking remote CLI tools so the orchestrator can auto-install
 *    missing dependencies via `system.tool_installer`
 */
import { spawnBashScriptOverSsh, spawnWithRemotePolicy } from "../remoteExec.js";
export function summariseContext(input) {
    return {
        host: input.host,
        ip: input.ip,
        knownPorts: input.knownPorts ?? [],
        knownServices: input.knownServices ?? [],
        knownDomains: input.knownDomains ?? []
    };
}
/** Runs a single program (with args) over SSH. Returns stdout/stderr. */
export async function remoteRun(program, args, signal, onLog) {
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
export async function remoteScript(script, signal, onLog) {
    const start = Date.now();
    const extracted = extractCommandsFromScript(script);
    for (const c of extracted)
        onLog?.(`$ ${c}\n`);
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
export function snippet(s, max = 1500) {
    if (!s)
        return "";
    if (s.length <= max)
        return s;
    return `${s.slice(0, max)}\n...[truncated ${s.length - max} chars]`;
}
export function uniqStrings(arr) {
    return [...new Set(arr.map((s) => s.trim()).filter(Boolean))];
}
export function safeNumber(v, fallback = 0) {
    const n = typeof v === "string" ? Number(v) : v;
    return Number.isFinite(n) ? n : fallback;
}
/**
 * Check whether a CLI binary is installed on the remote tools host. This is the
 * preflight every specialist runs before invoking a heavy command — if the tool
 * is missing, the orchestrator queues `system.tool_installer` and retries.
 */
export async function requireRemoteTool(toolName, signal, opts) {
    const safe = toolName.replace(/[^a-zA-Z0-9_.\-]/g, "");
    if (!safe) {
        return { missing: true, envelope: missingToolEnvelope(toolName, "Invalid tool name") };
    }
    const script = `if command -v ${safe} >/dev/null 2>&1; then echo PRESENT; else echo MISSING; fi`;
    const r = await remoteScript(script, signal);
    if (/PRESENT/.test(r.stdout))
        return { missing: false };
    return { missing: true, envelope: missingToolEnvelope(toolName, undefined, opts?.installCommand) };
}
/**
 * Build a uniform `failed` envelope that signals to the orchestrator that the
 * given tool is missing on the remote host. The orchestrator looks for
 * `meta.missingTool` and queues the installer.
 */
export function missingToolEnvelope(toolName, reason, installCommand) {
    const hint = typeof installCommand === "string" ? installCommand.trim() : "";
    const meta = { missingTool: toolName };
    if (hint)
        meta.missingToolInstallCommand = hint;
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
function extractCommandsFromScript(script) {
    const lines = script
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean);
    const cmds = [];
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
        if (!bare)
            continue;
        if (skip.has(bare))
            continue;
        if (skipStarts.some((p) => bare.startsWith(p)))
            continue;
        // Keep echo lines only when they are being used as section headers.
        if (bare.startsWith("echo ") && !/====|==/.test(bare))
            continue;
        cmds.push(bare);
    }
    // Avoid huge lists.
    return cmds.slice(0, 40);
}
