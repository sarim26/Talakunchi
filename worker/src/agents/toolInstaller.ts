import { Buffer } from "node:buffer";
import { ToolDefinition, ToolEnvelope } from "../mcp/types.js";
import { env } from "../env.js";
import { remoteScript, snippet } from "./shared.js";

const MAX_INSTALL_COMMAND_CHARS = 8000;

/**
 * system.tool_installer — installs a missing CLI on the remote SSH/Kali tools host.
 * Either runs a caller-supplied shell snippet (`args.installCommand`) or falls back to
 * `apt-get install` when only `args.tool` is provided.
 *
 * Contract:
 *   args.tool              – binary name for `command -v` checks (sanitised)
 *   args.installCommand    – optional full shell to run (e.g. go install, curl|tar).
 *                            When omitted, uses apt-get install -y <tool>.
 *
 * The remote script exports `SUDO` (passwordless or sudo -S) so installCommand may use `$SUDO`.
 *
 * Success: `command -v <tool>` succeeds after the install attempt.
 */
export const toolInstallerTool: ToolDefinition = {
  name: "system.tool_installer",
  description:
    "Install a missing CLI on the remote SSH/Kali tools host. Pass args.tool (binary to verify). Optionally pass args.installCommand: a full shell snippet to run when apt is wrong (e.g. Katana: install Go then `go install github.com/projectdiscovery/katana/cmd/katana@latest`; use `$SUDO` for privileged steps). If installCommand is omitted, runs apt-get update && apt-get install -y <tool>.",
  tags: ["system", "installer"],
  defaultTimeoutMs: 5 * 60 * 1000,
  argSchema: {
    tool: { type: "string", description: "Binary name to verify with command -v after install" },
    installCommand: {
      type: "string",
      description:
        "Optional shell script/commands to run on the remote host (omit to use apt-get install -y <tool>). Use $SUDO for privileged steps; PATH should include GOPATH/bin if using go install."
    }
  },
  handler: async (input, emit): Promise<ToolEnvelope> => {
    const args = (input.args ?? {}) as { tool?: string; installCommand?: string };
    const raw = (args.tool ?? "").trim();
    const tool = raw.replace(/[^a-zA-Z0-9_.\-]/g, "");
    if (!tool) {
      return {
        status: "failed",
        error: "system.tool_installer requires args.tool to be a valid binary name",
        facts: [],
        findings: [],
        recommendations: [],
        artifacts: { commands: [] },
        meta: {}
      };
    }

    const rawCmd = typeof args.installCommand === "string" ? args.installCommand.trim() : "";
    if (rawCmd.length > MAX_INSTALL_COMMAND_CHARS) {
      return {
        status: "failed",
        error: `system.tool_installer: installCommand exceeds ${MAX_INSTALL_COMMAND_CHARS} characters`,
        facts: [],
        findings: [],
        recommendations: [],
        artifacts: { commands: [] },
        meta: { tool }
      };
    }

    const sudoPass = (env.REMOTE_SSH_SUDO_PASSWORD ?? "").trim();
    const useCustom = rawCmd.length > 0;
    const installSource = useCustom ? "custom" : "apt-get";

    emit.log(
      useCustom
        ? `Installing '${tool}' via custom remote command (${rawCmd.length} chars)...`
        : `Installing missing tool '${tool}' via apt-get on the remote host...`
    );

    const script = useCustom ? buildCustomInstallScript(tool, sudoPass, rawCmd) : buildAptInstallScript(tool, sudoPass);

    const r = await remoteScript(script, input.signal, (s) => emit.log(s));
    const present = /PRESENT/.test(r.stdout);

    if (!present) {
      return {
        status: "failed",
        durationMs: r.durationMs,
        error: useCustom
          ? `Failed to install '${tool}' via custom command (exitCode=${r.exitCode ?? "?"})`
          : `Failed to install '${tool}' via apt-get (exitCode=${r.exitCode ?? "?"})`,
        facts: [],
        findings: [],
        recommendations: [],
        artifacts: { commands: r.commands, stdoutSnippet: snippet(r.stdout), stderrSnippet: snippet(r.stderr) },
        meta: {
          tool,
          exitCode: r.exitCode,
          installed: false,
          installSource,
          commandSummary: useCustom
            ? `Custom install on remote tools host (failed).`
            : `apt-get install '${tool}' on the remote tools host (failed).`
        }
      };
    }

    return {
      status: "succeeded",
      durationMs: r.durationMs,
      facts: [{ type: "installed_tool", value: { tool }, source: installSource }],
      findings: [],
      recommendations: [],
      artifacts: { commands: r.commands, stdoutSnippet: snippet(r.stdout), stderrSnippet: snippet(r.stderr) },
      meta: {
        tool,
        exitCode: r.exitCode,
        installed: true,
        installSource,
        commandSummary: useCustom
          ? `Custom install for '${tool}' on the remote tools host.`
          : `Install '${tool}' via apt-get on the remote tools host.`
      }
    };
  }
};

function buildAptInstallScript(tool: string, sudoPass: string): string {
  return [
    `set +e`,
    `export DEBIAN_FRONTEND=noninteractive`,
    `TOOL=${quote(tool)}`,
    `SUDO_PASS=${quote(sudoPass)}`,
    `if [ -n "$SUDO_PASS" ]; then SUDO="sudo -S -p ''"; else SUDO="sudo -n"; fi`,
    `export SUDO`,
    `echo "== command -v before =="`,
    `command -v "$TOOL" || echo "(absent)"`,
    `echo "== apt-get update =="`,
    `if [ -n "$SUDO_PASS" ]; then printf '%s\\n' "$SUDO_PASS" | $SUDO apt-get update -y 2>&1 | tail -n 30; else $SUDO apt-get update -y 2>&1 | tail -n 30; fi`,
    `echo "== apt-get install =="`,
    `if [ -n "$SUDO_PASS" ]; then printf '%s\\n' "$SUDO_PASS" | $SUDO apt-get install -y "$TOOL" 2>&1 | tail -n 80; else $SUDO apt-get install -y "$TOOL" 2>&1 | tail -n 80; fi`,
    `INSTALL_RC=$?`,
    `echo "== command -v after =="`,
    `if command -v "$TOOL" >/dev/null 2>&1; then echo PRESENT; else echo MISSING; fi`,
    `exit $INSTALL_RC`
  ].join("\n");
}

function buildCustomInstallScript(tool: string, sudoPass: string, installCommand: string): string {
  const b64 = Buffer.from(installCommand, "utf8").toString("base64");
  return [
    `set +e`,
    `export DEBIAN_FRONTEND=noninteractive`,
    `TOOL=${quote(tool)}`,
    `SUDO_PASS=${quote(sudoPass)}`,
    `if [ -n "$SUDO_PASS" ]; then SUDO="sudo -S -p ''"; else SUDO="sudo -n"; fi`,
    `export SUDO`,
    `echo "== command -v before =="`,
    `command -v "$TOOL" || echo "(absent)"`,
    `echo "== custom install =="`,
    `INSTALL_B64=${quote(b64)}`,
    `set -o pipefail`,
    `echo "$INSTALL_B64" | base64 -d | bash`,
    `INSTALL_RC=$?`,
    `set +o pipefail`,
    `echo "== command -v after =="`,
    `if command -v "$TOOL" >/dev/null 2>&1; then echo PRESENT; else echo MISSING; fi`,
    `exit $INSTALL_RC`
  ].join("\n");
}

function quote(s: string) {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}
