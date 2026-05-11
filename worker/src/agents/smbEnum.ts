import { ToolDefinition, ToolEnvelope } from "../mcp/types.js";
import { remoteScript, requireRemoteTool, snippet } from "./shared.js";

const E4N_BIN = "enum4linux-ng";

/**
 * recon.smb_enum — JSON-native SMB enumeration using enum4linux-ng.
 *
 * Runs `enum4linux-ng -A -oJ /tmp/_e4n` against the target host (anonymous,
 * read-only) and parses the JSON output. We emit:
 *   - `smb_shares`, `smb_users`, `smb_signing`, `smb_os`, `smb_dialects` facts
 *   - findings for each share and user (info), anonymous read/write shares,
 *     and SMB signing not required when enum4linux-ng reports it
 */
export const smbEnumTool: ToolDefinition = {
  name: "recon.smb_enum",
  description: "Enumerate SMB on the target with enum4linux-ng (JSON output): dialects, signing, anonymous share listing.",
  tags: ["recon", "smb"],
  requires: ["services"],
  defaultTimeoutMs: 6 * 60 * 1000,
  handler: async (input, emit): Promise<ToolEnvelope> => {
    const hasSmb = (input.context?.knownServices ?? []).some((s) => [139, 445].includes(s.port));
    if (!hasSmb) {
      return {
        status: "skipped",
        error: "No SMB ports in context",
        artifacts: { commands: [] },
        facts: [],
        findings: [],
        recommendations: [],
        meta: { commandSummary: `Enumerate SMB shares and signing posture on ${input.target.host} (anonymous / read-only).` }
      };
    }

    const presence = await requireRemoteTool(E4N_BIN, input.signal);
    if (presence.missing) return presence.envelope;

    const host = input.target.host;
    const script = [
      `set +e`,
      `HOST=${quote(host)}`,
      `OUT_BASE=/tmp/_e4n_$$`,
      `rm -f $OUT_BASE.json`,
      `${E4N_BIN} -A -oJ "$OUT_BASE" "$HOST" >/dev/null 2>&1 || true`,
      `echo "==== ENUM4LINUX_NG ===="`,
      `if [ -f "$OUT_BASE.json" ]; then`,
      `  cat "$OUT_BASE.json"`,
      `else`,
      `  echo '{"_error":"no_output"}'`,
      `fi`
    ].join("\n");

    emit.log(`enum4linux-ng on ${host}`);
    const r = await remoteScript(script, input.signal, (s) => emit.log(s));

    const facts: ToolEnvelope["facts"] = [];
    const findings: ToolEnvelope["findings"] = [];

    const jsonStart = r.stdout.indexOf("{", r.stdout.indexOf("==== ENUM4LINUX_NG ===="));
    const jsonEnd = r.stdout.lastIndexOf("}");
    if (jsonStart < 0 || jsonEnd <= jsonStart) {
      return {
        status: "failed",
        durationMs: r.durationMs,
        error: "enum4linux-ng produced no JSON output",
        artifacts: { commands: r.commands, stdoutSnippet: snippet(r.stdout), stderrSnippet: snippet(r.stderr) },
        facts: [],
        findings: [],
        recommendations: [],
        meta: { exitCode: r.exitCode }
      };
    }
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(r.stdout.slice(jsonStart, jsonEnd + 1)) as Record<string, unknown>;
    } catch (e) {
      return {
        status: "failed",
        durationMs: r.durationMs,
        error: `enum4linux-ng JSON parse failed: ${(e as Error).message}`,
        artifacts: { commands: r.commands, stdoutSnippet: snippet(r.stdout), stderrSnippet: snippet(r.stderr) },
        facts: [],
        findings: [],
        recommendations: [],
        meta: { exitCode: r.exitCode }
      };
    }

    const shares = (parsed.shares ?? {}) as Record<string, unknown>;
    if (Object.keys(shares).length > 0) {
      facts.push({ type: "smb_shares", value: shares, source: "enum4linux-ng" });
      for (const [shareName, info] of Object.entries(shares)) {
        const row = info as Record<string, unknown> | undefined;
        const mapping = shareAccessSummary(row).toLowerCase();
        const evidence = shareEvidenceLine(shareName, row);

        findings.push({
          title: `SMB share enumerated: '${shareName}' on ${host}`,
          severity: "info",
          port: 445,
          protocol: "tcp",
          evidence,
          fingerprint: `smb-share|${host}|${shareName}`
        });

        if (/(^|[\s,])(ok|listable|read|rw|write)([\s,]|$)/i.test(mapping)) {
          findings.push({
            title: `SMB anonymous access to share '${shareName}' on ${host}`,
            severity: /write|rw/i.test(mapping) ? "high" : "medium",
            port: 445,
            protocol: "tcp",
            evidence: `enum4linux-ng access=${mapping || "unknown"}`,
            fingerprint: `smb-anon|${host}|${shareName}`
          });
        }
      }
    }

    const users = (parsed.users ?? {}) as Record<string, unknown>;
    if (Object.keys(users).length > 0) {
      facts.push({ type: "smb_users", value: users, source: "enum4linux-ng" });
      for (const [rid, info] of Object.entries(users)) {
        const row = info as Record<string, unknown> | undefined;
        const username = typeof row?.username === "string" ? row.username : rid;
        const name = typeof row?.name === "string" ? row.name : "";
        const desc = typeof row?.description === "string" ? row.description : "";
        const bits = [`RID ${rid}`, `user=${username}`];
        if (name) bits.push(`name=${name}`);
        if (desc) bits.push(`description=${desc}`);
        findings.push({
          title: `SMB user enumerated: ${username} on ${host}`,
          severity: "info",
          port: 445,
          protocol: "tcp",
          evidence: bits.join(", "),
          fingerprint: `smb-user|${host}|${rid}|${username}`
        });
      }
    }

    const dialectsObj = (parsed.smb_dialects ?? parsed.smb_protocols) as Record<string, unknown> | undefined;
    if (dialectsObj) facts.push({ type: "smb_dialects", value: dialectsObj, source: "enum4linux-ng" });

    const os = (parsed.os_info ?? parsed.smb_os) as Record<string, unknown> | undefined;
    if (os) facts.push({ type: "smb_os", value: os, source: "enum4linux-ng" });

    const signing =
      (parsed.smb_signing as Record<string, unknown> | undefined) ??
      (dialectsObj?.Signing as Record<string, unknown> | undefined) ??
      signingFromDialects(dialectsObj);
    if (signing) {
      facts.push({ type: "smb_signing", value: signing, source: "enum4linux-ng" });
      if (isSmbSigningWeak(signing, dialectsObj)) {
        findings.push({
          title: `SMB signing not required on ${host}`,
          severity: "medium",
          port: 445,
          protocol: "tcp",
          evidence: signingWeakEvidence(signing, dialectsObj),
          fingerprint: `smb-signing|${host}`
        });
      }
    }

    return {
      status: "succeeded",
      durationMs: r.durationMs,
      artifacts: { commands: r.commands, stdoutSnippet: snippet(r.stdout), stderrSnippet: snippet(r.stderr) },
      facts,
      findings,
      recommendations: [],
      meta: {
        exitCode: r.exitCode,
        commandSummary: `Run enum4linux-ng -A -oJ on ${host} (anonymous), parse JSON, emit shares/signing/os facts and findings.`
      }
    };
  }
};

/** Human-readable access line for nested enum4linux-ng `access` objects. */
function shareAccessSummary(info: Record<string, unknown> | undefined): string {
  if (!info) return "";
  const a = info.access;
  if (a && typeof a === "object" && !Array.isArray(a)) {
    const o = a as Record<string, unknown>;
    return [o.mapping, o.listing].filter((x) => typeof x === "string").join(" ");
  }
  if (typeof info.mapping === "string") return info.mapping;
  if (typeof a === "string") return a;
  return "";
}

function shareEvidenceLine(shareName: string, info: Record<string, unknown> | undefined): string {
  if (!info) return `share=${shareName}`;
  const type = typeof info.type === "string" ? info.type : "";
  const comment = typeof info.comment === "string" ? info.comment : "";
  const acc = shareAccessSummary(info);
  const parts = [`share=${shareName}`];
  if (type) parts.push(`type=${type}`);
  if (comment) parts.push(`comment=${comment}`);
  if (acc) parts.push(`access=${acc}`);
  return parts.join(", ");
}

function signingFromDialects(d: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
  if (!d || typeof d["SMB signing required"] !== "boolean") return undefined;
  return { "SMB signing required": d["SMB signing required"] };
}

function isSmbSigningWeak(signing: Record<string, unknown>, dialects: Record<string, unknown> | undefined): boolean {
  if (dialects && typeof dialects["SMB signing required"] === "boolean") {
    return dialects["SMB signing required"] === false;
  }
  const req = String(signing.required ?? signing.message_signing ?? "").trim().toLowerCase();
  if (!req) return false;
  if (/\bnot\s+required\b|\bdisabled\b|\bfalse\b|\boptional\b|\boff\b/i.test(req)) return true;
  if (/\brequired\b|\bmandatory\b|\benabled\b|\btrue\b|\byes\b/i.test(req)) return false;
  return false;
}

function signingWeakEvidence(signing: Record<string, unknown>, dialects: Record<string, unknown> | undefined): string {
  if (dialects && typeof dialects["SMB signing required"] === "boolean") {
    return `SMB signing required (dialects): ${dialects["SMB signing required"]}`;
  }
  const req = signing.required ?? signing.message_signing;
  return typeof req === "string" ? req : JSON.stringify(signing);
}

function quote(s: string) {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}
