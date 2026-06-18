import { ToolDefinition, ToolEnvelope, ToolFinding, ToolInput, Severity } from "../mcp/types.js";
import { remoteScript, requireRemoteTool, snippet } from "./shared.js";
import { hostAllowed, resolveWebScanFromInput } from "./webTarget.js";

function quote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/** Collect on-target HTTP(S) seed URLs from args first, then discovered endpoints. */
function collectHttpSeeds(input: ToolInput, max = 25): string[] {
  const args = (input.args ?? {}) as { http_targets?: unknown; url?: string };
  const host = input.target.host;
  const webScan = resolveWebScanFromInput(host, input.target.vhost, input.context?.webScan);
  const ordered: string[] = [];
  const seen = new Set<string>();
  const push = (raw: unknown) => {
    if (typeof raw !== "string") return;
    try {
      const u = new URL(raw.trim());
      if (!hostAllowed(u.hostname, host, webScan.vhost)) return;
      if (u.protocol !== "http:" && u.protocol !== "https:") return;
      if (seen.has(u.href)) return;
      seen.add(u.href);
      ordered.push(u.href);
    } catch {
      /* ignore */
    }
  };
  if (Array.isArray(args.http_targets)) for (const t of args.http_targets) push(t);
  push(args.url);
  for (const ep of input.context?.discoveredEndpoints ?? []) push(ep.url);
  return ordered.slice(0, max);
}

const NUCLEI_INSTALL_COMMAND = [
  "$SUDO apt-get update -y && $SUDO apt-get install -y golang-go",
  'export PATH="$PATH:$(go env GOPATH)/bin"',
  "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
].join(" && ");

const DEFAULT_SAFE_TAGS = ["misconfiguration", "exposure", "tech", "ssl", "dns", "default-login"];

/**
 * recon.nuclei — template-based scanning restricted to safe, low-impact tags.
 *
 * Severity is capped at info/low/medium and intrusive/dos/fuzz/brute-force
 * templates are excluded, so this stays a reconnaissance-grade check.
 */
export const nucleiTool: ToolDefinition = {
  name: "recon.nuclei",
  description: "Run nuclei against discovered HTTP(S) URLs using safe template tags only (no intrusive/dos/fuzz).",
  tags: ["recon", "web", "vuln"],
  requires: ["http_targets"],
  defaultTimeoutMs: 12 * 60 * 1000,
  argSchema: {
    http_targets: { type: "array", items: { type: "string" }, description: "Seed URLs on the target host" },
    url: { type: "string", description: "Single seed URL (alternative to http_targets)" },
    tags: { type: "array", items: { type: "string" }, description: `Safe nuclei tags (default: ${DEFAULT_SAFE_TAGS.join(",")})` }
  },
  handler: async (input, emit): Promise<ToolEnvelope> => {
    const seeds = collectHttpSeeds(input);
    if (seeds.length === 0) {
      return {
        status: "skipped",
        error: "No HTTP(S) seeds. Run recon.http_probe first; nuclei needs `http_targets`/`url` or discovered endpoints.",
        artifacts: { commands: [] },
        facts: [],
        findings: [],
        recommendations: [],
        meta: {}
      };
    }

    const presence = await requireRemoteTool("nuclei", input.signal, { installCommand: NUCLEI_INSTALL_COMMAND });
    if (presence.missing) return presence.envelope;

    const rawTags = (input.args as { tags?: unknown } | undefined)?.tags;
    const tags = Array.isArray(rawTags) && rawTags.length > 0
      ? rawTags.filter((t): t is string => typeof t === "string")
      : DEFAULT_SAFE_TAGS;

    const listLines = seeds.map((s) => `echo ${quote(s)}`).join("\n");
    const script = [
      "set +e",
      "TARGETS=$(mktemp)",
      `{`,
      listLines,
      `} > "$TARGETS"`,
      [
        "nuclei",
        '-l "$TARGETS"',
        "-jsonl",
        "-silent",
        "-no-color",
        "-severity info,low,medium",
        `-tags ${quote(tags.join(","))}`,
        "-etags intrusive,dos,fuzz,brute-force,sqli,xss",
        "-rate-limit 50",
        "-timeout 10",
        "-retries 1"
      ].join(" ") + " 2>/dev/null || true",
      'rm -f "$TARGETS"'
    ].join("\n");

    emit.log(`nuclei on ${seeds.length} URL(s), tags=${tags.join(",")}`);
    const r = await remoteScript(script, input.signal, (s) => emit.log(s));

    const findings: ToolFinding[] = [];
    const facts: ToolEnvelope["facts"] = [];
    const seenFp = new Set<string>();
    for (const line of r.stdout.split("\n")) {
      const t = line.trim();
      if (!t.startsWith("{")) continue;
      let obj: Record<string, unknown>;
      try {
        obj = JSON.parse(t) as Record<string, unknown>;
      } catch {
        continue;
      }
      const templateId = typeof obj["template-id"] === "string" ? (obj["template-id"] as string) : "nuclei";
      const info = (obj.info ?? {}) as Record<string, unknown>;
      const name = typeof info.name === "string" ? (info.name as string) : templateId;
      const sev = String(info.severity ?? "info").toLowerCase();
      const matchedAt = typeof obj["matched-at"] === "string" ? (obj["matched-at"] as string) : typeof obj.host === "string" ? (obj.host as string) : seeds[0]!;
      const severity: Severity = sev === "critical" ? "critical" : sev === "high" ? "high" : sev === "medium" ? "medium" : sev === "low" ? "low" : "info";
      const fingerprint = `nuclei|${templateId}|${matchedAt}`;
      if (seenFp.has(fingerprint)) continue;
      seenFp.add(fingerprint);
      facts.push({ type: "nuclei_match", value: { templateId, name, severity, matchedAt }, source: "nuclei" });
      findings.push({
        title: `nuclei: ${name}`,
        severity,
        evidence: `Template ${templateId} matched at ${matchedAt}`,
        fingerprint,
        confidence: "high",
        requiresVerification: false,
        claimType: "nuclei_finding"
      });
    }

    return {
      status: "succeeded",
      durationMs: r.durationMs,
      artifacts: { commands: r.commands, stdoutSnippet: snippet(r.stdout), stderrSnippet: snippet(r.stderr) },
      facts,
      findings,
      recommendations: [],
      meta: { exitCode: r.exitCode, seeds, tags, matches: findings.length, commandSummary: `Scan ${seeds.length} URL(s) with nuclei (safe tags: ${tags.join(",")}).` }
    };
  }
};

const WAFW00F_INSTALL_COMMAND = "$SUDO apt-get update -y && $SUDO apt-get install -y wafw00f";

/**
 * recon.waf_detect — identify WAF/CDN in front of discovered web origins using wafw00f.
 */
export const wafDetectTool: ToolDefinition = {
  name: "recon.waf_detect",
  description: "Fingerprint WAF/CDN protecting discovered HTTP(S) origins using wafw00f.",
  tags: ["recon", "web"],
  requires: ["http_targets"],
  defaultTimeoutMs: 5 * 60 * 1000,
  argSchema: {
    http_targets: { type: "array", items: { type: "string" }, description: "Seed URLs on the target host" },
    url: { type: "string", description: "Single seed URL (alternative to http_targets)" }
  },
  handler: async (input, emit): Promise<ToolEnvelope> => {
    const seeds = collectHttpSeeds(input, 10);
    if (seeds.length === 0) {
      return {
        status: "skipped",
        error: "No HTTP(S) seeds. Run recon.http_probe first; waf_detect needs `http_targets`/`url` or discovered endpoints.",
        artifacts: { commands: [] },
        facts: [],
        findings: [],
        recommendations: [],
        meta: {}
      };
    }

    const presence = await requireRemoteTool("wafw00f", input.signal, { installCommand: WAFW00F_INSTALL_COMMAND });
    if (presence.missing) return presence.envelope;

    const script = [
      "set +e",
      ...seeds.map((s) => `echo "==== WAF ${s} ===="\nwafw00f ${quote(s)} -a 2>/dev/null || true\necho`)
    ].join("\n");

    emit.log(`wafw00f on ${seeds.length} origin(s)`);
    const r = await remoteScript(script, input.signal, (s) => emit.log(s));

    const findings: ToolFinding[] = [];
    const facts: ToolEnvelope["facts"] = [];
    const blocks = r.stdout.split(/^==== WAF /m).slice(1);
    for (const block of blocks) {
      const urlMatch = /^(\S+)\s+====/.exec(block);
      if (!urlMatch) continue;
      const url = urlMatch[1]!;
      const behind = /is behind (.+?)(?: WAF| \()/i.exec(block);
      const noWaf = /No WAF detected/i.test(block);
      if (behind) {
        const waf = behind[1]!.trim();
        facts.push({ type: "waf", value: { url, waf }, source: "wafw00f" });
        findings.push({
          title: `WAF/CDN detected on ${url}: ${waf}`,
          severity: "info",
          evidence: snippet(block.trim(), 400),
          fingerprint: `waf|${url}|${waf}`,
          confidence: "high",
          requiresVerification: false,
          claimType: "waf_detected"
        });
      } else if (noWaf) {
        facts.push({ type: "waf", value: { url, waf: null }, source: "wafw00f" });
      }
    }

    return {
      status: "succeeded",
      durationMs: r.durationMs,
      artifacts: { commands: r.commands, stdoutSnippet: snippet(r.stdout), stderrSnippet: snippet(r.stderr) },
      facts,
      findings,
      recommendations: [],
      meta: { exitCode: r.exitCode, seeds, commandSummary: `Fingerprint WAF/CDN on ${seeds.length} origin(s) with wafw00f.` }
    };
  }
};

export const webScanTools: ToolDefinition[] = [nucleiTool, wafDetectTool];
