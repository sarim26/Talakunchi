import { ToolDefinition, ToolEnvelope } from "../mcp/types.js";
import { remoteScript, requireRemoteTool, snippet } from "./shared.js";

const KATANA_BIN = "katana";

/** Suggested remote install when Katana is absent (not via apt). Uses $SUDO from tool_installer. */
const KATANA_INSTALL_COMMAND = [
  "$SUDO apt-get update -y && $SUDO apt-get install -y golang-go",
  "export PATH=\"$PATH:$(go env GOPATH)/bin\"",
  "go install github.com/projectdiscovery/katana/cmd/katana@latest"
].join(" && ");

const INTERESTING_PATH = /(phpmyadmin|drupal|wp-admin|wp-login|admin|login|signin|signup|register|uploads?|backup|config|setup|test|debug|api|graphql|swagger|openapi|actuator|jenkins|kibana|grafana|metrics|console|jmx-console|server-status)/i;

/**
 * recon.spider — Katana-based crawler. Starts from a reachable HTTP(S)
 * endpoint and walks the site (incl. JS endpoints + robots.txt + sitemap)
 * staying in scope of the target host by default.
 *
 * Parses Katana output into:
 *   - `web_url` facts (JSONL rows with status, or plain http(s) URL lines)
 *   - findings for high-signal paths (admin/login/api/swagger/etc.)
 */
export const spiderTool: ToolDefinition = {
  name: "recon.spider",
  description:
    "Crawl a discovered HTTP(S) endpoint with Katana to enumerate URLs, JS endpoints, robots.txt and sitemap entries.",
  tags: ["recon", "web"],
  requires: ["http_targets"],
  defaultTimeoutMs: 8 * 60 * 1000,
  argSchema: {
    url: { type: "string", description: "Seed URL (must match the run's target host)" },
    depth: { type: "number", default: 3 },
    jsCrawl: { type: "boolean", default: true },
    concurrency: { type: "number", default: 10 },
    timeoutSec: { type: "number", default: 10 },
    includeSubdomains: { type: "boolean", default: false }
  },
  handler: async (input, emit): Promise<ToolEnvelope> => {
    const args = (input.args ?? {}) as {
      url?: string;
      depth?: number;
      jsCrawl?: boolean;
      concurrency?: number;
      timeoutSec?: number;
      includeSubdomains?: boolean;
    };

    let url: string | undefined;
    if (args.url) {
      try {
        const u = new URL(args.url);
        if (u.hostname === input.target.host) url = args.url;
      } catch {
        // ignore
      }
    }
    if (!url) {
      const httpFact = (input.context?.priorFindings ?? []).find((f) => /Reachable web endpoint:/i.test(f.title));
      if (httpFact) {
        const m = /Reachable web endpoint:\s*(\S+)/.exec(httpFact.title);
        if (m) url = m[1];
      }
    }
    if (!url) {
      const knownWeb = (input.context?.knownServices ?? []).find((s) => [80, 8080, 443, 8443].includes(s.port));
      if (knownWeb) {
        const scheme = knownWeb.port === 443 || knownWeb.port === 8443 ? "https" : "http";
        url = `${scheme}://${input.target.host}:${knownWeb.port}/`;
      }
    }

    if (!url) {
      return {
        status: "skipped",
        error: "No HTTP target available (run recon.http_probe first)",
        artifacts: { commands: [] },
        facts: [],
        findings: [],
        recommendations: [],
        meta: {}
      };
    }

    const presence = await requireRemoteTool(KATANA_BIN, input.signal, { installCommand: KATANA_INSTALL_COMMAND });
    if (presence.missing) return presence.envelope;

    const depth = clampInt(args.depth ?? 3, 1, 6);
    const concurrency = clampInt(args.concurrency ?? 10, 1, 30);
    const timeoutSec = clampInt(args.timeoutSec ?? 10, 3, 30);
    const jsCrawl = args.jsCrawl !== false;
    const fieldScope = args.includeSubdomains ? "rdn" : "fqdn";

    const flags: string[] = [
      `-u ${quote(url)}`,
      `-d ${depth}`,
      `-c ${concurrency}`,
      `-timeout ${timeoutSec}`,
      `-fs ${fieldScope}`,
      `-kf robotstxt sitemapxml`,
      `-iqp`,
      `-jsonl`,
      `-silent`,
      `-no-color`
    ];
    if (jsCrawl) flags.push("-jc");

    const script = [
      `set +e`,
      `${KATANA_BIN} ${flags.join(" ")}`
    ].join("\n");

    emit.log(`Running katana against ${url} (de=${depth}, concurrency=${concurrency}, jsCrawl=${jsCrawl})`);
    const r = await remoteScript(script, input.signal, (s) => emit.log(s));

    const facts: ToolEnvelope["facts"] = [];
    const findings: ToolEnvelope["findings"] = [];
    const seen = new Set<string>();
    const seenFindingFp = new Set<string>();

    const combined = `${r.stdout}\n${r.stderr}`;
    for (const line of combined.split("\n")) {
      const raw = stripAnsi(line).trim();
      if (!raw || raw.startsWith("+")) continue;

      if (raw.startsWith("{")) {
        ingestJsonlLine(raw, url, facts, findings, seen, seenFindingFp);
        continue;
      }

      const plain = parsePlainUrlLine(raw);
      if (plain) ingestPlainUrlLine(plain, url, facts, findings, seen, seenFindingFp);
    }

    const recs: ToolEnvelope["recommendations"] = [];
    if (facts.length > 0) {
      recs.push({
        agent: "recon.gobuster",
        reason: "Spider discovered URLs — brute-force common paths to find more",
        priority: 55
      });
    }

    // Layer 3: endpoint amplification.
    //
    // 1) For any discovered URL whose path matches API conventions, queue a
    //    surgical recon.ffuf run pointed at that exact subtree. We pick at
    //    most a handful so the manager isn't drowned in recommendations.
    const apiPathRegex = /\/(api|graphql|v\d+|rest|gql)(\/|$)/i;
    const ffufedTargets = new Set<string>();
    for (const fact of facts) {
      if (fact.type !== "web_url") continue;
      const v = (fact.value ?? {}) as { url?: string };
      if (!v.url) continue;
      try {
        const u = new URL(v.url);
        if (!apiPathRegex.test(u.pathname)) continue;
        // Strip the trailing segment so we fuzz the directory, not the file.
        const dir = u.pathname.replace(/\/[^/]*$/, "/") || "/";
        const targetUrl = `${u.origin}${dir.endsWith("/") ? dir : dir + "/"}FUZZ`;
        if (ffufedTargets.has(targetUrl)) continue;
        ffufedTargets.add(targetUrl);
        recs.push({
          agent: "recon.ffuf",
          reason: `Spider found API-shaped path ${u.pathname} — fuzz ${dir} for more endpoints`,
          priority: 70,
          args: { targetUrl }
        });
        if (ffufedTargets.size >= 4) break;
      } catch {
        // ignore
      }
    }

    // 2) Backup amplifier: when katana's output is thin (<10 URLs), recommend
    //    recon.waybackurls so the manager has historical paths to consider.
    if (facts.length < 10) {
      recs.push({
        agent: "recon.waybackurls",
        reason: `Katana returned only ${facts.length} URL(s) — query Wayback Machine for historical endpoints`,
        priority: 65
      });
    }

    return {
      status: facts.length > 0 ? "succeeded" : "partial",
      durationMs: r.durationMs,
      artifacts: { commands: r.commands, stdoutSnippet: snippet(r.stdout), stderrSnippet: snippet(r.stderr) },
      facts,
      findings,
      recommendations: recs,
      meta: {
        exitCode: r.exitCode,
        seedUrl: url,
        depth,
        urlsDiscovered: facts.length,
        commandSummary: `Crawl ${url} with katana (depth=${depth}, scope=${fieldScope}) and emit discovered URLs as facts.`
      }
    };
  }
};

function stripAnsi(s: string): string {
  return s.replace(/\u001b\[[0-9;]*m/g, "");
}

/** Katana often prints one discovered URL per line; accept that in addition to JSONL. */
function parsePlainUrlLine(line: string): string | undefined {
  const t = line.trim();
  if (!/^https?:\/\//i.test(t)) return undefined;
  const token = t.split(/\s+/)[0]?.replace(/["',);]+$/, "") ?? "";
  try {
    const u = new URL(token);
    if (u.protocol !== "http:" && u.protocol !== "https:") return undefined;
    return u.href;
  } catch {
    return undefined;
  }
}

function ingestJsonlLine(
  trimmed: string,
  seedUrl: string,
  facts: ToolEnvelope["facts"],
  findings: ToolEnvelope["findings"],
  seen: Set<string>,
  seenFindingFp: Set<string>
): void {
  let obj: Record<string, unknown>;
  try {
    obj = JSON.parse(trimmed) as Record<string, unknown>;
  } catch {
    return;
  }
  const req = (obj.request ?? {}) as Record<string, unknown>;
  const res = (obj.response ?? {}) as Record<string, unknown>;
  const endpoint = typeof req.endpoint === "string" ? req.endpoint : typeof obj.url === "string" ? (obj.url as string) : undefined;
  if (!endpoint) return;
  const status = typeof res.status_code === "number" ? (res.status_code as number) : null;
  const method = typeof req.method === "string" ? (req.method as string) : "GET";
  recordDiscoveredUrl(endpoint, method, status, seedUrl, facts, findings, seen, seenFindingFp);
}

function ingestPlainUrlLine(
  endpoint: string,
  seedUrl: string,
  facts: ToolEnvelope["facts"],
  findings: ToolEnvelope["findings"],
  seen: Set<string>,
  seenFindingFp: Set<string>
): void {
  recordDiscoveredUrl(endpoint, "GET", null, seedUrl, facts, findings, seen, seenFindingFp);
}

function recordDiscoveredUrl(
  endpoint: string,
  method: string,
  status: number | null,
  seedUrl: string,
  facts: ToolEnvelope["facts"],
  findings: ToolEnvelope["findings"],
  seen: Set<string>,
  seenFindingFp: Set<string>
): void {
  const key = `${method} ${endpoint}`;
  if (seen.has(key)) return;
  seen.add(key);

  facts.push({
    type: "web_url",
    value: { url: endpoint, status, method },
    source: "katana"
  });

  let path = "";
  try {
    path = new URL(endpoint).pathname || "";
  } catch {
    return;
  }
  if (!INTERESTING_PATH.test(path)) return;

  if (status !== null && [200, 301, 302, 401, 403].includes(status)) {
    const fp = `spider|${seedUrl}|${path || endpoint}|${status}`;
    if (seenFindingFp.has(fp)) return;
    seenFindingFp.add(fp);
    findings.push({
      title: `Interesting web path discovered: ${path || endpoint}`,
      severity: status === 200 ? "medium" : "low",
      evidence: `${endpoint} -> HTTP ${status} (${method})`,
      fingerprint: fp,
      // Katana fetched the page and observed this status code — definitive.
      confidence: "high",
      requiresVerification: false,
      claimType: "web_path"
    });
    return;
  }

  if (status === null) {
    const fp = `spider|${seedUrl}|${path || endpoint}|plain`;
    if (seenFindingFp.has(fp)) return;
    seenFindingFp.add(fp);
    findings.push({
      title: `Interesting web path discovered: ${path || endpoint}`,
      severity: "low",
      evidence: `${endpoint} (Katana; HTTP status not captured in output)`,
      fingerprint: fp,
      // No status captured — prefer corroboration by ffuf/gobuster.
      confidence: "medium",
      requiresVerification: true,
      claimType: "web_path"
    });
  }
}

function clampInt(v: number, min: number, max: number): number {
  const n = Math.floor(Number(v));
  if (!Number.isFinite(n)) return min;
  return Math.max(min, Math.min(max, n));
}

function quote(s: string) {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}
