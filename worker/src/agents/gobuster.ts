import { ToolDefinition, ToolEnvelope } from "../mcp/types.js";
import { remoteScript, snippet } from "./shared.js";
import { getWordlistCatalog, isWordlistAllowed } from "./wordlists.js";

/**
 * recon.gobuster — directory/file content discovery on previously-discovered
 * web endpoints. The wordlist comes from the SecLists catalog and is chosen
 * either by the manager (via args.wordlist) or falls back to the catalog
 * default. Hardcoded paths are no longer used.
 */
export const gobusterTool: ToolDefinition = {
  name: "recon.gobuster",
  description: "Brute-force common content paths on a discovered HTTP(S) endpoint using gobuster. Wordlist is chosen by the manager from the SecLists catalog.",
  tags: ["recon", "web"],
  requires: ["http_targets"],
  defaultTimeoutMs: 6 * 60 * 1000,
  argSchema: {
    url: { type: "string" },
    wordlist: { type: "string", description: "Absolute path under /home/kali/Desktop/SecLists/. Manager should pick from the run-time catalog." },
    threads: { type: "number", default: 20 }
  },
  handler: async (input, emit): Promise<ToolEnvelope> => {
    const args = (input.args ?? {}) as { url?: string; wordlist?: string; threads?: number };
    let url = args.url;
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

    const catalog = await getWordlistCatalog({ signal: input.signal });
    let wordlist: string | null = null;
    let wordlistSource: "manager" | "default" | "missing" = "missing";

    if (args.wordlist && isWordlistAllowed(catalog, args.wordlist)) {
      wordlist = args.wordlist;
      wordlistSource = "manager";
    } else if (catalog.defaults.webContent) {
      wordlist = catalog.defaults.webContent;
      wordlistSource = "default";
    }

    if (!wordlist) {
      return {
        status: "failed",
        error:
          `No usable wordlist found. SecLists root ${catalog.root} does not contain a Web-Content list. ` +
          `Install SecLists on the SSH host or pass an absolute path that resolves under ${catalog.root}.`,
        artifacts: { commands: [] },
        facts: [],
        findings: [],
        recommendations: [],
        meta: { catalogRoot: catalog.root, rootExists: catalog.rootExists }
      };
    }

    const threads = Math.max(1, Math.min(50, Number(args.threads ?? 20)));

    const script = [
      `set -euo pipefail`,
      `URL=${quote(url)}`,
      `WORDLIST=${quote(wordlist)}`,
      `if [ ! -f "$WORDLIST" ]; then`,
      `  echo "WORDLIST_MISSING: $WORDLIST"`,
      `  exit 0`,
      `fi`,
      `gobuster dir -u "$URL" -w "$WORDLIST" -k --no-error --quiet -t ${threads} -b 404,403`
    ].join("\n");

    emit.log(`Running gobuster against ${url} (wordlist=${wordlistSource}: ${wordlist})`);
    const r = await remoteScript(script, input.signal, (s) => emit.log(s));

    if (r.stdout.includes("WORDLIST_MISSING")) {
      return {
        status: "failed",
        error: `Wordlist not present on tools host: ${wordlist}`,
        artifacts: { commands: r.commands, stdoutSnippet: snippet(r.stdout), stderrSnippet: snippet(r.stderr) },
        facts: [],
        findings: [],
        recommendations: [],
        meta: { wordlist, wordlistSource }
      };
    }

    const flagErr = /Cannot use two forms of the same flag|unknown flag|flag provided but not defined/i.test(`${r.stdout}\n${r.stderr}`);
    if ((r.exitCode != null && r.exitCode !== 0) || flagErr) {
      return {
        status: "failed",
        error: flagErr ? "Gobuster CLI flag error (invalid args)" : `Gobuster failed (exitCode=${r.exitCode ?? "?"})`,
        durationMs: r.durationMs,
        artifacts: { commands: r.commands, stdoutSnippet: snippet(r.stdout), stderrSnippet: snippet(r.stderr) },
        facts: [],
        findings: [],
        recommendations: [],
        meta: { exitCode: r.exitCode, wordlist, wordlistSource, threads }
      };
    }

    const lines = r.stdout
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l && /Status:\s*\d{3}/.test(l));

    const findings: ToolEnvelope["findings"] = [];
    const facts: ToolEnvelope["facts"] = [];

    for (const line of lines) {
      const pathMatch = /^(\/\S+)/.exec(line);
      const codeMatch = /Status:\s*(\d{3})/.exec(line);
      if (!pathMatch || !codeMatch) continue;
      const path = pathMatch[1];
      const code = Number(codeMatch[1]);
      facts.push({ type: "web_path", value: { url: `${url.replace(/\/$/, "")}${path}`, status: code }, source: "gobuster" });
      if (code === 200 && /(admin|login|backup|config|setup|test|debug|api|graphql)/i.test(path)) {
        findings.push({
          title: `Sensitive web path discovered: ${path}`,
          severity: "medium",
          evidence: `${url}${path} → HTTP ${code}`,
          fingerprint: `gobuster|${url}|${path}`
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
      meta: { exitCode: r.exitCode, wordlist, wordlistSource, count: facts.length }
    };
  }
};

function quote(s: string) {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}
