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
    /**
     * Optional path under the base URL to brute-force from. Layer 3 lets the
     * manager point gobuster at a directory spider already discovered
     * (e.g. `/admin/`) instead of always starting at `/`.
     */
    basePath: { type: "string", description: "Optional path under the base URL to brute-force from (e.g. /admin/)." },
    wordlist: { type: "string", description: "Absolute path under /home/kali/Desktop/SecLists/. Manager should pick from the run-time catalog." },
    threads: { type: "number", default: 20 }
  },
  handler: async (input, emit): Promise<ToolEnvelope> => {
    const args = (input.args ?? {}) as { url?: string; basePath?: string; wordlist?: string; threads?: number };
    let url: string | undefined = undefined;
    if (args.url) {
      try {
        const u = new URL(args.url);
        if (u.hostname === input.target.host) url = args.url;
      } catch {
        // ignore invalid urls
      }
    }

    // Apply basePath so the brute-force starts at a discovered directory.
    if (url && typeof args.basePath === "string" && args.basePath.trim()) {
      try {
        const base = new URL(url);
        const pathClean = "/" + args.basePath.replace(/^\/+/, "").replace(/\/+$/, "") + "/";
        base.pathname = pathClean;
        url = base.toString();
      } catch {
        // ignore invalid basePath
      }
    }

    if (!url) {
      return {
        status: "skipped",
        error: "No HTTP target in args.url (manager + execution writer must supply a URL on the target host). Run recon.http_probe first.",
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
      const codeMatch = /Status:\s*(\d{3})/.exec(line);
      if (!codeMatch?.[1]) continue;
      const code = Number(codeMatch[1]);
      if (!Number.isFinite(code)) continue;

      // gobuster can output either:
      //  - "/admin (Status: 200) ..."
      //  - "admin (Status: 301) ... [--> http://host/admin/]"
      const redirectUrlMatch = /\[-->\s*(https?:\/\/[^\]\s]+)\s*\]/i.exec(line);
      const leadingTokenMatch = /^(\S+)\s+\(Status:\s*\d{3}\)/.exec(line);
      const leadingPathMatch = /^(\/\S+)\s+\(Status:\s*\d{3}\)/.exec(line);

      let fullUrl: string | null = null;
      let path: string | null = null;

      if (redirectUrlMatch?.[1]) {
        fullUrl = redirectUrlMatch[1];
        try {
          const u = new URL(fullUrl);
          path = u.pathname || "/";
        } catch {
          path = null;
        }
      } else if (leadingPathMatch?.[1]) {
        path = leadingPathMatch[1];
        fullUrl = `${url.replace(/\/$/, "")}${path}`;
      } else if (leadingTokenMatch?.[1]) {
        path = `/${leadingTokenMatch[1].replace(/^\/+/, "")}`;
        fullUrl = `${url.replace(/\/$/, "")}${path}`;
      }

      if (!fullUrl) continue;

      facts.push({ type: "web_path", value: { url: fullUrl, status: code }, source: "gobuster" });

      // Promote high-signal paths into Findings so they show in the Findings tab.
      const interesting =
        /(phpmyadmin|drupal|wp-admin|wp-login|admin|login|uploads|backup|config|setup|test|debug|api|graphql)|(?:^|\/)chats?(?:\/|$)/i.test(
          path ?? fullUrl
        );
      if (interesting && [200, 301, 302, 401, 403].includes(code)) {
        findings.push({
          title: `Interesting web path discovered: ${path ?? fullUrl}`,
          severity: code === 200 ? "medium" : "low",
          evidence: `${fullUrl} → HTTP ${code}`,
          fingerprint: `gobuster|${url}|${path ?? fullUrl}|${code}`,
          // gobuster actually retrieved this response from the server.
          confidence: "high",
          requiresVerification: false,
          claimType: "web_path"
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
        wordlist,
        wordlistSource,
        count: facts.length,
        commandSummary: `Brute-force common web paths on ${url} using gobuster.`
      }
    };
  }
};

function quote(s: string) {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}
