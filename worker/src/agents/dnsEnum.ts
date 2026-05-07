import { ToolDefinition, ToolEnvelope } from "../mcp/types.js";
import { remoteScript, snippet } from "./shared.js";

/**
 * recon.dns_enum — DNS records + reverse lookup + zone transfer attempt.
 */
export const dnsEnumTool: ToolDefinition = {
  name: "recon.dns_enum",
  description: "Enumerate DNS records (A/AAAA/MX/NS/TXT), reverse PTR and attempt safe zone transfers.",
  tags: ["recon", "dns"],
  requires: ["target"],
  defaultTimeoutMs: 3 * 60 * 1000,
  handler: async (input, emit): Promise<ToolEnvelope> => {
    const host = input.target.host;
    const script = [
      `set +e`,
      `HOST=${quote(host)}`,
      `echo "== DIG ANY =="`,
      `dig +nocmd "$HOST" ANY +noall +answer || true`,
      `echo "== DIG MX =="`,
      `dig +nocmd "$HOST" MX +noall +answer || true`,
      `echo "== DIG TXT =="`,
      `dig +nocmd "$HOST" TXT +noall +answer || true`,
      `echo "== DIG NS =="`,
      `dig +nocmd "$HOST" NS +noall +answer || true`,
      `echo "== DIG PTR ==" `,
      `IP=$(dig +short "$HOST" | head -n1)`,
      `if [ -n "$IP" ]; then dig -x "$IP" +noall +answer || true; fi`,
      `echo "== AXFR (best-effort) =="`,
      `for NS in $(dig +short "$HOST" NS); do`,
      `  echo "-- $NS --"`,
      `  dig @"$NS" "$HOST" AXFR +short +time=4 +tries=1 || true`,
      `done`
    ].join("\n");

    emit.log(`DNS enum for ${host}`);
    const r = await remoteScript(script, input.signal, (s) => emit.log(s));

    const facts: ToolEnvelope["facts"] = [];
    const findings: ToolEnvelope["findings"] = [];
    const subdomains = new Set<string>();

    const blocks = r.stdout.split(/== ([A-Z0-9 _]+) ==/);
    for (let i = 1; i < blocks.length; i += 2) {
      const label = blocks[i].trim();
      const body = (blocks[i + 1] ?? "").trim();
      if (!body) continue;
      facts.push({ type: "dns_block", value: { label, sample: body.slice(0, 600) }, source: "dig" });

      if (label === "AXFR (BEST-EFFORT)" && /SOA|IN\s+A\s+/.test(body)) {
        findings.push({
          title: `DNS zone transfer (AXFR) succeeded for ${host}`,
          severity: "high",
          evidence: body.slice(0, 800),
          fingerprint: `axfr|${host}`
        });
      }
      const matches = body.match(/\b([a-z0-9-]+\.)+[a-z]{2,}\b/gi) ?? [];
      for (const m of matches) {
        if (m.endsWith(host) || host.endsWith(m)) subdomains.add(m.toLowerCase());
      }
    }

    for (const sd of subdomains) {
      facts.push({ type: "subdomain", value: sd, source: "dig" });
    }

    return {
      status: "succeeded",
      durationMs: r.durationMs,
      artifacts: { commands: r.commands, stdoutSnippet: snippet(r.stdout), stderrSnippet: snippet(r.stderr) },
      facts,
      findings,
      recommendations: subdomains.size > 0 ? [{ agent: "recon.http_probe", reason: "Probe newly discovered subdomains", priority: 50 }] : [],
      meta: { exitCode: r.exitCode, subdomainCount: subdomains.size }
    };
  }
};

function quote(s: string) {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}
