import { ToolDefinition, ToolEnvelope } from "../mcp/types.js";
import { remoteScript, snippet } from "./shared.js";

/**
 * recon.tls_check — fetches the cert + handshake info per TLS port and flags
 * obvious misconfigurations (expired, self-signed, weak protocol).
 */
export const tlsCheckTool: ToolDefinition = {
  name: "recon.tls_check",
  description: "Inspect TLS certificate and protocol versions on TLS-enabled ports for the target host.",
  tags: ["recon", "tls"],
  requires: ["tls_targets"],
  defaultTimeoutMs: 5 * 60 * 1000,
  handler: async (input, emit): Promise<ToolEnvelope> => {
    const tlsPorts = new Set<number>();
    for (const s of input.context?.knownServices ?? []) {
      if ([443, 8443, 993, 995, 465, 5986].includes(s.port) || /^https?$|tls/i.test(s.name ?? "")) {
        tlsPorts.add(s.port);
      }
    }
    const explicit = (input.args as Record<string, unknown> | undefined)?.ports as number[] | undefined;
    if (explicit) for (const p of explicit) tlsPorts.add(p);
    if (tlsPorts.size === 0) tlsPorts.add(443);

    const host = input.target.host;
    const script = [
      `set +e`,
      `HOST=${quote(host)}`,
      `for PORT in ${[...tlsPorts].join(" ")}; do`,
      `  echo "==== TLS $PORT ===="`,
      `  echo | timeout 8 openssl s_client -connect "$HOST:$PORT" -servername "$HOST" -showcerts 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null || echo "TLS_FAIL"`,
      `  echo "---- protocols ----"`,
      `  for VER in tls1 tls1_1 tls1_2 tls1_3; do`,
      `    R=$(echo | timeout 5 openssl s_client -connect "$HOST:$PORT" -$VER -servername "$HOST" 2>&1 | grep -E '^(SSL handshake|Verification|Cipher|Protocol)')`,
      `    echo "$VER: $R"`,
      `  done`,
      `done`
    ].join("\n");

    emit.log(`TLS check on ${host} ports: ${[...tlsPorts].join(",")}`);
    const r = await remoteScript(script, input.signal, (s) => emit.log(s));

    const facts: ToolEnvelope["facts"] = [];
    const findings: ToolEnvelope["findings"] = [];

    const blocks = r.stdout.split(/^==== TLS /m).slice(1);
    for (const block of blocks) {
      const portMatch = /^(\d+)\s+====/.exec(block);
      if (!portMatch) continue;
      const port = Number(portMatch[1]);
      const subject = /subject=([^\n]+)/.exec(block)?.[1]?.trim();
      const issuer = /issuer=([^\n]+)/.exec(block)?.[1]?.trim();
      const notBefore = /notBefore=([^\n]+)/.exec(block)?.[1]?.trim();
      const notAfter = /notAfter=([^\n]+)/.exec(block)?.[1]?.trim();

      facts.push({
        type: "tls_cert",
        value: { port, subject, issuer, notBefore, notAfter },
        source: "openssl"
      });

      if (notAfter && new Date(notAfter).getTime() < Date.now()) {
        findings.push({
          title: `Expired TLS certificate on ${host}:${port}`,
          severity: "high",
          port,
          protocol: "tcp",
          evidence: `notAfter=${notAfter} subject=${subject ?? "?"}`,
          fingerprint: `tls-expired|${host}|${port}`
        });
      }
      if (issuer && subject && issuer === subject) {
        findings.push({
          title: `Self-signed certificate on ${host}:${port}`,
          severity: "low",
          port,
          protocol: "tcp",
          evidence: `subject=${subject} issuer=${issuer}`,
          fingerprint: `tls-selfsigned|${host}|${port}`
        });
      }
      const protoLines = block.match(/(tls1[_3]?):.*Protocol\s*:\s*(\S+)/gi) ?? [];
      const supportsTls10 = /tls1:/i.test(block) && /Cipher\s*:/i.test(block);
      if (supportsTls10) {
        findings.push({
          title: `Weak TLS 1.0 supported on ${host}:${port}`,
          severity: "medium",
          port,
          protocol: "tcp",
          evidence: protoLines.slice(0, 4).join("\n"),
          fingerprint: `tls10|${host}|${port}`
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
        ports: [...tlsPorts],
        commandSummary: `Check TLS certificate details and supported protocol versions on ${host} (ports: ${[...tlsPorts].join(",")}).`
      }
    };
  }
};

function quote(s: string) {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}
