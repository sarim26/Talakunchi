import { remoteScript, requireRemoteTool, snippet } from "./shared.js";
const TESTSSL_BIN = "testssl";
/**
 * recon.tls_check — JSON-native TLS posture check using testssl.
 *
 * For each TLS port we run testssl with --jsonfile-pretty, then read the
 * JSON result file. testssl emits an array of finding objects with a
 * standardized severity scale; we map LOW+ to our severities and emit the
 * cert details (subject/issuer/dates) as facts.
 */
export const tlsCheckTool = {
    name: "recon.tls_check",
    description: "Inspect TLS certificate, protocols and known vulnerabilities on TLS-enabled ports for the target host using testssl.",
    tags: ["recon", "tls"],
    requires: ["tls_targets"],
    defaultTimeoutMs: 10 * 60 * 1000,
    argSchema: {
        ports: {
            type: "array",
            items: { type: "number" },
            description: "Optional TLS ports to scan; defaults to inferred TLS ports from services plus 443."
        }
    },
    handler: async (input, emit) => {
        const tlsPorts = new Set();
        for (const s of input.context?.knownServices ?? []) {
            if ([443, 8443, 993, 995, 465, 5986].includes(s.port) || /^https?$|tls/i.test(s.name ?? "")) {
                tlsPorts.add(s.port);
            }
        }
        const explicit = input.args?.ports;
        if (explicit)
            for (const p of explicit)
                tlsPorts.add(p);
        if (tlsPorts.size === 0)
            tlsPorts.add(443);
        const presence = await requireRemoteTool(TESTSSL_BIN, input.signal);
        if (presence.missing)
            return presence.envelope;
        const host = input.target.host;
        const portList = [...tlsPorts];
        const script = [
            `set +e`,
            `HOST=${quote(host)}`,
            `for PORT in ${portList.join(" ")}; do`,
            `  OUT="/tmp/_testssl_\${PORT}.json"`,
            `  rm -f "$OUT"`,
            `  echo "==== TESTSSL $PORT ===="`,
            `  ${TESTSSL_BIN} --jsonfile-pretty "$OUT" --warnings batch --color 0 --quiet "$HOST:$PORT" >/dev/null 2>&1 || true`,
            `  if [ -f "$OUT" ]; then`,
            `    cat "$OUT"`,
            `  else`,
            `    echo '{"_error":"no_output"}'`,
            `  fi`,
            `  echo`,
            `done`
        ].join("\n");
        emit.log(`testssl on ${host} ports: ${portList.join(",")}`);
        const r = await remoteScript(script, input.signal, (s) => emit.log(s));
        const facts = [];
        const findings = [];
        const blocks = r.stdout.split(/^==== TESTSSL /m).slice(1);
        for (const block of blocks) {
            const portMatch = /^(\d+)\s+====/.exec(block);
            if (!portMatch)
                continue;
            const port = Number(portMatch[1]);
            const jsonStart = block.indexOf("[");
            const jsonEnd = block.lastIndexOf("]");
            if (jsonStart < 0 || jsonEnd <= jsonStart)
                continue;
            const jsonText = block.slice(jsonStart, jsonEnd + 1);
            let parsed;
            try {
                parsed = JSON.parse(jsonText);
            }
            catch {
                continue;
            }
            const certSubject = pickFinding(parsed, ["cert_subject"]);
            const certIssuer = pickFinding(parsed, ["cert_caIssuers", "cert_issuer"]);
            const notBefore = pickFinding(parsed, ["cert_notBefore"]);
            const notAfter = pickFinding(parsed, ["cert_notAfter"]);
            facts.push({
                type: "tls_cert",
                value: {
                    port,
                    subject: certSubject,
                    issuer: certIssuer,
                    notBefore,
                    notAfter
                },
                source: "testssl"
            });
            // Emit a "TLS reachable" finding that also verifies nmap's open-port
            // claim for this port (Situation 1: corroborated by an independent tool).
            if (certSubject || certIssuer) {
                findings.push({
                    title: `TLS service reachable on ${host}:${port}`,
                    severity: "info",
                    port,
                    protocol: "tcp",
                    evidence: `TLS handshake completed; subject=${certSubject ?? "?"}`,
                    fingerprint: `tls-reachable|${host}|${port}`,
                    confidence: "high",
                    requiresVerification: false,
                    claimType: "tls_reachable",
                    verifiesFingerprint: `open-port|${host}|tcp|${port}`
                });
            }
            for (const item of parsed) {
                const sev = String(item.severity ?? "INFO").toUpperCase();
                const mapped = mapSeverity(sev);
                if (!mapped)
                    continue;
                const id = String(item.id ?? "tls_finding");
                const finding = String(item.finding ?? "").slice(0, 600);
                const cve = typeof item.cve === "string" ? item.cve : undefined;
                findings.push({
                    title: `TLS ${id} on ${host}:${port}`,
                    severity: mapped,
                    port,
                    protocol: "tcp",
                    evidence: `${finding}${cve ? ` (CVE: ${cve})` : ""}`,
                    fingerprint: `testssl|${host}|${port}|${id}`,
                    // testssl either negotiates a TLS session and reads the
                    // certificate / cipher list or it doesn't — no ambiguity.
                    confidence: "high",
                    requiresVerification: false,
                    claimType: "tls_finding"
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
                ports: portList,
                commandSummary: `Run testssl JSON output against ${host} (ports: ${portList.join(",")}) and lift LOW+ findings into our severity scale.`
            }
        };
    }
};
function pickFinding(arr, ids) {
    for (const id of ids) {
        const hit = arr.find((x) => String(x.id ?? "") === id);
        if (hit && typeof hit.finding === "string")
            return hit.finding;
    }
    return undefined;
}
function mapSeverity(s) {
    switch (s) {
        case "LOW":
        case "WARN":
            return "low";
        case "MEDIUM":
            return "medium";
        case "HIGH":
            return "high";
        case "CRITICAL":
            return "critical";
        default:
            return null;
    }
}
function quote(s) {
    return `'${s.replace(/'/g, `'\\''`)}'`;
}
