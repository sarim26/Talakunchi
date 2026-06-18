import { remoteScript, requireRemoteTool, snippet } from "./shared.js";
const DNSX_BIN = "dnsx";
/**
 * recon.dns_enum — DNS records + reverse lookup + zone transfer attempt.
 *
 * Uses `dig` for the human-readable evidence blocks (great for AXFR + raw
 * answer sections) AND ProjectDiscovery's `dnsx` for structured JSON
 * record extraction. Only `dnsx` is treated as a required missing tool;
 * `dig` is a base utility that is essentially always present on Kali.
 */
export const dnsEnumTool = {
    name: "recon.dns_enum",
    description: "Enumerate DNS records (A/AAAA/MX/NS/TXT/CNAME), reverse PTR and attempt safe zone transfers (dig + dnsx).",
    tags: ["recon", "dns"],
    requires: ["target"],
    defaultTimeoutMs: 4 * 60 * 1000,
    handler: async (input, emit) => {
        const host = input.target.host;
        const presence = await requireRemoteTool(DNSX_BIN, input.signal);
        if (presence.missing)
            return presence.envelope;
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
            `echo "== DIG PTR =="`,
            `IP=$(dig +short "$HOST" | head -n1)`,
            `if [ -n "$IP" ]; then dig -x "$IP" +noall +answer || true; fi`,
            `echo "== AXFR (best-effort) =="`,
            `for NS in $(dig +short "$HOST" NS); do`,
            `  echo "-- $NS --"`,
            `  dig @"$NS" "$HOST" AXFR +short +time=4 +tries=1 || true`,
            `done`,
            `echo "== DNSX JSON =="`,
            `echo "$HOST" | ${DNSX_BIN} -a -aaaa -mx -ns -txt -cname -resp -silent -json || true`
        ].join("\n");
        emit.log(`DNS enum for ${host} (dig + dnsx)`);
        const r = await remoteScript(script, input.signal, (s) => emit.log(s));
        const facts = [];
        const findings = [];
        const subdomains = new Set();
        const sections = r.stdout.split(/== ([A-Z0-9 _()-]+) ==/);
        for (let i = 1; i < sections.length; i += 2) {
            const label = sections[i].trim();
            const body = (sections[i + 1] ?? "").trim();
            if (!body)
                continue;
            if (label === "DNSX JSON") {
                for (const line of body.split("\n")) {
                    const trimmed = line.trim();
                    if (!trimmed || trimmed[0] !== "{")
                        continue;
                    let obj;
                    try {
                        obj = JSON.parse(trimmed);
                    }
                    catch {
                        continue;
                    }
                    const record = {
                        host: obj.host,
                        a: obj.a,
                        aaaa: obj.aaaa,
                        mx: obj.mx,
                        ns: obj.ns,
                        txt: obj.txt,
                        cname: obj.cname
                    };
                    facts.push({ type: "dns_record", value: record, source: "dnsx" });
                    collectSubdomains(record.cname, host, subdomains);
                    collectSubdomains(record.ns, host, subdomains);
                    collectSubdomains(record.mx, host, subdomains);
                }
                continue;
            }
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
                if (m.endsWith(host) || host.endsWith(m))
                    subdomains.add(m.toLowerCase());
            }
        }
        for (const sd of subdomains) {
            facts.push({ type: "subdomain", value: sd, source: "dig+dnsx" });
        }
        return {
            status: "succeeded",
            durationMs: r.durationMs,
            artifacts: { commands: r.commands, stdoutSnippet: snippet(r.stdout), stderrSnippet: snippet(r.stderr) },
            facts,
            findings,
            recommendations: subdomains.size > 0
                ? [{ agent: "recon.http_probe", reason: "Probe newly discovered subdomains", priority: 50 }]
                : [],
            meta: {
                exitCode: r.exitCode,
                subdomainCount: subdomains.size,
                commandSummary: `Query DNS records for ${host} (dig blocks + dnsx structured JSON) and attempt a zone transfer (AXFR) where possible.`
            }
        };
    }
};
function collectSubdomains(value, host, into) {
    if (!value)
        return;
    const list = Array.isArray(value) ? value : [value];
    for (const v of list) {
        if (typeof v !== "string")
            continue;
        const cleaned = v.replace(/\.$/, "").toLowerCase();
        if (!cleaned)
            continue;
        if (cleaned.endsWith(host.toLowerCase()) || host.toLowerCase().endsWith(cleaned)) {
            into.add(cleaned);
        }
    }
}
function quote(s) {
    return `'${s.replace(/'/g, `'\\''`)}'`;
}
