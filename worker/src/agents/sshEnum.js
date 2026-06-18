import { remoteScript, requireRemoteTool, snippet } from "./shared.js";
const SSH_AUDIT_BIN = "ssh-audit";
/**
 * recon.ssh_enum — JSON-native SSH posture audit using `ssh-audit -j`.
 *
 * For each known SSH port we run ssh-audit and parse the JSON. We emit:
 *   - `ssh_banner` fact (banner.raw, software, protocol)
 *   - `ssh_kex` / `ssh_mac` / `ssh_enc` / `ssh_key` facts (algorithm lists)
 *   - findings derived from the `cves`, recommendations.critical and
 *     recommendations.warning sections.
 */
export const sshEnumTool = {
    name: "recon.ssh_enum",
    description: "Audit SSH banner, supported algorithms and known CVEs using ssh-audit (JSON output).",
    tags: ["recon", "ssh"],
    requires: ["services"],
    defaultTimeoutMs: 4 * 60 * 1000,
    handler: async (input, emit) => {
        const sshPorts = (input.context?.knownServices ?? [])
            .filter((s) => s.port === 22 || /^ssh$/i.test(s.name ?? ""))
            .map((s) => s.port);
        if (sshPorts.length === 0)
            sshPorts.push(22);
        const presence = await requireRemoteTool(SSH_AUDIT_BIN, input.signal);
        if (presence.missing)
            return presence.envelope;
        const host = input.target.host;
        const script = [
            `set +e`,
            `HOST=${quote(host)}`,
            `for PORT in ${sshPorts.join(" ")}; do`,
            `  echo "==== SSHAUDIT $PORT ===="`,
            `  ${SSH_AUDIT_BIN} -j -p $PORT "$HOST" 2>/dev/null || true`,
            `  echo`,
            `done`
        ].join("\n");
        emit.log(`ssh-audit on ${host} ports: ${sshPorts.join(",")}`);
        const r = await remoteScript(script, input.signal, (s) => emit.log(s));
        const facts = [];
        const findings = [];
        const blocks = r.stdout.split(/^==== SSHAUDIT /m).slice(1);
        for (const block of blocks) {
            const portMatch = /^(\d+)\s+====/.exec(block);
            if (!portMatch)
                continue;
            const port = Number(portMatch[1]);
            const jsonStart = block.indexOf("{");
            const jsonEnd = block.lastIndexOf("}");
            if (jsonStart < 0 || jsonEnd <= jsonStart)
                continue;
            let obj;
            try {
                obj = JSON.parse(block.slice(jsonStart, jsonEnd + 1));
            }
            catch {
                continue;
            }
            const banner = (obj.banner ?? {});
            const raw = typeof banner.raw === "string" ? banner.raw : undefined;
            const software = typeof banner.software === "string" ? banner.software : undefined;
            const protocol = banner.protocol;
            facts.push({
                type: "ssh_banner",
                value: { port, raw: raw ?? null, software: software ?? null, protocol },
                source: "ssh-audit"
            });
            // ssh-audit successfully negotiated a session and read the banner — this
            // independently confirms nmap's open-port claim for this port.
            if (raw || software) {
                findings.push({
                    title: `SSH banner observed on ${host}:${port}`,
                    severity: "info",
                    port,
                    protocol: "tcp",
                    evidence: `Banner: ${raw ?? software ?? "(none)"}`,
                    fingerprint: `ssh-reachable|${host}|${port}`,
                    confidence: "high",
                    requiresVerification: false,
                    claimType: "ssh_reachable",
                    verifiesFingerprint: `open-port|${host}|tcp|${port}`
                });
            }
            for (const key of ["kex", "key", "mac", "enc", "compression"]) {
                const list = obj[key];
                if (Array.isArray(list)) {
                    facts.push({
                        type: `ssh_${key}`,
                        value: { port, count: list.length, algorithms: list.slice(0, 30) },
                        source: "ssh-audit"
                    });
                }
            }
            const cves = Array.isArray(obj.cves) ? obj.cves : [];
            for (const cve of cves) {
                const name = typeof cve.name === "string" ? cve.name : "CVE";
                const description = typeof cve.description === "string" ? cve.description : "";
                const cvssv2 = typeof cve.cvssv2 === "number" ? cve.cvssv2 : null;
                const severity = cvssv2 !== null && cvssv2 >= 9 ? "critical" : cvssv2 !== null && cvssv2 >= 7 ? "high" : cvssv2 !== null && cvssv2 >= 4 ? "medium" : "low";
                findings.push({
                    title: `SSH ${name} on ${host}:${port}`,
                    severity,
                    port,
                    protocol: "tcp",
                    evidence: `${description}${cvssv2 !== null ? ` (CVSSv2: ${cvssv2})` : ""}`,
                    fingerprint: `ssh-cve|${host}|${port}|${name}`,
                    // CVE match against the ssh-audit fingerprint database is definitive.
                    confidence: "high",
                    requiresVerification: false,
                    claimType: "ssh_cve"
                });
            }
            const recsObj = (obj.recommendations ?? {});
            const critical = (recsObj.critical ?? {});
            const warning = (recsObj.warning ?? {});
            const issuesFound = collectIssues(critical).map((e) => ({ ...e, severity: "high" }));
            const warns = collectIssues(warning).map((e) => ({ ...e, severity: "medium" }));
            for (const e of [...issuesFound, ...warns]) {
                findings.push({
                    title: `Weak/legacy SSH ${e.kind}: ${e.algorithm} on ${host}:${port}`,
                    severity: e.severity,
                    port,
                    protocol: "tcp",
                    evidence: `ssh-audit recommends removing ${e.kind} ${e.algorithm}`,
                    fingerprint: `ssh-weak|${host}|${port}|${e.kind}|${e.algorithm}`,
                    // The server negotiated/advertised this algorithm to ssh-audit; it
                    // is observed directly, no follow-up verifier needed.
                    confidence: "high",
                    requiresVerification: false,
                    claimType: "ssh_weak_algorithm"
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
                ports: sshPorts,
                commandSummary: `Run ssh-audit -j on ${host} (ports: ${sshPorts.join(",")}) and lift CVEs / weak algorithms into findings.`
            }
        };
    }
};
function collectIssues(section) {
    const out = [];
    for (const action of Object.keys(section)) {
        const block = section[action];
        if (!block)
            continue;
        for (const kind of Object.keys(block)) {
            const list = block[kind];
            if (!Array.isArray(list))
                continue;
            for (const item of list) {
                const algorithm = typeof item === "string" ? item : typeof item?.name === "string" ? String(item.name) : null;
                if (algorithm)
                    out.push({ kind, algorithm });
            }
        }
    }
    return out;
}
function quote(s) {
    return `'${s.replace(/'/g, `'\\''`)}'`;
}
