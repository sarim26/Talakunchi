import net from "node:net";
import { withClient } from "../db.js";
import { censysHost, enabledConnectors, securityTrailsPassiveDns, shodanHost } from "../osint/connectors.js";
/** Upsert an OSINT-derived asset into recon_assets (shared with the classic pipeline). */
async function persistReconAsset(targetId, assetType, value, source, confidence, metadata) {
    await withClient(async (c) => {
        await c.query(`insert into recon_assets (target_id, asset_type, value, source, confidence, metadata, first_seen_at, last_seen_at)
       values ($1, $2, $3, $4, $5, $6::jsonb, now(), now())
       on conflict (target_id, asset_type, value, source)
       do update set confidence = excluded.confidence, metadata = excluded.metadata, last_seen_at = now()`, [targetId, assetType, value, source, confidence, JSON.stringify(metadata)]);
    });
}
/**
 * recon.osint — passive host intelligence via Shodan/Censys (env-gated).
 * No active packets are sent to the target; results come from third-party APIs.
 */
export const osintTool = {
    name: "recon.osint",
    description: "Passive host intelligence (Shodan/Censys) for the target IP. No active scanning; requires API keys.",
    tags: ["recon", "osint"],
    requires: ["target"],
    defaultTimeoutMs: 60_000,
    handler: async (input, emit) => {
        const enabled = enabledConnectors().filter((c) => c === "shodan" || c === "censys");
        if (enabled.length === 0) {
            emit.log("recon.osint: no Shodan/Censys API keys configured — skipping.");
            return {
                status: "skipped",
                error: "No OSINT host connectors configured (set SHODAN_API_KEY or CENSYS_API_ID/SECRET).",
                artifacts: { commands: [] },
                facts: [],
                findings: [],
                recommendations: [],
                meta: { enabledConnectors: [] }
            };
        }
        const host = input.target.host;
        const ip = input.target.ip && net.isIP(input.target.ip) ? input.target.ip : net.isIP(host) ? host : null;
        if (!ip) {
            return {
                status: "skipped",
                error: "recon.osint host lookup needs an IP (target.ip or numeric host). Resolve the hostname first.",
                artifacts: { commands: [] },
                facts: [],
                findings: [],
                recommendations: [],
                meta: { enabledConnectors: enabled }
            };
        }
        emit.log(`recon.osint: querying ${enabled.join(", ")} for ${ip}`);
        const results = [];
        const shodan = await shodanHost(ip, input.signal);
        if (shodan)
            results.push(shodan);
        const censys = await censysHost(ip, input.signal);
        if (censys)
            results.push(censys);
        const facts = [];
        const findings = [];
        for (const r of results) {
            facts.push({ type: "osint_host", value: { ...r }, source: r.source });
            await persistReconAsset(input.target.targetId, "osint_host", ip, r.source, 60, { ...r });
            for (const hn of r.hostnames ?? []) {
                await persistReconAsset(input.target.targetId, "hostname", hn, r.source, 55, { ip });
            }
            if ((r.ports ?? []).length > 0) {
                findings.push({
                    title: `OSINT (${r.source}): ${r.ports.length} exposed port(s) known for ${ip}`,
                    severity: "info",
                    evidence: `Ports: ${r.ports.slice(0, 30).join(", ")}${r.org ? ` | Org: ${r.org}` : ""}`,
                    fingerprint: `osint-ports|${r.source}|${ip}`,
                    confidence: "medium",
                    requiresVerification: true,
                    claimType: "osint_exposure"
                });
            }
        }
        return {
            status: "succeeded",
            facts,
            findings,
            recommendations: [],
            artifacts: { commands: [] },
            meta: { enabledConnectors: enabled, ip, sources: results.map((r) => r.source), commandSummary: `Passive host intel for ${ip} via ${enabled.join(", ")}.` }
        };
    }
};
/**
 * recon.passive_dns — passive DNS history for the target hostname via
 * SecurityTrails (env-gated). Persists discovered IPs/hostnames to recon_assets.
 */
export const passiveDnsTool = {
    name: "recon.passive_dns",
    description: "Passive DNS history for the target hostname via SecurityTrails (requires SECURITYTRAILS_API_KEY).",
    tags: ["recon", "osint", "dns"],
    requires: ["target"],
    defaultTimeoutMs: 60_000,
    handler: async (input, emit) => {
        const host = input.target.host;
        if (net.isIP(host)) {
            return {
                status: "skipped",
                error: "recon.passive_dns needs a hostname target, not an IP.",
                artifacts: { commands: [] },
                facts: [],
                findings: [],
                recommendations: [],
                meta: {}
            };
        }
        emit.log(`recon.passive_dns: SecurityTrails history for ${host}`);
        const records = await securityTrailsPassiveDns(host, input.signal);
        if (records === null) {
            return {
                status: "skipped",
                error: "SecurityTrails not configured (set SECURITYTRAILS_API_KEY) or no data returned.",
                artifacts: { commands: [] },
                facts: [],
                findings: [],
                recommendations: [],
                meta: { enabledConnectors: enabledConnectors() }
            };
        }
        const facts = [];
        const seenIps = new Set();
        for (const rec of records) {
            for (const ip of rec.ips) {
                if (seenIps.has(ip))
                    continue;
                seenIps.add(ip);
                facts.push({ type: "passive_dns", value: { hostname: rec.hostname, ip }, source: rec.source });
                await persistReconAsset(input.target.targetId, "ip", ip, "securitytrails", 50, { hostname: rec.hostname, via: "passive_dns" });
            }
        }
        return {
            status: "succeeded",
            facts,
            findings: [],
            recommendations: [],
            artifacts: { commands: [] },
            meta: { historicalIps: [...seenIps], commandSummary: `Passive DNS A-history for ${host} via SecurityTrails.` }
        };
    }
};
export const osintTools = [osintTool, passiveDnsTool];
