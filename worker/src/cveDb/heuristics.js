import { z } from "zod";
import { readFile } from "node:fs/promises";
import path from "node:path";
const JsonHeuristicSchema = z.object({
    match: z.string().min(1),
    flags: z.string().optional(),
    cves: z.array(z.string().min(1)).min(1),
    severity: z.enum(["info", "low", "medium", "high", "critical"]),
    description: z.string().min(1)
});
const JsonHeuristicsSchema = z.array(JsonHeuristicSchema);
/**
 * Default built-in heuristics (used if the on-disk feed is missing/invalid).
 * Kept intentionally small; the dynamic feed lives in `data/cve-heuristics.json`.
 */
export const DEFAULT_HEURISTICS = [
    { match: /OpenSSH[_ ]?7\.[0-3]/i, cves: ["CVE-2016-10009", "CVE-2016-10010"], severity: "medium", description: "OpenSSH 7.0–7.3 has known agent-related issues" },
    { match: /Apache\/2\.4\.49/i, cves: ["CVE-2021-41773"], severity: "critical", description: "Apache 2.4.49 path traversal" },
    { match: /Apache\/2\.4\.50/i, cves: ["CVE-2021-42013"], severity: "critical", description: "Apache 2.4.50 path traversal (incomplete fix)" },
    { match: /nginx\/1\.(?:1[0-7]|[0-9])\b/i, cves: ["CVE-2019-9511"], severity: "medium", description: "Older nginx HTTP/2 DoS family" },
    { match: /Microsoft IIS httpd\/?\s*(?:6|7|7\.5)\b/i, cves: ["EOL"], severity: "high", description: "End-of-life IIS — patches no longer issued" },
    { match: /vsftpd 2\.3\.4/i, cves: ["CVE-2011-2523"], severity: "critical", description: "vsftpd 2.3.4 backdoor" },
    { match: /\bJetty\b.*\b8\./i, cves: ["EOL"], severity: "medium", description: "Older Jetty 8.x is end-of-life; review upgrade path" },
    { match: /\bProFTPD\b.*\b1\.3\.5\b/i, cves: ["CVE-2015-3306"], severity: "high", description: "ProFTPD 1.3.5 has known mod_copy file copy issues (context-dependent)" }
];
export async function loadCveHeuristics(opts) {
    const p = opts?.path ? path.resolve(opts.path) : path.resolve(process.cwd(), "data", "cve-heuristics.json");
    try {
        const raw = await readFile(p, "utf8");
        const parsed = JsonHeuristicsSchema.safeParse(JSON.parse(raw));
        if (!parsed.success) {
            return {
                source: "default",
                path: p,
                heuristics: DEFAULT_HEURISTICS,
                error: parsed.error.errors.slice(0, 3).map((e) => `${e.path.join(".")}: ${e.message}`).join("; ")
            };
        }
        const compiled = [];
        for (const h of parsed.data) {
            try {
                compiled.push({
                    match: new RegExp(h.match, h.flags ?? "i"),
                    cves: h.cves,
                    severity: h.severity,
                    description: h.description
                });
            }
            catch {
                // Ignore invalid regex entries.
            }
        }
        if (compiled.length === 0) {
            return { source: "default", path: p, heuristics: DEFAULT_HEURISTICS, error: "No valid regex rules in file" };
        }
        return { source: "file", path: p, heuristics: compiled };
    }
    catch (e) {
        return { source: "default", path: p, heuristics: DEFAULT_HEURISTICS, error: e.message };
    }
}
