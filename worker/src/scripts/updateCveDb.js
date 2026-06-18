import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { z } from "zod";
const JsonHeuristicSchema = z.object({
    match: z.string().min(1),
    flags: z.string().optional(),
    cves: z.array(z.string().min(1)).min(1),
    severity: z.enum(["info", "low", "medium", "high", "critical"]),
    description: z.string().min(1)
});
const JsonHeuristicsSchema = z.array(JsonHeuristicSchema);
async function main() {
    const url = process.env.CVE_HEURISTICS_FEED_URL;
    if (!url) {
        console.error("Missing CVE_HEURISTICS_FEED_URL. Example: set CVE_HEURISTICS_FEED_URL=https://.../cve-heuristics.json");
        process.exit(2);
    }
    const outPath = path.resolve(process.env.CVE_HEURISTICS_PATH || path.resolve(process.cwd(), "data", "cve-heuristics.json"));
    const res = await fetch(url, { headers: { "user-agent": "talakunchi-worker/0.1" } });
    if (!res.ok) {
        console.error(`Feed download failed: HTTP ${res.status} ${res.statusText}`);
        process.exit(3);
    }
    const text = await res.text();
    let json;
    try {
        json = JSON.parse(text);
    }
    catch (e) {
        console.error(`Feed is not valid JSON: ${e.message}`);
        process.exit(4);
    }
    const parsed = JsonHeuristicsSchema.safeParse(json);
    if (!parsed.success) {
        console.error(`Feed JSON schema invalid: ${parsed.error.errors
            .slice(0, 5)
            .map((er) => `${er.path.join(".")}: ${er.message}`)
            .join("; ")}`);
        process.exit(5);
    }
    await mkdir(path.dirname(outPath), { recursive: true });
    await writeFile(outPath, JSON.stringify(parsed.data, null, 2) + "\n", "utf8");
    console.log(`Updated CVE heuristics feed: ${outPath} (${parsed.data.length} rules)`);
}
main().catch((e) => {
    console.error(e.stack || String(e));
    process.exit(1);
});
