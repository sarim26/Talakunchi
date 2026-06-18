import { XMLParser } from "fast-xml-parser";
import { spawnWithRemotePolicy } from "./remoteExec.js";
/** Live nmap stderr often includes NSOCK socket-trace lines when -d/--debug is used; drop those from logs. */
function isNmapNoiseLine(line) {
    return /^\s*NSOCK\b/i.test(line);
}
/** Line-buffered sink that drops NSOCK debug lines (for agent-mode `execute_command` nmap as well). */
export function wrapOutputStripNmapNoise(onOutput) {
    let buf = "";
    return {
        push(chunk) {
            if (!onOutput)
                return;
            buf += chunk;
            const parts = buf.split(/\r?\n/);
            buf = parts.pop() ?? "";
            for (const line of parts) {
                if (isNmapNoiseLine(line))
                    continue;
                onOutput(line + "\n");
            }
        },
        flush() {
            if (!onOutput || !buf)
                return;
            if (!isNmapNoiseLine(buf))
                onOutput(buf.endsWith("\n") ? buf : buf + "\n");
            buf = "";
        }
    };
}
function ensureNmapVerboseFlags(argv) {
    const hasV = argv.some((a) => /^-v+$/i.test(a));
    if (hasV)
        return argv;
    return ["-vv", ...argv];
}
/** With `-oX -`, XML goes to stdout; human/progress output goes to stderr. */
export async function nmapScan(targetAddress, nmapArgs, opts) {
    const baseArgs = ensureNmapVerboseFlags(nmapArgs.split(/\s+/).filter(Boolean));
    const args = [...baseArgs, "-oX", "-", targetAddress];
    const noise = wrapOutputStripNmapNoise(opts?.onOutput);
    let stdout = "";
    let stderr = "";
    try {
        const result = await spawnWithRemotePolicy("nmap", args, {
            onStdout: (c) => {
                stdout += c;
            },
            onStderr: (c) => {
                stderr += c;
                noise.push(c);
            },
            signal: opts?.signal
        });
        if (result.exitCode !== 0) {
            throw new Error(`nmap failed (exit=${result.exitCode}). stderr=${stderr.slice(0, 2000)}`);
        }
    }
    finally {
        noise.flush();
    }
    const parsed = parseNmapXml(stdout, targetAddress);
    if (!parsed) {
        throw new Error("nmap XML could not be parsed");
    }
    return { ...parsed, rawXml: stdout };
}
/**
 * Parses nmap `-oX -` XML into NmapResult (without rawXml). Returns null if
 * the document cannot be parsed.
 */
export function parseNmapXml(rawXml, fallbackHost = "") {
    if (!rawXml || !rawXml.trim().startsWith("<"))
        return null;
    const parser = new XMLParser({
        ignoreAttributes: false,
        attributeNamePrefix: "",
        allowBooleanAttributes: true
    });
    let doc;
    try {
        doc = parser.parse(rawXml);
    }
    catch {
        return null;
    }
    const host = doc?.nmaprun?.host;
    if (!host)
        return { host: fallbackHost, status: "down", services: [] };
    const hostStatus = host?.status?.state === "up" ? "up" : "down";
    const hostAddresses = Array.isArray(host?.address) ? host.address : host?.address ? [host.address] : [];
    const ipv4 = hostAddresses.find((a) => a?.addrtype === "ipv4")?.addr;
    const firstAddress = hostAddresses[0]?.addr;
    const resolvedHost = ipv4 ?? firstAddress ?? fallbackHost;
    const ports = host?.ports?.port;
    const portList = Array.isArray(ports) ? ports : ports ? [ports] : [];
    const services = [];
    for (const p of portList) {
        const state = p?.state?.state;
        const port = Number(p.portid);
        const protocol = p.protocol ?? "tcp";
        const svc = p?.service ?? {};
        services.push({
            port,
            protocol,
            state: String(state ?? "unknown"),
            serviceName: svc.name,
            product: svc.product,
            version: svc.version,
            banner: svc.extrainfo
        });
    }
    return { host: resolvedHost, status: hostStatus, services };
}
