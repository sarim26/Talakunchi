import { XMLParser } from "fast-xml-parser";
import { spawnWithRemotePolicy } from "./remoteExec.js";

export type NmapService = {
  port: number;
  protocol: "tcp" | "udp";
  state: string;
  serviceName?: string;
  product?: string;
  version?: string;
  banner?: string;
};

export type NmapResult = {
  host: string;
  status: "up" | "down";
  services: NmapService[];
  rawXml: string;
};

/** Live nmap stderr often includes NSOCK socket-trace lines when -d/--debug is used; drop those from logs. */
function isNmapNoiseLine(line: string): boolean {
  return /^\s*NSOCK\b/i.test(line);
}

/** Line-buffered sink that drops NSOCK debug lines (for agent-mode `execute_command` nmap as well). */
export function wrapOutputStripNmapNoise(onOutput?: (line: string) => void) {
  let buf = "";
  return {
    push(chunk: string) {
      if (!onOutput) return;
      buf += chunk;
      const parts = buf.split(/\r?\n/);
      buf = parts.pop() ?? "";
      for (const line of parts) {
        if (isNmapNoiseLine(line)) continue;
        onOutput(line + "\n");
      }
    },
    flush() {
      if (!onOutput || !buf) return;
      if (!isNmapNoiseLine(buf)) onOutput(buf.endsWith("\n") ? buf : buf + "\n");
      buf = "";
    }
  };
}

function ensureNmapVerboseFlags(argv: string[]): string[] {
  const hasV = argv.some((a) => /^-v+$/i.test(a));
  if (hasV) return argv;
  return ["-vv", ...argv];
}

/** With `-oX -`, XML goes to stdout; human/progress output goes to stderr. */
export async function nmapScan(
  targetAddress: string,
  nmapArgs: string,
  opts?: {
    onOutput?: (line: string) => void;
    signal?: AbortSignal;
  }
) {
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
  } finally {
    noise.flush();
  }

  const rawXml = stdout;

  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: "",
    allowBooleanAttributes: true
  });
  const doc: any = parser.parse(rawXml);

  const host = doc?.nmaprun?.host;
  const hostStatus = host?.status?.state === "up" ? "up" : "down";
  const hostAddresses = Array.isArray(host?.address) ? host.address : host?.address ? [host.address] : [];
  const ipv4 = hostAddresses.find((a: any) => a?.addrtype === "ipv4")?.addr;
  const firstAddress = hostAddresses[0]?.addr;
  const resolvedHost = ipv4 ?? firstAddress ?? targetAddress;
  const ports = host?.ports?.port;
  const portList = Array.isArray(ports) ? ports : ports ? [ports] : [];

  const services: NmapService[] = [];
  for (const p of portList) {
    const state = p?.state?.state;
    const port = Number(p.portid);
    const protocol = (p.protocol as "tcp" | "udp") ?? "tcp";
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

  return { host: resolvedHost, status: hostStatus, services, rawXml } satisfies NmapResult;
}
