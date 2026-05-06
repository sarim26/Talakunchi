import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { XMLParser } from "fast-xml-parser";

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

function run(
  cmd: string,
  args: string[],
  opts?: {
    onStdout?: (chunk: string) => void;
    onStderr?: (chunk: string) => void;
    signal?: AbortSignal;
  }
) {
  return new Promise<{ stdout: string; stderr: string; exitCode: number | null }>((resolve, reject) => {
    const child = spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";

    const onAbort = () => {
      child.kill("SIGKILL");
      reject(new Error("aborted"));
    };
    if (opts?.signal) {
      if (opts.signal.aborted) return void onAbort();
      opts.signal.addEventListener("abort", onAbort, { once: true });
    }

    child.stdout.on("data", (d: Buffer) => {
      const s = d.toString("utf8");
      stdout += s;
      opts?.onStdout?.(s);
    });
    child.stderr.on("data", (d: Buffer) => {
      const s = d.toString("utf8");
      stderr += s;
      opts?.onStderr?.(s);
    });
    child.on("error", (e) => {
      reject(e);
    });
    child.on("close", (code) => {
      if (opts?.signal) opts.signal.removeEventListener("abort", onAbort);
      resolve({ stdout, stderr, exitCode: code });
    });
  });
}

export async function nmapScan(
  targetAddress: string,
  nmapArgs: string,
  opts?: {
    onOutput?: (line: string) => void;
    signal?: AbortSignal;
  }
) {
  const xmlPath = path.join(os.tmpdir(), `nmap-${Date.now()}-${Math.random().toString(36).slice(2)}.xml`);
  const baseArgs = ensureNmapVerboseFlags(nmapArgs.split(/\s+/).filter(Boolean));
  const args = [...baseArgs, "-oX", xmlPath, targetAddress];
  const noise = wrapOutputStripNmapNoise(opts?.onOutput);

  let rawXml = "";
  try {
    try {
      const { stderr, exitCode } = await run("nmap", args, {
        onStdout: (c) => noise.push(c),
        onStderr: (c) => noise.push(c),
        signal: opts?.signal
      });
      if (exitCode !== 0) {
        throw new Error(`nmap failed (exit=${exitCode}). stderr=${stderr.slice(0, 2000)}`);
      }
      rawXml = await fs.readFile(xmlPath, "utf8");
    } finally {
      noise.flush();
    }
  } finally {
    await fs.unlink(xmlPath).catch(() => undefined);
  }

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

