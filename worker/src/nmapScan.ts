import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import { XMLParser } from "fast-xml-parser";

export type NmapService = {
  port: number;
  protocol: "tcp" | "udp";
  serviceName?: string;
  product?: string;
  version?: string;
  banner?: string;
};

export type NmapResult = {
  services: NmapService[];
  rawXml: string;
};

function run(
  cmd: string,
  args: string[],
  timeoutMs: number,
  opts?: {
    onStdout?: (chunk: string) => void;
    onStderr?: (chunk: string) => void;
  }
) {
  return new Promise<{ stdout: string; stderr: string; exitCode: number | null }>((resolve, reject) => {
    const child = spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";

    const t = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`Command timeout after ${timeoutMs}ms: ${cmd} ${args.join(" ")}`));
    }, timeoutMs);

    child.stdout.on("data", (d) => {
      const s = d.toString("utf8");
      stdout += s;
      opts?.onStdout?.(s);
    });
    child.stderr.on("data", (d) => {
      const s = d.toString("utf8");
      stderr += s;
      opts?.onStderr?.(s);
    });
    child.on("error", (e) => {
      clearTimeout(t);
      reject(e);
    });
    child.on("close", (code) => {
      clearTimeout(t);
      resolve({ stdout, stderr, exitCode: code });
    });
  });
}

export async function nmapScan(
  targetAddress: string,
  nmapArgs: string,
  opts?: {
    onOutput?: (line: string) => void;
  }
) {
  // Write XML to file (keeps stdout/stderr free for live logs).
  const xmlPath = "/tmp/nmap.xml";
  const args = [...nmapArgs.split(/\s+/).filter(Boolean), "-oX", xmlPath, targetAddress];

  const { stderr, exitCode } = await run("nmap", args, 10 * 60 * 1000, {
    onStdout: (c) => opts?.onOutput?.(c),
    onStderr: (c) => opts?.onOutput?.(c)
  });
  if (exitCode !== 0) {
    throw new Error(`nmap failed (exit=${exitCode}). stderr=${stderr.slice(0, 2000)}`);
  }

  const rawXml = await fs.readFile(xmlPath, "utf8");

  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: "",
    allowBooleanAttributes: true
  });
  const doc: any = parser.parse(rawXml);

  const host = doc?.nmaprun?.host;
  const ports = host?.ports?.port;
  const portList = Array.isArray(ports) ? ports : ports ? [ports] : [];

  const services: NmapService[] = [];
  for (const p of portList) {
    const state = p?.state?.state;
    if (state !== "open") continue;
    const port = Number(p.portid);
    const protocol = (p.protocol as "tcp" | "udp") ?? "tcp";
    const svc = p?.service ?? {};
    services.push({
      port,
      protocol,
      serviceName: svc.name,
      product: svc.product,
      version: svc.version,
      banner: svc.extrainfo
    });
  }

  return { services, rawXml } satisfies NmapResult;
}

