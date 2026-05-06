import { spawnWithRemotePolicy } from "./remoteExec.js";

export type HydraService =
  | "ssh"
  | "ftp"
  | "rdp"
  | "smb"
  | "mysql"
  | "mssql"
  | "postgres"
  | "smtp"
  | "imap"
  | "pop3"
  | "telnet"
  | "vnc"
  | "http-get"
  | "http-post-form"
  | "https-get"
  | "https-post-form";

export type HydraCredential = {
  host: string;
  port: number;
  service: HydraService;
  username: string;
  password: string;
};

export type HydraResult = {
  credentials: HydraCredential[];
  raw: string;
};

type HydraBaseOpts = {
  port?: number;
  threads?: number;
  stopOnFirstFind?: boolean;
  outputFile?: string;
  extraArgs?: string[];
  onOutput?: (line: string) => void;
  signal?: AbortSignal;
};

type HydraUsernameSource =
  | { username: string; userList?: never }
  | { username?: never; userList: string };

type HydraPasswordSource =
  | { password: string; passwordList?: never }
  | { password?: never; passwordList: string };

export type HydraCredSource = HydraUsernameSource & HydraPasswordSource;

export type HydraHttpFormOpts = HydraBaseOpts & {
  formPath: string;
  formBody: string;
  failureString: string;
};

function parseHydraOutput(raw: string, host: string, service: HydraService): HydraCredential[] {
  const results: HydraCredential[] = [];
  const lineRe = /\[(\d+)\]\[([^\]]+)\]\s+host:\s*\S+\s+login:\s*(\S+)\s+password:\s*(.+)/g;
  let m: RegExpExecArray | null;
  while ((m = lineRe.exec(raw)) !== null) {
    results.push({
      host,
      port: parseInt(m[1], 10),
      service,
      username: m[3].trim(),
      password: m[4].trim()
    });
  }
  return results;
}

function buildBaseArgs(credSource: HydraCredSource, opts: HydraBaseOpts): string[] {
  const args: string[] = [];

  if ("userList" in credSource && credSource.userList) {
    args.push("-L", credSource.userList);
  } else if ("username" in credSource && credSource.username) {
    args.push("-l", credSource.username);
  }

  if ("passwordList" in credSource && credSource.passwordList) {
    args.push("-P", credSource.passwordList);
  } else if ("password" in credSource && credSource.password) {
    args.push("-p", credSource.password);
  }

  args.push("-t", String(opts.threads ?? 16));
  // -V: show each login attempt (verbose). Avoid -d (debug) — very noisy.
  args.push("-V");
  if (opts.stopOnFirstFind) args.push("-f");
  if (opts.outputFile) args.push("-o", opts.outputFile);
  if (opts.port) args.push("-s", String(opts.port));
  if (opts.extraArgs) args.push(...opts.extraArgs);

  return args;
}

export async function hydraScan(
  targetAddress: string,
  service: HydraService,
  credSource: HydraCredSource,
  opts: HydraBaseOpts = {}
): Promise<HydraResult> {
  const safeThreads = opts.threads ?? (service === "rdp" || service === "smb" ? 4 : 16);
  const args = buildBaseArgs(credSource, { ...opts, threads: safeThreads });
  args.push(`${service}://${targetAddress}`);

  const { stdout, stderr, exitCode } = await spawnWithRemotePolicy("hydra", args, {
    onStdout: (c) => opts.onOutput?.(c),
    onStderr: (c) => opts.onOutput?.(c),
    signal: opts.signal
  });

  if (exitCode !== 0 && exitCode !== 1) {
    throw new Error(`hydra failed (exit=${exitCode}). stderr=${stderr.slice(0, 2000)}`);
  }

  const raw = stdout + stderr;
  const credentials = parseHydraOutput(raw, targetAddress, service);
  return { credentials, raw };
}

export async function hydraHttpForm(
  targetAddress: string,
  service: "http-post-form" | "https-post-form" | "http-get" | "https-get",
  credSource: HydraCredSource,
  opts: HydraHttpFormOpts
): Promise<HydraResult> {
  const args = buildBaseArgs(credSource, opts);
  const formSpec = `${opts.formPath}:${opts.formBody}:${opts.failureString}`;
  args.push(targetAddress, service, formSpec);

  const { stdout, stderr, exitCode } = await spawnWithRemotePolicy("hydra", args, {
    onStdout: (c) => opts.onOutput?.(c),
    onStderr: (c) => opts.onOutput?.(c),
    signal: opts.signal
  });

  if (exitCode !== 0 && exitCode !== 1) {
    throw new Error(`hydra failed (exit=${exitCode}). stderr=${stderr.slice(0, 2000)}`);
  }

  const raw = stdout + stderr;
  const credentials = parseHydraOutput(raw, targetAddress, service as HydraService);
  return { credentials, raw };
}

export async function hydraFromNmapServices(
  targetAddress: string,
  services: Array<{ port: number; serviceName?: string }>,
  credSource: HydraCredSource,
  opts: HydraBaseOpts = {}
): Promise<HydraResult[]> {
  const supportedServices: Record<string, HydraService> = {
    ssh: "ssh",
    ftp: "ftp",
    "microsoft-rdp": "rdp",
    rdp: "rdp",
    "microsoft-ds": "smb",
    "netbios-ssn": "smb",
    smb: "smb",
    mysql: "mysql",
    "ms-sql-s": "mssql",
    postgresql: "postgres",
    smtp: "smtp",
    imap: "imap",
    pop3: "pop3",
    telnet: "telnet",
    vnc: "vnc"
  };

  const results: HydraResult[] = [];
  for (const svc of services) {
    const hydraService = svc.serviceName ? supportedServices[svc.serviceName.toLowerCase()] : undefined;
    if (!hydraService) {
      opts.onOutput?.(`[hydra] Skipping port ${svc.port} - unsupported service: ${svc.serviceName ?? "unknown"}\n`);
      continue;
    }

    opts.onOutput?.(`[hydra] Attacking ${targetAddress}:${svc.port} (${hydraService})\n`);
    const result = await hydraScan(targetAddress, hydraService, credSource, { ...opts, port: svc.port });
    results.push(result);
  }

  return results;
}
