import { ToolDefinition, ToolEnvelope, ToolFinding, ToolInput } from "../mcp/types.js";
import { remoteRun, remoteScript, requireRemoteTool, snippet } from "./shared.js";

/**
 * Infra specialist agents (Phase 4).
 *
 * Each tool is triggered by a specific service/port and runs a read-only
 * enumeration over the SSH bastion. They all emit a corroboration finding
 * (`verifiesFingerprint: open-port|host|<proto>|<port>`) when the service
 * actually responds, plus protocol-specific security findings.
 */

function quote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/** Ports from context that match `predicate`, falling back to `defaults`. */
function matchedPorts(input: ToolInput, predicate: (s: { port: number; protocol: string; name?: string }) => boolean, defaults: number[]): number[] {
  const matched = (input.context?.knownServices ?? []).filter(predicate).map((s) => s.port);
  return [...new Set(matched.length > 0 ? matched : defaults)];
}

/** Detect open `PORT/proto open` lines in nmap's normal output. */
function openPortsFromNmapText(stdout: string, protocol: "tcp" | "udp"): number[] {
  const out = new Set<number>();
  const re = new RegExp(`^(\\d+)\\/${protocol}\\s+open`, "gm");
  let m: RegExpExecArray | null;
  while ((m = re.exec(stdout)) !== null) out.add(Number(m[1]));
  return [...out];
}

function corroboration(host: string, port: number, protocol: "tcp" | "udp", tool: string, evidence: string): ToolFinding {
  return {
    title: `${protocol.toUpperCase()} ${port} reachable on ${host}`,
    severity: "info",
    port,
    protocol,
    evidence,
    fingerprint: `${tool}-reachable|${host}|${protocol}|${port}`,
    confidence: "high",
    requiresVerification: false,
    claimType: "service_reachable",
    verifiesFingerprint: `open-port|${host}|${protocol}|${port}`
  };
}

/** Build an nmap NSE-script based specialist (TCP). */
function makeNmapScriptTool(opts: {
  name: string;
  description: string;
  tags: string[];
  scripts: string[];
  match: (s: { port: number; protocol: string; name?: string }) => boolean;
  defaultPorts: number[];
  analyze: (stdout: string, host: string, ports: number[]) => ToolFinding[];
  serviceVersion?: boolean;
}): ToolDefinition {
  return {
    name: opts.name,
    description: opts.description,
    tags: opts.tags,
    requires: ["services"],
    defaultTimeoutMs: 6 * 60 * 1000,
    handler: async (input, emit): Promise<ToolEnvelope> => {
      const ports = matchedPorts(input, opts.match, opts.defaultPorts);
      const presence = await requireRemoteTool("nmap", input.signal, {
        knownPresent: input.context?.knownPresentTools
      });
      if (presence.missing) return presence.envelope;

      const host = input.target.host;
      const args = ["-Pn"];
      if (opts.serviceVersion) args.push("-sV", "--version-light");
      args.push("--script", opts.scripts.join(","), "-p", ports.join(","), host);

      emit.log(`${opts.name}: nmap --script ${opts.scripts.join(",")} on ${host}:${ports.join(",")}`);
      const r = await remoteRun("nmap", args, input.signal, (s) => emit.log(s));

      const findings: ToolFinding[] = [];
      for (const port of openPortsFromNmapText(r.stdout, "tcp")) {
        findings.push(corroboration(host, port, "tcp", opts.name.split(".").pop()!, `nmap reports ${port}/tcp open`));
      }
      findings.push(...opts.analyze(r.stdout, host, ports));

      return {
        status: "succeeded",
        durationMs: r.durationMs,
        artifacts: { commands: r.commands, stdoutSnippet: snippet(r.stdout), stderrSnippet: snippet(r.stderr) },
        facts: [],
        findings,
        recommendations: [],
        meta: { exitCode: r.exitCode, ports, commandSummary: `${opts.name} via nmap NSE on ${host}.` }
      };
    }
  };
}

/** Extract nmap NSE output for a given script id (lines under `| <script>:`). */
function nseSection(stdout: string, scriptId: string): string {
  const lines = stdout.split("\n");
  const out: string[] = [];
  let inSection = false;
  for (const line of lines) {
    if (new RegExp(`^\\|_?\\s*${scriptId}:`).test(line.trim())) {
      inSection = true;
      out.push(line.trim().replace(/^\|_?\s*/, ""));
      continue;
    }
    if (inSection) {
      if (/^\|/.test(line.trim())) out.push(line.trim().replace(/^\|_?\s*/, ""));
      else inSection = false;
    }
  }
  return out.join("\n");
}

// ---- RDP (TCP 3389) ----------------------------------------------------------
export const rdpEnumTool = makeNmapScriptTool({
  name: "recon.rdp_enum",
  description: "Enumerate RDP (3389) encryption level and NTLM info using nmap rdp-* scripts.",
  tags: ["recon", "rdp"],
  scripts: ["rdp-enum-encryption", "rdp-ntlm-info"],
  match: (s) => s.protocol === "tcp" && (s.port === 3389 || /ms-wbt-server|rdp/i.test(s.name ?? "")),
  defaultPorts: [3389],
  analyze: (stdout, host) => {
    const findings: ToolFinding[] = [];
    const ntlm = nseSection(stdout, "rdp-ntlm-info");
    if (ntlm) {
      findings.push({
        title: `RDP NTLM info disclosed on ${host}:3389`,
        severity: "low",
        port: 3389,
        protocol: "tcp",
        evidence: snippet(ntlm, 600),
        fingerprint: `rdp-ntlm|${host}|3389`,
        confidence: "high",
        requiresVerification: false,
        claimType: "rdp_ntlm_info"
      });
    }
    if (/CredSSP|NLA.*not|protocol.*RDP Security/i.test(stdout) && /SSL|TLS/i.test(stdout) === false) {
      findings.push({
        title: `RDP weak/legacy security layer on ${host}:3389`,
        severity: "medium",
        port: 3389,
        protocol: "tcp",
        evidence: "rdp-enum-encryption indicates a non-TLS/weak RDP security layer",
        fingerprint: `rdp-weak-sec|${host}|3389`,
        confidence: "medium",
        requiresVerification: true,
        claimType: "rdp_weak_security"
      });
    }
    return findings;
  }
});

// ---- FTP (TCP 21) ------------------------------------------------------------
export const ftpEnumTool = makeNmapScriptTool({
  name: "recon.ftp_enum",
  description: "Check FTP (21) for anonymous login and banner using nmap ftp-* scripts.",
  tags: ["recon", "ftp"],
  scripts: ["ftp-anon", "ftp-syst"],
  match: (s) => s.protocol === "tcp" && (s.port === 21 || /^ftp/i.test(s.name ?? "")),
  defaultPorts: [21],
  serviceVersion: true,
  analyze: (stdout, host) => {
    const findings: ToolFinding[] = [];
    if (/ftp-anon:.*Anonymous FTP login allowed/i.test(stdout)) {
      findings.push({
        title: `Anonymous FTP login allowed on ${host}:21`,
        severity: "high",
        port: 21,
        protocol: "tcp",
        evidence: snippet(nseSection(stdout, "ftp-anon"), 600),
        fingerprint: `ftp-anon|${host}|21`,
        confidence: "high",
        requiresVerification: false,
        claimType: "ftp_anonymous"
      });
    }
    return findings;
  }
});

// ---- SMTP (TCP 25/587/465) ---------------------------------------------------
export const smtpEnumTool = makeNmapScriptTool({
  name: "recon.smtp_enum",
  description: "Enumerate SMTP (25/587/465) commands, open relay and user enumeration via nmap smtp-* scripts.",
  tags: ["recon", "smtp"],
  scripts: ["smtp-commands", "smtp-open-relay"],
  match: (s) => s.protocol === "tcp" && ([25, 587, 465].includes(s.port) || /smtp/i.test(s.name ?? "")),
  defaultPorts: [25, 587],
  analyze: (stdout, host) => {
    const findings: ToolFinding[] = [];
    if (/smtp-open-relay:.*(is an open relay|relaying)/i.test(stdout) && /not an open relay/i.test(stdout) === false) {
      findings.push({
        title: `Potential SMTP open relay on ${host}`,
        severity: "high",
        port: 25,
        protocol: "tcp",
        evidence: snippet(nseSection(stdout, "smtp-open-relay"), 600),
        fingerprint: `smtp-open-relay|${host}|25`,
        confidence: "medium",
        requiresVerification: true,
        claimType: "smtp_open_relay"
      });
    }
    const cmds = nseSection(stdout, "smtp-commands");
    if (cmds) {
      findings.push({
        title: `SMTP commands enumerated on ${host}`,
        severity: "info",
        port: 25,
        protocol: "tcp",
        evidence: snippet(cmds, 600),
        fingerprint: `smtp-commands|${host}|25`,
        confidence: "high",
        requiresVerification: false,
        claimType: "smtp_commands"
      });
    }
    return findings;
  }
});

// ---- DB banners (3306/5432/1433) --------------------------------------------
export const dbBannerTool = makeNmapScriptTool({
  name: "recon.db_banner",
  description: "Grab database banners/info for MySQL (3306), PostgreSQL (5432) and MSSQL (1433).",
  tags: ["recon", "database"],
  scripts: ["mysql-info", "ms-sql-info"],
  match: (s) => s.protocol === "tcp" && [3306, 5432, 1433, 1521, 27017].includes(s.port),
  defaultPorts: [3306, 5432, 1433],
  serviceVersion: true,
  analyze: (stdout, host) => {
    const findings: ToolFinding[] = [];
    const mysql = nseSection(stdout, "mysql-info");
    if (mysql) {
      findings.push({
        title: `MySQL server info exposed on ${host}`,
        severity: "low",
        port: 3306,
        protocol: "tcp",
        evidence: snippet(mysql, 600),
        fingerprint: `db-mysql-info|${host}|3306`,
        confidence: "high",
        requiresVerification: false,
        claimType: "db_banner"
      });
    }
    const mssql = nseSection(stdout, "ms-sql-info");
    if (mssql) {
      findings.push({
        title: `MSSQL server info exposed on ${host}`,
        severity: "low",
        port: 1433,
        protocol: "tcp",
        evidence: snippet(mssql, 600),
        fingerprint: `db-mssql-info|${host}|1433`,
        confidence: "high",
        requiresVerification: false,
        claimType: "db_banner"
      });
    }
    return findings;
  }
});

// ---- SNMP (UDP 161) ----------------------------------------------------------
export const snmpEnumTool: ToolDefinition = {
  name: "recon.snmp_enum",
  description: "Probe SNMP (UDP 161) for readable community strings using snmpwalk.",
  tags: ["recon", "snmp"],
  requires: ["services"],
  defaultTimeoutMs: 4 * 60 * 1000,
  handler: async (input, emit): Promise<ToolEnvelope> => {
    const presence = await requireRemoteTool("snmpwalk", input.signal, { installCommand: "apt-get install -y snmp" });
    if (presence.missing) return presence.envelope;

    const host = input.target.host;
    const communities = ["public", "private"];
    const script = [
      "set +e",
      `HOST=${quote(host)}`,
      `for COMMUNITY in ${communities.join(" ")}; do`,
      `  echo "==== SNMP $COMMUNITY ===="`,
      `  snmpwalk -v2c -c "$COMMUNITY" -t 2 -r 1 "$HOST" 1.3.6.1.2.1.1 2>/dev/null || true`,
      "  echo",
      "done"
    ].join("\n");

    emit.log(`snmpwalk on ${host} (communities: ${communities.join(",")})`);
    const r = await remoteScript(script, input.signal, (s) => emit.log(s));

    const findings: ToolFinding[] = [];
    const blocks = r.stdout.split(/^==== SNMP /m).slice(1);
    let anyReadable = false;
    for (const block of blocks) {
      const cm = /^(\w+)\s+====/.exec(block);
      if (!cm) continue;
      const community = cm[1]!;
      if (/iso\.|\bSTRING\b|\bOID\b|::/.test(block) && /1\.3\.6\.1/.test(block) === false && /=\s/.test(block) === false) continue;
      if (/=\s/.test(block)) {
        anyReadable = true;
        findings.push({
          title: `SNMP community '${community}' readable on ${host}`,
          severity: community === "public" ? "medium" : "high",
          port: 161,
          protocol: "udp",
          evidence: snippet(block.split("\n").slice(1).join("\n").trim(), 600),
          fingerprint: `snmp-community|${host}|${community}`,
          confidence: "high",
          requiresVerification: false,
          claimType: "snmp_readable"
        });
      }
    }
    if (anyReadable) findings.push(corroboration(host, 161, "udp", "snmp", "snmpwalk returned OIDs"));

    return {
      status: "succeeded",
      durationMs: r.durationMs,
      artifacts: { commands: r.commands, stdoutSnippet: snippet(r.stdout), stderrSnippet: snippet(r.stderr) },
      facts: [],
      findings,
      recommendations: [],
      meta: { exitCode: r.exitCode, commandSummary: `snmpwalk default communities against ${host}:161/udp.` }
    };
  }
};

// ---- LDAP (TCP 389/636) ------------------------------------------------------
export const ldapEnumTool: ToolDefinition = {
  name: "recon.ldap_enum",
  description: "Test LDAP (389/636) anonymous bind and read naming contexts using ldapsearch.",
  tags: ["recon", "ldap"],
  requires: ["services"],
  defaultTimeoutMs: 4 * 60 * 1000,
  handler: async (input, emit): Promise<ToolEnvelope> => {
    const ports = matchedPorts(
      input,
      (s) => s.protocol === "tcp" && ([389, 636, 3268, 3269].includes(s.port) || /ldap/i.test(s.name ?? "")),
      [389]
    );
    const presence = await requireRemoteTool("ldapsearch", input.signal, { installCommand: "apt-get install -y ldap-utils" });
    if (presence.missing) return presence.envelope;

    const host = input.target.host;
    const script = [
      "set +e",
      `HOST=${quote(host)}`,
      `for PORT in ${ports.join(" ")}; do`,
      "  SCHEME=ldap",
      '  if [ "$PORT" = "636" ] || [ "$PORT" = "3269" ]; then SCHEME=ldaps; fi',
      `  echo "==== LDAP $PORT ===="`,
      `  ldapsearch -x -LLL -H "$SCHEME://$HOST:$PORT" -s base -b "" namingContexts defaultNamingContext 2>/dev/null || true`,
      "  echo",
      "done"
    ].join("\n");

    emit.log(`ldapsearch anonymous base query on ${host}:${ports.join(",")}`);
    const r = await remoteScript(script, input.signal, (s) => emit.log(s));

    const findings: ToolFinding[] = [];
    const blocks = r.stdout.split(/^==== LDAP /m).slice(1);
    for (const block of blocks) {
      const pm = /^(\d+)\s+====/.exec(block);
      if (!pm) continue;
      const port = Number(pm[1]);
      if (/namingContexts:|defaultNamingContext:/i.test(block)) {
        findings.push(corroboration(host, port, "tcp", "ldap", "ldapsearch base query responded"));
        findings.push({
          title: `LDAP anonymous bind allowed on ${host}:${port}`,
          severity: "medium",
          port,
          protocol: "tcp",
          evidence: snippet(block.split("\n").slice(1).join("\n").trim(), 600),
          fingerprint: `ldap-anon|${host}|${port}`,
          confidence: "high",
          requiresVerification: false,
          claimType: "ldap_anonymous_bind"
        });
      }
    }

    return {
      status: "succeeded",
      durationMs: r.durationMs,
      artifacts: { commands: r.commands, stdoutSnippet: snippet(r.stdout), stderrSnippet: snippet(r.stderr) },
      facts: [],
      findings,
      recommendations: [],
      meta: { exitCode: r.exitCode, ports, commandSummary: `ldapsearch anonymous bind test on ${host}.` }
    };
  }
};

// ---- NFS (TCP 2049) ----------------------------------------------------------
export const nfsEnumTool: ToolDefinition = {
  name: "recon.nfs_enum",
  description: "List exported NFS shares (2049) using showmount -e.",
  tags: ["recon", "nfs"],
  requires: ["services"],
  defaultTimeoutMs: 3 * 60 * 1000,
  handler: async (input, emit): Promise<ToolEnvelope> => {
    const presence = await requireRemoteTool("showmount", input.signal, { installCommand: "apt-get install -y nfs-common" });
    if (presence.missing) return presence.envelope;

    const host = input.target.host;
    emit.log(`showmount -e ${host}`);
    const r = await remoteRun("showmount", ["-e", host], input.signal, (s) => emit.log(s));

    const findings: ToolFinding[] = [];
    const exportLines = r.stdout
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l && !/^Export list for/i.test(l));
    if (exportLines.length > 0) {
      findings.push(corroboration(host, 2049, "tcp", "nfs", "showmount returned export list"));
      for (const line of exportLines.slice(0, 30)) {
        const [path, clients] = line.split(/\s+/, 2);
        const worldReadable = /(\*|0\.0\.0\.0\/0|everyone)/i.test(clients ?? "");
        findings.push({
          title: `NFS export ${path} on ${host}${worldReadable ? " (world-accessible)" : ""}`,
          severity: worldReadable ? "high" : "medium",
          port: 2049,
          protocol: "tcp",
          evidence: `Export: ${line}`,
          fingerprint: `nfs-export|${host}|${path}`,
          confidence: "high",
          requiresVerification: false,
          claimType: "nfs_export"
        });
      }
    }

    return {
      status: "succeeded",
      durationMs: r.durationMs,
      artifacts: { commands: r.commands, stdoutSnippet: snippet(r.stdout), stderrSnippet: snippet(r.stderr) },
      facts: [],
      findings,
      recommendations: [],
      meta: { exitCode: r.exitCode, commandSummary: `showmount -e ${host} to list NFS exports.` }
    };
  }
};

// ---- Redis (TCP 6379) --------------------------------------------------------
export const redisEnumTool: ToolDefinition = {
  name: "recon.redis_enum",
  description: "Check Redis (6379) for unauthenticated access via redis-cli INFO (read-only).",
  tags: ["recon", "redis"],
  requires: ["services"],
  defaultTimeoutMs: 3 * 60 * 1000,
  handler: async (input, emit): Promise<ToolEnvelope> => {
    const ports = matchedPorts(input, (s) => s.protocol === "tcp" && (s.port === 6379 || /redis/i.test(s.name ?? "")), [6379]);
    const presence = await requireRemoteTool("redis-cli", input.signal, { installCommand: "apt-get install -y redis-tools" });
    if (presence.missing) return presence.envelope;

    const host = input.target.host;
    const script = [
      "set +e",
      `HOST=${quote(host)}`,
      `for PORT in ${ports.join(" ")}; do`,
      `  echo "==== REDIS $PORT ===="`,
      `  redis-cli -h "$HOST" -p $PORT -t 3 INFO server 2>&1 || true`,
      "  echo",
      "done"
    ].join("\n");

    emit.log(`redis-cli INFO on ${host}:${ports.join(",")}`);
    const r = await remoteScript(script, input.signal, (s) => emit.log(s));

    const findings: ToolFinding[] = [];
    const blocks = r.stdout.split(/^==== REDIS /m).slice(1);
    for (const block of blocks) {
      const pm = /^(\d+)\s+====/.exec(block);
      if (!pm) continue;
      const port = Number(pm[1]);
      if (/redis_version:/i.test(block)) {
        findings.push(corroboration(host, port, "tcp", "redis", "redis-cli INFO succeeded"));
        const versionMatch = /redis_version:([^\r\n]+)/i.exec(block);
        findings.push({
          title: `Unauthenticated Redis access on ${host}:${port}`,
          severity: "high",
          port,
          protocol: "tcp",
          evidence: `redis-cli INFO returned server data without authentication${versionMatch ? ` (version ${versionMatch[1]!.trim()})` : ""}`,
          fingerprint: `redis-unauth|${host}|${port}`,
          confidence: "high",
          requiresVerification: false,
          claimType: "redis_unauthenticated"
        });
      } else if (/NOAUTH|Authentication required/i.test(block)) {
        findings.push(corroboration(host, port, "tcp", "redis", "redis-cli got NOAUTH (auth required)"));
      }
    }

    return {
      status: "succeeded",
      durationMs: r.durationMs,
      artifacts: { commands: r.commands, stdoutSnippet: snippet(r.stdout), stderrSnippet: snippet(r.stderr) },
      facts: [],
      findings,
      recommendations: [],
      meta: { exitCode: r.exitCode, ports, commandSummary: `redis-cli INFO against ${host} to detect unauthenticated access.` }
    };
  }
};

export const infraEnumTools: ToolDefinition[] = [
  rdpEnumTool,
  snmpEnumTool,
  ldapEnumTool,
  nfsEnumTool,
  ftpEnumTool,
  smtpEnumTool,
  redisEnumTool,
  dbBannerTool
];
