import { spawn } from "node:child_process";
import {
  GoogleGenerativeAI,
  type Content,
  type FunctionDeclaration,
  type Tool
} from "@google/generative-ai";
import { withClient } from "./db.js";
import { withSession } from "./neo4j.js";
import { INSTALLABLE_PACKAGES } from "./installable-packages.js";

export type Severity = "info" | "low" | "medium" | "high" | "critical";

type AgentFinding = {
  title: string;
  severity: Severity;
  port?: number;
  evidence: string;
  fingerprint: string;
};

type CommandRecord = {
  step: number;
  command: string;
  exitCode: number | null;
  truncated: boolean;
  blockedReason?: string;
};

export type AgentState = {
  findings: AgentFinding[];
  commandHistory: CommandRecord[];
  stepsTaken: number;
  done: boolean;
  riskLevel: Severity;
  summary: string;
  reasoning: string[];
};

export type AgentOpts = {
  geminiApiKey: string;
  geminiModel?: string;
  maxSteps?: number;
  cmdTimeoutMs?: number;
  installTimeoutMs?: number;
  whitelist: string[];
  wordlistPath?: string;
};

export const ALLOWED_BINARIES = new Set([
  "nmap", "masscan", "rustscan", "apt-get", 
  "ls", "apt", "dpkg", "dpkg-query", "gem", 
  "pip3", 
  "pip", "npm", "cargo", "go", "make", 
  "cmake", 
  "git", "bash", "sh", "sudo", 
  "which", "command", "test", 
  "env", 
  "xargs", "tee", "timeout", 
  "stdbuf", "script", "screen", 
  "tmux", "netexec",
  "ping", "ping6", "traceroute", 
  "tracepath", "arping", "arp-scan", 
  "netstat", "ss", "ip", "ifconfig", 
  "route", 
  "nslookup", "fierce", "amass",
  "hydra", "medusa", "ncrack",
  "nikto", "gobuster", "dirb", "ffuf", "whatweb", "wpscan",
  "enum4linux", "enum4linux-ng", "smbclient", "smbmap", "rpcclient",
  "psql",
  "apt-cache",
  "ldapsearch", "onesixtyone", "snmpwalk",
  "dig", "host", "whois", "dnsenum", "dnsrecon",
  "curl", "wget", "nc", "netcat", "openssl",
  "searchsploit", "theHarvester",
  "sqlmap",
  "echo", "cat", "grep", "awk", "sed", "sort", "uniq",
  "head", "tail", "wc", "cut", "tr", "printf", "jq"
]);

export const BLOCKED_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
  { pattern: /rm\s+(-[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*r[a-zA-Z]*)\s/i, reason: "file deletion" },
  { pattern: />\s*\/etc\//, reason: "writing to /etc" },
  { pattern: />\s*\/usr\//, reason: "writing to /usr" },
  { pattern: />\s*\/bin\//, reason: "writing to /bin" },
  { pattern: /curl[^|]*\|\s*(ba)?sh/, reason: "curl pipe to shell" },
  { pattern: /wget[^|]*\|\s*(ba)?sh/, reason: "wget pipe to shell" },
  { pattern: /python[23]?\s+-c\s+['"].*exec/i, reason: "python arbitrary exec" },
  { pattern: /perl\s+-e\s+['"].*exec/i, reason: "perl arbitrary exec" },
  { pattern: /:\(\)\s*\{\s*:\|:/, reason: "fork bomb" },
  { pattern: /mkfs/, reason: "disk format" },
  { pattern: /dd\s+if=/, reason: "disk operation" },
  { pattern: /shutdown|reboot|halt|poweroff/, reason: "system shutdown" },
  { pattern: /passwd\s+/, reason: "changing passwords" },
  { pattern: /useradd|userdel|usermod/, reason: "user management" },
  { pattern: /crontab\s+-[eri]/, reason: "modifying cron" },
  { pattern: /iptables.*-F|iptables.*--flush/, reason: "flushing firewall rules" }
];

export function extractIPs(command: string): string[] {
  const re = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\/\d{1,2})?\b/g;
  const out: string[] = [];
  let match: RegExpExecArray | null;
  while ((match = re.exec(command)) !== null) out.push(match[1]);
  return [...new Set(out)];
}

function ipv4ToInt(addr: string) {
  return addr.split(".").map(Number).reduce((acc, octet) => (acc << 8) + octet, 0) >>> 0;
}

function isInCidr(ip: string, cidr: string): boolean {
  const [base, prefixRaw] = cidr.split("/");
  if (!base || !prefixRaw) return false;
  const prefix = Number(prefixRaw);
  if (!Number.isFinite(prefix) || prefix < 0 || prefix > 32) return false;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (ipv4ToInt(ip) & mask) === (ipv4ToInt(base) & mask);
}

export function isAddressAllowed(address: string, whitelist: string[]): boolean {
  const norm = address.trim().toLowerCase();
  for (const raw of whitelist) {
    const entry = raw.trim().toLowerCase();
    if (!entry) continue;
    if (entry.includes("/")) {
      if (isInCidr(norm, entry)) return true;
    } else if (entry === norm) {
      return true;
    }
  }
  return false;
}

export type ValidationResult = { allowed: true } | { allowed: false; reason: string };

export type ValidateCommandOpts = {
  whitelist: string[];
  allowedBinaries?: Set<string>;
  extraBlockedPatterns?: Array<{ pattern: RegExp; reason: string }>;
  extraGuard?: (command: string) => string | null;
};

export function validateCommand(command: string, opts: ValidateCommandOpts): ValidationResult {
  const trimmed = command.trim();
  if (!trimmed) return { allowed: false, reason: "empty command" };

  const allowed = opts.allowedBinaries ?? ALLOWED_BINARIES;
  const binary = (trimmed.split(/\s+/)[0] ?? "").split("/").pop() ?? "";
  if (!allowed.has(binary)) {
    return {
      allowed: false,
      reason: `"${binary}" is not in the allowed binary list. Allowed: ${[...allowed].join(", ")}`
    };
  }

  for (const { pattern, reason } of BLOCKED_PATTERNS) {
    if (pattern.test(trimmed)) return { allowed: false, reason: `blocked: ${reason}` };
  }
  if (opts.extraBlockedPatterns) {
    for (const { pattern, reason } of opts.extraBlockedPatterns) {
      if (pattern.test(trimmed)) return { allowed: false, reason: `blocked: ${reason}` };
    }
  }

  for (const ip of extractIPs(trimmed)) {
    if (!isAddressAllowed(ip, opts.whitelist)) {
      return { allowed: false, reason: `IP ${ip} is outside the authorised scope` };
    }
  }

  if (opts.extraGuard) {
    const reason = opts.extraGuard(trimmed);
    if (reason) return { allowed: false, reason };
  }

  return { allowed: true };
}

export const MAX_OUTPUT_CHARS = 8_000;

export type ExecResult = {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  truncated: boolean;
  durationMs: number;
};

function parseNmapOpenPortLines(output: string): string[] {
  const lines = output.split(/\r?\n/);
  const out: string[] = [];
  for (const line of lines) {
    // Typical: "445/tcp open microsoft-ds? syn-ack ttl 63"
    if (/^\d+\/(tcp|udp)\s+open\s+/i.test(line.trim())) out.push(line.trim());
  }
  return out;
}

export function execCommand(
  command: string,
  timeoutMs: number,
  onChunk?: (s: string) => void,
  signal?: AbortSignal
): Promise<ExecResult> {
  const start = Date.now();

  return new Promise((resolve, reject) => {
    const child = spawn("sh", ["-c", command], {
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, DEBIAN_FRONTEND: "noninteractive", TERM: "dumb" }
    });

    let stdout = "";
    let stderr = "";
    let storedChars = 0;
    let truncated = false;

    const absorb = (s: string, target: "out" | "err") => {
      onChunk?.(s);
      if (storedChars >= MAX_OUTPUT_CHARS) {
        truncated = true;
        return;
      }
      const remaining = MAX_OUTPUT_CHARS - storedChars;
      const chunk = s.slice(0, remaining);
      if (target === "out") stdout += chunk;
      else stderr += chunk;
      storedChars += chunk.length;
      if (chunk.length < s.length || storedChars >= MAX_OUTPUT_CHARS) truncated = true;
    };

    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    const onAbort = () => {
      child.kill("SIGKILL");
      reject(new Error("aborted"));
    };

    if (signal) {
      if (signal.aborted) {
        clearTimeout(timer);
        return void onAbort();
      }
      signal.addEventListener("abort", onAbort, { once: true });
    }

    child.stdout.on("data", (d: Buffer) => absorb(d.toString("utf8"), "out"));
    child.stderr.on("data", (d: Buffer) => absorb(d.toString("utf8"), "err"));
    child.on("error", (e) => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      reject(e);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      resolve({ stdout, stderr, exitCode: code, truncated, durationMs: Date.now() - start });
    });
  });
}

const TOOL_DECLARATIONS: FunctionDeclaration[] = [
  {
    name: "execute_command",
    description:
      "Execute a real shell command on the assessment machine and receive the full output. " +
      "Use this to run nmap, hydra, nikto, enum4linux, gobuster, sqlmap, dig, curl, etc. " +
      "Write the exact command with all flags. You are at a real terminal.",
    parameters: {
      type: "object" as any,
      properties: {
        command: {
          type: "string" as any,
          description:
            "The exact shell command to execute. Write it exactly as you would at a terminal.\n" +
            "Examples:\n" +
            "  nmap -sV -sC -O --top-ports 200 192.168.1.10\n" +
            "  hydra -l root -P /wordlists/rockyou.txt ssh://192.168.1.10 -t 8 -f\n" +
            "  nikto -h http://192.168.1.10 -C all\n" +
            "  enum4linux -a 192.168.1.10\n" +
            "  gobuster dir -u http://192.168.1.10 -w /usr/share/wordlists/dirb/common.txt\n" +
            "  dig axfr @192.168.1.10 target.local\n" +
            "  smbmap -H 192.168.1.10\n" +
            "  sqlmap -u 'http://192.168.1.10/login?id=1' --batch --level 2"
        },
        reasoning: {
          type: "string" as any,
          description: "Why you are running this command and what you expect to find. Logged in the audit trail."
        }
      },
      required: ["command", "reasoning"]
    }
  },
  {
    name: "install_tool",
    description:
      "Install a missing tool via apt on this worker image. Only a curated whitelist is allowed. " +
      "Use when execute_command fails with 'not found', exit 127, or similar.",
    parameters: {
      type: "object" as any,
      properties: {
        package: {
          type: "string" as any,
          description:
            "Debian package name, e.g. nmap, netcat-openbsd (provides nc), masscan, seclists, hydra."
        },
        reasoning: {
          type: "string" as any,
          description: "Why this install is needed."
        }
      },
      required: ["package", "reasoning"]
    }
  },
  {
    name: "add_finding",
    description:
      "Record a confirmed security finding based on command output you have observed. " +
      "Call this for vulnerabilities, weak credentials, misconfigurations, policy violations. " +
      "Only record findings you have actually confirmed from real output and do not speculate.",
    parameters: {
      type: "object" as any,
      properties: {
        title: {
          type: "string" as any,
          description:
            "Specific, descriptive title. Examples:\n" +
            "  'vsftpd 2.3.4 Backdoor (CVE-2011-2523) on port 21'\n" +
            "  'Weak SSH credentials accepted: root / password'\n" +
            "  'SMB signing disabled - vulnerable to relay attacks'\n" +
            "  'Apache 2.4.49 path traversal (CVE-2021-41773)'"
        },
        severity: {
          type: "string" as any,
          enum: ["info", "low", "medium", "high", "critical"],
          description:
            "critical: RCE / full system compromise likely. " +
            "high: significant access, credential exposure, or data leakage. " +
            "medium: notable risk that needs fixing. " +
            "low: minor hardening item. " +
            "info: observation, no immediate risk."
        },
        port: { type: "number" as any, description: "Port number this finding relates to (if applicable)." },
        evidence: {
          type: "string" as any,
          description: "Quote the relevant output that confirms this finding. Mask real passwords (e.g. p*****3)."
        }
      },
      required: ["title", "severity", "evidence"]
    }
  },
  {
    name: "finish_engagement",
    description:
      "Call this when the assessment is complete. You have scanned ports, investigated services, " +
      "tested credentials where applicable, and recorded all findings. Do not call this prematurely.",
    parameters: {
      type: "object" as any,
      properties: {
        summary: {
          type: "string" as any,
          description: "2-5 sentence executive summary of what you found."
        },
        risk_level: {
          type: "string" as any,
          enum: ["info", "low", "medium", "high", "critical"],
          description: "Overall risk determined by your highest confirmed finding."
        },
        next_steps: {
          type: "string" as any,
          description: "Top 3-5 remediation recommendations for the target owner."
        }
      },
      required: ["summary", "risk_level", "next_steps"]
    }
  }
];

const GEMINI_TOOLS: Tool[] = [{ functionDeclarations: TOOL_DECLARATIONS }];

function buildSystemPrompt(target: string, name: string, whitelist: string[], wordlist: string): string {
  return `You are an expert penetration tester conducting an authorised security assessment.
You have a real shell. Write real commands and analyse the real output.

TARGET
  Name    : ${name}
  Address : ${target}
  Scope   : ${whitelist.join(", ")}

AVAILABLE WORDLISTS
  Primary : ${wordlist}
  Dirs    : /usr/share/wordlists/dirb/common.txt
  Users   : /usr/share/seclists/Usernames/top-usernames-shortlist.txt

YOUR APPROACH
  1. Start with nmap -sV -sC to find open ports and service versions
  2. Look up service versions and note anything outdated or known-vulnerable
  3. Run service-specific tools:
       HTTP/HTTPS  -> nikto, gobuster
       SMB/445     -> enum4linux, smbmap
       SSH/FTP/RDP -> hydra for weak credentials
       DNS/53      -> dig axfr for zone transfers
       SNMP/161    -> snmpwalk with community strings
       SQL ports   -> sqlmap on any web forms
  4. Investigate banners and version strings carefully
  5. Record every confirmed issue with add_finding
  6. Do a full port scan (-p-) if the initial one looked sparse
  7. Call finish_engagement when you have a thorough picture

MISSING BINARIES / exit 127
  - Run install_tool with the correct Debian package (e.g. nmap → package "nmap", nc → often "netcat-openbsd").
  - Then repeat the intended execute_command.

RULES
  - Only target IPs in scope: ${whitelist.join(", ")}
  - Do NOT run exploits, bind shells, or destructive commands
  - Do NOT record plaintext passwords. Always mask them (p*****3)
  - Read output carefully before deciding the next command
  - Be methodical and do not repeat the same scan twice
  - Every execute_command call must have clear reasoning
  - Prefer install_tool over ad-hoc apt-get commands (those are blocked)

You are thorough, methodical, and evidence-based. Call finish_engagement when done.`;
}

async function runAgentLoop(
  targetAddress: string,
  targetName: string,
  opts: AgentOpts,
  onLog: (text: string) => Promise<void>,
  signal?: AbortSignal
): Promise<AgentState> {
  const parseRetryDelayMs = (msg: string): number | null => {
    const fromJson = /"retryDelay"\s*:\s*"(\d+)s"/i.exec(msg);
    if (fromJson?.[1]) return Math.max(0, Number(fromJson[1])) * 1000;
    const fromText = /retry in ([0-9.]+)s/i.exec(msg);
    if (fromText?.[1]) return Math.max(0, Math.ceil(Number(fromText[1]) * 1000));
    return null;
  };

  const state: AgentState = {
    findings: [],
    commandHistory: [],
    stepsTaken: 0,
    done: false,
    riskLevel: "info",
    summary: "",
    reasoning: []
  };

  const maxSteps = opts.maxSteps ?? 25;
  const cmdTimeout = opts.cmdTimeoutMs ?? 120_000;
  const installTimeout = opts.installTimeoutMs ?? 600_000;
  const wordlist = opts.wordlistPath ?? "/usr/share/wordlists/rockyou.txt";

  const client = new GoogleGenerativeAI(opts.geminiApiKey);
  const modelName = opts.geminiModel ?? "gemini-3.1-flash-lite-preview";

  const model = client.getGenerativeModel({
    model: modelName,
    tools: GEMINI_TOOLS,
    generationConfig: { temperature: 0.1, maxOutputTokens: 2048 },
    systemInstruction: buildSystemPrompt(targetAddress, targetName, opts.whitelist, wordlist)
  });

  const history: Content[] = [];

  await onLog("\n╔══════════════════════════════════════════════╗\n");
  await onLog("║  TALAKUNCHI · AI AGENT · FREE-FORM COMMANDS  ║\n");
  await onLog("╚══════════════════════════════════════════════╝\n");
  await onLog(`  target  : ${targetAddress} (${targetName})\n`);
  await onLog(`  model   : ${modelName}\n`);
  await onLog(`  steps   : max ${maxSteps}\n`);
  await onLog(
    `  timeout : ${cmdTimeout / 1000}s per command (${installTimeout / 1000}s for installs)\n\n`
  );

  history.push({
    role: "user",
    parts: [{ text: `Begin the security assessment of ${targetAddress}. Think step by step and run your first command` }]
  });

  let stoppedEarlyReason: string | null = null;

  while (!state.done && state.stepsTaken < maxSteps) {
    let response: any;
    while (true) {
      if (signal?.aborted) {
        stoppedEarlyReason = "aborted";
        break;
      }
      try {
        const chat = model.startChat({ history: history.slice(0, -1) });
        const result = await chat.sendMessage(history[history.length - 1].parts);
        response = result.response;
        break;
      } catch (err: any) {
        const msg = err?.message ?? String(err);
        await onLog(`[agent] Gemini API error: ${msg}\n`);

        // Don't burn a step on transient 429s — wait, then try again.
        if (/\b429\b/.test(msg) || /Too Many Requests/i.test(msg)) {
          const retryMs = parseRetryDelayMs(msg) ?? 10_000;
          const capped = Math.min(Math.max(retryMs, 1000), 120_000);
          await new Promise((resolve) => setTimeout(resolve, capped + 250));
          continue;
        }

        await new Promise((resolve) => setTimeout(resolve, 3000));
        try {
          const fallback = client.getGenerativeModel({
            model: `models/${modelName}`,
            tools: GEMINI_TOOLS,
            generationConfig: { temperature: 0.1, maxOutputTokens: 2048 },
            systemInstruction: buildSystemPrompt(targetAddress, targetName, opts.whitelist, wordlist)
          });
          const chat = fallback.startChat({ history: history.slice(0, -1) });
          const result = await chat.sendMessage(history[history.length - 1].parts);
          response = result.response;
          break;
        } catch (err2: any) {
          const msg2 = err2?.message ?? String(err2);
          stoppedEarlyReason = `Gemini API error: ${msg2}`;
          await onLog("[agent] retry failed - stopping loop\n");
          break;
        }
      }
    }

    if (!response) {
      if (!stoppedEarlyReason) stoppedEarlyReason = "Gemini API returned no response";
      break;
    }

    state.stepsTaken++;
    await onLog(`\n┌─ step ${state.stepsTaken}/${maxSteps} ${"─".repeat(46 - String(state.stepsTaken).length)}\n`);

    const parts: any[] = response.candidates?.[0]?.content?.parts ?? [];
    history.push({ role: "model", parts });

    const toolResultParts: Array<{ functionResponse: { name: string; response: { result: string } } }> = [];
    let hadToolCall = false;

    for (const part of parts) {
      if (part.text?.trim()) {
        const text = part.text.trim();
        await onLog(`│ 🧠 ${text.replace(/\n/g, "\n│    ")}\n`);
        state.reasoning.push(text);
      }

      if (part.functionCall) {
        hadToolCall = true;
        const { name, args } = part.functionCall;
        const toolArgs = (args ?? {}) as Record<string, any>;
        let result = "";

        if (name === "execute_command") {
          const command = (toolArgs.command as string | undefined)?.trim() ?? "";
          const reasoning = (toolArgs.reasoning as string | undefined)?.trim() ?? "";

          await onLog(`│\n│ 💭 ${reasoning}\n│ $ ${command}\n│\n`);

          const validation = validateCommand(command, { whitelist: opts.whitelist });
          if (!validation.allowed) {
            result = `BLOCKED: ${validation.reason}`;
            await onLog(`│ ⛔ ${result}\n`);
            state.commandHistory.push({
              step: state.stepsTaken,
              command,
              exitCode: null,
              truncated: false,
              blockedReason: validation.reason
            });
            await logAuditEvent("agent.command.blocked", {
              step: state.stepsTaken,
              command,
              reason: validation.reason
            });
          } else {
            await logAuditEvent("agent.command.run", {
              step: state.stepsTaken,
              command,
              reasoning
            });
            let exec: ExecResult;
            try {
              exec = await execCommand(
                command,
                cmdTimeout,
                (chunk) => onLog(`│ ${chunk.replace(/\n(?!$)/g, "\n│ ")}`),
                signal
              );
            } catch (err: any) {
              result = `execution failed: ${err?.message ?? String(err)}`;
              await onLog(`│ ✗ ${result}\n`);
              state.commandHistory.push({
                step: state.stepsTaken,
                command,
                exitCode: null,
                truncated: false
              });
              toolResultParts.push({ functionResponse: { name, response: { result } } });
              continue;
            }

            state.commandHistory.push({
              step: state.stepsTaken,
              command,
              exitCode: exec.exitCode,
              truncated: exec.truncated
            });

            const combined = [exec.stdout, exec.stderr ? `\n[stderr]\n${exec.stderr}` : ""].join("").trim();
            result = combined || "(no output)";
            if (exec.truncated) {
              result += `\n\n[output truncated at ${MAX_OUTPUT_CHARS} chars - ran for ${exec.durationMs}ms]`;
            }

            await onLog(`│\n│ ✓ exit=${exec.exitCode}  ${exec.durationMs}ms${exec.truncated ? "  [truncated]" : ""}\n`);

            // If the model gets rate-limited after the scan, we still want a durable record of what we observed.
            const binary = (command.split(/\s+/)[0] ?? "").split("/").pop()?.toLowerCase() ?? "";
            if (binary === "nmap" && exec.exitCode === 0) {
              const ports = parseNmapOpenPortLines(combined);
              if (ports.length > 0) {
                const fingerprint = `fp:agent|${targetAddress}|nmap-open-ports`;
                if (!state.findings.some((f) => f.fingerprint === fingerprint)) {
                  const evidence = [`Command: ${command}`, "", ...ports.slice(0, 50)].join("\n");
                  state.findings.push({
                    title: `Open ports/services discovered via Nmap (${ports.length})`,
                    severity: "info",
                    evidence,
                    fingerprint
                  });
                  await onLog(`│ 📋 [INFO] Open ports/services discovered via Nmap (${ports.length})\n`);
                  await logAuditEvent("agent.finding.auto.nmap_ports", {
                    ports: ports.slice(0, 50),
                    total: ports.length
                  });
                }
              }
            }
          }
        } else if (name === "install_tool") {
          let pkg = (toolArgs.package as string | undefined)?.trim() ?? "";
          const reasoning = (toolArgs.reasoning as string | undefined)?.trim() ?? "";

          // Aliases for Debian: prefer pip installs for tools that are unreliable/unavailable via apt.
          if (pkg === "smbmap") pkg = "pip:smbmap";
          if (pkg === "python3-impacket" || pkg === "impacket") pkg = "pip:impacket";

          if (!INSTALLABLE_PACKAGES.has(pkg)) {
            result = `BLOCKED: package "${pkg}" is not in the installable allow-list`;
            await onLog(`│ ⛔ ${result}\n`);
            await logAuditEvent("agent.tool.install.blocked", {
              step: state.stepsTaken,
              package: pkg,
              reason: "not in allow-list"
            });
          } else {
            const aptEnv =
              "DEBIAN_FRONTEND=noninteractive " +
              "apt-get -o DPkg::Lock::Timeout=120 -o Dpkg::Options::=--force-confnew ";
            const installCmd = pkg.startsWith("pip:")
              ? [
                  "python3 -m venv /opt/talakunchi-venv",
                  "/opt/talakunchi-venv/bin/python -m pip install --no-cache-dir --upgrade pip",
                  `/opt/talakunchi-venv/bin/python -m pip install --no-cache-dir --upgrade ${pkg.slice("pip:".length)}`,
                  // expose common entrypoints on PATH (best-effort)
                  `for b in smbmap crackmapexec netexec nxc secretsdump.py psexec.py wmiexec.py; do ` +
                    `if [ -f "/opt/talakunchi-venv/bin/$b" ]; then ln -sf "/opt/talakunchi-venv/bin/$b" "/usr/local/bin/$b"; fi; ` +
                  "done"
                ].join(" && ")
              : "apt-get clean && " +
                "rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/partial/* && " +
                `apt-get -o DPkg::Lock::Timeout=120 -o Acquire::Retries=3 -o Acquire::http::No-Cache=true -o Acquire::https::No-Cache=true update && ` +
                // if a prior attempt left dpkg/apt in a broken state, recover before installing more
                `${aptEnv}-y --no-install-recommends --fix-broken install || true && ` +
                `${aptEnv}-o Acquire::Retries=3 -o Acquire::http::No-Cache=true -o Acquire::https::No-Cache=true install -y --no-install-recommends --fix-missing ${pkg}`;
            await onLog(`│\n│ 📦 install ${pkg} — ${reasoning}\n│ $ ${installCmd}\n│\n`);
            await logAuditEvent("agent.tool.install.start", {
              step: state.stepsTaken,
              package: pkg,
              reasoning
            });
            let exec: ExecResult;
            try {
              exec = await execCommand(
                installCmd,
                installTimeout,
                (chunk) => onLog(`│ ${chunk.replace(/\n(?!$)/g, "\n│ ")}`),
                signal
              );
            } catch (err: any) {
              result = `install failed: ${err?.message ?? String(err)}`;
              await onLog(`│ ✗ ${result}\n`);
              toolResultParts.push({ functionResponse: { name, response: { result } } });
              continue;
            }
            if (exec.exitCode === 0) {
              result = `installed ${pkg}`;
              await onLog(`│ ✓ installed ${pkg} (${exec.durationMs}ms)\n`);
              await logAuditEvent("agent.tool.install.done", { step: state.stepsTaken, package: pkg });
            } else {
              const tail = (exec.stderr || exec.stdout).slice(-1500);
              result = `install exit=${exec.exitCode}\n${tail}`;
              await onLog(`│ ✗ install ${pkg} exit=${exec.exitCode}\n`);
            }
          }
        } else if (name === "add_finding") {
          const title = toolArgs.title as string;
          const severity = toolArgs.severity as Severity;
          const port = toolArgs.port as number | undefined;
          const evidence = toolArgs.evidence as string;

          const fingerprint = `fp:agent|${targetAddress}|${port ?? "none"}|${title
            .toLowerCase()
            .replace(/[^a-z0-9]/g, "-")
            .slice(0, 60)}`;

          if (!state.findings.some((finding) => finding.fingerprint === fingerprint)) {
            state.findings.push({ title, severity, port, evidence, fingerprint });
            await onLog(`│ 📋 [${severity.toUpperCase()}] ${title}\n`);
            result = `Finding recorded: "${title}" (${severity})`;
            await logAuditEvent("agent.finding.added", { title, severity, port });
          } else {
            result = `Already recorded: "${title}" - skipped`;
          }
        } else if (name === "finish_engagement") {
          state.done = true;
          state.summary = toolArgs.summary as string;
          state.riskLevel = toolArgs.risk_level as Severity;
          const nextSteps = toolArgs.next_steps as string;

          await onLog("│\n└─ engagement complete\n");
          await onLog(`\n  risk     : ${state.riskLevel.toUpperCase()}\n`);
          await onLog(`  summary  : ${state.summary}\n`);
          await onLog(`  remediate: ${nextSteps}\n\n`);
          result = "Engagement marked as complete.";
        } else {
          result = `Unknown tool: ${name}`;
        }

        toolResultParts.push({ functionResponse: { name, response: { result } } });
        if (state.done) break;
      }
    }

    if (toolResultParts.length > 0) {
      history.push({ role: "function", parts: toolResultParts });
    }

    if (!hadToolCall && !state.done) {
      await onLog("│ ↩ no tool call - nudging\n");
      history.push({
        role: "user",
        parts: [{
          text: "You must call a tool. Run execute_command, install_tool (when a binary is missing), add_finding, or finish_engagement."
        }]
      });
    }
  }

  if (!state.done && state.stepsTaken >= maxSteps) {
    await onLog(`\n⚠ step limit (${maxSteps}) reached\n`);
    state.done = true;
    state.summary =
      state.summary ||
      `Assessment reached step limit after ${state.stepsTaken} steps. Found ${state.findings.length} finding(s).`;
    if (state.findings.length > 0) state.riskLevel = deriveRiskLevel(state.findings);
  } else if (!state.done && stoppedEarlyReason) {
    state.done = true;
    state.riskLevel = state.findings.length > 0 ? deriveRiskLevel(state.findings) : "info";
    state.summary =
      state.summary ||
      `Assessment stopped early after ${state.stepsTaken} step(s): ${stoppedEarlyReason}. Found ${state.findings.length} finding(s).`;
    await onLog(`\n⚠ stopped early: ${stoppedEarlyReason}\n`);
  }

  return state;
}

export async function runAgentScan(scanRunId: string, opts: AgentOpts) {
  const ctx = await withClient(async (c) => {
    const result = await c.query(
      `select sr.id, sr.target_id, t.name as target_name, t.address as target_address
       from scan_runs sr join targets t on t.id = sr.target_id where sr.id = $1`,
      [scanRunId]
    );
    return result.rows[0] as {
      id: string;
      target_id: string;
      target_name: string;
      target_address: string;
    };
  });

  if (!isAddressAllowed(ctx.target_address, opts.whitelist)) {
    await withClient(async (c) => {
      await c.query(`update scan_runs set status='failed', finished_at=now() where id=$1`, [scanRunId]);
    });
    throw new Error(`[agent] ${ctx.target_address} is out of scope`);
  }

  const stepId = await withClient(async (c) => {
    await c.query(`update scan_runs set status='running', started_at=now() where id=$1`, [scanRunId]);
    await c.query(
      `insert into scan_steps (scan_run_id, name, status, started_at) values ($1,'AI Agent','running',now())`,
      [scanRunId]
    );
    const result = await c.query(
      `select id from scan_steps where scan_run_id=$1 and name='AI Agent' limit 1`,
      [scanRunId]
    );
    return result.rows[0].id as string;
  });

  let logBuf = "";
  let lastFlush = Date.now();
  const flush = async (force = false) => {
    if (!force && Date.now() - lastFlush < 1500) return;
    if (!logBuf) return;
    const out = logBuf;
    logBuf = "";
    lastFlush = Date.now();
    await withClient(async (c) => {
      await c.query(`update scan_steps set log = log || $2 where id=$1`, [stepId, out]);
    });
  };
  const onLog = async (text: string) => {
    process.stdout.write(text);
    logBuf += text;
    await flush();
  };

  const abortController = new AbortController();
  const cancelPoll = setInterval(async () => {
    const cancelled = await withClient(async (c) => {
      const result = await c.query(`select cancel_requested from scan_runs where id=$1`, [scanRunId]);
      return Boolean(result.rows?.[0]?.cancel_requested);
    });
    if (cancelled) {
      await onLog("\n[agent] cancel requested\n");
      abortController.abort();
    }
  }, 2000);

  let state: AgentState;
  try {
    state = await runAgentLoop(ctx.target_address, ctx.target_name, opts, onLog, abortController.signal);
  } catch (err: any) {
    clearInterval(cancelPoll);
    await flush(true);
    await withClient(async (c) => {
      await c.query(
        `update scan_steps set status='failed', finished_at=now(), log=log||$2 where id=$1`,
        [stepId, `\n[agent error] ${err?.message ?? String(err)}\n`]
      );
      await c.query(`update scan_runs set status='failed', finished_at=now() where id=$1`, [scanRunId]);
    });
    throw err;
  } finally {
    clearInterval(cancelPoll);
  }

  await flush(true);

  await withClient(async (c) => {
    for (const finding of state.findings) {
      await c.query(
        `insert into findings
           (target_id, service_id, title, severity, status, fingerprint,
            evidence_redacted, first_seen_at, last_seen_at, last_scan_run_id)
         values ($1,null,$2,$3,'open',$4,$5,now(),now(),$6)
         on conflict (fingerprint) do update
           set last_seen_at=now(), evidence_redacted=excluded.evidence_redacted,
               last_scan_run_id=excluded.last_scan_run_id`,
        [ctx.target_id, finding.title, finding.severity, finding.fingerprint, finding.evidence, scanRunId]
      );
    }

    if (state.summary) {
      const fingerprint = `fp:agent-summary|${ctx.target_address}|${scanRunId}`;
      await c.query(
        `insert into findings
           (target_id, service_id, title, severity, status, fingerprint,
            evidence_redacted, first_seen_at, last_seen_at, last_scan_run_id)
         values ($1,null,$2,$3,'open',$4,$5,now(),now(),$6)
         on conflict (fingerprint) do update
           set evidence_redacted=excluded.evidence_redacted, last_seen_at=now()`,
        [
          ctx.target_id,
          `AI Agent Summary - ${state.riskLevel.toUpperCase()} risk`,
          state.riskLevel,
          fingerprint,
          [
            state.summary,
            `\nCommands run: ${state.commandHistory.length}`,
            `Steps taken : ${state.stepsTaken}`,
            `Findings    : ${state.findings.length}`,
            `\n--- Agent reasoning (last 5 steps) ---`,
            state.reasoning.slice(-5).join("\n\n")
          ].join("\n"),
          scanRunId
        ]
      );
    }

    await c.query(
      `update scan_steps set status='succeeded', finished_at=now(), log=log||$2 where id=$1`,
      [
        stepId,
        `\n✓ agent done\n` +
          `  findings : ${state.findings.length}\n` +
          `  commands : ${state.commandHistory.length}\n` +
          `  steps    : ${state.stepsTaken}\n` +
          `  risk     : ${state.riskLevel.toUpperCase()}\n`
      ]
    );
    await c.query(`update scan_runs set status='succeeded', finished_at=now() where id=$1`, [scanRunId]);
  });

  await withSession(async (session) => {
    await session.run(
      `merge (t:Target {id:$id}) set t.name=$name, t.address=$address`,
      { id: ctx.target_id, name: ctx.target_name, address: ctx.target_address }
    );
  }).catch(() => {});

  return state;
}

function deriveRiskLevel(findings: AgentFinding[]): Severity {
  for (const severity of ["critical", "high", "medium", "low", "info"] as Severity[]) {
    if (findings.some((finding) => finding.severity === severity)) return severity;
  }
  return "info";
}

async function logAuditEvent(action: string, payload: Record<string, unknown>) {
  await writeAuditEvent("agent", action, payload);
}

export async function writeAuditEvent(actor: string, action: string, payload: Record<string, unknown>) {
  await withClient(async (c) => {
    await c.query(
      `insert into audit_events (actor, action, payload) values ($1,$2,$3::jsonb) on conflict do nothing`,
      [actor, action, JSON.stringify(payload)]
    );
  }).catch(() => {});
}
