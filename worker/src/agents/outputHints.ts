/**
 * Extract actionable "try next" hints from any recon/exploit tool stdout/stderr
 * so the manager can automatically tweak args on a follow-up invoke.
 */
export type OutputTweakHint = {
  plainEnglish: string;
  suggestedArgs?: Record<string, unknown>;
  nextTool?: string;
  nextToolArgs?: Record<string, unknown>;
  priority?: number;
};

function pushUnique(hints: OutputTweakHint[], hint: OutputTweakHint) {
  if (hints.some((h) => h.plainEnglish === hint.plainEnglish)) return;
  hints.push(hint);
}

/** @deprecated use extractToolOutputHints — kept for import compatibility */
export function extractExploitOutputHints(
  tool: string,
  stdout: string | undefined | null,
  priorArgs?: Record<string, unknown>
): OutputTweakHint[] {
  return extractToolOutputHints(tool, stdout, priorArgs);
}

export function extractToolOutputHints(
  tool: string,
  stdout: string | undefined | null,
  priorArgs?: Record<string, unknown>
): OutputTweakHint[] {
  const text = (stdout ?? "").trim();
  if (!text) return [];
  const hints: OutputTweakHint[] = [];
  const args = priorArgs ?? {};

  // ===================== RECON =====================
  if (tool.includes("nmap") || tool === "recon.nmap") {
    if (/Failed to parse|0 services|hostStatus.:.down|0 hosts up|Note: Host seems down/i.test(text) || /host seems down/i.test(text)) {
      pushUnique(hints, {
        plainEnglish: "nmap: host down/unreachable or empty results. Retry with profile=fast and -Pn, or verify Kali can reach the target.",
        suggestedArgs: { profile: "fast" },
        priority: 90
      });
    }
    if (/timed out|Tool timed out|aborted/i.test(text)) {
      const profile = String(args.profile ?? "deep");
      const next = profile === "full" || profile === "deep" ? "fast" : "targeted";
      pushUnique(hints, {
        plainEnglish: `nmap: scan timed out on profile=${profile}. Retry lighter profile=${next}.`,
        suggestedArgs: { profile: next },
        priority: 92
      });
    }
    if (/open tcp|ports?=\"open\"|state=\"open\"/i.test(text) && !tool.includes("port_recheck")) {
      // Successful nmap with opens — nudge web/ssh follow-ups via next tools (manager also has coverage-first).
      if (/portid=\"80\"|portid=\"443\"|portid=\"8080\"|service name=\"http/i.test(text)) {
        pushUnique(hints, {
          plainEnglish: "nmap found HTTP(S). Next: recon.http_probe on discovered web ports.",
          nextTool: "recon.http_probe",
          priority: 85
        });
      }
    }
  }

  if (tool.includes("http_probe")) {
    if (/0 origins|no http|connection refused|timed out/i.test(text)) {
      pushUnique(hints, {
        plainEnglish: "http_probe: no live HTTP origins. Confirm open 80/443/8080 from nmap or retry with explicit ports.",
        suggestedArgs: { ...(args.ports ? {} : { ports: [80, 443, 8080] }) },
        priority: 80
      });
    }
    if (/cdn|akamai|cloudflare|vhost/i.test(text)) {
      pushUnique(hints, {
        plainEnglish: "http_probe: CDN/vhost signals present. Prefer Host-header web tools with webScan.vhost.",
        priority: 70
      });
    }
  }

  if (tool.includes("gobuster") || tool.includes("ffuf") || tool.includes("spider") || tool.includes("wayback")) {
    if (/Status: 403|WAF|blocked|forbidden/i.test(text)) {
      pushUnique(hints, {
        plainEnglish: `${tool}: blocked/403 — run recon.waf_detect or retry with vhost/Host header if CDN.`,
        nextTool: "recon.waf_detect",
        priority: 75
      });
    }
    if (/wordlist.*not found|No such file|SECLISTS/i.test(text)) {
      pushUnique(hints, {
        plainEnglish: `${tool}: wordlist missing on Kali. Fix SecLists path or pick another catalog wordlist.`,
        priority: 88
      });
    }
    if (/0 results|Status: 404.*0 |Found: 0|no paths/i.test(text)) {
      pushUnique(hints, {
        plainEnglish: `${tool}: no paths found. Retry once with a different/smaller wordlist, or switch to spider/waybackurls.`,
        priority: 72
      });
    }
  }

  if (tool.includes("dns_enum") || tool.includes("passive_dns") || tool.includes("osint")) {
    if (/NXDOMAIN|no records|0 facts|SERVFAIL|timed out/i.test(text)) {
      pushUnique(hints, {
        plainEnglish: `${tool}: little/no DNS data. Skip further DNS and proceed to nmap/http_probe.`,
        nextTool: "recon.nmap",
        nextToolArgs: { profile: "fast" },
        priority: 70
      });
    }
  }

  if (tool.includes("tls_check")) {
    if (/handshake failed|connection refused|no certificate/i.test(text)) {
      pushUnique(hints, {
        plainEnglish: "tls_check failed — TLS may be absent on that port. Skip repeat unless a new HTTPS port appears.",
        priority: 50
      });
    }
  }

  if (tool.includes("smb_enum")) {
    if (/timed out|NT_STATUS|Connection refused|could not connect/i.test(text)) {
      pushUnique(hints, {
        plainEnglish: "smb_enum: SMB unreachable or denied. Don't identical-retry; note for exploit phase NetExec.",
        priority: 60
      });
    }
  }

  if (tool.includes("ssh_enum")) {
    if (/Connection refused|timed out|No route/i.test(text)) {
      pushUnique(hints, {
        plainEnglish: "ssh_enum: SSH unreachable. Skip until network is fixed.",
        priority: 55
      });
    }
  }

  if (tool.includes("nuclei")) {
    if (/no results|0 findings|templates.*not found/i.test(text)) {
      pushUnique(hints, {
        plainEnglish: "nuclei: no matches (or templates missing). Continue with other recon specialists.",
        priority: 55
      });
    }
  }

  // ===================== EXPLOIT (gated) =====================
  if (tool.includes("sqlmap")) {
    const level = Math.min(5, Math.max(1, Number(args.level ?? 2)));
    const risk = Math.min(3, Math.max(1, Number(args.risk ?? 2)));
    if (/do not appear to be injectable|all tested parameters do not appear/i.test(text)) {
      pushUnique(hints, {
        plainEnglish:
          "sqlmap: no injection at current settings. Retry parameterized URLs at higher level/risk (not static CSS/JS).",
        suggestedArgs: { mode: "detect", level: Math.min(5, level + 1), risk: Math.min(3, risk + 1) },
        priority: 88
      });
    }
    if (/--tamper/i.test(text) || (/WAF|IPS/i.test(text) && /injectable/i.test(text))) {
      pushUnique(hints, {
        plainEnglish: "sqlmap: try WAF bypass — tamper=space2comment and random-agent.",
        suggestedArgs: {
          mode: "detect",
          level: Math.min(5, level + 1),
          risk,
          tamper: "space2comment",
          randomAgent: true
        },
        priority: 87
      });
    }
  }

  if (tool.includes("commix")) {
    if (/not vulnerable|no command injection|does not seem to be injectable/i.test(text)) {
      pushUnique(hints, {
        plainEnglish: "commix: no command injection on these URLs. Prefer forms/?cmd= params; or move to sqlmap/msf.",
        priority: 70
      });
    }
    if (/increase.*level|try.*--level|--technique/i.test(text)) {
      const level = Math.min(3, Math.max(1, Number(args.level ?? 1) + 1));
      pushUnique(hints, {
        plainEnglish: "commix suggested deeper testing — retry with higher level.",
        suggestedArgs: { ...args, level },
        priority: 85
      });
    }
  }

  if (tool.includes("msf_search")) {
    if (/No results from search|0 modules|modules:\s*\[\]/i.test(text)) {
      pushUnique(hints, {
        plainEnglish: "msf_search: no modules for that query. Retry with a shorter keyword (product name only).",
        suggestedArgs: {
          query: String(args.query ?? "")
            .split(/\s+/)[0]
            ?.replace(/[^a-z0-9_-]/gi, "") || "ftp"
        },
        priority: 90
      });
    }
    const mod = /((?:exploit|auxiliary)\/[a-z0-9_\/\-]+)/i.exec(text)?.[1];
    if (/Matching Modules|exploit\//i.test(text) && mod) {
      pushUnique(hints, {
        plainEnglish: `msf_search found module(s). Next: exploit.msf_module check on ${mod}.`,
        nextTool: "exploit.msf_module",
        nextToolArgs: { module: mod, action: "check" },
        priority: 92
      });
    }
  }

  if (tool.includes("msf_module")) {
    if (/Failed to load module|No results from search/i.test(text)) {
      pushUnique(hints, {
        plainEnglish: "msf_module: bad/missing module path. Search Metasploit for a real path.",
        nextTool: "exploit.msf_search",
        nextToolArgs: {
          query: String(args.module ?? "")
            .split("/")
            .pop() || "proftpd"
        },
        priority: 92
      });
    }
    if (/The target is vulnerable|appears to be vulnerable/i.test(text)) {
      pushUnique(hints, {
        plainEnglish: "msf_module check: target vulnerable. Next run with sensitiveOk=true after approval.",
        suggestedArgs: { ...args, action: "run", sensitiveOk: true },
        priority: 95
      });
    }
    if (/Unknown command: check/i.test(text)) {
      pushUnique(hints, {
        plainEnglish: "This MSF module has no check — retry with action=run only if operator sets sensitiveOk=true.",
        suggestedArgs: { ...args, action: "run" },
        priority: 80
      });
    }
  }

  if (tool.includes("crackmapexec") || tool.includes("nxc") || /\bnxc\b/i.test(text)) {
    if (/against\s+0\s+targets/i.test(text)) {
      pushUnique(hints, {
        plainEnglish: "NetExec: 0 targets parsed — do not mark shares done; use recon.smb_enum or retry guest null session.",
        nextTool: "recon.smb_enum",
        priority: 85
      });
    }
    if (/timed out|unreachable|NXC_EXIT=124|connection.*fail|No route to host/i.test(text)) {
      pushUnique(hints, {
        plainEnglish: "NetExec: SMB unreachable/timeout. Do not retry shares until 445 is reachable.",
        priority: 60
      });
    }
    if (/\[-\].*STATUS_LOGON_FAILURE|Login failed/i.test(text) && !/Pwn3d!/i.test(text)) {
      pushUnique(hints, {
        plainEnglish: "NetExec: auth failed. Retry spray only with engagement wordlists, or move on.",
        suggestedArgs: { action: "spray" },
        priority: 75
      });
    }
  }

  if (tool.includes("hydra")) {
    if (/0 valid password|completed, 0 valid/i.test(text)) {
      pushUnique(hints, {
        plainEnglish: "Hydra: no valid passwords with current lists. Change wordlists or try other services.",
        priority: 55
      });
    }
    if (/login:\s*\S+\s+password:/i.test(text) || /host:.*login:.*password:/i.test(text)) {
      pushUnique(hints, {
        plainEnglish: "Hydra found credentials. Next: postex.session_recon (SSH) or crackmapexec auth (SMB).",
        nextTool: "postex.session_recon",
        priority: 90
      });
    }
  }

  if (tool.includes("postex") || tool.includes("session_recon")) {
    if (/Permission denied|Authentication failed|Connection refused/i.test(text)) {
      pushUnique(hints, {
        plainEnglish: "postex: session failed (auth/network). Re-check credentials or skip post-ex.",
        priority: 50
      });
    }
  }

  // ===================== GENERIC (all tools) =====================
  if (/try (to )?(increase|raise|use|add|retry|run)|suggested?|you (could|should|may) try|consider using/i.test(text)) {
    if (hints.length === 0) {
      const line =
        text
          .split(/\r?\n/)
          .map((l) => l.trim())
          .find((l) => /try |increase |--[a-z]|suggested|consider /i.test(l) && l.length < 240) ??
        "Tool output suggested a different approach — adjust args using the stdout snippet and retry once.";
      pushUnique(hints, {
        plainEnglish: `Output hint: ${line.replace(/^\[.*?\]\s*/g, "").slice(0, 220)}`,
        suggestedArgs: { ...args },
        priority: 72
      });
    }
  }

  if (/timed out|timeout|hang|Tool timed out/i.test(text) && hints.length === 0) {
    pushUnique(hints, {
      plainEnglish: `${tool}: timed out. Retry with a lighter profile/timeout, or switch tools.`,
      priority: 65
    });
  }

  if (/command not found|No such file|not installed|missingTool/i.test(text) && hints.length === 0) {
    pushUnique(hints, {
      plainEnglish: `${tool}: dependency missing on Kali. Run system.tool_installer then retry.`,
      nextTool: "system.tool_installer",
      priority: 100
    });
  }

  if (/Failed to parse|parse.*failed|invalid xml/i.test(text) && hints.length === 0) {
    pushUnique(hints, {
      plainEnglish: `${tool}: output parse failed (often incomplete/timeout). Retry once with lighter settings.`,
      priority: 80
    });
  }

  return hints.slice(0, 5);
}

export function recommendationsFromOutputHints(
  tool: string,
  hints: OutputTweakHint[],
  priorArgs?: Record<string, unknown>
): Array<{ agent: string; reason: string; priority: number; args?: Record<string, unknown> }> {
  const out: Array<{ agent: string; reason: string; priority: number; args?: Record<string, unknown> }> = [];
  for (const h of hints) {
    if (h.nextTool) {
      out.push({
        agent: h.nextTool,
        reason: h.plainEnglish,
        priority: h.priority ?? 80,
        args: h.nextToolArgs
      });
      continue;
    }
    if (h.suggestedArgs) {
      out.push({
        agent: tool,
        reason: h.plainEnglish,
        priority: h.priority ?? 80,
        args: { ...(priorArgs ?? {}), ...h.suggestedArgs }
      });
    }
  }
  return out.slice(0, 3);
}

export function rankSqlmapUrls(urls: string[]): string[] {
  const score = (u: string): number => {
    let s = 0;
    if (/[?&][^=]+=/.test(u)) s += 50;
    if (/\.php($|\?)/i.test(u)) s += 20;
    if (/dvwa|mutillidae|bwapp|webgoat|login|search|product|cat=|id=/i.test(u)) s += 40;
    if (/phpmyadmin\/?(index\.php)?$/i.test(u)) s += 15;
    if (/\.(css|js|png|jpg|jpeg|gif|ico|woff2?|map|svg)($|\?)/i.test(u)) s -= 100;
    if (/jquery|documentation\.html|print\.css|get_image/i.test(u)) s -= 80;
    return s;
  };
  return [...urls].sort((a, b) => score(b) - score(a)).filter((u) => score(u) > -50);
}
