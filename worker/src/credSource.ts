/**
 * Engagement credential / wordlist resolution for hydra, crackmapexec, etc.
 *
 * Priority (first usable match wins — operator config beats the LLM):
 *   1. Per-target engagement fields (Targets page)
 *   2. Worker env HYDRA_* defaults
 *   3. Pipeline → allowedWordlists
 *   4. Tool invocation args (LLM) — junk SecLists (e.g. 3bb router) are ignored
 *
 * Missing files fail loudly so operators fix paths for each client engagement.
 */
import { withClient } from "./db.js";
import { env } from "./env.js";
import { remoteScript } from "./agents/shared.js";
import { shellQuote } from "./agents/webTarget.js";
import { SECLISTS_ROOT } from "./agents/wordlists.js";
import type { HydraCredSource } from "./hydraScan.js";

export type EngagementCreds = {
  username?: string | null;
  password?: string | null;
  userlist?: string | null;
  passlist?: string | null;
};

export type ResolveCredSourceInput = {
  args?: Record<string, unknown>;
  engagement?: EngagementCreds | null;
  signal?: AbortSignal;
  emitLog?: (s: string) => void;
};

export type ResolveCredSourceResult = {
  source: HydraCredSource | null;
  error?: string;
  meta?: Record<string, unknown>;
};

function strArg(args: Record<string, unknown> | undefined, key: string): string | undefined {
  const v = args?.[key];
  return typeof v === "string" && v.trim() ? v.trim() : undefined;
}

/** Absolute paths allowed for engagement wordlists on the tools host. */
export function allowedWordlistRoots(): string[] {
  const roots = new Set<string>([SECLISTS_ROOT]);
  for (const r of (env.WORDLISTS_EXTRA_ROOTS ?? "").split(/[\n,]+/)) {
    const t = r.trim();
    if (t) roots.add(t.replace(/\/+$/, ""));
  }
  return [...roots];
}

export function isAllowedWordlistPath(path: string, pipelineAllowlist: string[] = []): boolean {
  const p = path.trim();
  if (!p.startsWith("/")) return false;
  if (pipelineAllowlist.some((w) => w.trim() === p)) return true;
  return allowedWordlistRoots().some((root) => p === root || p.startsWith(`${root}/`));
}

/**
 * Tiny vendor/router lists the LLM loves to pick from SecLists — useless for
 * general auth attacks (e.g. 3bb_default-passwords.txt → password "3bb" only).
 */
export function isJunkPasswordWordlist(path: string): boolean {
  const p = path.replace(/\\/g, "/").toLowerCase();
  if (/3bb_default-passwords/.test(p)) return true;
  if (/\/passwords\/default-credentials\/routers\//.test(p)) return true;
  if (/\/passwords\/default-credentials\/.*router/.test(p)) return true;
  if (/cisco.*default|huawei.*default|tp-link|d-link_default/.test(p)) return true;
  return false;
}

async function remoteFileExists(path: string, signal?: AbortSignal): Promise<boolean> {
  const script = `test -f ${shellQuote(path)} && echo FILE_OK || echo FILE_MISSING`;
  const r = await remoteScript(script, signal);
  return /FILE_OK/.test(r.stdout);
}

async function resolveExistingPath(
  label: string,
  candidates: Array<{ path: string; source: string }>,
  pipelineAllowlist: string[],
  signal?: AbortSignal,
  emitLog?: (s: string) => void
): Promise<{ path: string; source: string } | null> {
  for (const c of candidates) {
    const p = c.path.trim();
    if (!p) continue;
    if (label === "passlist" && isJunkPasswordWordlist(p) && c.source === "args") {
      emitLog?.(`[creds] ignoring LLM passlist (vendor/router junk, e.g. 3bb): ${p}`);
      continue;
    }
    if (!isAllowedWordlistPath(p, pipelineAllowlist)) {
      emitLog?.(`[creds] skipping ${label} (path not under allowed roots): ${p}`);
      continue;
    }
    if (await remoteFileExists(p, signal)) {
      emitLog?.(`[creds] ${label} from ${c.source}: ${p}`);
      return { path: p, source: c.source };
    }
    emitLog?.(`[creds] ${label} not found on tools host: ${p}`);
  }
  return null;
}

export async function loadPipelineWordlists(): Promise<string[]> {
  return withClient(async (c) => {
    const r = await c.query(`select config from pipeline_configs where id = 1`);
    const cfg = r.rows[0]?.config as { allowedWordlists?: unknown } | undefined;
    if (!Array.isArray(cfg?.allowedWordlists)) return [];
    return cfg.allowedWordlists.filter((x): x is string => typeof x === "string" && x.trim().length > 0);
  });
}

/**
 * Resolve hydra / SMB spray credentials from engagement config.
 * Operator paths beat LLM args so the model cannot force a 1-line router list.
 */
export async function resolveCredSource(input: ResolveCredSourceInput): Promise<ResolveCredSourceResult> {
  const args = input.args ?? {};
  const engagement = input.engagement ?? {};
  const pipelineWordlists = await loadPipelineWordlists();
  const tried: string[] = [];

  const username =
    engagement.username?.trim() ||
    env.HYDRA_USERNAME?.trim() ||
    strArg(args, "username") ||
    undefined;
  const password =
    engagement.password?.trim() ||
    env.HYDRA_PASSWORD?.trim() ||
    strArg(args, "password") ||
    undefined;

  // Single password must not be a wordlist path the LLM stuffed into "password".
  const passwordLooksLikePath = Boolean(password && password.startsWith("/") && password.includes("/"));
  if (username && password && !passwordLooksLikePath) {
    return { source: { username, password }, meta: { credMode: "single", source: "configured" } };
  }

  const userCandidates: Array<{ path: string; source: string }> = [];
  const passCandidates: Array<{ path: string; source: string }> = [];

  const push = (list: typeof userCandidates, path: string | undefined | null, source: string) => {
    if (path?.trim()) list.push({ path: path.trim(), source });
  };

  // Operator-first, then LLM args last.
  push(userCandidates, engagement.userlist, "target");
  push(passCandidates, engagement.passlist, "target");
  push(userCandidates, env.HYDRA_USERLIST, "env");
  push(passCandidates, env.HYDRA_PASSLIST, "env");
  for (const w of pipelineWordlists) {
    if (!isJunkPasswordWordlist(w)) push(passCandidates, w, "pipeline");
  }
  push(userCandidates, strArg(args, "userlist"), "args");
  push(passCandidates, strArg(args, "passlist"), "args");
  // If LLM put a list path into password=, treat as passlist candidate.
  if (passwordLooksLikePath) push(passCandidates, password, "args");

  const userHit = await resolveExistingPath(
    "userlist",
    userCandidates,
    pipelineWordlists,
    input.signal,
    input.emitLog
  );
  const passHit = await resolveExistingPath(
    "passlist",
    passCandidates,
    pipelineWordlists,
    input.signal,
    input.emitLog
  );

  for (const c of [...userCandidates, ...passCandidates]) tried.push(c.path);

  if (username && passHit) {
    return {
      source: { username, passwordList: passHit.path },
      meta: { credMode: "user+passlist", userList: null, passList: passHit.path, passSource: passHit.source }
    };
  }
  if (userHit && password && !passwordLooksLikePath) {
    return {
      source: { userList: userHit.path, password },
      meta: { credMode: "userlist+pass", userList: userHit.path, passList: null, userSource: userHit.source }
    };
  }
  if (userHit && passHit) {
    return {
      source: { userList: userHit.path, passwordList: passHit.path },
      meta: {
        credMode: "lists",
        userList: userHit.path,
        passList: passHit.path,
        userSource: userHit.source,
        passSource: passHit.source
      }
    };
  }

  const roots = allowedWordlistRoots().join(", ");
  return {
    source: null,
    error:
      `No usable credential source. Configure per-target wordlists on the Targets page, ` +
      `set HYDRA_USERLIST/HYDRA_PASSLIST (or HYDRA_USERNAME/HYDRA_PASSWORD) in .env, ` +
      `or add paths under Pipeline → allowed wordlists. ` +
      `Do not rely on LLM-picked SecLists (tiny router lists like 3bb are ignored). ` +
      `Paths must exist on the Kali tools host under: ${roots}. ` +
      (tried.length ? `Tried: ${[...new Set(tried)].join(", ")}` : ""),
    meta: { tried: [...new Set(tried)], allowedRoots: allowedWordlistRoots(), pipelineWordlists }
  };
}
