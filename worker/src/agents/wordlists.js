/**
 * SecLists wordlist catalog.
 *
 * Discovers wordlists installed on the SSH bastion (Kali) under SECLISTS_ROOT
 * and exposes them to the manager + prompter so the agent can choose which
 * list each specialist (gobuster, hydra, ffuf, etc.) should use, instead of
 * hardcoded paths.
 *
 * Strategy:
 *   - One discovery per orchestrated run (cached on the WordlistCatalog).
 *   - We list small / common files, classify them by SecLists subtree, and
 *     attach byte-size so the prompter can hint "prefer smaller".
 *   - We also keep an explicit allowlist: any wordlist actually used must
 *     resolve under SECLISTS_ROOT (no path escape).
 */
import { remoteScript } from "./shared.js";
export const SECLISTS_ROOT = "/home/kali/Desktop/SecLists";
const EMPTY_CATALOG = {
    root: SECLISTS_ROOT,
    rootExists: false,
    entries: [],
    byCategory: {
        "discovery-web-content": [],
        "discovery-dns": [],
        passwords: [],
        usernames: [],
        fuzzing: [],
        miscellaneous: [],
        other: []
    },
    defaults: { webContent: null, dnsSubdomains: null, passwords: null, usernames: null }
};
let cachedPromise = null;
let cachedAt = 0;
const CACHE_MS = 10 * 60 * 1000;
/**
 * Resolve and cache the wordlist catalog. Subsequent calls within CACHE_MS
 * return the cached value to avoid re-walking SecLists.
 */
export async function getWordlistCatalog(opts) {
    if (!opts?.force && cachedPromise && Date.now() - cachedAt < CACHE_MS) {
        return cachedPromise;
    }
    const p = discoverCatalog(opts?.signal).catch(() => EMPTY_CATALOG);
    cachedPromise = p;
    cachedAt = Date.now();
    return p;
}
async function discoverCatalog(signal) {
    // We list common .txt files under specific SecLists subtrees with size,
    // skipping mega-files (>50MB) so the menu the LLM sees stays short.
    const script = [
        `set +e`,
        `ROOT=${quote(SECLISTS_ROOT)}`,
        `if [ ! -d "$ROOT" ]; then`,
        `  echo "ROOT_MISSING"`,
        `  exit 0`,
        `fi`,
        `echo "ROOT_OK"`,
        // Each line: SIZE\tABSPATH
        `find "$ROOT" \\
      -type f \\
      \\( -path '*Discovery/Web-Content/*' \\
         -o -path '*Discovery/DNS/*' \\
         -o -path '*Passwords/Common-Credentials/*' \\
         -o -path '*Passwords/Default-Credentials/*' \\
         -o -path '*Usernames/*' \\
         -o -path '*Fuzzing/*' \\
         -o -path '*Miscellaneous/*' \\) \\
      \\( -name '*.txt' -o -name '*.lst' \\) \\
      -size -50000k \\
      -printf '%s\\t%p\\n' 2>/dev/null \\
      | sort -k2`
    ].join("\n");
    const r = await remoteScript(script, signal);
    if (r.stderr && /No such file/i.test(r.stderr))
        return EMPTY_CATALOG;
    const out = r.stdout || "";
    if (out.includes("ROOT_MISSING"))
        return { ...EMPTY_CATALOG, root: SECLISTS_ROOT };
    const entries = [];
    for (const line of out.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed || trimmed === "ROOT_OK")
            continue;
        const m = /^(\d+)\t(.+)$/.exec(trimmed);
        if (!m)
            continue;
        const sizeBytes = Number(m[1]);
        const absPath = m[2];
        if (!absPath.startsWith(SECLISTS_ROOT))
            continue;
        const relPath = absPath.slice(SECLISTS_ROOT.length).replace(/^\/+/, "");
        entries.push({
            path: absPath,
            relPath,
            category: classify(relPath),
            sizeBytes,
            label: makeLabel(relPath, sizeBytes)
        });
    }
    // Group by category + sort by size ascending so smaller lists come first.
    const byCategory = {
        "discovery-web-content": [],
        "discovery-dns": [],
        passwords: [],
        usernames: [],
        fuzzing: [],
        miscellaneous: [],
        other: []
    };
    for (const e of entries)
        byCategory[e.category].push(e);
    for (const cat of Object.keys(byCategory)) {
        byCategory[cat].sort((a, b) => a.sizeBytes - b.sizeBytes);
    }
    const pickDefault = (cat, regex) => {
        const list = byCategory[cat];
        if (!list.length)
            return null;
        if (regex) {
            const match = list.find((e) => regex.test(e.relPath));
            if (match)
                return match.path;
        }
        return list[0].path;
    };
    return {
        root: SECLISTS_ROOT,
        rootExists: true,
        entries,
        byCategory,
        defaults: {
            webContent: pickDefault("discovery-web-content", /common\.txt$/i) ?? pickDefault("discovery-web-content"),
            dnsSubdomains: pickDefault("discovery-dns", /subdomains-top1million-5000\.txt$/i) ?? pickDefault("discovery-dns"),
            passwords: pickDefault("passwords", /10-million.*-top-?(?:1000|10000)\.txt$/i) ?? pickDefault("passwords"),
            usernames: pickDefault("usernames", /top-?usernames-shortlist|cirt-default-usernames/i) ?? pickDefault("usernames")
        }
    };
}
function classify(relPath) {
    if (/^Discovery\/Web-Content\//i.test(relPath))
        return "discovery-web-content";
    if (/^Discovery\/DNS\//i.test(relPath))
        return "discovery-dns";
    if (/^Passwords\//i.test(relPath))
        return "passwords";
    if (/^Usernames\//i.test(relPath))
        return "usernames";
    if (/^Fuzzing\//i.test(relPath))
        return "fuzzing";
    if (/^Miscellaneous\//i.test(relPath))
        return "miscellaneous";
    return "other";
}
function makeLabel(relPath, sizeBytes) {
    const kb = Math.round(sizeBytes / 1024);
    const human = kb >= 1024 ? `${(kb / 1024).toFixed(1)} MB` : `${kb} KB`;
    return `${relPath} (${human})`;
}
/**
 * Validate a wordlist path the manager / agent picked is part of the catalog
 * (defends against the LLM hallucinating arbitrary paths).
 */
export function isWordlistAllowed(catalog, candidate) {
    if (!candidate)
        return false;
    const trimmed = candidate.trim();
    if (!trimmed)
        return false;
    if (!trimmed.startsWith(SECLISTS_ROOT))
        return false;
    return catalog.entries.some((e) => e.path === trimmed);
}
/**
 * Compact summary the manager + prompter receive — keep this small to avoid
 * burning the context window. We hand it ~15 paths per category max.
 */
export function summariseCatalogForLLM(catalog) {
    const cap = (list, n = 15) => list.slice(0, n).map((e) => ({ path: e.path, label: e.label, sizeBytes: e.sizeBytes }));
    return {
        root: catalog.root,
        rootExists: catalog.rootExists,
        defaults: catalog.defaults,
        categories: {
            webContent: cap(catalog.byCategory["discovery-web-content"]),
            dnsSubdomains: cap(catalog.byCategory["discovery-dns"]),
            passwords: cap(catalog.byCategory.passwords),
            usernames: cap(catalog.byCategory.usernames),
            fuzzing: cap(catalog.byCategory.fuzzing)
        }
    };
}
/** Reset the cached catalog — exposed so an admin endpoint can force-refresh. */
export function resetWordlistCache() {
    cachedPromise = null;
    cachedAt = 0;
}
function quote(s) {
    return `'${s.replace(/'/g, `'\\''`)}'`;
}
