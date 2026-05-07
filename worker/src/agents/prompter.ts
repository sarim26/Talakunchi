/**
 * Prompter (a.k.a. translator) agent.
 *
 * Converts the manager's chosen agent + intent goal into a concise,
 * specialist-flavoured English prompt with an embedded JSON schema hint.
 * Always returns a string; the LLM is consulted but a deterministic
 * fallback ensures we never block the pipeline.
 */
import { env } from "../env.js";
import { chat } from "../llm/ollama.js";
import type { ToolDefinition } from "../mcp/types.js";
import type { WordlistCatalog } from "./wordlists.js";

type PrompterInput = {
  agent: ToolDefinition;
  intentGoal: string;
  targetHost: string;
  knownPorts: number[];
  knownServices: Array<{ port: number; protocol: string; name?: string }>;
  /** Optional wordlist catalog so the prompter can hint which list to use. */
  wordlistCatalog?: WordlistCatalog;
  /** Wordlist path the manager already chose (if any) — surfaced to the agent. */
  selectedWordlist?: string;
  signal?: AbortSignal;
};

function wordlistLines(input: PrompterInput): string[] {
  if (!input.wordlistCatalog?.rootExists) return [];
  const cat = input.wordlistCatalog;
  const tag = (input.agent.tags ?? []).join(",");
  const wantsWeb = /web|gobuster/i.test(input.agent.name) || /web/i.test(tag);
  const wantsDns = /dns/i.test(input.agent.name) || /dns/i.test(tag);
  const wantsCreds = /hydra|brute|password|credential/i.test(input.agent.name + " " + tag);

  if (!wantsWeb && !wantsDns && !wantsCreds) return [];

  const top = (list: { path: string; label: string }[], n = 6) =>
    list.slice(0, n).map((e) => `  - ${e.label} → ${e.path}`).join("\n");

  const lines: string[] = ["", "Wordlists available on tools host (under /home/kali/Desktop/SecLists/):"];
  if (wantsWeb) {
    lines.push("Web-Content (smaller is faster, prefer common.txt unless evidence demands more):");
    lines.push(top(cat.byCategory["discovery-web-content"]));
  }
  if (wantsDns) {
    lines.push("DNS subdomains:");
    lines.push(top(cat.byCategory["discovery-dns"]));
  }
  if (wantsCreds) {
    lines.push("Passwords:");
    lines.push(top(cat.byCategory.passwords));
    lines.push("Usernames:");
    lines.push(top(cat.byCategory.usernames));
  }
  if (input.selectedWordlist) {
    lines.push("");
    lines.push(`Manager already selected wordlist: ${input.selectedWordlist}`);
  }
  return lines;
}

export async function generatePrompt(input: PrompterInput): Promise<string> {
  const { agent, intentGoal, targetHost, knownPorts, knownServices } = input;

  const systemMsg = [
    "You are the prompt translator for an autonomous penetration-testing system.",
    "Given a manager intent and a specialist agent description, produce a SHORT plain-English instruction",
    "that the specialist (an LLM-backed worker) can execute.",
    "Constraints:",
    "- Always remind the agent of its identity and the target.",
    "- Respect read-only / safe-recon scope (no exploitation).",
    "- Tell the agent to return STRICT JSON when it finishes.",
    "- Keep it under 8 sentences."
  ].join("\n");

  const userMsg = [
    `Specialist agent: ${agent.name}`,
    `Capability: ${agent.description}`,
    `Tags: ${(agent.tags ?? []).join(", ") || "(none)"}`,
    `Target host: ${targetHost}`,
    `Known open ports: ${knownPorts.length ? knownPorts.join(",") : "(none yet)"}`,
    `Known services: ${knownServices.map((s) => `${s.port}/${s.protocol}${s.name ? ` ${s.name}` : ""}`).join(", ") || "(none)"}`,
    `Manager intent: ${intentGoal}`,
    ...wordlistLines(input),
    "",
    'Return ONLY the prompt text (no JSON, no markdown fences).'
  ].join("\n");

  try {
    const r = await chat({
      model: env.OLLAMA_PROMPTER_MODEL,
      messages: [
        { role: "system", content: systemMsg },
        { role: "user", content: userMsg }
      ],
      temperature: 0.3,
      maxTokens: 400,
      signal: input.signal
    });
    const text = r.content.trim();
    if (text.length > 20) return text;
  } catch {
    // fall through to deterministic prompt
  }

  return [
    `You are the specialised "${agent.name}" agent.`,
    `Your task: ${agent.description}`,
    `Target: ${targetHost}.`,
    knownPorts.length ? `Known open ports: ${knownPorts.join(", ")}.` : "",
    `Manager intent: ${intentGoal}`,
    input.selectedWordlist ? `Use wordlist: ${input.selectedWordlist}.` : "",
    "Operate in safe, read-only recon mode. Return STRICT JSON when finished."
  ]
    .filter(Boolean)
    .join(" ");
}
