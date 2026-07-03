# Talakunchi

Local agentic recon platform. You register targets, kick off a run, and a multi-LLM loop drives real tools on a Kali box over SSH — nmap, httpx, gobuster, nuclei, hydra, sqlmap, the usual. Findings land in Postgres; the graph view is Neo4j. Exploit-phase tools sit behind pipeline approvals when `RECON_MODE=gated_exploit`.

Built for lab work (Metasploitable, vulnweb, LAN VMs), not production pentest delivery yet.

## How the agent works

Each run is orchestrated in `worker/src/orchestrator/reconRun.ts`:

1. **Manager** (Ollama) — reads the tool manifest, what's already been found, and picks the next tool or stops.
2. **Prompter** — turns that intent into instructions the specialist can act on.
3. **Execution writer** — for tools with structured args, fills the JSON payload (targets, wordlists, flags).
4. **Tool invoke** — worker SSHs into Kali and runs the command. Output gets parsed into findings/services and fed back into context for the next step.

Recon runs until the manager stops or you hit `RECON_MAX_STEPS`. When recon finishes, you can hit **Start exploit phase** in the UI — same run, new phase, gated tools only (hydra, sqlmap, msf, commix, crackmapexec). Each gated command waits for approval in the Pipeline before it executes.

Tools don't run inside Docker. The worker container is Node + SSH client. Kali is the tools host.

## Requirements

- Docker Desktop + Compose
- Ollama on the host (models pulled locally)
- Kali VM with SSH reachable from Docker (`host.docker.internal` + port forward is the usual setup)
- SecLists on Kali at `/home/kali/Desktop/SecLists` (or symlink from apt's `seclists` package)

## Quick start

```bash
docker compose up --build
```

- Web UI: http://localhost:5173
- API health: http://localhost:8080/health
- Neo4j: http://localhost:7474 (`neo4j` / `neo4jpassword`)

Add a target (hostname or IP in **IP/Hostname**; **vhost** is only for CDN/IP targets where you need a `Host` header). Start agentic recon from the UI.

## Config

Copy `.env.example` → `.env`. The important bits:

**Kali SSH**
- `REMOTE_SSH_HOST`, `REMOTE_SSH_PORT`, `REMOTE_SSH_USER`
- `REMOTE_SSH_PASSWORD` or `REMOTE_SSH_IDENTITY_FILE`
- `REMOTE_SSH_SUDO_PASSWORD` if you want `system.tool_installer` to apt-install missing tools

`REMOTE_SSH_HOST=host.docker.internal` is the Docker host, not your scan target. Port-forward VM SSH (e.g. host `2227` → guest `22`) or use a bridged IP Docker can reach.

**Agent / models**
- `OLLAMA_URL` — usually `http://host.docker.internal:11434`
- `OLLAMA_MANAGER_MODEL` — tool choice (`qwen3:8b` on 16 GB RAM; avoid keeping DeepSeek 14B loaded alongside everything else)
- `OLLAMA_PROMPTER_MODEL`, `OLLAMA_SPECIALIST_MODEL`, `OLLAMA_COMMAND_WRITER_MODEL`
- `OLLAMA_EXPLAIN_MODEL` — API-side summaries/reports

**Modes**
- `RECON_MODE=readonly` — recon tools only
- `RECON_MODE=gated_exploit` — recon + gated exploit tools (needs `HYDRA_ENABLED=true` etc.)
- `RECON_MAX_STEPS`, `APPROVAL_WAIT_MS`, `EXPLOIT_LHOST_ALLOWLIST`

Go binaries on Kali (`httpx`, `katana`, `nuclei`) need to be on PATH for non-interactive SSH — put `$HOME/go/bin` in `.bashrc` / `.profile`.

## Missing tools

Specialists check `command -v` before running. If something's missing, the orchestrator can queue `system.tool_installer` (allowlisted apt packages) and retry. Custom installs go through `args.installCommand`.

## Layout

- `web/` — React dashboard
- `api/` — Fastify API, Postgres, Neo4j
- `worker/` — job poller, MCP tools, orchestrator
- `db/init.sql` — schema

## 16 GB RAM / Ollama

Several models get called in one run but not all at once. Still, don't leave a 14B model resident while Docker + WSL eat half your RAM.

| Role | Env var | What I'd use on 16 GB |
|------|---------|------------------------|
| Manager | `OLLAMA_MANAGER_MODEL` | `qwen3:8b` |
| Prompter | `OLLAMA_PROMPTER_MODEL` | `qwen3:8b` |
| Arg writer | `OLLAMA_COMMAND_WRITER_MODEL` | `qwen2.5-coder:7b` |
| Summaries | `OLLAMA_EXPLAIN_MODEL` | `qwen3:8b` |

`ollama ps` / `ollama stop <model>` to free memory. Cap WSL in `%UserProfile%\.wslconfig` if Ollama OOMs on step 1 — orchestrator falls back to `recon.nmap` on a cold manager failure.

## Not done yet

Auth, strict production hardening, cloud deploy, recon brief/RAG for exploit phase. This is a working lab stack, not a shipped product.
