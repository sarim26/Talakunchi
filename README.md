# Talakunchi Security Prototype (Local)

Local, CEO-demo-friendly prototype for:
- Target onboarding (Windows host on LAN)
- Scan runs (MCP recon loop; mock data still supported)
- Findings tracking (first seen / last seen, status)
- Neo4j graph view (Target → Service → Finding)
- "AI Explain" button (mock now, Azure OpenAI later)

## Requirements
- Docker Desktop (with Compose)
- OLLAMA
- VirtualBox Kali (tools host)

## Quick start

```bash
docker compose up --build
```

Then open:
- Web UI: `http://localhost:5173`
- API: `http://localhost:8080/health`
- Neo4j Browser: `http://localhost:7474` (user: `neo4j`, password: `neo4jpassword`)

## Prototype behavior
- You can add targets without knowing the final IP yet.
- Running a scan executes a **manager → prompter → specialist** recon loop (see `worker/src/orchestrator/reconRun.ts`).
- Tools execute on a **Kali tools host over SSH** (the worker container is Node + ssh; it does not run nmap/katana/etc locally).
- Re-running scans will update `lastSeenAt` and show deltas (new/fixed).

## Config: tools host (Kali over SSH)
Configure these in `.env`:
- `REMOTE_SSH_HOST`, `REMOTE_SSH_USER`, `REMOTE_SSH_PORT`
- One auth method: `REMOTE_SSH_PASSWORD` **or** `REMOTE_SSH_IDENTITY_FILE`
- Optional sudo: `REMOTE_SSH_SUDO_PASSWORD` (used by the installer)

Important notes:
- `REMOTE_SSH_HOST=host.docker.internal` means “the Docker host machine”, not your scan target IP. If your Kali is a VM, you usually need **port-forwarding** (host port → guest sshd 22) or a bridged/host-only IP that Docker can reach.
- If a tool is installed under `~/go/bin` on Kali, ensure it is on PATH for non-interactive SSH sessions, or symlink it into `/usr/local/bin`.

## Auto-install missing tools (`system.tool_installer`)
Specialists preflight required binaries with `command -v <tool>`. If a tool is missing, the orchestrator queues `system.tool_installer` and retries.

`system.tool_installer` supports:
- `args.tool`: binary name to verify (required)
- `args.installCommand`: optional full install snippet (for tools not available via apt). The script exposes `$SUDO` for privileged steps.

## Project layout
- `web/`: Vite + React + TypeScript dashboard
- `api/`: TypeScript API (Fastify) backed by Postgres + Neo4j
- `worker/`: TypeScript worker that polls Postgres for scan jobs
- `db/init.sql`: DB schema for prototype

## Notes
- This is a prototype. Hardening (Okta, approvals, strict allowlists, Azure deployment) comes next.

