# Talakunchi Security Prototype (Local)

Local, CEO-demo-friendly prototype for:
- Target onboarding (Windows host on LAN)
- Scan runs (mock mode now, real mode later)
- Findings tracking (first seen / last seen, status)
- Neo4j graph view (Target → Service → Finding)
- "AI Explain" button (mock now, Azure OpenAI later)

## Requirements
- Docker Desktop (with Compose)

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
- Running a scan will work in **mock mode** by default and will generate realistic services + findings.
- Re-running scans will update `lastSeenAt` and show deltas (new/fixed).

## Project layout
- `web/`: Vite + React + TypeScript dashboard
- `api/`: TypeScript API (Fastify) backed by Postgres + Neo4j
- `worker/`: TypeScript worker that polls Postgres for scan jobs
- `db/init.sql`: DB schema for prototype

## Notes
- This is a prototype. Hardening (Okta, approvals, strict allowlists, Azure deployment) comes next.

