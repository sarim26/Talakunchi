# Orchestrator only: schedules jobs, talks to Gemini/Postgres/Neo4j, forwards every CLI to your Kali host over SSH.
# Nmap/Hydra/Metasploit/etc. live on Kali — not in this image.
FROM node:20-bookworm-slim

WORKDIR /app
ENV DEBIAN_FRONTEND=noninteractive

# Hash Sum mismatch on deb.debian.org is usually CDN/mirror inconsistency or a flaky proxy —
# drop cached lists, retry, and Prefer IPv4 if IPv6 routes break some edges.
RUN rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/partial \
  && apt-get update \
     -o Acquire::Retries=5 \
     -o Acquire::http::Timeout=120 \
     -o Acquire::https::Timeout=120 \
     -o Acquire::http::ForceIPv4=true \
  && apt-get install -y --no-install-recommends \
     -o Acquire::Retries=5 \
     ca-certificates \
     openssh-client \
     sshpass \
  && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json* ./
RUN npm ci

COPY tsconfig.json ./
COPY src ./src

CMD ["npm", "run", "dev"]
