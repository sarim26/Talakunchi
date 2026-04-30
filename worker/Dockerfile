FROM node:20-bookworm-slim

WORKDIR /app

ENV DEBIAN_FRONTEND=noninteractive

# Minimal deps for the worker itself.
# Core recon tooling is baked in to avoid flaky runtime apt mirrors (hash sum mismatch).
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
       ca-certificates \
       curl \
       git \
       python3 \
       make \
       g++ \
       nmap \
       netcat-openbsd \
  && rm -rf /var/lib/apt/lists/*

# ── Node deps ─────────────────────────────────────────────────────────────────
COPY package.json package-lock.json* ./
RUN npm ci

COPY tsconfig.json ./
COPY src ./src

CMD ["npm", "run", "dev"]