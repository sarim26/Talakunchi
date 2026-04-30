FROM node:20-bookworm-slim

WORKDIR /app

ENV DEBIAN_FRONTEND=noninteractive

# Minimal deps for the worker itself.
# All offensive tooling will be installed at runtime via your tool installation function.
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
       ca-certificates \
       curl \
       git \
       python3 \
       make \
       g++ \
  && rm -rf /var/lib/apt/lists/*

# ── Node deps ─────────────────────────────────────────────────────────────────
COPY package.json package-lock.json* ./
RUN npm ci

COPY tsconfig.json ./
COPY src ./src

CMD ["npm", "run", "dev"]