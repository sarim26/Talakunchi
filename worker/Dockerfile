FROM node:20-bookworm-slim

WORKDIR /app

RUN rm -rf /var/lib/apt/lists/* \
  && apt-get clean \
  && apt-get update -o Acquire::Retries=3 \
  && apt-get install -y --no-install-recommends --fix-missing nmap hydra bind9-dnsutils \
  && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json* ./
RUN npm ci

COPY tsconfig.json ./
COPY src ./src

CMD ["npm","run","dev"]

