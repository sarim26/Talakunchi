FROM node:20-bookworm-slim

WORKDIR /app

# Prevent interactive apt prompts
ENV DEBIAN_FRONTEND=noninteractive

# ── System deps + stable pentest core ────────────────────────────────────────
# Keep only strong/stable tools here.
# Fragile tools are installed separately with fallback logic.
#
RUN rm -rf /var/lib/apt/lists/* \
  && apt-get clean \
  && apt-get update \
      -o Acquire::Retries=6 \
      -o Acquire::http::Timeout=30 \
      -o Acquire::https::Timeout=30 \
\
# ── Runtime essentials ───────────────────────────────────────────────────────
  && apt-get install -y --no-install-recommends --fix-missing \
      ca-certificates \
      curl wget git \
      python3 python3-pip python3-venv \
      ruby ruby-dev \
      golang-go \
      build-essential cmake \
      net-tools iputils-ping traceroute \
      bind9-dnsutils dnsutils \
      openssl \
      jq xxd file \
      tar gzip zip unzip \
      procps \
\
# ── Core network tools ───────────────────────────────────────────────────────
  && apt-get install -y --no-install-recommends --fix-missing \
      nmap \
      netcat-openbsd \
      tcpdump \
      tshark \
      socat \
      proxychains4 \
      sshuttle \
      stunnel4 \
\
# ── Web exploitation (stable only) ───────────────────────────────────────────
  && apt-get install -y --no-install-recommends --fix-missing \
      sqlmap \
      gobuster \
      ffuf \
      dirb \
      wfuzz \
      whatweb \
\
# ── Credential attacks ───────────────────────────────────────────────────────
  && apt-get install -y --no-install-recommends --fix-missing \
      hydra \
      medusa \
      ncrack \
      john \
      john-data \
      hashcat \
      crunch \
      cewl \
\
# ── SMB / LDAP / Enumeration ────────────────────────────────────────────────
  && apt-get install -y --no-install-recommends --fix-missing \
      smbclient \
      enum4linux \
      ldap-utils \
      snmp \
      dnsrecon \
      dnsenum \
\
# ── Exploitation support ─────────────────────────────────────────────────────
  && apt-get install -y --no-install-recommends --fix-missing \
      python3-impacket \
      python3-scapy \
      python3-requests \
      python3-bs4 \
      python3-paramiko \
\
# ── Post exploitation basics ────────────────────────────────────────────────
  && apt-get install -y --no-install-recommends --fix-missing \
      gdb \
      ltrace \
      strace \
      binutils \
      fcrackzip \
      steghide \
\
# ── Cleanup ─────────────────────────────────────────────────────────────────
  && rm -rf /var/lib/apt/lists/*

# ── Optional fragile packages (never break build) ───────────────────────────

RUN apt-get update \
 && apt-get install -y --no-install-recommends masscan \
 || echo "Skipping masscan"

RUN apt-get update \
 && apt-get install -y --no-install-recommends nikto \
 || echo "Skipping nikto"

RUN apt-get update \
 && apt-get install -y --no-install-recommends smbmap \
 || echo "Skipping smbmap"

RUN apt-get update \
 && apt-get install -y --no-install-recommends bettercap \
 || echo "Skipping bettercap"

RUN apt-get update \
 && apt-get install -y --no-install-recommends reaver \
 || echo "Skipping reaver"

RUN apt-get update \
 && apt-get install -y --no-install-recommends onesixtyone \
 || echo "Skipping onesixtyone"

RUN apt-get update \
 && apt-get install -y --no-install-recommends fierce \
 || echo "Skipping fierce"

RUN apt-get update \
 && apt-get install -y --no-install-recommends binwalk \
 || echo "Skipping binwalk"

RUN apt-get update \
 && apt-get install -y --no-install-recommends upx-ucl \
 || echo "Skipping upx-ucl"

RUN apt-get update \
 && apt-get install -y --no-install-recommends aircrack-ng \
 || echo "Skipping aircrack-ng"

RUN apt-get update \
 && apt-get install -y --no-install-recommends ettercap-common \
 || echo "Skipping ettercap"

# ── Python tools ────────────────────────────────────────────────────────────

RUN pip3 install --break-system-packages --no-cache-dir \
    impacket \
    certipy-ad \
    pypykatz \
    ldapdomaindump \
    mitmproxy \
    scapy \
    pwntools \
    boofuzz \
    arjun \
 || true

# crackmapexec often breaks depending on arch/version
RUN pip3 install --break-system-packages --no-cache-dir crackmapexec \
 || echo "Skipping crackmapexec"

# ── Ruby gems ───────────────────────────────────────────────────────────────

RUN gem install wpscan evil-winrm || true

# ── Go tools ────────────────────────────────────────────────────────────────

ENV GOPATH=/root/go
ENV PATH="${PATH}:/root/go/bin"

RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || true
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest || true
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || true
RUN go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest || true
RUN go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest || true

# ── ExploitDB / searchsploit ────────────────────────────────────────────────

RUN git clone --depth=1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb \
 && ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit \
 || true

# ── Wordlists ───────────────────────────────────────────────────────────────

RUN mkdir -p /usr/share/wordlists \
 && curl -fsSL \
    "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt" \
    -o /usr/share/wordlists/rockyou.txt \
 || true

# ── linpeas ─────────────────────────────────────────────────────────────────

RUN mkdir -p /opt/privesc \
 && curl -fsSL \
    "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh" \
    -o /opt/privesc/linpeas.sh \
 && chmod +x /opt/privesc/linpeas.sh \
 && ln -sf /opt/privesc/linpeas.sh /usr/local/bin/linpeas \
 || true

# ── Node deps ───────────────────────────────────────────────────────────────

COPY package.json package-lock.json* ./
RUN npm ci

COPY tsconfig.json ./
COPY src ./src

CMD ["npm", "run", "dev"]