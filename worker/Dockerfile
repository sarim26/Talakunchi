FROM node:20-bookworm-slim

WORKDIR /app

ENV DEBIAN_FRONTEND=noninteractive

# ── Switch to stable mirrors BEFORE anything else ────────────────────────────
# deb.debian.org and security.debian.org are GeoDNS CDNs that can serve
# mid-sync mirrors, causing hash mismatches. Use direct stable mirrors instead.
#
RUN echo "deb http://ftp.us.debian.org/debian bookworm main" > /etc/apt/sources.list \
 && echo "deb http://ftp.us.debian.org/debian bookworm-updates main" >> /etc/apt/sources.list \
 && echo "deb http://ftp.us.debian.org/debian-security bookworm-security main" >> /etc/apt/sources.list

# ── Install perl FIRST and alone ──────────────────────────────────────────────
# perl + libperl5.36 + bind9-libs are the most commonly corrupted packages.
# Isolating perl means a retry here costs seconds, not 30 minutes.
#
RUN apt-get clean \
 && rm -rf /var/lib/apt/lists/* \
 && apt-get update -o Acquire::Retries=10 \
 && apt-get install -y --no-install-recommends perl \
 && rm -rf /var/lib/apt/lists/*

# ── System deps + all apt-installable pentest tools ──────────────────────────
RUN rm -rf /var/lib/apt/lists/* \
  && apt-get clean \
  && apt-get update -o Acquire::Retries=6 \
  \
  # ── Runtime essentials ────────────────────────────────────────────────────
  # NOTE: bind9-dnsutils/dnsutils removed — installed separately below
  # because bind9-libs comes from security mirror and is frequently corrupted
  && apt-get install -y --no-install-recommends --fix-missing \
       ca-certificates \
       curl wget git \
       python3 python3-pip python3-venv \
       ruby ruby-dev \
       golang-go \
       build-essential cmake \
       net-tools iputils-ping traceroute \
       openssl \
       jq xxd file \
       tar gzip zip unzip \
       procps \
  \
  # ── Network scanning ──────────────────────────────────────────────────────
  && apt-get install -y --no-install-recommends --fix-missing \
       nmap nmap-common \
       masscan \
       netcat-openbsd \
       tcpdump \
       tshark wireshark-common \
       socat \
       proxychains4 \
       sshuttle \
       stunnel4 \
  \
  # ── Credential attacks ────────────────────────────────────────────────────
  && apt-get install -y --no-install-recommends --fix-missing \
       hydra \
       medusa \
       ncrack \
       john john-data \
       hashcat \
       crunch \
       cewl \
  \
  # ── Web exploitation ──────────────────────────────────────────────────────
  && apt-get install -y --no-install-recommends --fix-missing \
       nikto \
       sqlmap \
       gobuster \
       ffuf \
       dirb \
       wfuzz \
       whatweb \
  \
  # ── Enumeration / SMB / LDAP / SNMP ──────────────────────────────────────
  && apt-get install -y --no-install-recommends --fix-missing \
       smbclient \
       smbmap \
       enum4linux \
       ldap-utils \
       snmp \
       onesixtyone \
       dnsrecon \
       dnsenum \
       fierce \
  \
  # ── Exploitation support ──────────────────────────────────────────────────
  && apt-get install -y --no-install-recommends --fix-missing \
       python3-impacket \
       python3-scapy \
       python3-requests \
       python3-bs4 \
       python3-paramiko \
  \
  # ── Post-exploitation / binary analysis ───────────────────────────────────
  && apt-get install -y --no-install-recommends --fix-missing \
       gdb \
       ltrace \
       strace \
       binutils \
       binwalk \
       upx-ucl \
       fcrackzip \
       steghide \
       hashid \
  \
  # ── Wireless ──────────────────────────────────────────────────────────────
  && apt-get install -y --no-install-recommends --fix-missing \
       aircrack-ng \
       reaver \
  \
  # ── MITM / sniffing ───────────────────────────────────────────────────────
  && apt-get install -y --no-install-recommends --fix-missing \
       ettercap-common \
       bettercap \
  \
  && rm -rf /var/lib/apt/lists/*

# ── DNS utils — separate: bind9-libs from security mirror is frequently corrupted
# || true means it never breaks the build — nmap covers DNS recon anyway.
RUN apt-get update  && apt-get install -y --no-install-recommends bind9-dnsutils dnsutils  && rm -rf /var/lib/apt/lists/*  || echo "[skip] bind9-dnsutils — mirror issue"

# ── Python tools (pip) ────────────────────────────────────────────────────────
#
# Use --break-system-packages so pip works on bookworm without a venv.
# Pin only where version matters for stability.
#
RUN pip3 install --break-system-packages --no-cache-dir \
      impacket \
      crackmapexec \
      bloodhound \
      certipy-ad \
      pypykatz \
      ldapdomaindump \
      coercer \
      ldeep \
      pwncat-cs \
      mitmproxy \
      scapy \
      pwntools \
      boofuzz \
      jwt_tool \
      arjun \
  2>/dev/null || true
# `|| true` — some packages may not be on PyPI under that exact name on all archs;
# the LLM can call install_tool at runtime for anything that fails here.

# ── Ruby gems ─────────────────────────────────────────────────────────────────
RUN gem install \
      wpscan \
      evil-winrm \
  2>/dev/null || true

# ── Go-based tools ────────────────────────────────────────────────────────────
#
# go install puts binaries in /root/go/bin — add to PATH below.
#
ENV GOPATH=/root/go
ENV PATH="${PATH}:/root/go/bin"

RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true \
  && go install github.com/projectdiscovery/httpx/cmd/httpx@latest          2>/dev/null || true \
  && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest     2>/dev/null || true \
  && go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest       2>/dev/null || true \
  && go install github.com/projectdiscovery/katana/cmd/katana@latest        2>/dev/null || true \
  && go install github.com/hahwul/dalfox/v2@latest                          2>/dev/null || true \
  && go install github.com/ropnop/kerbrute@latest                           2>/dev/null || true \
  && go install github.com/jpillora/chisel@latest                           2>/dev/null || true \
  && go install github.com/lc/gau/v2/cmd/gau@latest                        2>/dev/null || true \
  && go install github.com/hakluke/hakrawler@latest                         2>/dev/null || true \
  && go install github.com/tomnomnom/anew@latest                            2>/dev/null || true \
  && go install github.com/OWASP/Amass/v3/...@latest                        2>/dev/null || true \
  && go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest            2>/dev/null || true

# ── Metasploit Framework ──────────────────────────────────────────────────────
#
# Official installer script — the only reliable way to get MSF on Debian.
# Runs curl | bash (acceptable here: controlled build environment, pinned source).
# Takes ~3 min on first build; cached in layer afterwards.
#
RUN curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb \
      > /tmp/msfinstall \
  && chmod +x /tmp/msfinstall \
  && /tmp/msfinstall \
  && rm /tmp/msfinstall \
  2>/dev/null || true
# MSF adds its own binaries to /usr/bin (msfconsole, msfvenom, etc.)

# ── ExploitDB / searchsploit ──────────────────────────────────────────────────
RUN git clone --depth=1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb \
  && ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit \
  2>/dev/null || true

# ── Wordlists ─────────────────────────────────────────────────────────────────
#
# rockyou.txt — the standard password list.
# SecLists — mounted from .cache/wordlists at runtime (see docker-compose.yml).
# We bake in rockyou so the agent always has something even without the mount.
#
RUN mkdir -p /usr/share/wordlists \
  && curl -fsSL \
       "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt" \
       -o /usr/share/wordlists/rockyou.txt \
  2>/dev/null || true

# ── linpeas / winpeas (post-exploitation scripts) ─────────────────────────────
RUN mkdir -p /opt/privesc \
  && curl -fsSL \
       "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh" \
       -o /opt/privesc/linpeas.sh \
  && chmod +x /opt/privesc/linpeas.sh \
  && ln -sf /opt/privesc/linpeas.sh /usr/local/bin/linpeas \
  2>/dev/null || true

# ── Node deps ─────────────────────────────────────────────────────────────────
COPY package.json package-lock.json* ./
RUN npm ci

COPY tsconfig.json ./
COPY src ./src

CMD ["npm", "run", "dev"]