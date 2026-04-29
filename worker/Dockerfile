FROM node:20-bookworm-slim

WORKDIR /app

ENV DEBIAN_FRONTEND=noninteractive

# ── Switch to a stable mirror BEFORE anything else ───────────────────────────
# The default deb.debian.org is a CDN redirect that can serve mid-sync mirrors.
# ftp.us.debian.org is a direct, stable mirror — avoids hash mismatch errors.
#
RUN echo "deb http://ftp.us.debian.org/debian bookworm main" > /etc/apt/sources.list \
 && echo "deb http://security.debian.org/debian-security bookworm-security main" >> /etc/apt/sources.list \
 && echo "deb http://ftp.us.debian.org/debian bookworm-updates main" >> /etc/apt/sources.list

# ── Install perl FIRST and alone ─────────────────────────────────────────────
# perl + libperl5.36 are the most commonly corrupted packages on bookworm
# because they're large and frequently updated.
# Isolating them means a retry here costs seconds, not 30 minutes.
#
RUN apt-get clean \
 && rm -rf /var/lib/apt/lists/* \
 && apt-get update -o Acquire::Retries=10 \
 && apt-get install -y --no-install-recommends \
      perl \
 && rm -rf /var/lib/apt/lists/*

# ── Runtime essentials ────────────────────────────────────────────────────────
RUN apt-get update -o Acquire::Retries=6 \
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
 && rm -rf /var/lib/apt/lists/*

# ── Core network tools ────────────────────────────────────────────────────────
RUN apt-get update -o Acquire::Retries=6 \
 && apt-get install -y --no-install-recommends --fix-missing \
      nmap \
      netcat-openbsd \
      tcpdump \
      tshark \
      socat \
      proxychains4 \
      sshuttle \
      stunnel4 \
 && rm -rf /var/lib/apt/lists/*

# ── Web exploitation ──────────────────────────────────────────────────────────
RUN apt-get update -o Acquire::Retries=6 \
 && apt-get install -y --no-install-recommends --fix-missing \
      sqlmap \
      gobuster \
      ffuf \
      dirb \
      wfuzz \
      whatweb \
 && rm -rf /var/lib/apt/lists/*

# ── Credential attacks ────────────────────────────────────────────────────────
RUN apt-get update -o Acquire::Retries=6 \
 && apt-get install -y --no-install-recommends --fix-missing \
      hydra \
      medusa \
      ncrack \
      john \
      john-data \
      hashcat \
      crunch \
      cewl \
 && rm -rf /var/lib/apt/lists/*

# ── SMB / LDAP / Enumeration ──────────────────────────────────────────────────
RUN apt-get update -o Acquire::Retries=6 \
 && apt-get install -y --no-install-recommends --fix-missing \
      smbclient \
      enum4linux \
      ldap-utils \
      snmp \
      dnsrecon \
      dnsenum \
 && rm -rf /var/lib/apt/lists/*

# ── Exploitation support ──────────────────────────────────────────────────────
RUN apt-get update -o Acquire::Retries=6 \
 && apt-get install -y --no-install-recommends --fix-missing \
      python3-impacket \
      python3-scapy \
      python3-requests \
      python3-bs4 \
      python3-paramiko \
 && rm -rf /var/lib/apt/lists/*

# ── Post-exploitation basics ──────────────────────────────────────────────────
RUN apt-get update -o Acquire::Retries=6 \
 && apt-get install -y --no-install-recommends --fix-missing \
      gdb \
      ltrace \
      strace \
      binutils \
      fcrackzip \
      steghide \
 && rm -rf /var/lib/apt/lists/*

# ── Optional / fragile packages (never break the build) ──────────────────────
# Each in its own RUN so a failure only invalidates that one layer on retry.
#
RUN apt-get update && apt-get install -y --no-install-recommends masscan      && rm -rf /var/lib/apt/lists/* || echo "[skip] masscan"
RUN apt-get update && apt-get install -y --no-install-recommends nikto        && rm -rf /var/lib/apt/lists/* || echo "[skip] nikto"
RUN apt-get update && apt-get install -y --no-install-recommends smbmap       && rm -rf /var/lib/apt/lists/* || echo "[skip] smbmap"
RUN apt-get update && apt-get install -y --no-install-recommends bettercap    && rm -rf /var/lib/apt/lists/* || echo "[skip] bettercap"
RUN apt-get update && apt-get install -y --no-install-recommends reaver       && rm -rf /var/lib/apt/lists/* || echo "[skip] reaver"
RUN apt-get update && apt-get install -y --no-install-recommends onesixtyone  && rm -rf /var/lib/apt/lists/* || echo "[skip] onesixtyone"
RUN apt-get update && apt-get install -y --no-install-recommends fierce       && rm -rf /var/lib/apt/lists/* || echo "[skip] fierce"
RUN apt-get update && apt-get install -y --no-install-recommends binwalk      && rm -rf /var/lib/apt/lists/* || echo "[skip] binwalk"
RUN apt-get update && apt-get install -y --no-install-recommends upx-ucl      && rm -rf /var/lib/apt/lists/* || echo "[skip] upx-ucl"
RUN apt-get update && apt-get install -y --no-install-recommends aircrack-ng  && rm -rf /var/lib/apt/lists/* || echo "[skip] aircrack-ng"
RUN apt-get update && apt-get install -y --no-install-recommends ettercap-common && rm -rf /var/lib/apt/lists/* || echo "[skip] ettercap"
RUN apt-get update && apt-get install -y --no-install-recommends hashid       && rm -rf /var/lib/apt/lists/* || echo "[skip] hashid"

# ── Python tools ──────────────────────────────────────────────────────────────
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

RUN pip3 install --break-system-packages --no-cache-dir crackmapexec || echo "[skip] crackmapexec"
RUN pip3 install --break-system-packages --no-cache-dir bloodhound   || echo "[skip] bloodhound"
RUN pip3 install --break-system-packages --no-cache-dir coercer      || echo "[skip] coercer"
RUN pip3 install --break-system-packages --no-cache-dir ldeep        || echo "[skip] ldeep"
RUN pip3 install --break-system-packages --no-cache-dir pwncat-cs    || echo "[skip] pwncat-cs"

# ── Ruby gems ─────────────────────────────────────────────────────────────────
RUN gem install wpscan     || echo "[skip] wpscan"
RUN gem install evil-winrm || echo "[skip] evil-winrm"

# ── Go tools ──────────────────────────────────────────────────────────────────
ENV GOPATH=/root/go
ENV PATH="${PATH}:/root/go/bin"

RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || echo "[skip] subfinder"
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest            || echo "[skip] httpx"
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest       || echo "[skip] nuclei"
RUN go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest         || echo "[skip] naabu"
RUN go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest              || echo "[skip] dnsx"
RUN go install github.com/hahwul/dalfox/v2@latest                            || echo "[skip] dalfox"
RUN go install github.com/ropnop/kerbrute@latest                             || echo "[skip] kerbrute"
RUN go install github.com/jpillora/chisel@latest                             || echo "[skip] chisel"

# ── ExploitDB / searchsploit ──────────────────────────────────────────────────
RUN git clone --depth=1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb \
 && ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit \
 || echo "[skip] exploitdb"

# ── Wordlists ─────────────────────────────────────────────────────────────────
RUN mkdir -p /usr/share/wordlists \
 && curl -fsSL \
      "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt" \
      -o /usr/share/wordlists/rockyou.txt \
 || echo "[skip] rockyou"

# ── linpeas ───────────────────────────────────────────────────────────────────
RUN mkdir -p /opt/privesc \
 && curl -fsSL \
      "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh" \
      -o /opt/privesc/linpeas.sh \
 && chmod +x /opt/privesc/linpeas.sh \
 && ln -sf /opt/privesc/linpeas.sh /usr/local/bin/linpeas \
 || echo "[skip] linpeas"

# ── Node deps ─────────────────────────────────────────────────────────────────
COPY package.json package-lock.json* ./
RUN npm ci

COPY tsconfig.json ./
COPY src ./src

CMD ["npm", "run", "dev"]