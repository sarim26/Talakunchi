FROM kalilinux/kali-last-release:latest

WORKDIR /app
ENV DEBIAN_FRONTEND=noninteractive

# Force official mirror only
RUN rm -f /etc/apt/sources.list && rm -rf /etc/apt/sources.list.d/* \
    && echo 'deb http://http.kali.org/kali kali-last-snapshot main non-free contrib' > /etc/apt/sources.list \
    && echo 'Acquire::http::Pipeline-Depth "0";' > /etc/apt/apt.conf.d/99custom \
    && echo 'Acquire::Retries "5";' >> /etc/apt/apt.conf.d/99custom

# Layer 1: Core tools + Hydra (gnupg: Rapid7 MSF repo signing key)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git gnupg \
    python3 python3-pip python3-venv \
    make g++ \
    nmap netcat-traditional postgresql-client \
    gobuster \
    smbclient ldap-utils \
    hydra \
    && rm -rf /var/lib/apt/lists/*

# Layer 2: Node via NodeSource (bypasses broken kali node-* packages)
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Layer 3: Network tools (same as previous Dockerfile)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap netcat-traditional postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Layer 4: samba-client only (skip samba-common-bin — it pulls via 403)
RUN apt-get update && apt-get install -y --no-install-recommends \
    smbclient \
    && rm -rf /var/lib/apt/lists/*

# Metasploit Framework: Rapid7 apt (Kali pool on kali.download often 403s the large .deb during Docker builds)
RUN curl -fsSL https://apt.metasploit.com/metasploit-framework.gpg.key | gpg --dearmor -o /usr/share/keyrings/metasploit-framework-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/metasploit-framework-archive-keyring.gpg] https://apt.metasploit.com kali main" > /etc/apt/sources.list.d/metasploit-framework.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends metasploit-framework \
    && rm -f /etc/apt/sources.list.d/metasploit-framework.list \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install impacket smbmap --break-system-packages

RUN apt-get update && apt-get install -y --no-install-recommends \
    nikto \
    hydra \
    sqlmap \
    && rm -rf /var/lib/apt/lists/*

# SecLists for proper wordlists
RUN git clone --depth 1 https://github.com/danielmiessler/SecLists.git /opt/SecLists

# Metasploit for CVE exploitation
RUN curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb \
    > /tmp/msfinstall \
    && chmod +x /tmp/msfinstall \
    && /tmp/msfinstall

# enum4linux has no pip package — clone from source
RUN git clone https://github.com/CiscoCXSecurity/enum4linux.git /opt/enum4linux \
    && ln -s /opt/enum4linux/enum4linux.pl /usr/local/bin/enum4linux

# ── Node deps ──────────────────────────────────────────────────────────────
COPY package.json package-lock.json* ./
RUN npm ci

COPY tsconfig.json ./
COPY src ./src

CMD ["npm", "run", "dev"]
