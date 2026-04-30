/**
 * Allow-list for install_tool across recon (agent) and exploit phases.
 * Used with apt-get on Debian-based worker images.
 */
export const INSTALLABLE_PACKAGES = new Set([
  // ── Metasploit ────────────────────────────────────────────────
  "metasploit-framework",
  "armitage",

  // ── Credential attacks ────────────────────────────────────────
  "hydra",
  "medusa",
  "ncrack",
  "thc-hydra",
  "john",
  "john-data",
  "hashcat",
  "hashcat-utils",
  "crunch",
  "cewl",
  "cupp",

  // ── Web exploitation ──────────────────────────────────────────
  "nikto",
  "sqlmap",
  "gobuster",
  "ffuf",
  "dirb",
  "dirbuster",
  "wfuzz",
  "wpscan",
  "whatweb",
  "wafw00f",
  "commix",

  // ── Enumeration ───────────────────────────────────────────────
  "enum4linux",
  "enum4linux-ng",
  "smbmap",
  "smbclient",
  "rpcclient",
  "ldap-utils",
  "snmp",
  "onesixtyone",
  "dnsrecon",
  "dnsenum",
  "fierce",
  "amass",
  "subfinder",
  "dnsx",
  "httpx-toolkit",
  "eyewitness",
  "aquatone",

  // ── Network scanning ──────────────────────────────────────────
  "nmap",
  "masscan",
  "rustscan",
  "netcat-openbsd",
  "netcat-traditional",
  "ncat",
  "hping3",
  "arp-scan",
  "arping",
  "tcpdump",
  "tshark",
  "wireshark-common",

  // ── SMB / Windows / Active Directory ─────────────────────────
  "crackmapexec",
  "impacket-scripts",
  "python3-impacket",
  "kerbrute",
  "bloodhound",
  "bloodhound.py",
  "ldapdomaindump",
  "windapsearch",
  "evil-winrm",

  // ── Exploitation frameworks ────────────────────────────────────
  "beef-xss",
  "set",
  "routersploit",
  "exploitdb",
  "exploitdb-papers",
  "exploitdb-bin-sploits",

  // ── Wordlists & SecLists ──────────────────────────────────────
  "seclists",
  "wordlists",
  "rockyou",

  // ── Post-exploitation / privesc ───────────────────────────────
  "pspy",
  "unix-privesc-check",
  "linux-exploit-suggester",
  "linpeas",
  "pwncat-cs",
  "pwncat",

  // ── Wireless ──────────────────────────────────────────────────
  "aircrack-ng",
  "airmon-ng",
  "reaver",
  "bully",
  "wifite",
  "wash",
  "hcxdumptool",
  "hcxtools",
  "cowpatty",

  // ── MITM / sniffing ───────────────────────────────────────────
  "ettercap-common",
  "ettercap-graphical",
  "bettercap",
  "responder",
  "mitm6",
  "arpwatch",
  "dsniff",

  // ── Tunnelling / pivoting ──────────────────────────────────────
  "proxychains",
  "proxychains4",
  "proxychains-ng",
  "chisel",
  "socat",
  "sshuttle",
  "stunnel4",
  "ligolo-ng",

  // ── Fuzzing / binary exploitation ─────────────────────────────
  "gdb",
  "gdb-peda",
  "pwndbg",
  "peda",
  "pwntools",
  "radare2",
  "r2",
  "binwalk",
  "ltrace",
  "strace",
  "valgrind",
  "afl",
  "afl++",
  "aflplusplus",
  "boofuzz",

  // ── Web proxies / interceptors ────────────────────────────────
  "burpsuite",
  "zaproxy",
  "mitmproxy",
  "caido",

  // ── Crypto / encoding tools ───────────────────────────────────
  "hashid",
  "hash-identifier",
  "fcrackzip",
  "pdfcrack",
  "rarcrack",
  "steghide",
  "stegseek",
  "exiftool",
  "binutils",

  // ── Python tooling (pip packages) ────────────────────────────
  "impacket",
  "bloodhound",
  "certipy-ad",
  "coercer",
  "pypykatz",
  "ldeep",
  "msldap",
  "ldap3",
  "scapy",
  "paramiko",
  "requests",
  "bs4",
  "lxml",

  // ── Ruby gems ─────────────────────────────────────────────────
  "wpscan",

  // ── Go tools (go install) ─────────────────────────────────────
  "httpx",
  "nuclei",
  "naabu",
  "katana",
  "gau",
  "hakrawler",
  "anew",
  "qsreplace",
  "dalfox",
  "interactsh-client",

  // ── Kali meta-packages (install many at once) ─────────────────
  "kali-tools-top10",
  "kali-tools-web",
  "kali-tools-passwords",
  "kali-tools-wireless",
  "kali-tools-exploitation",
  "kali-tools-post-exploitation",
  "kali-tools-sniffing-spoofing",
  "kali-tools-forensics",
  "kali-tools-information-gathering",
  "kali-tools-vulnerability"
]);
