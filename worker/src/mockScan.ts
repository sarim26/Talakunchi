import crypto from "node:crypto";

export type MockService = {
  port: number;
  protocol: "tcp";
  serviceName: string;
  product?: string;
  version?: string;
  banner?: string;
};

export type MockFinding = {
  title: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  servicePort?: number;
  evidenceRedacted: string;
  fingerprint: string;
};

function hash(s: string) {
  return crypto.createHash("sha256").update(s).digest("hex").slice(0, 16);
}

export function generateMockScan(targetAddress: string) {
  const baseSeed = hash(targetAddress);
  const common: MockService[] = [
    { port: 135, protocol: "tcp", serviceName: "msrpc" },
    { port: 445, protocol: "tcp", serviceName: "microsoft-ds", product: "SMB", version: "3.x" },
    { port: 3389, protocol: "tcp", serviceName: "ms-wbt-server", product: "RDP" }
  ];
  // Add a couple "sometimes present" services to make reruns interesting.
  const extras: MockService[] = [
    { port: 5985, protocol: "tcp", serviceName: "wsman", product: "WinRM" },
    { port: 80, protocol: "tcp", serviceName: "http", product: "IIS", version: "10.0" },
    { port: 443, protocol: "tcp", serviceName: "https", product: "IIS", version: "10.0" }
  ];

  const pick = (n: number) => extras.filter((_, i) => (baseSeed.charCodeAt(i % baseSeed.length) + i) % n === 0);
  const services = [...common, ...pick(2)];

  const findings: MockFinding[] = [];

  for (const svc of services) {
    if (svc.port === 445) {
      findings.push({
        title: "SMB exposed on host",
        severity: "medium",
        servicePort: 445,
        evidenceRedacted: "Port 445/tcp is open. Validate whether SMB exposure is required for this host/environment.",
        fingerprint: `fp:${hash(`${targetAddress}|tcp|445|smb-exposed`)}`
      });
    }
    if (svc.port === 3389) {
      findings.push({
        title: "RDP exposed on host",
        severity: "medium",
        servicePort: 3389,
        evidenceRedacted:
          "Port 3389/tcp is open. Restrict RDP to admin subnets and require MFA/jump host where possible.",
        fingerprint: `fp:${hash(`${targetAddress}|tcp|3389|rdp-exposed`)}`
      });
    }
    if (svc.port === 80) {
      findings.push({
        title: "HTTP service detected (review TLS/redirect)",
        severity: "low",
        servicePort: 80,
        evidenceRedacted: "HTTP port 80 is open. Ensure it redirects to HTTPS and does not serve sensitive content.",
        fingerprint: `fp:${hash(`${targetAddress}|tcp|80|http-detected`)}`
      });
    }
    if (svc.port === 443) {
      findings.push({
        title: "HTTPS service detected (validate TLS baseline)",
        severity: "info",
        servicePort: 443,
        evidenceRedacted: "HTTPS port 443 is open. Validate certificate validity and TLS configuration baseline.",
        fingerprint: `fp:${hash(`${targetAddress}|tcp|443|https-detected`)}`
      });
    }
  }

  // A "wow" finding that feels like a vuln detection without being exploit-y.
  findings.push({
    title: "Missing host firewall restriction on management ports (policy)",
    severity: "high",
    evidenceRedacted:
      "Management ports appear reachable from broader network segments. Recommended: restrict to admin subnet/jumpbox, log access, and enforce baseline.",
    fingerprint: `fp:${hash(`${targetAddress}|policy|mgmt-ports-restriction`)}`
  });

  return { services, findings };
}

