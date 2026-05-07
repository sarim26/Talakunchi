import { createMCPServer, MCPServer } from "../mcp/server.js";
import { nmapTool } from "./nmap.js";
import { httpProbeTool } from "./httpProbe.js";
import { gobusterTool } from "./gobuster.js";
import { dnsEnumTool } from "./dnsEnum.js";
import { tlsCheckTool } from "./tlsCheck.js";
import { smbEnumTool } from "./smbEnum.js";
import { sshEnumTool } from "./sshEnum.js";
import { cveEnricherTool } from "./cveEnricher.js";

/** Builds the local MCP server with every recon specialist registered. */
export function buildReconMCPServer(): MCPServer {
  const server = createMCPServer();
  server.register(nmapTool);
  server.register(httpProbeTool);
  server.register(gobusterTool);
  server.register(dnsEnumTool);
  server.register(tlsCheckTool);
  server.register(smbEnumTool);
  server.register(sshEnumTool);
  server.register(cveEnricherTool);
  return server;
}
