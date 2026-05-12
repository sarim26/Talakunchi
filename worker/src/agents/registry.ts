import { createMCPServer, MCPServer } from "../mcp/server.js";
import { nmapTool } from "./nmap.js";
import { toolInstallerTool } from "./toolInstaller.js";
import { gobusterTool } from "./gobuster.js";
import { ffufTool } from "./ffuf.js";
import { httpProbeTool } from "./httpProbe.js";
import { spiderTool } from "./spider.js";
import { waybackUrlsTool } from "./waybackurls.js";
import { dnsEnumTool } from "./dnsEnum.js";
import { tlsCheckTool } from "./tlsCheck.js";
import { sshEnumTool } from "./sshEnum.js";
import { smbEnumTool } from "./smbEnum.js";
import { cveEnricherTool } from "./cveEnricher.js";

/**
 * MCP recon tools. Flow: manager LLM → prompter → executionCommandWriter (when
 * the tool has argSchema) → invoke.
 */
export function buildReconMCPServer(): MCPServer {
  const server = createMCPServer();
  server.register(nmapTool);
  server.register(dnsEnumTool);
  server.register(httpProbeTool);
  server.register(sshEnumTool);
  server.register(smbEnumTool);
  server.register(tlsCheckTool);
  server.register(cveEnricherTool);
  server.register(spiderTool);
  server.register(waybackUrlsTool);
  server.register(gobusterTool);
  server.register(ffufTool);
  server.register(toolInstallerTool);
  return server;
}
