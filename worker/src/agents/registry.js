import { createMCPServer } from "../mcp/server.js";
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
import { portRecheckTool } from "./portRecheck.js";
import { infraEnumTools } from "./infraEnum.js";
import { webScanTools } from "./webScan.js";
import { osintTools } from "./osint.js";
import { hydraTool } from "./hydra.js";
import { postexTools } from "./postex.js";
import { env } from "../env.js";
/**
 * MCP recon tools. Flow: manager LLM → prompter → executionCommandWriter (when
 * the tool has argSchema) → invoke.
 */
export function buildReconMCPServer() {
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
    server.register(portRecheckTool);
    for (const tool of infraEnumTools)
        server.register(tool);
    for (const tool of webScanTools)
        server.register(tool);
    for (const tool of osintTools)
        server.register(tool);
    // Gated exploitation tools are only exposed in gated_exploit mode.
    if (env.RECON_MODE === "gated_exploit") {
        if (env.HYDRA_ENABLED)
            server.register(hydraTool);
        for (const tool of postexTools)
            server.register(tool);
    }
    server.register(toolInstallerTool);
    return server;
}
