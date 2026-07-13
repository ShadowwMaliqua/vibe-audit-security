import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { registerScanCodeTool } from "./tools/scan_code.js";
import { registerScanProjectTool } from "./tools/scan_project.js";
import { registerScanUrlTool } from "./tools/scan_url.js";

/**
 * Starts the vibe-audit MCP server over stdio. This is the entry point
 * `claude mcp add` should point at (via `vibe-audit mcp`). It only wires
 * tools to the core scan functions, no scanning logic lives here.
 */
export async function startMcpServer(): Promise<void> {
  const server = new McpServer({ name: "vibe-audit", version: "0.1.0" });

  registerScanCodeTool(server);
  registerScanUrlTool(server);
  registerScanProjectTool(server);

  const transport = new StdioServerTransport();
  await server.connect(transport);
}
