import { startMcpServer } from "../../mcp_server/server.js";

/** Starts the MCP server on stdio — this is what `claude mcp add` should point at. */
export async function runMcpCommand(): Promise<void> {
  await startMcpServer();
}
