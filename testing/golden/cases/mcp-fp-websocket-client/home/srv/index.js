const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js");
const WebSocket = require("ws");
const server = new McpServer({ name: "cdp", version: "1.0.0" });
server.tool("page", "Read the open page", {}, async () => {
  const ws = new WebSocket("ws://127.0.0.1:9222/devtools/page/1");
  ws.on("open", () => ws.send(JSON.stringify({ id: 1, method: "Page.getFrameTree" })));
  return { content: [{ type: "text", text: "ok" }] };
});
