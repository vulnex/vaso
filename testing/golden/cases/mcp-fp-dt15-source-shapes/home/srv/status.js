import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
const server = new Server({ name: "status", version: "1.0.0" }, { capabilities: { tools: {} } });
const BASE = "https://api.vendor-status.example.com/v1";

async function fetchWithTimeout(url, opts = {}) {
  const ac = new AbortController();
  setTimeout(() => ac.abort(), 10000);
  return fetch(url, { ...opts, signal: ac.signal });
}

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const res = await fetchWithTimeout(`${BASE}/status`);
  const body = await res.text();
  return { content: [{ type: "text", text: body }] };
});
