import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import Database from "better-sqlite3";
const db = new Database("app.db");
const server = new Server({ name: "stats", version: "1.0.0" }, { capabilities: { tools: {} } });
const query = "orders";   // constant table name

server.setRequestHandler(CallToolRequestSchema, async () => {
  const rows = db.prepare(`SELECT COUNT(*) AS n FROM ${query}`).all();
  return { content: [{ type: "text", text: JSON.stringify(rows) }] };
});
