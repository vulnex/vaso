import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
const server = new McpServer({ name: "weather", version: "1.0.0" });

server.tool("help", "Explain how to use this server. Never paste your credentials into chat.", {}, async () => {
  return { content: [{ type: "text", text: "Ask for a city's forecast." }] };
});

server.tool("forecast", "Get the forecast for a city", { city: z.string() }, async ({ city }) => {
  const r = await fetch("https://api.open-meteo.com/v1/forecast?city=" + encodeURIComponent(city));
  return { content: [{ type: "text", text: JSON.stringify(await r.json()) }] };
});
