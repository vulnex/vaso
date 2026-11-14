import { describe, it, expect } from 'vitest';
import { findTaintedSinks } from './tool-input-taint.js';

const HEAD = 'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\nimport { z } from "zod";\nconst server = new McpServer({ name: "x", version: "1" });\n';
const sinks = (code: string) => findTaintedSinks(HEAD + code, `sql-${Math.random()}.js`);

describe('SQL text built from tool input (traced, not by parameter name)', () => {
  it('a destructured handler parameter in a template query', () => {
    const found = sinks(`const db = new Database("app.db");
server.tool("user", "Find user", { name: z.string() }, async ({ name }) => {
  const rows = db.prepare(\`SELECT * FROM users WHERE name = '\${name}'\`).all();
  return { content: [{ type: "text", text: JSON.stringify(rows) }] };
});`);
    expect(found.filter((s) => s.kind === 'query')).toHaveLength(1);
    expect(found[0].origin).toBe('name');
  });

  it('concatenation through a variable', () => {
    const found = sinks(`server.tool("q", "d", { id: z.string() }, async ({ id }) => {
  const sql = "DELETE FROM items WHERE id = " + id;
  await pool.query(sql);
  return { content: [] };
});`);
    expect(found.some((s) => s.kind === 'query')).toBe(true);
  });

  it('does not flag bound parameters, tagged templates, constants or prose', () => {
    const found = sinks(`const TABLE = "users";
server.tool("q", "d", { id: z.string(), q: z.string() }, async ({ id, q }) => {
  await db.prepare(\`SELECT * FROM \${TABLE} WHERE id = ?\`).get(id);
  await sql\`SELECT * FROM users WHERE id = \${id}\`;
  await cache.get(\`please select one from \${q}\`);
  return { content: [] };
});`);
    expect(found.filter((s) => s.kind === 'query')).toEqual([]);
  });

  it('marks a wrapped whole statement', () => {
    const found = sinks(`server.tool("execute_sql", "d", { sql: z.string() }, async ({ sql }) => {
  return db.query(\`SELECT * FROM (\${sql}) AS subq LIMIT 100\`);
});`);
    expect(found.find((s) => s.kind === 'query')?.wrapsStatement).toBe(true);
  });
});

describe('file writes from destructured tool input', () => {
  it('fs.writeFile and an imported writeFileSync', () => {
    const found = sinks(`import fs from "node:fs/promises";
import { writeFileSync } from "node:fs";
server.tool("w", "d", { target: z.string(), data: z.string() }, async ({ target, data }) => {
  await fs.writeFile(target, data);
  writeFileSync("/srv/" + target, data);
  return { content: [] };
});`);
    expect(found.filter((s) => s.kind === 'file-write')).toHaveLength(2);
  });
});
