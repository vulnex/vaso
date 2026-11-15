import { describe, it, expect } from 'vitest';
import { findTaintedSinks } from './tool-input-taint.js';

// Shapes of the safe query builders and the string-building evasions seen in
// MCP server code: placeholder lists, escaping helpers, allow-lists and schema
// enums are not injection; joined/concatenated/formatted/appended SQL is.
const HEAD = 'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\nimport { z } from "zod";\nimport pg from "pg";\nimport util from "node:util";\nconst pool = new pg.Pool();\nconst db = pool;\nconst server = new McpServer({ name: "x", version: "1" });\n';
const tool = (body: string, params = '{ name: z.string() }', args = '{ name }'): string =>
  `server.tool("t", "d", ${params}, async (${args}) => {\n${body}\n  return { content: [{ type: "text", text: "ok" }] };\n});\n`;
const queries = (code: string) => findTaintedSinks(HEAD + code, `sqlb-${Math.random()}.js`).filter((s) => s.kind === 'query');

describe('SQL taint: safe builders are not injection', () => {
  it.each([
    ['IN-list of placeholders', tool('  const rows = db.prepare(`SELECT * FROM users WHERE id IN (${ids.map(() => "?").join(",")})`).all(...ids);', '{ ids: z.array(z.string()) }', '{ ids }')],
    ['numbered placeholders', tool('  const ph = name.split(",").map((_, i) => `$${i + 1}`).join(",");\n  await pool.query(`SELECT * FROM users WHERE id IN (${ph})`, name.split(","));')],
    ['driver escaping', tool('  await pool.query(`SELECT * FROM users WHERE name = ${mysql.escape(name)}`);\n  await pool.query(`SELECT * FROM ${pg.escapeIdentifier(name)}`);\n  await pool.query(`SELECT * FROM t WHERE a = ${client.escapeLiteral(name)}`);')],
    ['allow-list ternary', tool('  const col = ["id", "name"].includes(name) ? name : "id";\n  await pool.query(`SELECT * FROM users ORDER BY ${col}`);')],
    ['allow-list Set', tool('  const SORTS = new Set(["asc", "desc"]);\n  const dir = SORTS.has(name) ? name : "asc";\n  await pool.query(`SELECT * FROM users ORDER BY id ${dir}`);')],
    ['fixed-value lookup with fallback', 'const COLS = { name: "name", age: "age" };\n' + tool('  await pool.query(`SELECT * FROM users ORDER BY ${COLS[name] ?? "name"}`);')],
    ['schema enum', tool('  await pool.query(`SELECT * FROM users ORDER BY ${name}`);', '{ name: z.enum(["id", "created_at"]).optional() }')],
    ['schema number through the args object', tool('  await pool.query(`SELECT * FROM users LIMIT ${a.limit}`);', '{ limit: z.number().int().max(100) }', 'a')],
  ])('%s', (_label, code) => {
    expect(queries(code)).toEqual([]);
  });
});

describe('SQL taint: built SQL text stays injection', () => {
  it.each([
    ['concatenation', tool('  await pool.query("SELECT * FROM users WHERE name = \'" + name + "\'");')],
    ['array join', tool('  const q = ["SELECT * FROM users WHERE name = \'", name, "\'"].join("");\n  await pool.query(q);')],
    ['String#concat', tool('  const q = "SELECT * FROM users WHERE name = \'".concat(name, "\'");\n  await pool.query(q);')],
    ['util.format', tool('  const q = util.format("SELECT * FROM users WHERE name = \'%s\'", name);\n  await pool.query(q);')],
    ['+= appends', tool('  let q = "SELECT * FROM users";\n  q += " WHERE name = \'" + name + "\'";\n  await pool.query(q);')],
    ['helper returning SQL', 'function byName(n) { return `SELECT * FROM users WHERE name = \'${n}\'`; }\n' + tool('  await pool.query(byName(name));')],
    ['bound query method', tool('  const run = pool.query.bind(pool);\n  await run(`SELECT * FROM users WHERE name = \'${name}\'`);')],
    ['an enum next to a free string', tool('  await pool.query(`SELECT * FROM users WHERE name = \'${name}\' ORDER BY ${sort}`);', '{ name: z.string(), sort: z.enum(["id"]) }', '{ name, sort }')],
    ['a placeholder map that uses the element', tool('  await pool.query(`SELECT * FROM users WHERE id IN (${ids.map((x) => `\'${x}\'`).join(",")})`);', '{ ids: z.array(z.string()) }', '{ ids }')],
    ['an includes() on a caller-given list', tool('  const col = name.split(",").includes(name) ? name : "id";\n  await pool.query(`SELECT * FROM users ORDER BY ${col}`);')],
  ])('%s', (_label, code) => {
    expect(queries(code)).toHaveLength(1);
  });
});

describe('SQL taint: allow-lists, placeholder separators and escaping helpers are judged by what they check', () => {
  it.each([
    ['equality, value in the matching branch', tool('  const dir = name === "asc" ? name : "desc";\n  await pool.query(`SELECT * FROM users ORDER BY id ${dir}`);')],
    ['negated includes, value in the alternate', 'const ALLOWED = ["id", "name"];\n' + tool('  const col = !ALLOWED.includes(name) ? "id" : name;\n  await pool.query(`SELECT * FROM users ORDER BY ${col}`);')],
    ['inequality, value in the alternate', tool('  const dir = name !== "asc" ? "DESC" : name;\n  await pool.query(`SELECT * FROM users ORDER BY id ${dir}`);')],
    ['placeholders joined with a fixed separator', tool('  await pool.query(`SELECT * FROM users WHERE id IN (${ids.map(() => "?").join(", ")})`, ids);', '{ ids: z.array(z.string()) }', '{ ids }')],
    ['escape on a mysql2 connection', 'import mysql from "mysql2/promise";\nconst c = await mysql.createConnection({});\n' + tool('  await c.query(`SELECT * FROM users WHERE name = ${c.escape(name)}`);')],
    ['escapeLiteral on a pg client from a pool', 'const client = await pool.connect();\n' + tool('  await client.query(`SELECT * FROM t WHERE a = ${client.escapeLiteral(name)}`);')],
    ['escape imported from sqlstring', 'import { escape } from "sqlstring";\n' + tool('  await pool.query(`SELECT * FROM users WHERE name = ${escape(name)}`);')],
    ['escape on a connection passed in', 'async function find(conn, name) { return conn.query(`SELECT * FROM users WHERE name = ${conn.escape(name)}`); }\n' + tool('  await find(pool, name);')],
  ])('%s', (_label, code) => {
    expect(queries(code)).toEqual([]);
  });

  it.each([
    ['equality, value in the other branch', tool('  const dir = name === "asc" ? "ASC" : name;\n  await pool.query(`SELECT * FROM users ORDER BY id ${dir}`);')],
    ['includes, value in the alternate', 'const ALLOWED = ["id", "name"];\n' + tool('  const col = ALLOWED.includes(name) ? "id" : name;\n  await pool.query(`SELECT * FROM users ORDER BY ${col}`);')],
    ['negated includes, value in the consequent', 'const ALLOWED = ["id", "name"];\n' + tool('  const col = !ALLOWED.includes(name) ? name : "id";\n  await pool.query(`SELECT * FROM users ORDER BY ${col}`);')],
    ['placeholders joined with a caller-given separator', tool('  await pool.query(`SELECT * FROM users WHERE id IN (${ids.map(() => "?").join(name)})`, ids);', '{ ids: z.array(z.string()), name: z.string() }', '{ ids, name }')],
    ['a local function named escape', 'function escape(s) { return s; }\n' + tool('  await pool.query(`SELECT * FROM users WHERE name = \'${escape(name)}\'`);')],
    ['the global escape (a URL encoder)', tool('  await pool.query(`SELECT * FROM users WHERE name = \'${escape(name)}\'`);')],
    ['escape on a local object', 'const fake = { escape: (s) => s };\n' + tool('  await pool.query(`SELECT * FROM users WHERE name = ${fake.escape(name)}`);')],
  ])('%s', (_label, code) => {
    expect(queries(code)).toHaveLength(1);
  });
});
