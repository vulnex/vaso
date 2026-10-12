import { describe, it, expect } from 'vitest';
import { confinesPaths, findTaintedSinks } from './tool-input-taint.js';
import { sourceChunks } from './js-parse.js';

describe('findTaintedSinks', () => {
  it('traces a renamed tool argument into an eval template (appsecco malicious-code-exec)', () => {
    const code = `
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const format = request.params.arguments?.format || "default";
  const data = { quote: "q" };
  return eval(\`(function() {
    const d = \${JSON.stringify(data)};
    return \${format};
  })()\`);
});`;
    const sinks = findTaintedSinks(code, 'qotd.js');
    expect(sinks).toHaveLength(1);
    expect(sinks[0]).toMatchObject({ line: 5, sink: 'eval', origin: 'format ← request' });
  });

  it('ignores tool input interpolated into an error message', () => {
    const code = `
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  throw new Error(\`Unknown tool: \${request.params.name}\`);
});`;
    expect(findTaintedSinks(code, 'err.js')).toEqual([]);
  });

  it('treats destructured parameters of an McpServer tool handler as input', () => {
    const code = `
import { exec } from 'node:child_process';
server.tool('run', { cmd: z.string() }, async ({ cmd }) => {
  const line = \`bash -lc "\${cmd}"\`;
  exec(line);
});`;
    expect(findTaintedSinks(code, 'tool.js')).toEqual([
      expect.objectContaining({ sink: 'exec', origin: 'line ← cmd' }),
    ]);
  });

  it('follows reassignments and member access on child_process', () => {
    const code = `
const cp = require('child_process');
function handle(request) {
  let command = 'ls';
  command = request.params.arguments.command;
  cp.execSync(command);
}`;
    expect(findTaintedSinks(code, 'cp.js')).toEqual([
      expect.objectContaining({ sink: 'cp.execSync', origin: 'command ← request' }),
    ]);
  });

  it('carries tool input into helpers through their call sites', () => {
    const code = `
const { exec } = require('child_process');
class Server {
  setup() {
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => this.run(request.params.arguments));
  }
  async run(args) { return runShell(args.cmd); }
}
function runShell(cmd) { exec(cmd); }`;
    expect(findTaintedSinks(code, 'helpers.js')).toEqual([
      expect.objectContaining({ sink: 'exec', origin: 'cmd ← caller' }),
    ]);
  });

  it('does not treat a CLI entry point parameter named args as tool input (supergateway)', () => {
    const code = `
import { spawn } from 'node:child_process';
export async function stdioToSse(args) {
  const { stdioCmd, port } = args;
  const child = spawn(stdioCmd, { shell: true });
}`;
    expect(findTaintedSinks(code, 'gateway.js')).toEqual([]);
  });

  it('checks spawn argv only through a shell', () => {
    const viaShell = `server.tool('s', {}, async (input) => { spawn('sh', ['-c', input.script]); });`;
    const direct = `server.tool('s', {}, async (input) => { spawn('/usr/bin/grep', [input.pattern, 'log.txt']); });`;
    expect(findTaintedSinks(viaShell, 'a.js')).toHaveLength(1);
    expect(findTaintedSinks(direct, 'b.js')).toEqual([]);
  });

  it('does not treat RegExp.exec as a process sink', () => {
    const code = `function h(input) { const re = /a(b)/; return re.exec(input.text); }`;
    expect(findTaintedSinks(code, 're.js')).toEqual([]);
  });

  it('does not report sinks fed only by constants or unrelated data', () => {
    const code = `
const { execFileSync } = require('child_process');
async function status() {
  const res = await fetch('https://api.example.com/status');
  const body = await res.text();
  execFileSync('/usr/bin/logger', [body]);
  eval('1 + 1');
}`;
    expect(findTaintedSinks(code, 'c.js')).toEqual([]);
  });

  it('returns nothing for unparseable input', () => {
    expect(findTaintedSinks('def x(:\n  pass', 'x.py')).toEqual([]);
  });
});

describe('findTaintedSinks: file paths', () => {
  const server = (body: string) => `
import { promises as fs } from "fs";
import path from "path";
class S {
  setup() {
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      return this.handle(request.params.arguments);
    });
  }
  async handle(args) {
${body}
  }
}`;

  it('classifies fs calls fed by tool input (appsecco outdated-packages)', () => {
    const sinks = findTaintedSinks(server(`
    const items = await fs.readdir(args.path);
    const stats = await fs.stat(path.join(args.path, "x"));
    const text = await fs.readFile(args.path, "utf8");
    await fs.writeFile(args.dest, text);`), 'fs.js');
    expect(sinks.map((s) => [s.sink, s.kind])).toEqual([
      ['fs.readdir', 'file-meta'], ['fs.stat', 'file-meta'], ['fs.readFile', 'file-read'], ['fs.writeFile', 'file-write'],
    ]);
    expect(sinks[0].origin).toContain('args');
  });

  it('recognizes named fs imports and require destructuring, not same-named locals', () => {
    const named = `import { readFile } from "node:fs/promises";
server.tool("read", {}, async ({ file }) => ({ content: [{ type: "text", text: await readFile(file, "utf8") }] }));`;
    expect(findTaintedSinks(named).map((s) => s.kind)).toEqual(['file-read']);
    const required = `const { existsSync } = require("fs");
function check(request) { return existsSync(request.params.arguments.path); }`;
    expect(findTaintedSinks(required).map((s) => s.kind)).toEqual(['file-meta']);
    const local = `function readFile(p) { return cache[p]; }
function get(request) { return readFile(request.params.name); }`;
    expect(findTaintedSinks(local)).toEqual([]);
  });

  it('ignores paths the operator configured', () => {
    expect(findTaintedSinks(`import fs from "fs";
const root = process.argv[2];
server.tool("list", {}, async () => ({ content: [{ type: "text", text: fs.readdirSync(root).join("\\n") }] }));`)).toEqual([]);
  });
});

describe('confinesPaths', () => {
  it('needs a resolved path compared against a base', () => {
    expect(confinesPaths('const full = path.resolve(root, p); if (!full.startsWith(root)) throw new Error("outside");')).toBe(true);
    expect(confinesPaths('const rel = path.relative(base, fs.realpathSync(p)); if (rel.startsWith("..")) deny();')).toBe(true);
    // A literal-prefix check is about URLs or flags, not containment.
    expect(confinesPaths('const u = new URL(path.resolve(x)); if (u.href.startsWith("https:")) ok();')).toBe(false);
    expect(confinesPaths('fs.readFile(args.path)')).toBe(false);
  });
});

describe('sourceChunks', () => {
  it('neutralizes a bin file\'s hashbang after its --resolve-packages header', () => {
    const joined = ['// === dist/index.js ===', '#!/usr/bin/env node', 'eval(x);', '// === dist/lib.js ===', 'run();'].join('\n');
    const chunks = sourceChunks(joined);
    expect(chunks.map((c) => c.startLine)).toEqual([1, 4]);
    expect(chunks[0].code.split('\n')[1]).toBe('///usr/bin/env node');
    // A hashbang on line 1 of a single file is legal and left alone.
    expect(sourceChunks('#!/usr/bin/env node\nrun();')[0].code.startsWith('#!')).toBe(true);
  });

  it('lets the taint analyzer read a resolved package whose entry has a hashbang', () => {
    const joined = ['// === dist/index.js ===', '#!/usr/bin/env node', 'server.tool("e", {}, async ({ code }) => eval(code));'].join('\n');
    expect(findTaintedSinks(joined).map((s) => [s.sink, s.line])).toEqual([['eval', 3]]);
  });
});
