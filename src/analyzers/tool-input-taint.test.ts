import { describe, it, expect } from 'vitest';
import { findTaintedSinks } from './tool-input-taint.js';

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
