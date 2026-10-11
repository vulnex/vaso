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
function handle(args) {
  let command = 'ls';
  command = args.command;
  cp.execSync(command);
}`;
    expect(findTaintedSinks(code, 'cp.js')).toEqual([
      expect.objectContaining({ sink: 'cp.execSync', origin: 'command ← args' }),
    ]);
  });

  it('checks spawn argv only through a shell', () => {
    const viaShell = `function h(input) { spawn('sh', ['-c', input.script]); }`;
    const direct = `function h(input) { spawn('/usr/bin/grep', [input.pattern, 'log.txt']); }`;
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
