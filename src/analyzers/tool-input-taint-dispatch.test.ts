import { describe, it, expect } from 'vitest';
import { findTaintedSinks } from './tool-input-taint.js';

/** Files joined the way the source resolver joins a server's modules. */
const joined = (files: Record<string, string>): string =>
  Object.entries(files).map(([path, code]) => `// === ${path} ===\n${code}`).join('\n\n');

const sinks = (code: string) => findTaintedSinks(code, 'server.js').map((s) => `${s.sink}:${s.line}`);

describe('findTaintedSinks through methods, callbacks and dispatch maps', () => {
  it('follows tool input into a method of a class instance of the same file', () => {
    const code = [
      'import { spawn } from "child_process";',
      'class TerminalManager {',
      '  executeCommand(command, timeout) { return spawn(command, { shell: true }); }',
      '}',
      'const tm = new TerminalManager();',
      'server.tool("run", { cmd: z.string() }, async ({ cmd }) => tm.executeCommand(cmd, 10));',
    ].join('\n');
    expect(sinks(code)).toEqual(['spawn:3']);
    // the same method called with a constant only
    expect(sinks(code.replace('tm.executeCommand(cmd, 10)', 'tm.executeCommand("git status", cmd)'))).toEqual([]);
  });

  it('follows a method inherited from a class of the same file and a class-field arrow', () => {
    const code = [
      'import { exec } from "child_process";',
      'class Base { run(c) { return exec(c); } }',
      'class Child extends Base { go = (x) => exec(x); }',
      'const c = new Child();',
      'server.tool("a", {}, async (args) => c.run(args.cmd));',
      'server.tool("b", {}, async (args) => c.go(args.cmd));',
    ].join('\n');
    expect(sinks(code)).toEqual(['exec:2', 'exec:3']);
  });

  it('follows an instance another module exports (ES and TypeScript CommonJS output)', () => {
    const esm = joined({
      'dist/index.js': 'import { terminalManager } from "./tm.js";\nserver.tool("run", {}, async ({ cmd }) => terminalManager.executeCommand(cmd));',
      'dist/tm.js': 'import { spawn } from "child_process";\nexport class TerminalManager {\n  async executeCommand(command) {\n    const shell = "/bin/sh";\n    return spawn(shell, ["-c", command]);\n  }\n}\nexport const terminalManager = new TerminalManager();',
    });
    expect(findTaintedSinks(esm, 'x.js')).toEqual([expect.objectContaining({ sink: 'spawn', kind: 'process' })]);
    const cjs = joined({
      'dist/index.js': '"use strict";\nconst tm_1 = require("./tm");\nserver.tool("run", {}, async (args) => tm_1.terminalManager.executeCommand(args.cmd));',
      'dist/tm.js': '"use strict";\nconst child_process_1 = require("child_process");\nclass TerminalManager {\n  executeCommand(command) { return (0, child_process_1.exec)(command); }\n}\nexports.terminalManager = new TerminalManager();',
    });
    expect(findTaintedSinks(cjs, 'x.js')).toEqual([expect.objectContaining({ kind: 'process' })]);
  });

  it('follows tool input into array callbacks and for…of loops', () => {
    expect(sinks('import { execSync } from "child_process";\nserver.tool("run", {}, async ({ cmds }) => {\n  cmds.forEach((c) => execSync(c));\n});')).toEqual(['execSync:3']);
    expect(sinks('import { execSync } from "child_process";\nfunction one(c) { return execSync(c); }\nserver.tool("run", {}, async ({ cmds }) => cmds.map(one));')).toEqual(['execSync:2']);
    expect(sinks('import { execSync } from "child_process";\nserver.tool("run", {}, async ({ cmds }) => {\n  for (const c of cmds) execSync(c);\n});')).toEqual(['execSync:3']);
    // a fixed list iterated, input elsewhere
    expect(sinks('import { execSync } from "child_process";\nserver.tool("run", {}, async ({ cmds }) => {\n  ["git status"].forEach((c) => execSync(c));\n  return cmds;\n});')).toEqual([]);
  });

  it('follows a handlers[name](args) dispatch map', () => {
    const code = [
      'import { exec } from "child_process";',
      'const handlers = {',
      '  run: async (args) => { exec(args.cmd); return {}; },',
      '  async echo(args) { return { content: [{ type: "text", text: args.text }] }; },',
      '};',
      'server.setRequestHandler(CallToolRequestSchema, async (request) => {',
      '  const { name, arguments: a } = request.params;',
      '  return handlers[name](a);',
      '});',
    ].join('\n');
    expect(sinks(code)).toEqual(['exec:3']);
  });

  it('reads a local object literal field by field', () => {
    const tool = (body: string) => `import { exec } from "child_process";\nserver.tool("run", {}, async ({ cmd }) => {\n${body}\n});`;
    expect(sinks(tool('  const opts = {};\n  opts.command = cmd;\n  exec(opts.command);'))).toEqual(['exec:5']);
    expect(sinks(tool('  const opts = { command: cmd };\n  exec(opts.command);'))).toEqual(['exec:4']);
    // another field holds the input
    expect(sinks(tool('  const opts = { command: "git status" };\n  opts.label = cmd;\n  exec(opts.command);'))).toEqual([]);
    // fields unknown: a spread
    expect(sinks(tool('  const opts = { ...{ command: cmd } };\n  exec(opts.command);'))).toEqual(['exec:4']);
  });

  it('leaves a Function constructor that only compiles (syntax check) alone', () => {
    const tool = (body: string) => `server.tool("check", {}, async ({ code }) => {\n${body}\n});`;
    expect(sinks(tool('  try { new Function(code); return "ok"; } catch { return "bad"; }'))).toEqual([]);
    expect(sinks(tool('  const AsyncFn = (async () => {}).constructor;\n  new AsyncFn(code);'))).toEqual([]);
    expect(sinks(tool('  const f = new Function(code);\n  return f();'))).toEqual(['Function:2']);
  });

  it('recognises a registration written with a computed key', () => {
    expect(sinks('import { exec } from "child_process";\nserver["tool"]("run", {}, async ({ cmd }) => exec(cmd));')).toEqual(['exec:2']);
  });
});
