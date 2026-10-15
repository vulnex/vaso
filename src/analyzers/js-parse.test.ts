import { describe, it, expect } from 'vitest';
import { overNestedLines, parseLenient, ANALYSIS_NESTING_LIMIT } from './js-parse.js';
import { analyzeCode } from './ast-analyzer.js';
import { analyzeObfuscation } from './obfuscation.js';

const pad = (n: number) => `var _pad=${'['.repeat(n)}${']'.repeat(n)};`;

describe('overNestedLines', () => {
  it('flags only lines past the limit', () => {
    expect(overNestedLines(`a(b(c));\n${pad(ANALYSIS_NESTING_LIMIT + 1)}\nx();`)).toEqual([2]);
    expect(overNestedLines(pad(ANALYSIS_NESTING_LIMIT))).toEqual([]);
  });

  it('ignores brackets in strings, templates and comments', () => {
    const many = '('.repeat(500);
    expect(overNestedLines(`const s = "${many}";\nconst t = \`${many}\`;\n// ${many}\n/* ${many} */`)).toEqual([]);
  });
});

describe('parseLenient', () => {
  it('survives nesting that overflows the parser and keeps the rest of the file', () => {
    const code = `const { exec } = require('child_process');\n${pad(500)}\nexec(process.argv[2]);\n`;
    expect(parseLenient(code)).toBeDefined();
    const flows = analyzeCode(code, 'evade.js');
    expect(flows.some(f => f.line === 3)).toBe(true);
  });
});

describe('analyzeObfuscation fromCharCode pattern', () => {
  it('stays linear on a long line of single-argument calls', () => {
    const line = 'String.fromCharCode(1)+'.repeat(40_000);
    const start = Date.now();
    analyzeObfuscation(line);
    expect(Date.now() - start).toBeLessThan(2000);
  });

  it('still matches multi-argument calls', () => {
    expect(analyzeObfuscation('x = String.fromCharCode(104, 105, 33);').hits.map(h => h.label))
      .toContain('String.fromCharCode with multiple args');
  });
});

describe('JS direct process starts (SKL-003 tier)', () => {
  const flow = (code: string) => analyzeCode(code, `direct-${code.length}-${code.charCodeAt(30)}.js`).find(f => f.type === 'eval-exec');
  it('marks a literal non-shell program without shell: true as direct', () => {
    expect(flow("const { execFileSync } = require('child_process');\nexecFileSync('git', ['log', process.argv[2]]);")?.noShell).toBe(true);
    expect(flow("const cp = require('child_process');\ncp.spawn('ffmpeg', args, { cwd: dir });")?.noShell).toBe(true);
  });
  it('keeps shells, interpreters, shell: true and exec() as code execution', () => {
    expect(flow("const { spawn } = require('child_process');\nspawn('bash', ['-c', cmd]);")?.noShell).toBeUndefined();
    expect(flow("const { execFileSync } = require('child_process');\nexecFileSync('node', ['-e', code]);")?.noShell).toBeUndefined();
    expect(flow("const { spawn } = require('child_process');\nspawn('git', args, { shell: true });")?.noShell).toBeUndefined();
    expect(flow("const { exec } = require('child_process');\nexec(cmd);")?.noShell).toBeUndefined();
    expect(flow("const { spawn } = require('child_process');\nspawn(prog, args);")?.noShell).toBeUndefined();
  });
});
