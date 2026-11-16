import { describe, it, expect } from 'vitest';
import { compilePyFullmatch, isCatchAllPattern, judgeAllowPattern } from './nanobot/nb-004-exec-tool-filter.js';
import { compileGoRegex } from './picoclaw/shared.js';
import { judgeCustomAllow } from './picoclaw/pcl-002-exec-guard.js';
import { regexBudget, runSamples, testSamples } from '../analyzers/bounded-regex.js';
import type { AgentInstallation, ParsedConfig, ScanContext } from '../core/types.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { nb004 } from './nanobot/nb-004-exec-tool-filter.js';
import { pcl002 } from './picoclaw/pcl-002-exec-guard.js';
import { pcl007 } from './picoclaw/pcl-007-broad-tool-paths.js';

describe('config regexes that may backtrack are still judged', () => {
  it('nanobot exec patterns: catch-alls the static screen rejects are caught', () => {
    for (const p of ['.*', '(.|\\s)*', '(.+)+', '.*.*.*', '(.|\\n)*', '([\\s\\S])*']) {
      expect(judgeAllowPattern(p), p).toBe('catch-all');
    }
    expect(compilePyFullmatch('(a+)+$')).toBeDefined();
    const start = Date.now();
    expect(isCatchAllPattern('(.*)*x')).toBe(false);
    expect(isCatchAllPattern('(a+)+$')).toBe(false);
    expect(Date.now() - start).toBeLessThan(1000);
  });

  it('picoclaw allow patterns: catch-alls the static screen rejects are caught', () => {
    for (const p of ['(.|\\s)*', '(.+)+', '.*.*.*']) expect(judgeCustomAllow(p), p).toBe('catch-all');
    expect(compileGoRegex('(.*)*x')).toBeDefined();
    expect(compileGoRegex('(?i)^/home/.*')).toBeDefined();
    expect(judgeCustomAllow('^git (status|log)$')).toBeUndefined();
  });

  it('a pattern that runs out of time is not evaluated, never a pass', () => {
    const start = Date.now();
    expect(testSamples(/^(a|aa)+$/, ['a'.repeat(60) + 'b'], { budgetMs: 100 })).toBeUndefined();
    expect(Date.now() - start).toBeLessThan(2000);
    expect(testSamples(/^(a|aa)+$/, ['aaaa', 'b'])).toEqual([true, false]);
    // untilMiss: the first miss ends the run before a long sample can backtrack
    expect(testSamples(/^(a|aa)+$/, ['b', 'a'.repeat(60) + 'b'], { untilMiss: true })).toEqual([false, false]);
  });
});

// matches the short sample commands, backtracks exponentially on the long ones
const HOSTILE = (i: number) => `(?:(?:rm|cat|shutdown|mkfs\\S*|dd) .*|(.|.)*Q${i})`;

function scanCtx(agent: 'nanobot' | 'picoclaw', data: Record<string, unknown>): ScanContext {
  const filePath = agent === 'nanobot' ? '/home/test/.nanobot/config.json' : '/home/test/.picoclaw/config.json';
  const config: ParsedConfig = { raw: JSON.stringify(data), format: 'json', filePath, data };
  const installation: AgentInstallation = { agent, installDir: '/home/test', configFiles: [config] };
  const fs = new LocalFSProvider();
  fs.homedir = () => '/home/test';
  return { installation, configs: [config], platform: 'linux', fs };
}

describe('regex budget and partial results', () => {
  it('a spent budget leaves the remaining unscreened patterns unrun', () => {
    const budget = regexBudget(150);
    const start = Date.now();
    const runs = Array.from({ length: 50 }, (_, i) => runSamples(new RegExp(`^(?:${HOSTILE(i)})$`), ['a'.repeat(40) + 'b'], { budget }));
    expect(Date.now() - start).toBeLessThan(1500);
    expect(runs.every(r => !r.complete)).toBe(true);
    expect(runs.filter(r => r.reason === 'budget').length).toBeGreaterThan(45);
    // screened (linear) patterns still run after the budget is spent
    expect(runSamples(/^rm .*$/, ['rm -rf /'], { budget })).toEqual({ hits: [true], complete: true });
  });

  it('keeps the samples matched before the time ran out, and those of a linear alternative', () => {
    // a linear alternative decides the catch-all although the whole pattern backtracks
    expect(judgeCustomAllow('(?:(.|.)*Z|.*)')).toBe('catch-all');
    expect(judgeAllowPattern('(?:(.|.)*Z|.*)')).toBe('catch-all');
    const run = runSamples(/.*\/\.ssh\/.*|(?:(.|.)*Q)/, ['/home/test/.ssh/id_ed25519', 'a'.repeat(60)], { budgetMs: 100 });
    expect(run.complete).toBe(false);
    expect(run.hits[0]).toBe(true);
  });

  it('400 hostile allow patterns finish in seconds, reported once', async () => {
    const patterns = Array.from({ length: 400 }, (_, i) => HOSTILE(i));
    const start = Date.now();
    const nb = await nb004.run(scanCtx('nanobot', { tools: { exec: { allowPatterns: patterns, sandbox: 'bwrap' } } }));
    const pc = await pcl002.run(scanCtx('picoclaw', { tools: { exec: { enabled: true, custom_allow_patterns: patterns } } }));
    const pw = await pcl007.run(scanCtx('picoclaw', { tools: { allow_write_paths: patterns } }));
    expect(Date.now() - start).toBeLessThan(8000);
    for (const r of [nb, pc, pw]) {
      expect(r.passed).toBe(false);
      expect(r.severity).toBe('warning');
      expect(r.evidence!.length).toBeLessThan(20);
      expect(r.evidence!.some(e => /^\d+ patterns not evaluated: the time for judging slow patterns/.test(e.detail ?? ''))).toBe(true);
    }
  }, 20_000);

  it('PCL-007 keeps a sensitive path matched before a later target timed out', async () => {
    const r = await pcl007.run(scanCtx('picoclaw', { tools: { allow_write_paths: ['.*/\\.ssh/.*|(?:(.|.)*Q)'] } }));
    expect(r.severity).toBe('critical');
    expect(r.evidence![0].detail).toContain('/home/test/.ssh/id_ed25519');
  });

  it('dialect-only catch-all spellings fail the checks; untranslatable ones are not evaluated', async () => {
    for (const p of ['(?P<all>.*)', '\\A.*\\Z', '.*\\Z', '(?>.*)']) {
      const r = await nb004.run(scanCtx('nanobot', { tools: { exec: { allowPatterns: [p], sandbox: 'bwrap' } } }));
      expect(r.severity, p).toBe('critical');
    }
    for (const p of ['(?P<all>.*)', '\\A.*\\z', '(?i:.*)']) {
      const r = await pcl002.run(scanCtx('picoclaw', { tools: { exec: { enabled: true, custom_allow_patterns: [p] } } }));
      expect(r.severity, p).toBe('critical');
      const w = await pcl007.run(scanCtx('picoclaw', { tools: { allow_write_paths: [p] } }));
      expect(w.severity, p).toBe('critical');
    }
    const u = await pcl002.run(scanCtx('picoclaw', { tools: { exec: { enabled: true, custom_allow_patterns: ['\\pL*.*'] } } }));
    expect(u.severity).toBe('warning');
    expect(u.evidence![0].detail).toContain('VASO cannot translate its regex syntax');
    // Go rejects it: PicoClaw allows nothing through it
    const bad = await pcl002.run(scanCtx('picoclaw', { tools: { exec: { enabled: true, custom_allow_patterns: ['(?=.*).*'] } } }));
    expect(bad.passed).toBe(true);
  });
});
