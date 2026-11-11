import { describe, it, expect } from 'vitest';
import type { ScanResult } from '../core/types.js';
import { escapeJsonUnsafe } from './text-safety.js';
import { JsonReporter } from './json.js';
import { SarifReporter } from './sarif.js';

// dt21 g8-F23: bidi overrides and C1 controls from scanned text are escaped
// in JSON and SARIF reports (written as \uXXXX escapes, never dropped).

const HOSTILE = 'cfg\u202egnp.exe \u009B31m \u2066x\u2069 \u2028 end';
const LIVE = /[\u0080-\u009f\u202a-\u202e\u2066-\u2069\u2028]/;

function result(): ScanResult {
  return {
    timestamp: '2026-11-11T00:00:00.000Z',
    agents: [{
      agent: 'openclaw',
      installation: { agent: 'openclaw', installDir: '/h/.openclaw', configFiles: [] },
      results: [{ id: 'CFG-001', name: 'Gateway Binding', category: 'config', severity: 'critical', passed: false, message: HOSTILE, evidence: [{ file: '/h/.openclaw/openclaw.json', detail: HOSTILE }] }],
      score: 88, grade: 'B',
    }],
    totalScore: 88, totalGrade: 'B', fleetAverage: 88,
    summary: { critical: 1, warning: 0, info: 0, passed: 0, total: 1 },
  };
}

describe('escapeJsonUnsafe', () => {
  it('escapes the characters and keeps the parsed value', () => {
    const json = escapeJsonUnsafe(JSON.stringify({ s: HOSTILE }));
    expect(json).not.toMatch(LIVE);
    expect(json).toContain('\\u202e');
    expect(json).toContain('\\u009b');
    expect(JSON.parse(json).s).toBe(HOSTILE);
  });
});

describe('JSON and SARIF reports', () => {
  for (const reporter of [new JsonReporter(), new SarifReporter()]) {
    it(`${reporter.format}: no live bidi/C1 character, text preserved`, () => {
      const out = reporter.render(result());
      expect(out).not.toMatch(LIVE);
      expect(JSON.stringify(JSON.parse(out))).toContain('gnp.exe');
      expect(out).toContain('\\u202e');
    });
  }
});
