import { describe, it, expect } from 'vitest';
import { escapeControlChars, escapeControlCharsDeep, stripXmlInvalid } from './text-safety.js';
import { TerminalReporter } from './terminal.js';
import { JunitReporter } from './junit.js';
import { MarkdownReporter } from './markdown.js';
import { CsvReporter } from './csv.js';
import type { ScanResult } from '../core/types.js';

const HOSTILE = 'evil\u001b[2J\u001b]8;;https://x\u0007link\u001b]8;;\u0007\u009b31m';

function result(): ScanResult {
  return {
    timestamp: 't',
    agents: [{
      agent: 'claude-code',
      installation: { agent: 'claude-code', installDir: `/h/${HOSTILE}`, configFiles: [], agentName: 'proj<img onerror=x>\n# INJ' },
      results: [{
        id: 'CC-001', name: 'n', category: 'coding-agent', severity: 'critical', passed: false,
        message: `bad ${HOSTILE} | x`, evidence: [{ file: `/h/${HOSTILE}`, snippet: HOSTILE }],
      }],
      score: 10, grade: 'F',
    }],
    totalScore: 10, totalGrade: 'F', fleetAverage: 10,
    summary: { critical: 1, warning: 0, info: 0, passed: 0, total: 1 },
  };
}

describe('text safety', () => {
  it('escapes C0/C1 controls but keeps tab and newline', () => {
    expect(escapeControlChars('a\u001bb\u0007c\u009bd\te\nf')).toBe('a\\x1bb\\x07c\\x9bd\te\nf');
    expect(escapeControlCharsDeep({ a: ['\u001b'], n: 1 })).toEqual({ a: ['\\x1b'], n: 1 });
  });

  it('drops XML-invalid characters', () => {
    expect(stripXmlInvalid('a\u001bb\u0000c\td\ud800')).toBe('a\\x1bb\\x00c\td\\ud800');
  });

  it('terminal output carries no raw control characters from scanned text', () => {
    const out = new TerminalReporter().render(result());
    // Only chalk's own SGR sequences (ESC [ … m) may remain
    expect(out.replace(/\u001b\[[0-9;]*m/g, '')).not.toMatch(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/);
    expect(out).toContain('\\x1b[2J');
  });

  it('junit output is well-formed XML text', () => {
    const out = new JunitReporter().render(result());
    expect(out).not.toMatch(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/);
  });

  it('markdown keeps the heading on one line without raw HTML', () => {
    const out = new MarkdownReporter().render(result());
    expect(out).not.toContain('\n# INJ');
    expect(out).not.toContain('<img');
    expect(out).toContain('bad evil\\x1b[2J');
  });

  it('csv cells carry no raw ESC/BEL', () => {
    expect(new CsvReporter().render(result())).not.toMatch(/[\u0007\u001b]/);
  });

  it('neutralises bidi embedding/override/isolate controls, keeps other Unicode', () => {
    expect(escapeControlChars('a‮b⁦c⁩d‪e')).toBe('a\\u202eb\\u2066c\\u2069d\\u202ae');
    expect(escapeControlChars('café 中 ‍')).toBe('café 中 ‍');
    const r = result();
    r.agents[0].results[0].message = 'file ‮txt.exe';
    expect(new TerminalReporter().render(r)).not.toContain('‮');
  });

  it('junit text carries no raw CR or C1 control', () => {
    const r = result();
    r.agents[0].results[0].message = 'a\rb\u009bc\u0085d';
    const out = new JunitReporter().render(r);
    expect(out).not.toMatch(/[\r\u0080-\u009f]/);
    expect(out).toContain('a\\x0db\\x9bc\\x85d');
  });

  it('stripColor removes SGR colour escapes only', async () => {
    const { stripColor } = await import('./text-safety.js');
    expect(stripColor('\u001b[31mred\u001b[39m \u001b[1;4mbold\u001b[0m \\x1b[2J')).toBe('red bold \\x1b[2J');
  });
});

describe('escapeControlChars lineBreaks', () => {
  it('keeps newlines by default and escapes them on request', async () => {
    const { escapeControlChars } = await import('./text-safety.js');
    expect(escapeControlChars('a\nb')).toBe('a\nb');
    expect(escapeControlChars('a\nb c\u001b', { lineBreaks: true })).toBe('a\\nb\\u2029c\\x1b');
  });
});
