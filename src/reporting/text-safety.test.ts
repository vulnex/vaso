import { describe, it, expect } from 'vitest';
import { escapeControlChars, escapeControlCharsDeep, escapeJsonUnsafe, stripXmlInvalid } from './text-safety.js';
import { TerminalReporter } from './terminal.js';
import { JunitReporter } from './junit.js';
import { MarkdownReporter } from './markdown.js';
import { CsvReporter } from './csv.js';
import { HtmlReporter } from './html.js';
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
    expect(out).toContain('bad evil\\x1b\\[2J'); // `[` escaped: no link syntax
  });

  it('csv cells carry no raw ESC/BEL', () => {
    expect(new CsvReporter().render(result())).not.toMatch(/[\u0007\u001b]/);
  });

  it('neutralises bidi embedding/override/isolate controls, keeps other Unicode', () => {
    expect(escapeControlChars('a‮b⁦c⁩d‪e')).toBe('a\\u202eb\\u2066c\\u2069d\\u202ae');
    expect(escapeControlChars('café 中 ok')).toBe('café 中 ok');
    // invisible characters print alike different strings: zero-width, marks, BOM, tag characters
    expect(escapeControlChars('a\u200bb\u200dc\u200ed\u061ce\u2060f\ufeffg\u{e0041}h')).toBe('a\\u200bb\\u200dc\\u200ed\\u061ce\\u2060f\\ufeffg\\u{e0041}h');
    const r = result();
    r.agents[0].results[0].message = 'file ‮txt.exe';
    expect(new TerminalReporter().render(r)).not.toContain('‮');
  });

  it('JSON keeps invisible characters as escapes', () => {
    expect(escapeJsonUnsafe(JSON.stringify('a\u200bb\u{e0041}c'))).toBe('"a\\u200bb\\udb40\\udc41c"');
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

describe('HTML reports neutralise bidi and control characters (dt17)', () => {
  it('shows U+202E and ESC sequences visibly instead of letting the browser apply them', () => {
    const r = result();
    r.agents[0].results[0].evidence = [{ file: '/skills/invoice\u202Efdp.exe', snippet: HOSTILE }];
    const html = new HtmlReporter().render(r);
    expect(html).not.toContain('\u202E');
    expect(html).not.toContain('\u001b');
    expect(html).toContain('invoice\\u202efdp.exe');
    expect(html).not.toContain('<img onerror');
  });
});

describe('line and paragraph separators, SARIF values, every JSON (dt23 N8)', () => {
  it('escapes U+2028/U+2029 even when newlines are kept', () => {
    expect(escapeControlChars('a\u2028b\u2029c\nd')).toBe('a\\u2028b\\u2029c\nd');
  });

  it('SARIF snippet, message and rule description values carry no live bidi/zero-width/separator characters', async () => {
    const { SarifReporter } = await import('./sarif.js');
    const { checkRegistry } = await import('../core/check-registry.js');
    const r = result();
    r.agents[0].results[0].evidence = [{ file: '/h/x.json', line: 3, snippet: 'key\u202e\u200bvalue\u2028' }];
    r.agents[0].results[0].message = 'msg\u202e\u2028x';
    const id = 'TST-N8-1';
    if (!checkRegistry.getAll().some(c => c.id === id)) {
      checkRegistry.register({ id, name: 'n', category: 'config', severity: 'info', description: 'd\u2028e\u202e', run: async () => ({ id, name: 'n', category: 'config', severity: 'info', passed: true, message: '' }) });
    }
    const log = JSON.parse(new SarifReporter().render(r));
    const res = log.runs[0].results[0];
    const unsafe = /[\u200b\u202e\u2028\u2029]/;
    expect(res.locations[0].physicalLocation.region.snippet.text).toBe('key\\u202e\\u200bvalue\\u2028');
    expect(res.message.text).not.toMatch(unsafe);
    const rule = log.runs[0].tool.driver.rules.find((x: { id: string }) => x.id === id);
    expect(rule.fullDescription.text).toBe('d\\u2028e\\u202e');
  });

  it('every report JSON (detect, multi-host, baselines) writes them as \\u escapes', async () => {
    const { toReportJson } = await import('./serialize.js');
    const json = toReportJson([{ agentName: 'a\u202eb\u200bc\u{e0041}' }]);
    expect(json).not.toMatch(/[\u200b\u202e]|\u{e0041}/u);
    expect(JSON.parse(json)[0].agentName).toBe('a\u202eb\u200bc\u{e0041}');
  });
});
