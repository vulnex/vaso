import { describe, it, expect, vi, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { registerAllChecks } from '../checks/index.js';
import { checkRegistry } from '../core/check-registry.js';
import { runRulesValidate } from './rules.js';

const rule = (id: string) => `  - id: ${id}\n    name: n\n    category: config\n    severity: warning\n    description: d\n    file_exists:\n      path: ".env"\n      pass_when: "not-exists"\n`;

describe('vaso rules validate (dt17)', () => {
  afterEach(() => { process.exitCode = 0; vi.restoreAllMocks(); });

  it('reports a built-in check ID and a duplicate ID — the rules scan would skip', async () => {
    if (checkRegistry.getAll().length === 0) registerAllChecks();
    const file = join(mkdtempSync(join(tmpdir(), 'vaso-rules-')), 'r.yml');
    writeFileSync(file, `rules:\n${rule('CC-001')}${rule('ORG-100')}${rule('ORG-100')}`);
    const out: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.join(' ')); });
    await runRulesValidate(file, { format: 'json' });
    const report = JSON.parse(out.join('\n'));
    expect(report.valid).toBe(false);
    expect(report.rules).toBe(1);
    expect(report.errors.map((e: { message: string }) => e.message).join('\n')).toMatch(/built-in check ID[\s\S]*more than once/);
  });
});
