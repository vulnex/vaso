import { describe, it, expect } from 'vitest';
import { readFileSync, mkdtempSync, writeFileSync, chmodSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { parse } from 'yaml';

interface Step { id?: string; run?: string }
const action = parse(readFileSync(join(__dirname, '..', 'action.yml'), 'utf-8')) as { runs: { steps: Step[] } };
const runStep = action.runs.steps.find(s => s.id === 'run')!;

describe.skipIf(process.platform === 'win32')('action.yml run step', () => {
  it('records the report path and then fails the step when vaso reports findings', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vaso-action-'));
    try {
      const bin = join(dir, 'bin');
      spawnSync('mkdir', [bin]);
      // A stub vaso: writes the report it was asked for, exits 1 (findings)
      writeFileSync(join(bin, 'vaso'), '#!/bin/bash\nwhile [[ $# -gt 0 ]]; do [[ $1 == --output ]] && echo "{}" > "$2"; shift; done\nexit 1\n');
      chmodSync(join(bin, 'vaso'), 0o755);
      const out = join(dir, 'gh-output');
      writeFileSync(out, '');
      const r = spawnSync('bash', ['-c', runStep.run!], {
        cwd: dir,
        env: {
          PATH: `${bin}:/usr/bin:/bin`, GITHUB_OUTPUT: out,
          VASO_AGENT: '', VASO_FORMAT: 'sarif', VASO_OUTPUT: '', VASO_FAIL_ON: 'critical', VASO_DEBUG: 'false', VASO_EXTRA_ARGS: '',
        },
        encoding: 'utf-8',
      });
      expect(r.status).toBe(1);
      expect(readFileSync(out, 'utf-8')).toMatch(/^report-path=.*vaso-results\.sarif$/m);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
