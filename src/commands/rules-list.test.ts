import { describe, it, expect, vi, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { runRulesList } from './rules.js';

const RULE = (id: string) => `rules:\n  - id: ${id}\n    name: Repo rule\n    category: config\n    severity: warning\n    description: d\n    config:\n      path: "a.b"\n      operator: "exists"\n`;

function setup() {
  const root = mkdtempSync(join(tmpdir(), 'vaso-rules-list-'));
  const home = join(root, 'home');
  const project = join(root, 'repo');
  mkdirSync(join(home, '.vaso'), { recursive: true });
  mkdirSync(join(project, '.vaso', 'rules'), { recursive: true });
  writeFileSync(join(project, '.vaso', 'rules', 'r.yaml'), RULE('REPO-1'));
  vi.spyOn(process, 'cwd').mockReturnValue(project);
  vi.stubEnv('HOME', home);
  return { home, project };
}

async function list(format: string): Promise<string> {
  const out: string[] = [];
  vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.join(' ')); });
  vi.spyOn(console, 'error').mockImplementation(() => {});
  await runRulesList({ format });
  return out.join('\n');
}

describe('vaso rules list — project rules', () => {
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });

  it('shows an untrusted project\'s rules as not loaded', async () => {
    setup();
    const text = await list('terminal');
    expect(text).toMatch(/1 project rule\(s\) — untrusted \(not loaded\)/);
    expect(text).toContain('REPO-1');
    expect(text).toContain('--project-rules');
    const json = JSON.parse(await list('json'));
    expect(json).toEqual([expect.objectContaining({ id: 'REPO-1', status: 'untrusted' })]);
  });

  it('escapes bidi and control characters in JSON like scan JSON', async () => {
    const root = mkdtempSync(join(tmpdir(), 'vaso-rules-list-'));
    const home = join(root, 'home');
    const project = join(root, 'proj‮X');
    mkdirSync(join(home, '.vaso'), { recursive: true });
    mkdirSync(join(project, '.vaso', 'rules'), { recursive: true });
    writeFileSync(join(project, '.vaso', 'rules', 'r.yaml'), RULE('REPO-1'));
    vi.spyOn(process, 'cwd').mockReturnValue(project);
    vi.stubEnv('HOME', home);
    const raw = await list('json');
    expect(raw).not.toContain('‮');
    expect(raw).toContain('\\u202e');
    expect(JSON.parse(raw)[0].file).toContain('proj‮X');
  });

  it('names an untrusted project rule file it could not read (too large) instead of "no rules"', async () => {
    const { project } = setup();
    const big = join(project, '.vaso', 'rules', 'r.yaml');
    writeFileSync(big, `${RULE('REPO-1')}#${'x'.repeat(5 * 1024 * 1024)}\n`);
    const errors: string[] = [];
    const out: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.join(' ')); });
    vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => { errors.push(a.join(' ')); });
    await runRulesList({ format: 'terminal' });
    expect(errors.join('\n')).toMatch(/project rule file .*r\.yaml \(untrusted, not loaded\): Cannot read rule file: it is over 4 MiB/);
    expect(out.join('\n')).toMatch(/1 untrusted project rule file\(s\) could not be read/);
  });

  it.skipIf(process.platform === 'win32')('lists them as loaded once the project is in ~/.vaso/trusted-projects', async () => {
    const { home, project } = setup();
    const file = join(home, '.vaso', 'trusted-projects');
    writeFileSync(file, `${project}\n`);
    chmodSync(file, 0o600);
    const json = JSON.parse(await list('json'));
    expect(json).toEqual([expect.objectContaining({ id: 'REPO-1', status: 'loaded' })]);
  });
});
