import { describe, it, expect, vi } from 'vitest';
import type { ScanContext, ParsedConfig } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { captureConfigLoadErrors } from '../../core/config-loader.js';
import { osh008 } from './osh-008-key-material-exposed.js';
import { openshellChecks } from './index.js';

// dt20 g5-F3/F4/F9: OpenShell checks must not pass silently on what they never saw.

const HOME = '/home/test';
const CFG = `${HOME}/.config/openshell`;
const POLICY_CHECKS = ['OSH-011', 'OSH-012', 'OSH-013', 'OSH-014'];
const AFFIRMATIVE = /scoped to specific programs|inspected and enforced|target specific hosts|keep system paths read-only/;

interface Opts {
  modes?: Record<string, number>;
  files?: Record<string, string>;
  /** Paths whose read fails with this code */
  denied?: Record<string, string>;
  env?: Record<string, string>;
  exec?: (args: string[]) => { exitCode: number; stdout: string };
  kind?: 'snapshot';
}

function makeFs({ modes = {}, files = {}, denied = {}, env = {}, exec, kind }: Opts = {}): FSProvider {
  const fail = (p: string) => Object.assign(new Error(`${denied[p]} ${p}`), { code: denied[p] });
  return {
    platform: 'linux',
    kind,
    homedir: () => HOME,
    getEnv: (k: string) => env[k],
    access: vi.fn(async (p: string) => p in modes || p in files || denied[p] === 'EISDIR'),
    readFile: vi.fn(async (p: string) => {
      if (p in denied) throw fail(p);
      if (!(p in files)) throw Object.assign(new Error(`ENOENT ${p}`), { code: 'ENOENT' });
      return files[p];
    }),
    stat: vi.fn(async (p: string) => {
      if (p in denied && denied[p] !== 'EISDIR') throw fail(p);
      if (p in files || p in denied) return { mode: 0o100644, isFile: () => !(p in denied), isDirectory: () => p in denied };
      if (!(p in modes)) throw Object.assign(new Error(`ENOENT ${p}`), { code: 'ENOENT' });
      return { mode: modes[p], isFile: () => true, isDirectory: () => false };
    }),
    readdirEntries: vi.fn(async () => []),
    exec: vi.fn(async (_cmd: string, args: string[]) => ({ stderr: '', ...(exec?.(args) ?? { exitCode: 1, stdout: '' }) })),
  } as unknown as FSProvider;
}

function ctx(fs: FSProvider, envData: Record<string, string> = {}, cli?: string): ScanContext {
  const env: ParsedConfig = { raw: '', format: 'env', filePath: `${CFG}/gateway.env`, data: envData };
  return {
    installation: { agent: 'openshell', installDir: CFG, configFiles: [env], cliBinary: cli },
    configs: [env], platform: 'linux', fs,
  };
}

const check = (id: string) => openshellChecks.find(c => c.id === id)!;

describe('OSH-008 with gateway.env redirects (g5-F3)', () => {
  const redirect = { OPENSHELL_LOCAL_TLS_DIR: '~/srv/tls', OPENSHELL_DB_URL: 'sqlite:~/srv/db/openshell.db' };

  it('judges the redirected TLS directory and database locally', async () => {
    const r = await osh008.run(ctx(makeFs({
      modes: { [`${HOME}/srv/tls/ca.key`]: 0o100644, [`${HOME}/srv/db/openshell.db`]: 0o100644 },
    }), redirect));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('critical');
    expect(r.evidence!.map(e => e.file)).toEqual(expect.arrayContaining([`${HOME}/srv/tls/ca.key`, `${HOME}/srv/db/openshell.db`]));
    expect(r.message).not.toMatch(/unverified/);
  });

  it('names both redirects as unverified on a snapshot that lacks them, without claiming owner-only', async () => {
    const r = await osh008.run(ctx(makeFs({ kind: 'snapshot' }), redirect));
    expect(r.passed).toBe(true);
    expect(r.message).not.toMatch(/owner-only/);
    expect(r.message).toContain(`${HOME}/srv/tls/ (OPENSHELL_LOCAL_TLS_DIR)`);
    expect(r.message).toContain(`${HOME}/srv/db/openshell.db (OPENSHELL_DB_URL)`);
    // One line per redirect, not per file
    expect(r.message.match(/OPENSHELL_LOCAL_TLS_DIR/g)).toHaveLength(1);
  });

  it('keeps the plain verdict when a redirect points at a location the probe collects', async () => {
    const r = await osh008.run(ctx(makeFs({ kind: 'snapshot' }), { OPENSHELL_LOCAL_TLS_DIR: `${HOME}/.local/state/openshell/tls` }));
    expect(r.message).toBe('OpenShell key material is owner-only');
  });
});

describe('OSH-011–014 when no policy could be read (g5-F4, g5-F9)', () => {
  const POLICY = '/p/policy.yaml';

  async function runAll(fs: FSProvider, cli?: string) {
    const c = ctx(fs, {}, cli);
    return captureConfigLoadErrors(() => Promise.all(POLICY_CHECKS.map(id => check(id).run(c))));
  }

  for (const [label, opts] of [
    ['unreadable', { denied: { [POLICY]: 'EACCES' } }],
    ['a directory', { denied: { [POLICY]: 'EISDIR' } }],
    ['invalid YAML', { files: { [POLICY]: 'read_write: [/etc\n  bad: : :' } }],
    ['not a mapping', { files: { [POLICY]: '- /etc\n' } }],
  ] as const) {
    it(`raises CONFIG-LOAD and no affirmative pass for a $OPENSHELL_SANDBOX_POLICY that is ${label}`, async () => {
      const { result, loadErrors } = await runAll(makeFs({ env: { OPENSHELL_SANDBOX_POLICY: POLICY }, ...opts }));
      expect(loadErrors.map(e => e.filePath)).toEqual([POLICY]);
      for (const r of result) {
        expect(r.passed).toBe(true);
        expect(r.message).not.toMatch(AFFIRMATIVE);
        expect(r.message).toMatch(/not checked: .*\/p\/policy\.yaml could not be read/);
      }
    });
  }

  it('says live policies were not queried when no openshell CLI was found', async () => {
    const { result } = await runAll(makeFs({}));
    for (const r of result) {
      expect(r.message).not.toBe('No sandbox policies found — nothing to check');
      expect(r.message).toMatch(/no `openshell` CLI found/);
    }
  });

  it('says a failed `sandbox list` left the live policies unchecked', async () => {
    const { result } = await runAll(makeFs({ exec: () => ({ exitCode: 2, stdout: '' }) }), '/usr/bin/openshell');
    for (const r of result) {
      expect(r.message).not.toMatch(AFFIRMATIVE);
      expect(r.message).toMatch(/`openshell sandbox list` failed \(exit 2\)/);
    }
  });

  it('notes a partial read next to the verdict and says so when there are no policies at all', async () => {
    const policy = 'filesystem_policy:\n  read_write: [/sandbox]\n';
    const partial = await runAll(makeFs({
      env: { OPENSHELL_SANDBOX_POLICY: POLICY }, files: { [POLICY]: policy },
      exec: () => ({ exitCode: 2, stdout: '' }),
    }), '/usr/bin/openshell');
    expect(partial.result[3].message).toMatch(/^Sandbox filesystem policies keep system paths read-only \(1 policy read; not checked: /);

    const none = await runAll(makeFs({
      exec: (args) => args[1] === 'list' ? { exitCode: 0, stdout: '{"sandboxes":[]}' } : { exitCode: 1, stdout: '' },
    }), '/usr/bin/openshell');
    for (const r of none.result) expect(r.message).toBe('No sandbox policies found — nothing to check');
    expect(none.loadErrors).toEqual([]);
  });

  it('still judges a readable policy file', async () => {
    const { result } = await runAll(makeFs({ env: { OPENSHELL_SANDBOX_POLICY: POLICY }, files: { [POLICY]: 'filesystem_policy:\n  read_write: [/etc]\n' } }));
    expect(result[3].passed).toBe(false);
  });
});
