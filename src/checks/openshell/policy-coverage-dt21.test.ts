import { describe, it, expect, vi } from 'vitest';
import type { ScanContext, ParsedConfig } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { osh008 } from './osh-008-key-material-exposed.js';
import { openshellChecks } from './index.js';

// dt21 g5-F2 / g5-F4: unread sandboxes are named; redirect paths are compared normalised.

const HOME = '/home/test';
const CFG = `${HOME}/.config/openshell`;
const POLICY_CHECKS = ['OSH-011', 'OSH-012', 'OSH-013', 'OSH-014'];
const AFFIRMATIVE = /scoped to specific programs|inspected and enforced|target specific hosts|keep system paths read-only/;

type Exec = (args: string[]) => { exitCode: number; stdout: string; stderr?: string };

function makeFs(opts: { modes?: Record<string, number>; exec?: Exec; kind?: 'snapshot' } = {}): FSProvider {
  const modes = opts.modes ?? {};
  return {
    platform: 'linux',
    kind: opts.kind,
    homedir: () => HOME,
    getEnv: () => undefined,
    access: vi.fn(async (p: string) => p in modes),
    readFile: vi.fn(async (p: string) => { throw Object.assign(new Error(`ENOENT ${p}`), { code: 'ENOENT' }); }),
    stat: vi.fn(async (p: string) => {
      if (!(p in modes)) throw Object.assign(new Error(`ENOENT ${p}`), { code: 'ENOENT' });
      return { mode: modes[p], isFile: () => true, isDirectory: () => false };
    }),
    readdirEntries: vi.fn(async () => []),
    exec: vi.fn(async (_cmd: string, args: string[]) => ({ stderr: '', ...(opts.exec?.(args) ?? { exitCode: 1, stdout: '' }) })),
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
const GOOD = JSON.stringify({ policy: { filesystem_policy: { read_write: ['/sandbox'] } } });
const BAD = JSON.stringify({ policy: { filesystem_policy: { read_write: ['/etc'] } } });

/** A gateway with the five sandboxes of the g5 os-cov fixture. */
function gateway(extra: Record<string, ReturnType<Exec>> = {}): Exec {
  const list = { sandboxes: [
    { name: 'good', workspace: 'default' },
    { name: 'broken', workspace: 'default' },
    { name: 'garbage', workspace: 'default' },
    { name: 'nopolicyfield', workspace: 'default' },
    { name: 'bad name', workspace: 'default' },
    { name: 'empty', workspace: 'default' },
  ] };
  const answers: Record<string, ReturnType<Exec>> = {
    good: { exitCode: 0, stdout: GOOD },
    broken: { exitCode: 1, stdout: '', stderr: 'transport error: connection refused' },
    garbage: { exitCode: 0, stdout: 'not json at all' },
    nopolicyfield: { exitCode: 0, stdout: '{"sandbox":"x"}' },
    empty: { exitCode: 1, stdout: '', stderr: 'Error: no active policy configured for sandbox empty' },
    ...extra,
  };
  return (args) => {
    if (args[1] === 'list') return { exitCode: 0, stdout: JSON.stringify(list) };
    if (args.includes('--global')) return { exitCode: 1, stdout: '' };
    return answers[args[2]] ?? { exitCode: 1, stdout: '' };
  };
}

describe('OSH-011–014 name the sandboxes whose policy could not be read (dt21 g5-F2)', () => {
  it('lists a failed query, unparsable output, a missing policy field and an unusable name — not "no active policy"', async () => {
    const c = ctx(makeFs({ exec: gateway() }), {}, '/usr/bin/openshell');
    for (const id of POLICY_CHECKS) {
      const r = await check(id).run(c);
      expect(r.passed).toBe(true);
      expect(r.message).toContain('not checked:');
      expect(r.message).toContain('sandbox default/broken (`policy get` failed, exit 1)');
      expect(r.message).toContain('sandbox default/garbage (`policy get` output was not understood)');
      expect(r.message).toContain('sandbox default/nopolicyfield (`policy get` output was not understood)');
      expect(r.message).toContain('"bad name" (name not queried)');
      // a sandbox without a policy is not a failure
      expect(r.message).not.toContain('default/empty');
    }
  });

  it('adds the note to a failing verdict too', async () => {
    const c = ctx(makeFs({ exec: gateway({ good: { exitCode: 0, stdout: BAD } }) }), {}, '/usr/bin/openshell');
    const r = await check('OSH-014').run(c);
    expect(r.passed).toBe(false);
    expect(r.message).toMatch(/writable system paths \(not checked: .*default\/broken/);
  });

  it('keeps the affirmative verdict when every sandbox was read or has no policy', async () => {
    const exec = gateway({
      broken: { exitCode: 0, stdout: GOOD }, garbage: { exitCode: 0, stdout: GOOD }, nopolicyfield: { exitCode: 0, stdout: GOOD },
    });
    const list = (args: string[]) => args[1] === 'list'
      ? { exitCode: 0, stdout: JSON.stringify({ sandboxes: ['good', 'broken', 'garbage', 'nopolicyfield', 'empty'].map(name => ({ name })) }) }
      : exec(args);
    const r = await check('OSH-014').run(ctx(makeFs({ exec: list }), {}, '/usr/bin/openshell'));
    expect(r.message).toMatch(AFFIRMATIVE);
    expect(r.message).not.toContain('not checked');
  });

  it('names at most five unread sources and counts the rest', async () => {
    const many = { sandboxes: Array.from({ length: 8 }, (_, i) => ({ name: `s${i}` })) };
    const exec: Exec = (args) => args[1] === 'list' ? { exitCode: 0, stdout: JSON.stringify(many) } : { exitCode: 3, stdout: '', stderr: 'unauthenticated' };
    const r = await check('OSH-011').run(ctx(makeFs({ exec }), {}, '/usr/bin/openshell'));
    expect(r.message).toContain('and 3 more');
  });
});

describe('OSH-008 compares redirect paths normalised (dt21 g5-F4)', () => {
  const STATE = `${HOME}/.local/state/openshell`;

  it('reports a database spelled `gateway/./openshell.db` once', async () => {
    const r = await osh008.run(ctx(makeFs({ modes: { [`${STATE}/gateway/openshell.db`]: 0o100644 } }), {
      OPENSHELL_DB_URL: `sqlite://${STATE}/gateway/./openshell.db`,
      OPENSHELL_LOCAL_TLS_DIR: '~/.local/state/openshell/tls/',
    }));
    expect(r.evidence!.filter(e => e.file.endsWith('openshell.db'))).toHaveLength(1);
    expect(r.message).not.toContain('tls//');
  });

  it('keeps the plain verdict on a snapshot for NemoClaw\'s gateway layout (dirs the probe collects)', async () => {
    const nemo = `${HOME}/.local/state/nemoclaw/openshell-docker-gateway`;
    const r = await osh008.run(ctx(makeFs({ kind: 'snapshot', modes: { [`${nemo}/tls/ca.key`]: 0o100600, [`${nemo}/openshell.db`]: 0o100600 } }), {
      OPENSHELL_LOCAL_TLS_DIR: `${nemo}/tls`,
      OPENSHELL_DB_URL: `sqlite:${nemo}/openshell.db`,
    }));
    expect(r.passed).toBe(true);
    expect(r.message).toBe('OpenShell key material is owner-only');
  });

  it('still finds a readable key in NemoClaw\'s gateway dir', async () => {
    const nemo = `${HOME}/.local/state/nemoclaw/openshell-docker-gateway`;
    const r = await osh008.run(ctx(makeFs({ modes: { [`${nemo}/tls/ca.key`]: 0o100644 } })));
    expect(r.passed).toBe(false);
    expect(r.evidence!.map(e => e.file)).toContain(`${nemo}/tls/ca.key`);
  });
});
