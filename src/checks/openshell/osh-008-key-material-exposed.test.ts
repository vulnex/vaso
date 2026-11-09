import { describe, it, expect, vi } from 'vitest';
import type { ScanContext, ParsedConfig } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { osh008 } from './osh-008-key-material-exposed.js';

const HOME = '/home/test';
const CFG = `${HOME}/.config/openshell`;

function makeFs(modes: Record<string, number>, kind?: 'snapshot'): FSProvider {
  return {
    platform: 'linux',
    kind,
    homedir: () => HOME,
    getEnv: () => undefined,
    access: vi.fn(async (p: string) => p in modes),
    readFile: vi.fn(async (p: string) => { throw new Error(`ENOENT ${p}`); }),
    stat: vi.fn(async (p: string) => {
      if (!(p in modes)) throw new Error(`ENOENT ${p}`);
      return { mode: modes[p], isFile: () => true, isDirectory: () => false };
    }),
    readdirEntries: vi.fn(async () => []),
  } as unknown as FSProvider;
}

function ctx(fs: FSProvider): ScanContext {
  const env: ParsedConfig = { raw: '', format: 'env', filePath: `${CFG}/gateway.env`, data: { OPENSHELL_TLS_KEY: '/srv/certs/gw.key' } };
  return {
    installation: { agent: 'openshell', installDir: CFG, configFiles: [env] },
    configs: [env], platform: 'linux', fs,
  };
}

describe('OSH-008 (dt19)', () => {
  it('says a key path named in gateway.env that a snapshot lacks is unverified, not owner-only', async () => {
    const r = await osh008.run(ctx(makeFs({}, 'snapshot')));
    expect(r.passed).toBe(true);
    expect(r.message).toMatch(/unverified.*\/srv\/certs\/gw\.key/);
  });

  it('keeps the plain verdict locally, where a missing key file is simply absent', async () => {
    const r = await osh008.run(ctx(makeFs({})));
    expect(r.message).toBe('OpenShell key material is owner-only');
  });

  it('judges the key normally when the snapshot has it', async () => {
    const r = await osh008.run(ctx(makeFs({ '/srv/certs/gw.key': 0o100644 }, 'snapshot')));
    expect(r.passed).toBe(false);
    expect(r.message).not.toMatch(/unverified/);
  });
});
