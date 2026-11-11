import { describe, it, expect, vi } from 'vitest';
import type { ParsedConfig, ScanContext } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { gb004 } from './gb-004-standing-grants.js';
import { gb016 } from './gb-016-helper-integrity.js';

// dt21 g1-F1: a grant the daemon would not consult right now is not live.
// The daemon keys grants by [accountScope, scope, action, …] and checks them
// under the asking account's permission and ceiling; with Messages sending
// off the send tool is not offered at all.

const ROOT = '/home/test/.grokbot';
const GRANTS = `${ROOT}/local-tool-standing-grants.v1.json`;
const ACTIVE = '1'.repeat(64);
const PARKED = '2'.repeat(64);

function run(settings: Record<string, unknown>, grants: Record<string, unknown>[]) {
  const data = { version: 1, activeAccountScope: ACTIVE, ...settings };
  const config: ParsedConfig = { raw: JSON.stringify(data), format: 'json', filePath: `${ROOT}/settings.json`, data };
  const files: Record<string, string> = { [GRANTS]: JSON.stringify({ version: 1, grants }) };
  const fs = {
    platform: 'darwin',
    homedir: () => '/home/test',
    getEnv: () => undefined,
    access: vi.fn(async (p: string) => p in files),
    readFile: vi.fn(async (p: string) => files[p]),
  } as unknown as FSProvider;
  const ctx: ScanContext = { installation: { agent: 'grok-bot', installDir: ROOT, configFiles: [config] }, configs: [config], platform: 'darwin', fs };
  return gb004.run(ctx);
}

const grant = (action: string, accountScope: string) => ({ scope: 'action', action, accountScope, grantedAtMs: 1 });

describe('GB-004 grants that are not live (dt21 g1-F1)', () => {
  it('downgrades a send-imessage grant while sending Messages is off', async () => {
    const r = await run({ messagesEnabled: true, messagesSendEnabled: false }, [grant('send-imessage', ACTIVE)]);
    expect(r).toMatchObject({ passed: false, severity: 'info' });
    expect(r.evidence![0]).toMatchObject({ mitigated: true });
    expect(r.evidence![0].detail).toContain('messagesSendEnabled: false');
  });

  it('downgrades a grant for an account not signed in here', async () => {
    const r = await run({ localToolPermission: 'ask' }, [grant('use-app', 'Z'.repeat(64))]);
    expect(r).toMatchObject({ passed: false, severity: 'info' });
    expect(r.evidence![0]).toMatchObject({ mitigated: true });
    expect(r.evidence![0].detail).toContain('not signed in here');
  });

  it('judges a parked account\'s grant by that account\'s settings', async () => {
    const off = await run({ accountScopes: { [PARKED]: { localToolPermission: 'never' } } }, [grant('use-app', PARKED)]);
    expect(off.severity).toBe('info');
    const on = await run({ accountScopes: { [PARKED]: { localToolPermission: 'ask' } } }, [grant('use-app', PARKED)]);
    expect(on).toMatchObject({ passed: false, severity: 'warning' });
    expect(on.evidence![0].detail).toContain('takes effect when you switch');
  });

  it('keeps an active account\'s grant live (warning)', async () => {
    const r = await run({ messagesEnabled: true }, [grant('send-imessage', ACTIVE), grant('use-app', ` ${ACTIVE} `)]);
    expect(r).toMatchObject({ passed: false, severity: 'warning' });
    expect(r.evidence!.every(e => !e.mitigated)).toBe(true);
  });
});

describe('GB-016 with an unreadable computer-use dir', () => {
  it('says the helper copy was not verified instead of calling it intact', async () => {
    const fs = {
      platform: 'darwin',
      kind: 'snapshot',
      homedir: () => '/home/test',
      getEnv: () => undefined,
      access: vi.fn(async () => false),
      stat: vi.fn(async (p: string) => {
        if (p.startsWith(`${ROOT}/computer-use/`)) throw Object.assign(new Error('EACCES'), { code: 'EACCES' });
        throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
      }),
    } as unknown as FSProvider;
    const r = await gb016.run({ installation: { agent: 'grok-bot', installDir: ROOT, configFiles: [] }, configs: [], platform: 'darwin', fs });
    expect(r.passed).toBe(true);
    expect(r.message).toContain('was not verified (directory not readable)');
  });
});
