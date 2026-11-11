import { describe, it, expect } from 'vitest';
import type { ParsedConfig, ScanContext } from '../../core/types.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';
import { parseTomlSafe } from '../../core/toml-safe.js';
import { zc003 } from './zc-003-public-bind-no-tunnel.js';

// dt21 round 3: ZC-003 judges the resolved host — loopback in any spelling
// keeps the configured listener local, so allow_public_bind alone is information.
function run(raw: string) {
  const config: ParsedConfig = { filePath: '/h/.zeroclaw/config.toml', format: 'toml', raw, data: parseTomlSafe(raw) };
  const ctx: ScanContext = { installation: { agent: 'zeroclaw', installDir: '/h/.zeroclaw', configFiles: [config] }, configs: [config], platform: 'linux', fs: new LocalFSProvider() };
  return zc003.run(ctx);
}

describe('ZC-003 with a loopback host', () => {
  for (const host of ['::1', '0177.0.0.1', '127.1', 'localhost']) {
    it(`is information for allow_public_bind = true on ${host}`, async () => {
      const r = await run(`[gateway]\nhost = "${host}"\nallow_public_bind = true\nrequire_pairing = false\n`);
      expect(r).toMatchObject({ passed: false, severity: 'info' });
      expect(r.evidence!.every(e => e.mitigated)).toBe(true);
    });
  }

  it('still warns (critical without pairing) when the host is exposed', async () => {
    const r = await run('[gateway]\nhost = "0.0.0.0"\nallow_public_bind = true\nrequire_pairing = false\n');
    expect(r).toMatchObject({ passed: false, severity: 'critical' });
  });
});
