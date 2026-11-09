import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AgentInstallation, ScanContext } from '../../core/types.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';
import { loadConfig } from '../../core/config-loader.js';
import { grokBotChecks } from './index.js';

const check = (id: string) => grokBotChecks.find(c => c.id === id)!;

/**
 * dt20 g1-F1: Grok Bot reads settings.json with a plain JSON.parse (Rh.load,
 * readFileSync utf-8 — a BOM is not stripped). A file with a comment, JSON5
 * syntax or a BOM is rejected and the app runs on its defaults; VASO's lenient
 * loader must not judge it, and GB-001's fix must not turn it into a strict
 * file the app then accepts (which made every risky setting in it live).
 */
describe('Grok Bot settings.json the app cannot parse (dt20 g1-F1)', () => {
  let dir: string;
  let file: string;
  const settings = {
    version: 1,
    localToolPermission: 'always',
    egressTunnelEnabled: true,
    messagesEnabled: true,
  };
  const strict = JSON.stringify(settings, null, 2);

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'vaso-gb-syntax-'));
    mkdirSync(join(dir, '.grokbot'));
    file = join(dir, '.grokbot', 'settings.json');
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  async function scan(text: string): Promise<ScanContext> {
    writeFileSync(file, text, { mode: 0o600 });
    const fs = new LocalFSProvider();
    const config = await loadConfig(file, fs);
    const installation: AgentInstallation = { agent: 'grok-bot', installDir: join(dir, '.grokbot'), configFiles: [config] };
    return { installation, configs: [config], platform: fs.platform, fs };
  }

  const rejected: Array<[string, string]> = [
    ['a // comment', `// written by hand\n${strict}`],
    ['JSON5 syntax (unquoted keys, trailing comma)', '{ version: 1, localToolPermission: "always", egressTunnelEnabled: true, }'],
    ['a UTF-8 byte-order mark', `﻿${strict}`],
  ];

  for (const [what, text] of rejected) {
    it(`judges a file with ${what} as rejected and offers no fix`, async () => {
      const ctx = await scan(text);
      const r = await check('GB-001').run(ctx);
      expect(r.passed).toBe(true);
      expect(r.fixable).toBeFalsy();
      expect(r.message).toContain('not plain JSON');
      expect(r.message).toContain('runs on its defaults');
      expect((await check('GB-005').run(ctx)).passed).toBe(true);
      const fixed = await check('GB-001').fix!(ctx);
      expect(fixed.applied).toBe(false);
      expect(readFileSync(file, 'utf-8')).toBe(text);
    });
  }

  it('still judges and fixes the same settings as plain JSON', async () => {
    const ctx = await scan(strict);
    const r = await check('GB-001').run(ctx);
    expect(r).toMatchObject({ passed: false, severity: 'critical', fixable: true });
    expect((await check('GB-001').fix!(ctx)).applied).toBe(true);
    expect(JSON.parse(readFileSync(file, 'utf-8')).localToolPermission).toBe('ask');
  });

  it('flags the stripped byte-order mark on the parsed config', async () => {
    expect((await scan(`﻿${strict}`)).configs[0].bom).toBe(true);
    expect((await scan(strict)).configs[0].bom).toBeUndefined();
  });
});
