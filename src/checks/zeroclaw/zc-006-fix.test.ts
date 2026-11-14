import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { ParsedConfig, ScanContext } from '../../core/types.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';
import { parseTomlSafe } from '../../core/toml-safe.js';
import { zc006 } from './zc-006-workspace-unrestricted.js';

let home: string;
beforeEach(() => { home = mkdtempSync(join(tmpdir(), 'zc006-')); });
afterEach(() => { rmSync(home, { recursive: true, force: true }); });

function ctxFor(raw: string): { ctx: ScanContext; file: string } {
  const dir = join(home, '.zeroclaw');
  mkdirSync(dir, { recursive: true });
  const file = join(dir, 'config.toml');
  writeFileSync(file, raw);
  const config: ParsedConfig = { filePath: file, format: 'toml', raw, data: parseTomlSafe(raw) };
  const ctx: ScanContext = { installation: { agent: 'zeroclaw', installDir: dir, configFiles: [config] }, configs: [config], platform: 'linux', fs: new LocalFSProvider() };
  return { ctx, file };
}

describe('ZC-006 fix', () => {
  it('writes into a dotted agent alias, not a nested phantom table', async () => {
    const raw = 'schema_version = 3\n\n[agents."ops.v2"]\nrisk_profile = "default"\n\n[agents."ops.v2".workspace]\nunrestricted_filesystem = true\n';
    const { ctx, file } = ctxFor(raw);
    const r = await zc006.fix!(ctx);
    expect(r.applied).toBe(true);
    const out = readFileSync(file, 'utf8');
    const data = parseTomlSafe(out) as { agents: Record<string, { workspace?: { unrestricted_filesystem?: boolean } }> };
    expect(Object.keys(data.agents)).toEqual(['ops.v2']);
    expect(data.agents['ops.v2'].workspace?.unrestricted_filesystem).toBe(false);
    expect(out).not.toContain('[agents.ops.v2');
  });

  it('quotes a dotted alias in evidence', async () => {
    const raw = '[agents."ops.v2".workspace]\nunrestricted_filesystem = true\n';
    const { ctx } = ctxFor(raw);
    const r = await zc006.run(ctx);
    expect(r.evidence![0].detail).toContain('agents."ops.v2".workspace');
  });
});
