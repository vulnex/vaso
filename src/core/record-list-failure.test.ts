import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LocalFSProvider } from './local-fs-provider.js';
import { captureConfigLoadErrors, recordListFailure } from './config-loader.js';

// Deep test 2026-11-09: a regular file where a rules/instructions directory
// is expected (~/.claude/rules, ~/.codex/rules, ~/.copilot/instructions) holds
// no rules for the agent either — not a CONFIG-LOAD finding.
describe('recordListFailure', () => {
  let root: string | undefined;
  afterEach(() => { if (root) rmSync(root, { recursive: true, force: true }); root = undefined; });

  const listFailure = async (dir: string) => {
    const fs = new LocalFSProvider();
    return captureConfigLoadErrors(() => fs.readdirEntries(dir).then(() => false, err => recordListFailure(dir, fs, err)));
  };

  it('treats a regular file at the directory path (ENOTDIR) as absent', async () => {
    root = realpathSync(mkdtempSync(join(tmpdir(), 'vaso-listfail-')));
    writeFileSync(join(root, 'rules'), 'x\n');
    expect(await listFailure(join(root, 'rules'))).toEqual({ result: false, loadErrors: [] });
    // and a directory below such a file
    expect(await listFailure(join(root, 'rules', 'team'))).toEqual({ result: false, loadErrors: [] });
  });

  it('treats a missing directory as absent', async () => {
    root = realpathSync(mkdtempSync(join(tmpdir(), 'vaso-listfail-')));
    mkdirSync(join(root, 'a'));
    expect(await listFailure(join(root, 'a', 'missing'))).toEqual({ result: false, loadErrors: [] });
  });

  it('treats a snapshot-style ENOTDIR message as absent', async () => {
    const { result, loadErrors } = await captureConfigLoadErrors(() =>
      recordListFailure('/h/.codex/rules', new LocalFSProvider(), new Error('ENOTDIR: not a directory, scandir \'/h/.codex/rules\'')));
    expect(result).toBe(false);
    expect(loadErrors).toEqual([]);
  });
});
