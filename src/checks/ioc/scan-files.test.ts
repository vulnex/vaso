import { describe, it, expect, vi } from 'vitest';
import type { ScanContext } from '../../core/types.js';
import type { FSProvider, DirentInfo } from '../../core/fs-provider.js';
import { iocScanFiles, readScanFile, MAX_SCAN_FILE_BYTES } from './scan-files.js';

function makeCtx(tree: Record<string, string[]>, files: Record<string, string> = {}): { ctx: ScanContext; walks: string[] } {
  const walks: string[] = [];
  const fs = {
    readdirEntries: vi.fn(async (dir: string) => {
      walks.push(dir);
      return Object.entries(tree)
        .filter(([parent]) => parent === dir || parent.startsWith(`${dir}/`))
        .flatMap(([parentPath, names]) => names.map(name => ({ name, isFile: true, isDirectory: false, parentPath }) as DirentInfo));
    }),
    readFile: vi.fn(async (p: string) => {
      if (p in files) return files[p];
      throw new Error('ENOENT');
    }),
  } as unknown as FSProvider;
  const ctx: ScanContext = {
    installation: { agent: 'claude-code', installDir: '/h/.claude', skillsDir: '/h/.claude/skills', configFiles: [] },
    configs: [{ filePath: '/h/.claude/settings.json', format: 'json', raw: '{}', data: {} }],
    platform: 'linux',
    fs,
  };
  return { ctx, walks };
}

describe('iocScanFiles', () => {
  it('skips vendor/build/VCS dirs, already-parsed configs and non-code files; walks nested dirs once', async () => {
    const { ctx, walks } = makeCtx({
      '/h/.claude': ['settings.json', 'notes.txt'],
      '/h/.claude/skills/tool': ['index.js', 'SKILL.md'],
      '/h/.claude/skills/tool/node_modules/dep': ['index.js'],
      '/h/.claude/plugins/p/dist': ['bundle.js'],
      '/h/.claude/plugins/p/.git/hooks': ['pre-commit.sh'],
      '/h/.claude/plugins/p/src': ['main.ts'],
    });
    const files = await iocScanFiles(ctx);
    expect(files.sort()).toEqual(['/h/.claude/plugins/p/src/main.ts', '/h/.claude/skills/tool/index.js']);
    // skills dir sits inside the install dir — walked once, not twice
    expect(walks).toEqual(['/h/.claude']);
  });
});

describe('readScanFile', () => {
  it('returns content, and undefined for oversized or unreadable files', async () => {
    const big = 'x'.repeat(MAX_SCAN_FILE_BYTES + 1);
    const { ctx } = makeCtx({}, { '/a.js': 'const a = 1;', '/big.js': big });
    expect(await readScanFile(ctx, '/a.js')).toBe('const a = 1;');
    expect(await readScanFile(ctx, '/big.js')).toBeUndefined();
    expect(await readScanFile(ctx, '/missing.js')).toBeUndefined();
  });
});
