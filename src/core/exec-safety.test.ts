import { describe, it, expect, vi, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync, statSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { planExec, rootSafePath } from './exec-safety.js';

const posix = process.platform !== 'win32';

describe('planExec', () => {
  afterEach(() => vi.restoreAllMocks());

  it('isolated runs get a minimal environment without relocation variables', () => {
    vi.stubEnv('CODEX_HOME', '/home/u/.codex-alt');
    vi.stubEnv('CLAUDE_CONFIG_DIR', '/home/u/.claude-alt');
    const plan = planExec('codex', { isolateHome: true });
    try {
      expect(plan.env?.CODEX_HOME).toBeUndefined();
      expect(plan.env?.CLAUDE_CONFIG_DIR).toBeUndefined();
      expect(plan.env?.PATH).toBe(process.env.PATH);
      expect(plan.env?.HOME).toBe(plan.cwd);
      expect(existsSync(plan.env!.HOME!)).toBe(true);
    } finally {
      plan.cleanup();
      vi.unstubAllEnvs();
    }
  });

  it.skipIf(!posix)('falls back to the system temp dir when TMPDIR is unusable', () => {
    vi.stubEnv('TMPDIR', '/nonexistent/vaso-tmp');
    const plan = planExec('codex', { isolateHome: true });
    try {
      expect(plan.refuse).toBeUndefined();
      expect(plan.env?.HOME?.startsWith('/tmp/')).toBe(true);
    } finally {
      plan.cleanup();
      vi.unstubAllEnvs();
    }
  });

  it.skipIf(!posix)('as root: a user-owned binary runs as its owner, never as root', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vaso-exec-test-'));
    const bin = join(dir, 'claude');
    writeFileSync(bin, '#!/bin/sh\necho 1.0.0\n', { mode: 0o755 });
    vi.spyOn(process, 'getuid').mockReturnValue(0);
    try {
      const st = statSync(bin);
      const plan = planExec(bin, { isolateHome: false });
      expect(plan.refuse).toBeUndefined();
      expect(plan.uid).toBe(st.uid);
      expect(plan.gid).toBe(st.gid);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it.skipIf(!posix)('as root: a root-owned system binary runs as root with a root-safe PATH only', () => {
    const userDir = mkdtempSync(join(tmpdir(), 'vaso-exec-path-'));
    vi.stubEnv('PATH', `${userDir}:/usr/bin:/bin`);
    vi.spyOn(process, 'getuid').mockReturnValue(0);
    try {
      const plan = planExec('/bin/sh', undefined);
      expect(plan.uid).toBeUndefined();
      expect(plan.env?.PATH?.split(':')).not.toContain(userDir);
      expect(plan.env?.PATH?.split(':')).toContain('/bin');
    } finally {
      vi.unstubAllEnvs();
      rmSync(userDir, { recursive: true, force: true });
    }
  });
});

describe.skipIf(!posix)('rootSafePath', () => {
  it('accepts root-owned system paths and rejects user-owned ones', () => {
    expect(rootSafePath('/bin/sh')).toBe(true);
    const dir = mkdtempSync(join(tmpdir(), 'vaso-rootsafe-'));
    try {
      expect(rootSafePath(dir)).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
