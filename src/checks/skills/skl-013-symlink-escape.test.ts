import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ScanContext, AgentInstallation } from '../../core/types.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';
import { skl013 } from './skl-013-symlink-escape.js';

function makeCtx(skillsDir: string): ScanContext {
  const installation: AgentInstallation = {
    agent: 'skill-audit',
    installDir: skillsDir,
    skillsDir,
    configFiles: [],
  };
  return {
    installation,
    configs: [],
    platform: process.platform,
    fs: new LocalFSProvider(),
  };
}

describe('SKL-013: Workspace Symlink Escape', () => {
  let root: string;
  let workspace: string;
  let outside: string;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'skl013-'));
    workspace = join(root, 'repo');
    outside = join(root, 'outside');
    mkdirSync(workspace);
    mkdirSync(outside);
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  it('flags a symlink escaping to a sensitive target as critical', async () => {
    // Simulates GhostApproval: project_settings.json → outside/.ssh/authorized_keys
    const sensitive = join(outside, '.ssh', 'authorized_keys');
    mkdirSync(join(outside, '.ssh'));
    writeFileSync(sensitive, 'existing');
    symlinkSync(sensitive, join(workspace, 'project_settings.json'));

    const result = await skl013.run(makeCtx(workspace));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
    expect(result.evidence?.[0].detail).toContain('authorized_keys');
    expect(result.evidence?.[0].snippet).toContain('project_settings.json');
  });

  it('catches a dangling symlink to a sensitive target (planted before the file exists)', async () => {
    // No target file on disk — readlink still returns the raw target.
    symlinkSync(join(outside, '.ssh', 'authorized_keys'), join(workspace, 'config.json'));

    const result = await skl013.run(makeCtx(workspace));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('flags a non-sensitive out-of-workspace escape as a warning', async () => {
    const target = join(outside, 'notes.txt');
    writeFileSync(target, 'hi');
    symlinkSync(target, join(workspace, 'link.txt'));

    const result = await skl013.run(makeCtx(workspace));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('warning');
  });

  it('ignores symlinks that stay inside the workspace', async () => {
    const target = join(workspace, 'real.txt');
    writeFileSync(target, 'hi');
    symlinkSync(target, join(workspace, 'alias.txt'));

    const result = await skl013.run(makeCtx(workspace));
    expect(result.passed).toBe(true);
  });

  it('passes a clean workspace with no symlinks', async () => {
    writeFileSync(join(workspace, 'a.json'), '{}');
    const result = await skl013.run(makeCtx(workspace));
    expect(result.passed).toBe(true);
  });

  it('passes when the provider cannot observe symlinks (snapshot/mocks)', async () => {
    const ctx = makeCtx(workspace);
    // Drop readlink to emulate a provider that cannot resolve link status.
    (ctx.fs as unknown as { readlink?: unknown }).readlink = undefined;
    const result = await skl013.run(ctx);
    expect(result.passed).toBe(true);
  });
});
