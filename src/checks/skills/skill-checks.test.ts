import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, writeFile, mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { ScanContext, AgentInstallation } from '../../core/types.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';
import { skl011 } from './skl-011-dependency-audit.js';
import { skl012 } from './skl-012-code-complexity.js';

function makeContext(skillsDir?: string): ScanContext {
  const installation: AgentInstallation = {
    agent: 'openclaw',
    installDir: skillsDir ?? '/tmp/nonexistent',
    configFiles: [],
    skillsDir,
  };
  return { installation, configs: [], platform: 'darwin', fs: new LocalFSProvider() };
}

describe('SKL-011: Dependency Audit', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'vaso-skl011-'));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it('passes when no skills directory', async () => {
    const result = await skl011.run(makeContext(undefined));
    expect(result.passed).toBe(true);
  });

  it('passes with clean deps and lockfile', async () => {
    const skillDir = join(tempDir, 'my-skill');
    await mkdir(skillDir, { recursive: true });
    await writeFile(join(skillDir, 'package.json'), JSON.stringify({
      dependencies: { 'lodash': '^4.0.0', 'express': '^4.18.0' },
    }));
    await writeFile(join(skillDir, 'package-lock.json'), '{}');

    const result = await skl011.run(makeContext(tempDir));
    expect(result.passed).toBe(true);
  });

  it('fails when skill has known malicious dependency', async () => {
    const skillDir = join(tempDir, 'bad-skill');
    await mkdir(skillDir, { recursive: true });
    await writeFile(join(skillDir, 'package.json'), JSON.stringify({
      dependencies: { 'event-stream': '^3.3.4' },
    }));
    await writeFile(join(skillDir, 'package-lock.json'), '{}');

    const result = await skl011.run(makeContext(tempDir));
    expect(result.passed).toBe(false);
    expect(result.evidence).toBeDefined();
    expect(result.evidence!.some(e => e.detail?.includes('event-stream'))).toBe(true);
  });

  it('reports missing lockfile', async () => {
    const skillDir = join(tempDir, 'no-lock-skill');
    await mkdir(skillDir, { recursive: true });
    await writeFile(join(skillDir, 'package.json'), JSON.stringify({
      dependencies: { 'lodash': '^4.0.0' },
    }));

    const result = await skl011.run(makeContext(tempDir));
    expect(result.passed).toBe(false);
    expect(result.evidence).toBeDefined();
    expect(result.evidence!.some(e => e.detail?.includes('lockfile'))).toBe(true);
  });

  it('fails with scoped package from malicious publisher', async () => {
    const skillDir = join(tempDir, 'scoped-skill');
    await mkdir(skillDir, { recursive: true });
    await writeFile(join(skillDir, 'package.json'), JSON.stringify({
      dependencies: { '@clawhavoc/toolkit': '^1.0.0' },
    }));
    await writeFile(join(skillDir, 'package-lock.json'), '{}');

    const result = await skl011.run(makeContext(tempDir));
    expect(result.passed).toBe(false);
    expect(result.evidence).toBeDefined();
    expect(result.evidence!.some(e => e.detail?.includes('malicious publisher'))).toBe(true);
  });
});

describe('SKL-012: Code Complexity', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'vaso-skl012-'));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it('passes when no skills directory', async () => {
    const result = await skl012.run(makeContext(undefined));
    expect(result.passed).toBe(true);
  });

  it('passes with simple function', async () => {
    await writeFile(join(tempDir, 'simple.js'), `
function add(a, b) {
  return a + b;
}
`);
    const result = await skl012.run(makeContext(tempDir));
    expect(result.passed).toBe(true);
  });

  it('fails with function exceeding complexity threshold', async () => {
    // Generate a function with >15 decision points
    const decisions = Array.from({ length: 16 }, (_, i) =>
      `  if (x === ${i}) return ${i};`
    ).join('\n');

    await writeFile(join(tempDir, 'complex.js'), `
function complexFunc(x) {
${decisions}
  return -1;
}
`);
    const result = await skl012.run(makeContext(tempDir));
    expect(result.passed).toBe(false);
    expect(result.evidence).toBeDefined();
    expect(result.evidence![0].detail).toContain('complexFunc');
    expect(result.evidence![0].detail).toContain('17'); // 1 base + 16 ifs
  });
});
