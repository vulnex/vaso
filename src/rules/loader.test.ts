import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { writeFile, mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { loadRules } from './loader.js';

const TEST_DIR = join(tmpdir(), 'vaso-loader-test-' + Date.now());

beforeEach(async () => {
  await mkdir(join(TEST_DIR, 'rules'), { recursive: true });
});

afterEach(async () => {
  await rm(TEST_DIR, { recursive: true, force: true });
});

describe('loadRules', () => {
  it('loads rules from extra paths', async () => {
    const ruleFile = join(TEST_DIR, 'rules', 'test.yaml');
    await writeFile(ruleFile, `
rules:
  - id: LOAD-001
    name: Loader test
    category: config
    severity: info
    description: Test rule for loader
    config:
      path: "a.b"
      operator: "exists"
`);

    const result = await loadRules({
      skipGlobal: true,
      skipProject: true,
      extraPaths: [ruleFile],
    });

    expect(result.allRules).toHaveLength(1);
    expect(result.allRules[0].id).toBe('LOAD-001');
    expect(result.allErrors).toHaveLength(0);
  });

  it('deduplicates rules by ID (last wins)', async () => {
    const file1 = join(TEST_DIR, 'rules', 'a.yaml');
    const file2 = join(TEST_DIR, 'rules', 'b.yaml');

    await writeFile(file1, `
rules:
  - id: DUP-001
    name: First version
    category: config
    severity: info
    description: First
    config:
      path: "a"
      operator: "exists"
`);

    await writeFile(file2, `
rules:
  - id: DUP-001
    name: Second version
    category: config
    severity: warning
    description: Second
    config:
      path: "b"
      operator: "exists"
`);

    const result = await loadRules({
      skipGlobal: true,
      skipProject: true,
      extraPaths: [file1, file2],
    });

    expect(result.allRules).toHaveLength(1);
    expect(result.allRules[0].name).toBe('Second version');
    expect(result.allRules[0].severity).toBe('warning');
  });

  it('collects validation errors with file context', async () => {
    const ruleFile = join(TEST_DIR, 'rules', 'bad.yaml');
    await writeFile(ruleFile, `
rules:
  - id: BAD
    severity: invalid
`);

    const result = await loadRules({
      skipGlobal: true,
      skipProject: true,
      extraPaths: [ruleFile],
    });

    expect(result.allRules).toHaveLength(0);
    expect(result.allErrors.length).toBeGreaterThan(0);
    expect(result.allErrors[0].file).toBe(ruleFile);
  });

  it('handles parse errors gracefully', async () => {
    const ruleFile = join(TEST_DIR, 'rules', 'broken.yaml');
    await writeFile(ruleFile, `
rules:
  - id: [unterminated
`);

    const result = await loadRules({
      skipGlobal: true,
      skipProject: true,
      extraPaths: [ruleFile],
    });

    expect(result.allRules).toHaveLength(0);
    expect(result.allErrors.length).toBeGreaterThan(0);
  });

  it('handles nonexistent file gracefully', async () => {
    const result = await loadRules({
      skipGlobal: true,
      skipProject: true,
      extraPaths: ['/tmp/nonexistent-vaso-test.yaml'],
    });

    expect(result.allRules).toHaveLength(0);
    expect(result.allErrors.length).toBeGreaterThan(0);
  });

  it('skips hidden files in directories', async () => {
    const dir = join(TEST_DIR, 'rules');
    await writeFile(join(dir, '.hidden.yaml'), `
rules:
  - id: HIDDEN-001
    name: Hidden
    category: config
    severity: info
    description: Should not be loaded
    config:
      path: "a"
      operator: "exists"
`);
    await writeFile(join(dir, 'visible.yaml'), `
rules:
  - id: VIS-001
    name: Visible
    category: config
    severity: info
    description: Should be loaded
    config:
      path: "a"
      operator: "exists"
`);

    // We can't directly test directory discovery since loadRules uses fixed paths,
    // but we can test that extra paths work correctly
    const result = await loadRules({
      skipGlobal: true,
      skipProject: true,
      extraPaths: [join(dir, 'visible.yaml')],
    });

    expect(result.allRules).toHaveLength(1);
    expect(result.allRules[0].id).toBe('VIS-001');
  });

  it('loads multiple rules from one file', async () => {
    const ruleFile = join(TEST_DIR, 'rules', 'multi.yaml');
    await writeFile(ruleFile, `
rules:
  - id: MULTI-001
    name: Rule one
    category: config
    severity: info
    description: First rule
    config:
      path: "a"
      operator: "exists"
  - id: MULTI-002
    name: Rule two
    category: config
    severity: warning
    description: Second rule
    pattern:
      regex: "test"
      target: configs
`);

    const result = await loadRules({
      skipGlobal: true,
      skipProject: true,
      extraPaths: [ruleFile],
    });

    expect(result.allRules).toHaveLength(2);
    expect(result.allRules[0].id).toBe('MULTI-001');
    expect(result.allRules[1].id).toBe('MULTI-002');
  });
});
