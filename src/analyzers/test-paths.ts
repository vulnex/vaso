import type { AgentInstallation, Evidence } from '../core/types.js';

/**
 * Test/fixture code inside a skill directory: shipped alongside the skill but
 * not loaded by the agent. Security tooling's own tests are full of the very
 * patterns SKL-* hunt for (reverse-shell strings, curl|sh samples, keychain
 * access), so findings there are downgraded — not skipped, since a dropper
 * can still hide in test/.
 */
const TEST_DIRS = new Set([
  'test', 'tests', '__tests__', 'spec', 'specs', 'fixtures', '__fixtures__',
  'testdata', 'test-data', '__mocks__', 'e2e',
]);
const TEST_FILE = /(?:\.(?:test|spec)\.[cm]?[jt]sx?$|^test_.+\.py$|_test\.(?:py|go)$)/;

/**
 * Only path segments *below* a skills root count, so a user named "test"
 * (/home/test/...) or a repo under ~/dev/tests/ doesn't turn every finding
 * into test code. Files outside every root are never test code.
 */
export function isTestPath(file: string, roots: string[]): boolean {
  const root = roots.find(r => file === r || file.startsWith(r.endsWith('/') ? r : `${r}/`));
  if (!root) return false;
  const parts = file.slice(root.length).split(/[\\/]/).filter(p => p.length > 0);
  const name = parts[parts.length - 1] ?? '';
  return TEST_FILE.test(name) || parts.slice(0, -1).some(p => TEST_DIRS.has(p));
}

/** Mark evidence located in skill test/fixture code as mitigated (see `fromEvidence`). */
export function markTestCode(
  evidence: Evidence[],
  installation: Pick<AgentInstallation, 'skillsDir' | 'skillsDirs'>,
): void {
  const roots = [installation.skillsDir, ...(installation.skillsDirs ?? [])]
    .filter((r): r is string => typeof r === 'string' && r.length > 0);
  if (roots.length === 0) return;
  for (const e of evidence) {
    if (!e.file || e.mitigated || !isTestPath(e.file, roots)) continue;
    e.mitigated = true;
    e.detail = `${e.detail ? `${e.detail} — ` : ''}in test/fixture code, not loaded by the agent`;
  }
}
