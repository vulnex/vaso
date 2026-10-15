import type { AgentInstallation, Evidence } from '../core/types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { join } from 'node:path';

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
// CI configuration and scripts run by a CI service, never loaded by the agent.
const CI_DIRS = new Set(['.github', '.gitlab', '.circleci', '.buildkite']);

/**
 * Only path segments *below a skill* count: the first segment under a skills
 * root is the skill's own directory, which its author names — a skill called
 * `test` or `spec` must not turn all of its code into "test code". Likewise a
 * user named "test" (/home/test/...) or a repo under ~/dev/tests/. Files
 * outside every root are never test code.
 */
export function isTestPath(file: string, roots: string[], opts: { rootIsUnit?: boolean } = {}): boolean {
  return notLoadedReason(file, roots, opts.rootIsUnit) !== undefined;
}

interface Located { root: string; parts: string[] }

function locate(file: string, roots: string[]): Located | undefined {
  const root = roots.find(r => file === r || file.startsWith(r.endsWith('/') ? r : `${r}/`));
  if (!root) return undefined;
  return { root, parts: file.slice(root.length).split(/[\\/]/).filter(p => p.length > 0) };
}

/**
 * Why a file under a root is not loaded, if it isn't. For a skills root,
 * parts[0] is the skill directory itself; `rootIsUnit` is for a root that is
 * one package (a resolved MCP server), whose `test/` sits right below it.
 */
function notLoadedReason(file: string, roots: string[], rootIsUnit = false): string | undefined {
  const at = locate(file, roots);
  if (!at) return undefined;
  const name = at.parts[at.parts.length - 1] ?? '';
  const dirs = at.parts.slice(rootIsUnit ? 0 : 1, -1);
  if (TEST_FILE.test(name) || dirs.some(p => TEST_DIRS.has(p))) return 'in test/fixture code';
  if (dirs.some(p => CI_DIRS.has(p))) return 'in CI configuration';
  return undefined;
}

/** Files that tell the agent what a skill runs. */
const SKILL_ENTRY_FILES = ['SKILL.md', 'package.json'];

/**
 * Whether the skill names `file` (by its path inside the skill) in SKILL.md or
 * package.json — instructions such as "run `node test/run.js`" make test-dir
 * code the code the agent executes.
 */
async function referencedBySkill(file: string, at: Located, fs: FSProvider, cache: Map<string, string>): Promise<boolean> {
  // A skills root may also be a single skill (`vaso skill audit <skill>`)
  const candidates = at.parts.length > 1
    ? [[join(at.root, at.parts[0]), at.parts.slice(1).join('/')], [at.root, at.parts.join('/')]]
    : [[at.root, at.parts.join('/')]];
  for (const [skillDir, rel] of candidates) {
    for (const entry of SKILL_ENTRY_FILES) {
      const path = join(skillDir, entry);
      if (!cache.has(path)) cache.set(path, await fs.readFile(path).catch(() => ''));
      const text = cache.get(path)!;
      if (text && (text.includes(rel) || text.includes(`./${rel}`))) return true;
    }
  }
  return false;
}

/**
 * Mark evidence located in skill test/fixture code or CI configuration as
 * mitigated (see `fromEvidence`) — unless the skill itself points at that file.
 */
export async function markTestCode(
  evidence: Evidence[],
  installation: Pick<AgentInstallation, 'skillsDir' | 'skillsDirs'>,
  fs?: FSProvider,
): Promise<void> {
  const roots = [installation.skillsDir, ...(installation.skillsDirs ?? [])]
    .filter((r): r is string => typeof r === 'string' && r.length > 0);
  if (roots.length === 0) return;
  const cache = new Map<string, string>();
  for (const e of evidence) {
    if (!e.file || e.mitigated) continue;
    const reason = notLoadedReason(e.file, roots);
    if (!reason) continue;
    const at = locate(e.file, roots)!;
    if (fs && await referencedBySkill(e.file, at, fs, cache)) continue;
    e.mitigated = true;
    e.detail = `${e.detail ? `${e.detail} — ` : ''}${reason}, not loaded by the agent`;
  }
}
