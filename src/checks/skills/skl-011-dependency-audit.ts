import { join } from 'node:path';
import { getAllSkillsDirs } from '../../core/utils.js';
import { listSkills } from '../../core/skill-walk.js';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getIOCDatabase } from '../../ioc/database.js';
import { markTestCode } from '../../analyzers/test-paths.js';
import { readCappedFile } from '../../core/file-limits.js';
import { collectServerDependencies } from '../../mcp/server-dependencies.js';
import { exactVersion } from '../../core/version-range.js';
import { noSkillsDirResult } from './skill-files.js';

/**
 * Packages hijacked or sabotaged in specific releases (npm has since pulled
 * them) — flagged only at those versions; '*' = malicious in every version.
 */
const COMPROMISED_VERSIONS: Record<string, readonly string[] | '*'> = {
  'flatmap-stream': '*',
  'peacenotwar': '*',
  'event-stream': ['3.3.6'],
  'ua-parser-js': ['0.7.29', '0.8.0', '1.0.0'],
  'coa': ['2.0.3', '2.0.4', '2.1.1', '2.1.3', '3.0.1', '3.1.3'],
  'rc': ['1.2.9', '1.3.9', '2.3.9'],
  'colors': ['1.4.1', '1.4.2'],
  'faker': ['6.6.6'],
  'node-ipc': ['9.2.2', '10.1.1', '10.1.2', '10.1.3', '11.0.0', '11.1.0'],
};

const LOCKFILES = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'];

export const skl011 = defineCheck({
  id: 'SKL-011',
  name: 'Dependency Audit',
  category: 'skills',
  severity: 'warning',
  description: 'Check skill package.json dependencies against known malicious packages and verify lockfile presence',

  async run(ctx, h) {
    const skillsDirs = getAllSkillsDirs(ctx.installation);
    const noDir = noSkillsDirResult(ctx, h);
    if (noDir) return noDir;

    const db = getIOCDatabase();
    const skills = await listSkills(ctx.fs, skillsDirs, { rootIsSkill: ctx.installation.agent === 'skill-audit' });
    const evidence: Evidence[] = [];

    for (const { dir: skillDir } of skills) {
      const pkgPath = join(skillDir, 'package.json');

      let pkgData: unknown;
      try {
        const raw = await readCappedFile(ctx.fs, pkgPath);
        pkgData = JSON.parse(raw);
      } catch {
        continue; // No package.json in this skill
      }
      // `null`, an array or a string parses but declares nothing; reading
      // fields off it threw and ended the check for every skill after it
      if (!isPlainObject(pkgData)) continue;

      const allDeps: Record<string, string> = {};
      for (const field of ['dependencies', 'devDependencies']) {
        const deps = pkgData[field];
        if (!isPlainObject(deps)) continue;
        for (const [name, range] of Object.entries(deps)) allDeps[name] = typeof range === 'string' ? range : '';
      }

      const depNames = Object.keys(allDeps);
      if (depNames.length === 0) continue;

      // Known-compromised releases, judged by the version that would run:
      // the installed copy, else the lockfile, else an exact pin
      const resolved = await collectServerDependencies(pkgPath, 'javascript', ctx.fs, { searchParents: false });
      for (const dep of resolved) {
        const bad = COMPROMISED_VERSIONS[dep.name];
        if (!bad) continue;
        const version = dep.version ?? (dep.range !== undefined ? exactVersion(dep.range) : undefined);
        if (bad === '*') {
          evidence.push({ file: dep.source, detail: `Known malicious package: ${dep.name}` });
        } else if (version && bad.includes(version)) {
          evidence.push({ file: dep.source, detail: `Known compromised release: ${dep.name}@${version}` });
        }
      }

      for (const dep of depNames) {

        // Check scoped package publishers
        const scopeMatch = dep.match(/^@([^/]+)\//);
        if (scopeMatch && db.maliciousPublishers.includes(scopeMatch[1])) {
          evidence.push({
            file: pkgPath,
            detail: `Package from malicious publisher: ${dep}`,
          });
        }
      }

      // Check lockfile presence
      let hasLockfile = false;
      for (const lockfile of LOCKFILES) {
        if (await ctx.fs.access(join(skillDir, lockfile))) {
          hasLockfile = true;
          break;
        }
      }

      if (!hasLockfile) {
        evidence.push({
          file: pkgPath,
          detail: 'No lockfile found (package-lock.json, yarn.lock, or pnpm-lock.yaml) — dependencies not pinned',
        });
      }
    }

    await markTestCode(evidence, ctx.installation, ctx.fs);
    return h.fromEvidence(evidence, {
      passed: 'All skill dependencies are clean',
      failed: (n) => `Found ${n} dependency issue(s)`,
    });
  },
});

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
