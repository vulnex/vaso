import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getIOCDatabase } from '../../ioc/database.js';
import { markTestCode } from '../../analyzers/test-paths.js';
import { readCappedFile } from '../../core/file-limits.js';
import { collectServerDependencies } from '../../mcp/server-dependencies.js';
import { exactVersion } from '../../core/version-range.js';

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
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) return h.passed('No skills directory found');

    const db = getIOCDatabase();

    let entries: { name: string; isFile: boolean; isDirectory: boolean; parentPath?: string }[];
    try {
      entries = await ctx.fs.readdirEntries(skillsDir);
    } catch {
      return h.passed('Skills directory not accessible');
    }

    const evidence: Evidence[] = [];

    for (const entry of entries) {
      if (!entry.isDirectory) continue;
      const skillDir = entry.parentPath ? join(entry.parentPath, entry.name) : join(skillsDir, entry.name);
      const pkgPath = join(skillDir, 'package.json');

      let pkgData: Record<string, unknown>;
      try {
        const raw = await readCappedFile(ctx.fs, pkgPath);
        pkgData = JSON.parse(raw) as Record<string, unknown>;
      } catch {
        continue; // No package.json in this skill
      }

      const allDeps: Record<string, string> = {
        ...(pkgData.dependencies as Record<string, string> ?? {}),
        ...(pkgData.devDependencies as Record<string, string> ?? {}),
      };

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

    markTestCode(evidence, ctx.installation);
    return h.fromEvidence(evidence, {
      passed: 'All skill dependencies are clean',
      failed: (n) => `Found ${n} dependency issue(s)`,
    });
  },
});
