import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getIOCDatabase } from '../../ioc/database.js';

const MALICIOUS_PACKAGES = new Set([
  'event-stream',
  'flatmap-stream',
  'ua-parser-js',
  'coa',
  'rc',
  'colors',
  'faker',
  'node-ipc',
  'peacenotwar',
  'es5-ext',
]);

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
        const raw = await ctx.fs.readFile(pkgPath);
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

      // Check for malicious packages
      for (const dep of depNames) {
        if (MALICIOUS_PACKAGES.has(dep)) {
          evidence.push({
            file: pkgPath,
            detail: `Known malicious package: ${dep}`,
          });
        }

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

    return h.fromEvidence(evidence, {
      passed: 'All skill dependencies are clean',
      failed: (n) => `Found ${n} dependency issue(s)`,
    });
  },
});
