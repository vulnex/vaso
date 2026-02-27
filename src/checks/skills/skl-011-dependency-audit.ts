import { readFile, readdir, access } from 'node:fs/promises';
import { join } from 'node:path';
import type { Dirent } from 'node:fs';
import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
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

export const skl011: CheckModule = {
  id: 'SKL-011',
  name: 'Dependency Audit',
  category: 'skills',
  severity: 'warning',
  description: 'Check skill package.json dependencies against known malicious packages and verify lockfile presence',

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];
    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) {
      return { id: 'SKL-011', name: 'Dependency Audit', category: 'skills', severity: 'warning', passed: true, message: 'No skills directory found' };
    }

    const db = getIOCDatabase();

    let entries: Dirent<string>[];
    try {
      entries = await readdir(skillsDir, { withFileTypes: true, encoding: 'utf-8' });
    } catch {
      return { id: 'SKL-011', name: 'Dependency Audit', category: 'skills', severity: 'warning', passed: true, message: 'Skills directory not accessible' };
    }

    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const skillDir = entry.parentPath ? join(entry.parentPath, entry.name) : join(skillsDir, entry.name);
      const pkgPath = join(skillDir, 'package.json');

      let pkgData: Record<string, unknown>;
      try {
        const raw = await readFile(pkgPath, 'utf-8');
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
        try {
          await access(join(skillDir, lockfile));
          hasLockfile = true;
          break;
        } catch {
          // Not found
        }
      }

      if (!hasLockfile) {
        evidence.push({
          file: pkgPath,
          detail: 'No lockfile found (package-lock.json, yarn.lock, or pnpm-lock.yaml) — dependencies not pinned',
        });
      }
    }

    return {
      id: 'SKL-011',
      name: 'Dependency Audit',
      category: 'skills',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'All skill dependencies are clean'
        : `Found ${evidence.length} dependency issue(s)`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};
