import { join } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getAdvisoryDatabase } from '../../advisory/database.js';
import { satisfies } from '../../core/semver.js';

export const adv002 = defineCheck({
  id: 'ADV-002',
  name: 'Dependency Vulnerability',
  category: 'advisory',
  severity: 'warning',
  description: 'Scan package.json/Cargo.toml dependencies against known advisory entries',

  async run(ctx, h) {
    const db = getAdvisoryDatabase();
    const depAdvisories = db.advisories.filter(a => a.affectedDependency);
    if (depAdvisories.length === 0) return h.passed('No dependency advisories in database');

    const evidence: Evidence[] = [];
    const installDir = ctx.installation.installDir;

    const deps = await loadPackageJsonDeps(ctx, installDir);
    const cargoDeps = await loadCargoTomlDeps(ctx, installDir);
    const allDeps = { ...deps, ...cargoDeps };

    for (const adv of depAdvisories) {
      const dep = adv.affectedDependency!;
      const installedVersion = allDeps[dep.name];
      if (!installedVersion) continue;
      if (satisfies(installedVersion, dep.versionConstraint)) {
        evidence.push({
          file: installDir,
          detail: `${adv.id}: ${dep.name}@${installedVersion} — ${adv.title}`,
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No vulnerable dependencies detected',
      failed: (n) => `${n} vulnerable dependenc${n === 1 ? 'y' : 'ies'} detected`,
    });
  },
});

async function loadPackageJsonDeps(ctx: ScanContext, dir: string): Promise<Record<string, string>> {
  try {
    const raw = await ctx.fs.readFile(join(dir, 'package.json'));
    const pkg = JSON.parse(raw);
    return {
      ...(pkg.dependencies ?? {}),
      ...(pkg.devDependencies ?? {}),
    };
  } catch {
    return {};
  }
}

async function loadCargoTomlDeps(ctx: ScanContext, dir: string): Promise<Record<string, string>> {
  try {
    const raw = await ctx.fs.readFile(join(dir, 'Cargo.toml'));
    const deps: Record<string, string> = {};
    const depSection = raw.match(/\[dependencies\]([\s\S]*?)(?:\n\[|$)/);
    if (depSection) {
      const lines = depSection[1].split('\n');
      for (const line of lines) {
        const m = /^(\S+)\s*=\s*"([^"]+)"/.exec(line.trim());
        if (m) deps[m[1]] = m[2];
      }
    }
    return deps;
  } catch {
    return {};
  }
}
