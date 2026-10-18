import { join } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getAdvisoryDatabase } from '../../advisory/database.js';
import { satisfies } from '../../core/semver.js';
import { fullVersion, rangeEntirelyAffected } from '../../core/version-range.js';
import { collectServerDependencies } from '../../mcp/server-dependencies.js';

export const adv002 = defineCheck({
  id: 'ADV-002',
  name: 'Dependency Vulnerability',
  category: 'advisory',
  severity: 'warning',
  description: 'Scan package.json/Cargo.toml dependencies against known advisory entries',

  async run(ctx, h) {
    const db = getAdvisoryDatabase();
    // package.json / Cargo.toml names; a PyPI advisory's `mcp` is another package.
    const depAdvisories = db.advisories.filter(a => a.affectedDependency && a.affectedDependency.ecosystem !== 'pypi');
    if (depAdvisories.length === 0) return h.passed('No dependency advisories in database');

    const evidence: Evidence[] = [];
    // Severities of the advisories matched by live (unmitigated) evidence: a
    // malicious package (an OSV MAL entry, critical) is not a warning
    const matched = new Set<string>();
    const installDir = ctx.installation.installDir;

    // npm: the installed copy, else the lockfile, else the declared range —
    // a range counts only when every version it admits is affected (as MCP-027).
    const npmDeps = await collectServerDependencies(join(installDir, 'package.json'), 'javascript', ctx.fs, { searchParents: false });
    const cargoDeps = await loadCargoTomlDeps(ctx, installDir);
    const undeclared = transitiveLookup(ctx, installDir);

    for (const adv of depAdvisories) {
      const dep = adv.affectedDependency!;
      const npm = npmDeps.find(d => d.name === dep.name);
      if (npm) {
        const affected = npm.version
          ? satisfies(fullVersion(npm.version), dep.versionConstraint)
          : npm.range !== undefined && rangeEntirelyAffected(npm.range, 'npm', dep.versionConstraint, adv.fixedVersion);
        if (affected) {
          matched.add(adv.severity);
          evidence.push({
            file: npm.source,
            detail: `${adv.id}: ${dep.name}${npm.version ? `@${npm.version}` : ` ${npm.range}`} — ${adv.title}`,
          });
        }
        continue;
      }
      const shipped = dep.ecosystem === 'npm' || dep.ecosystem === undefined ? await undeclared(dep.name) : [];
      for (const t of shipped) {
        if (!satisfies(fullVersion(t.version), dep.versionConstraint)) continue;
        if (!adv.appliesWhen) matched.add(adv.severity);
        // An advisory that needs a particular use of the library (appliesWhen)
        // can't be judged for code the agent doesn't own: report it, informationally.
        evidence.push({
          file: t.source,
          detail: `${adv.id}: ${dep.name}@${t.version} (installed as a dependency of a dependency) — ${adv.title}`
            + (adv.appliesWhen ? ` — applies only when ${adv.appliesWhen.usage}` : ''),
          ...(adv.appliesWhen ? { mitigated: true } : {}),
        });
      }
      if (shipped.length > 0) continue;
      const cargoVersion = cargoDeps[dep.name];
      if (cargoVersion && satisfies(cargoVersion, dep.versionConstraint)) {
        matched.add(adv.severity);
        evidence.push({
          file: join(installDir, 'Cargo.toml'),
          detail: `${adv.id}: ${dep.name}@${cargoVersion} — ${adv.title}`,
        });
      }
    }

    return h.fromEvidence(evidence, {
      severity: matched.has('critical') ? 'critical' : matched.has('warning') ? 'warning' : matched.size > 0 ? 'info' : undefined,
      passed: 'No vulnerable dependencies detected',
      failed: (n) => `${n} vulnerable dependenc${n === 1 ? 'y' : 'ies'} detected`,
    });
  },
});

/**
 * Exact versions of a package the project doesn't declare but ships anyway
 * (a dependency of a dependency): the hoisted installed copy, else every
 * lockfile entry for it (package-lock v2/v3 `packages`, nested copies too).
 * Looked up by advisory name only — no full tree walk.
 */
function transitiveLookup(ctx: ScanContext, dir: string): (name: string) => Promise<Array<{ version: string; source: string }>> {
  let lock: Promise<Record<string, { version?: unknown }>> | undefined;
  const readLock = async () => {
    try {
      const data = JSON.parse(await ctx.fs.readFile(join(dir, 'package-lock.json'))) as { packages?: Record<string, { version?: unknown }> };
      return data.packages ?? {};
    } catch {
      return {};
    }
  };
  return async (name) => {
    const installed = join(dir, 'node_modules', name, 'package.json');
    try {
      const version = (JSON.parse(await ctx.fs.readFile(installed)) as { version?: unknown }).version;
      if (typeof version === 'string') return [{ version, source: installed }];
    } catch {
      // not installed — try the lockfile
    }
    const packages = await (lock ??= readLock());
    const out: Array<{ version: string; source: string }> = [];
    const seen = new Set<string>();
    for (const [key, entry] of Object.entries(packages)) {
      if (key !== `node_modules/${name}` && !key.endsWith(`/node_modules/${name}`)) continue;
      if (typeof entry?.version !== 'string' || seen.has(entry.version)) continue;
      seen.add(entry.version);
      out.push({ version: entry.version, source: join(dir, 'package-lock.json') });
    }
    return out;
  };
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
