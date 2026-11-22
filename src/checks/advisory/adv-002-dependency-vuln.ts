import { join } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getAdvisoryDatabase } from '../../advisory/database.js';
import { satisfies } from '../../core/semver.js';
import { advisoryAppliesToPlatform } from '../../advisory/applicability.js';
import { fullVersion } from '../../core/version-range.js';
import { declaredRangeMatch } from '../mcp/mcp-027-vulnerable-version.js';
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
    const depAdvisories = db.advisories.filter(
      a => a.affectedDependency && a.affectedDependency.ecosystem !== 'pypi' && advisoryAppliesToPlatform(a, ctx.platform)
    );
    if (depAdvisories.length === 0) return h.passed('No dependency advisories in database');

    const evidence: Evidence[] = [];
    // Severities of the advisories matched by live (unmitigated) evidence: a
    // malicious package (an OSV MAL entry, critical) is not a warning
    const matched = new Set<string>();
    const installDir = ctx.installation.installDir;

    // npm: the installed copy, else the lockfile, else the declared range —
    // judged as MCP-027 judges an unpinned runner spec (declaredRangeMatch()).
    const npmDeps = await collectServerDependencies(join(installDir, 'package.json'), 'javascript', ctx.fs, { searchParents: false });
    const cargoDeps = await loadCargoTomlDeps(ctx, installDir);
    const undeclared = transitiveLookup(ctx, installDir);
    const pushShipped = (t: ShippedCopy, adv: (typeof depAdvisories)[number]) => {
      if (!adv.appliesWhen) matched.add(adv.severity);
      // An advisory that needs a particular use of the library (appliesWhen)
      // can't be judged for code the agent doesn't own: report it, informationally.
      evidence.push({
        file: t.source,
        detail: `${adv.id}: ${adv.affectedDependency!.name}@${t.version} (installed as a dependency of a dependency) — ${adv.title}`
          + (adv.appliesWhen ? ` — applies only when ${adv.appliesWhen.usage}` : ''),
        ...(adv.appliesWhen ? { mitigated: true } : {}),
      });
    };

    for (const adv of depAdvisories) {
      const dep = adv.affectedDependency!;
      const npm = npmDeps.find(d => d.name === dep.name);
      if (npm) {
        const match = npm.version
          ? satisfies(fullVersion(npm.version), dep.versionConstraint) ? 'affected' : undefined
          : npm.range !== undefined ? declaredRangeMatch(npm.range, 'npm', adv) : undefined;
        if (match) {
          // A range clear of a package's malicious releases: noted, not live
          if (match !== 'excluded') matched.add(adv.severity);
          const shown = `${dep.name}${npm.version ? `@${npm.version}` : ` ${npm.range}`}`;
          evidence.push({
            file: npm.source,
            detail: match === 'affected'
              ? `${adv.id}: ${shown} — ${adv.title}`
              : match === 'malware'
                ? `${adv.id}: ${shown} can install a malicious release (${dep.versionConstraint}) — ${adv.title}`
                : `${adv.id}: ${shown} excludes the malicious releases (${dep.versionConstraint}) — keep it pinned away from them — ${adv.title}`,
            ...(match === 'excluded' ? { mitigated: true } : {}),
          });
        }
        // Another package's own copy of it, nested in node_modules
        for (const t of (await undeclared(dep.name)).filter(c => c.nested)) {
          if (satisfies(fullVersion(t.version), dep.versionConstraint)) pushShipped(t, adv);
        }
        continue;
      }
      const shipped = dep.ecosystem === 'npm' || dep.ecosystem === undefined ? await undeclared(dep.name) : [];
      for (const t of shipped) {
        if (satisfies(fullVersion(t.version), dep.versionConstraint)) pushShipped(t, adv);
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

interface ShippedCopy {
  version: string;
  source: string;
  /** A copy nested under another package (`a/node_modules/<name>`), not the hoisted one. */
  nested: boolean;
}

/**
 * Exact versions of a package the project ships: the hoisted copy (installed,
 * else its lockfile entry) plus every nested copy the lockfile records
 * (package-lock v2/v3 `packages`, `…/node_modules/<name>`). A safe hoisted
 * copy doesn't hide a vulnerable nested one. Looked up by advisory name
 * only — no full tree walk.
 */
function transitiveLookup(ctx: ScanContext, dir: string): (name: string) => Promise<ShippedCopy[]> {
  let lock: Promise<Record<string, { version?: unknown }>> | undefined;
  const readLock = async () => {
    try {
      const data = JSON.parse(await ctx.fs.readFile(join(dir, 'package-lock.json'))) as { packages?: Record<string, { version?: unknown }> };
      return data.packages && typeof data.packages === 'object' ? data.packages : {};
    } catch {
      return {};
    }
  };
  return async (name) => {
    const out: ShippedCopy[] = [];
    const seen = new Set<string>();
    const add = (copy: ShippedCopy) => {
      const key = `${copy.nested ? 'n' : 'h'}:${copy.version}`;
      if (seen.has(key)) return;
      seen.add(key);
      out.push(copy);
    };
    const installed = join(dir, 'node_modules', name, 'package.json');
    let hoistedInstalled = false;
    try {
      const version = (JSON.parse(await ctx.fs.readFile(installed)) as { version?: unknown }).version;
      if (typeof version === 'string') {
        add({ version, source: installed, nested: false });
        hoistedInstalled = true;
      }
    } catch {
      // not installed — the lockfile says what would be
    }
    const lockFile = join(dir, 'package-lock.json');
    for (const [key, entry] of Object.entries(await (lock ??= readLock()))) {
      const hoisted = key === `node_modules/${name}`;
      if (!hoisted && !key.endsWith(`/node_modules/${name}`)) continue;
      if (hoisted && hoistedInstalled) continue; // the installed copy wins
      if (typeof entry?.version !== 'string') continue;
      add({ version: entry.version, source: lockFile, nested: !hoisted });
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
