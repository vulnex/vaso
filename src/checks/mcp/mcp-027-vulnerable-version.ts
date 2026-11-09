import { createHash } from 'node:crypto';
import type { Evidence, Severity } from '../../core/types.js';
import type { MCPServerEntry } from '../../mcp/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getAdvisoryDatabase } from '../../advisory/database.js';
import { satisfies, parseSemVer, compareSemVer, constraintBranches } from '../../core/semver.js';
import { defaultMcpStateStore } from '../../mcp/mcp-state-store.js';
import { fullVersion, rangeBounds, rangeEntirelyAffected, type VersionBounds } from '../../core/version-range.js';
import type { Advisory } from '../../advisory/advisory-types.js';
import { DEPRECATED_NPM_PACKAGES } from '../../advisory/library-advisories.js';
import { advisoryAppliesToPlatform } from '../../advisory/applicability.js';
import { runnerPackage, type PinKind } from '../../mcp/package-pin.js';

/**
 * MCP-027 — Vulnerable / Rolled-Back MCP Version.
 *
 * Update-phase risks from Hou et al. arXiv 2503.23278 §5.3.2: re-deploying a
 * known-vulnerable MCP server version, or rolling a server back to an older
 * version (silently undoing a security fix). Three detections:
 *  - advisory match: the pinned `pkg@version` matches a dependency advisory;
 *    an unpinned, tag or range spec whenever the package has a
 *    malicious-package advisory (a publisher that shipped malware once isn't
 *    trusted: the release it installs may be a malicious one), or when the
 *    release it installs is affected (every release it can install, or the
 *    newest one when the advisory has no fix).
 *  - rollback: the pinned version is lower than the highest version previously
 *    seen for that package (tracked in the cross-scan state store).
 *  - shipped dependency: a package the server's project ships with (the MCP
 *    SDK, …) matches an advisory — exact versions from the installed copy or
 *    lockfile, a declared range only when every version it admits is affected.
 *    An advisory scoped to a feature the server's code doesn't use is reported
 *    as mitigated.
 *
 * MCP-010 covers the missing pin itself; this covers bad versions.
 */

interface VersionState {
  highest: string;
}

/** PEP 503 name normalization (`MCP_Server` → `mcp-server`); npm names are exact. */
function packageKey(name: string, ecosystem: 'npm' | 'pypi'): string {
  return ecosystem === 'pypi' ? name.toLowerCase().replace(/[-_.]+/g, '-') : name;
}

/** Version-history name: npm names unchanged (existing history keeps working), PyPI ones prefixed so `mcp` (PyPI) isn't `mcp` (npm). */
function stateName(name: string, ecosystem: 'npm' | 'pypi'): string {
  return ecosystem === 'pypi' ? `pypi:${packageKey(name, ecosystem)}` : name;
}

/**
 * What an unpinned spec can install: the newest release (`pkg`, `pkg@latest`),
 * whatever a moving tag points at (`pkg@next`), or any release in a range
 * (`pkg@^1.2`, `pkg>=1.0,<2`).
 */
export type UnpinnedResolution = { kind: 'latest' } | { kind: 'tag' } | { kind: 'range'; range: string };

/**
 * The package a server's runner installs (npx, bunx, `pnpm dlx`, `npm exec`,
 * uvx, `pipx run`, … — via runnerPackage()), with its version when the spec
 * pins one exactly (`pkg@1.2.3`, `pkg==1.2.3`, `--from pkg==1.2.3`), or what an
 * unpinned registry spec can resolve to.
 */
export function pinnedRunnerPackage(
  server: MCPServerEntry,
): { name: string; ecosystem: 'npm' | 'pypi'; version?: string; resolves?: UnpinnedResolution } | undefined {
  const pkg = runnerPackage(server.command, server.args);
  if (!pkg || pkg.pin === 'local') return undefined;
  // A registry tarball URL names one release (`…/@scope/x/-/x-1.0.0.tgz`)
  const tarball = pkg.ecosystem === 'npm' ? REGISTRY_TARBALL.exec(pkg.spec.trim()) : null;
  if (tarball && parseSemVer(tarball[2])) return { name: decodeURIComponent(tarball[1]), ecosystem: 'npm', version: tarball[2] };
  const base = { name: pkg.name, ecosystem: pkg.ecosystem };
  if (pkg.pin !== 'exact') {
    const resolves = unpinnedResolution(pkg.spec.trim(), pkg.name, pkg.ecosystem, pkg.pin);
    return resolves ? { ...base, resolves } : base;
  }
  let version: string | undefined;
  if (pkg.ecosystem === 'npm') {
    // Exact git/sha pins carry no release number
    if (pkg.spec.startsWith(`${pkg.name}@`)) version = pkg.spec.slice(pkg.name.length + 1).replace(/^v/, '');
  } else {
    const m = /^[A-Za-z0-9][\w.-]*(?:\[[^\]]*\])?\s*(?:===?|@)\s*v?(\S+)$/.exec(pkg.spec.trim());
    if (m) version = fullVersion(m[1]);
  }
  return version && parseSemVer(version) ? { ...base, version } : base;
}

/** `https://registry.npmjs.org/<name>/-/<base>-<version>.tgz` (also yarn's mirror): name and version. */
const REGISTRY_TARBALL = /^https?:\/\/registry\.(?:npmjs\.org|yarnpkg\.com)\/((?:@[^/\s]+(?:\/|%2[fF]))?[^/\s]+)\/-\/[^/\s]+?-(\d+\.\d+\.\d+(?:-[\w.]+)?)\.tgz$/;

/** Registry specs only — a git URL or direct reference installs something the registry's advisories don't describe. */
function unpinnedResolution(spec: string, name: string, ecosystem: 'npm' | 'pypi', pin: PinKind): UnpinnedResolution | undefined {
  if (ecosystem === 'npm') {
    if (pin === 'none') return spec === name ? { kind: 'latest' } : undefined;
    if (!spec.startsWith(`${name}@`)) return undefined;
    const rest = spec.slice(name.length + 1).trim();
    if (pin === 'tag') return rest === 'latest' ? { kind: 'latest' } : { kind: 'tag' };
    return { kind: 'range', range: rest };
  }
  const m = /^[A-Za-z0-9][\w.-]*(?:\[[^\]]*\])?\s*(.*)$/.exec(spec);
  const rest = m?.[1].trim() ?? '';
  if (pin === 'none') return rest === '' ? { kind: 'latest' } : undefined;
  if (pin === 'tag') return rest === '@latest' ? { kind: 'latest' } : { kind: 'tag' };
  return rest ? { kind: 'range', range: rest.replace(/;.*$/, '').trim() } : undefined;
}

/** `pkg (unpinned)`, `pkg@next`-style tags, `pkg@^1.2` / `pkg>=1.0`. */
function unpinnedLabel(name: string, ecosystem: 'npm' | 'pypi', resolves: UnpinnedResolution): string {
  if (resolves.kind === 'range') return ecosystem === 'npm' ? `${name}@${resolves.range}` : `${name}${resolves.range}`;
  return resolves.kind === 'latest' ? `${name} (unpinned)` : `${name} (moving tag)`;
}

/** How an unpinned spec ends up affected: `every release pkg@^1 can install is`, `pkg (unpinned) installs the latest release, which is`. */
function unpinnedWhat(shown: string, resolves: UnpinnedResolution, ecosystem: 'npm' | 'pypi', constraint: string, fixedVersion: string | undefined): string {
  const open = openEndedBranches(constraint);
  const every = `every release ${shown} can install is`;
  if (open.some((b) => satisfies('0.0.0', b))) return every;
  if (resolves.kind === 'latest') return `${shown} installs the latest release, which is`;
  if (resolves.kind === 'tag') return every;
  // A range: entirely affected, or only the newest release it admits
  return specEntirelyAffected(resolves.range, ecosystem, constraint, fixedVersion)
    ? every
    : `${shown} installs the newest release it admits, which is`;
}

/** The alternatives of a range spec (`0.1.14 || 0.1.15`); PyPI specifiers have none. */
function specAlternatives(range: string, ecosystem: 'npm' | 'pypi'): string[] {
  return ecosystem === 'npm' ? range.split('||').map((r) => r.trim()).filter(Boolean) : [range];
}

/** Every release a range spec admits is affected (each `||` alternative). */
function specEntirelyAffected(range: string, ecosystem: 'npm' | 'pypi', constraint: string, fixedVersion: string | undefined): boolean {
  const open = openEndedBranches(constraint);
  return specAlternatives(range, ecosystem).every((alt) => {
    if (rangeEntirelyAffected(alt, ecosystem, constraint, fixedVersion)) return true;
    const bounds = rangeBounds(alt, ecosystem);
    return Boolean(bounds && open.some((b) => satisfies(bounds.min, b)));
  });
}

/**
 * Whether the newest release a range spec admits is affected — what the
 * installer picks: `mcp-remote@<0.1.16` gets 0.1.15, inside `>=0.0.5
 * <0.1.16`. Judged on the alternative reaching highest; a range without an
 * upper bound installs the latest release (see the `latest` rule).
 */
function newestAdmittedAffected(range: string, ecosystem: 'npm' | 'pypi', constraint: string, fixedVersion: string | undefined): boolean {
  const alts = specAlternatives(range, ecosystem).map((alt) => rangeBounds(alt, ecosystem));
  if (alts.length === 0 || alts.some((b) => !b || (!b.maxExclusive && !b.maxInclusive))) return false;
  // The alternative with the highest top (an inclusive top counts as just above itself)
  const topOf = (b: VersionBounds) => (b.maxInclusive ? nextPatch(b.maxInclusive) : b.maxExclusive!);
  const top = (alts as VersionBounds[]).reduce((a, b) => (compareVersions(topOf(b), topOf(a)) > 0 ? b : a));
  if (top.maxInclusive) return satisfies(top.maxInclusive, constraint);
  return constraintBranches(constraint).some((branch) => {
    const affected = rangeBounds(branch, 'npm');
    if (!affected || !intervalsMeet(top, affected)) return false;
    // the affected line reaches the range's top: the newest admitted release is
    // in it (an open-ended line ends at the fix, when the advisory names one)
    if (!affected.maxExclusive && !affected.maxInclusive) {
      const fixed = fixedVersion ? parseSemVer(fullVersion(fixedVersion.split(',')[0].trim())) : null;
      return !fixed || compareSemVer(fixed, parseSemVer(top.maxExclusive!)!) >= 0;
    }
    return compareVersions(topOf(affected), top.maxExclusive!) >= 0;
  });
}

function nextPatch(version: string): string {
  const v = parseSemVer(version)!;
  return `${v.major}.${v.minor}.${v.patch + 1}`;
}

/** A constraint branch bounded only from below (`>=0.0.0`, `>=1.0.16`): every later release is affected too. */
function openEndedBranches(constraint: string): string[] {
  return constraintBranches(constraint).filter((b) => b.split(/\s+/).every((t) => /^>=?\s*\d/.test(t)));
}

/** An advisory saying the package has shipped malware (any release of it). */
export function maliciousPackage(adv: Advisory): boolean {
  return Boolean(adv.tags?.includes('malicious-package') && adv.affectedDependency);
}

/**
 * A malicious-package advisory covering every release (`>=0.0.0`, `*`, or a
 * lower bound at 0.0.1 with no upper bound): the package is malware outright,
 * not a package with some malicious releases (`@dforge-core/dforge-mcp`
 * 0.2.20–0.2.21, a later takeover `>=0.9.0`, `mcp-teamviewer` =0.0.1). Both
 * are reported for an unpinned spec; only the wording differs.
 */
export function malwareFromFirstRelease(adv: Advisory): boolean {
  const constraint = adv.affectedDependency?.versionConstraint.trim();
  if (!maliciousPackage(adv) || constraint === undefined) return false;
  if (constraint === '' || constraint === '*' || constraint === 'x') return true;
  if (constraintBranches(constraint).length > 1) return false;
  const bounds = rangeBounds(constraint, 'npm');
  return Boolean(bounds && !bounds.maxExclusive && !bounds.maxInclusive && compareVersions(bounds.min, '0.0.1') <= 0);
}

function compareVersions(a: string, b: string): number {
  return compareSemVer(parseSemVer(a)!, parseSemVer(b)!);
}

/** Whether two version intervals share a version. */
function intervalsMeet(a: VersionBounds, b: VersionBounds): boolean {
  const low = compareVersions(a.min, b.min) >= 0 ? a.min : b.min;
  return [a, b].every((x) =>
    (!x.maxInclusive || compareVersions(low, x.maxInclusive) <= 0) &&
    (!x.maxExclusive || compareVersions(low, x.maxExclusive) < 0));
}

/**
 * Whether an unpinned spec can install a release in the advisory's range: a
 * moving tag or no pin always can; a range only when it meets one of the
 * affected branches (`^0.2.22` can't reach `>=0.2.20 <0.2.22`). A range or
 * constraint that can't be read counts as reaching it.
 */
export function canReachAffected(resolves: UnpinnedResolution, ecosystem: 'npm' | 'pypi', constraint: string): boolean {
  if (resolves.kind !== 'range') return true;
  return specAlternatives(resolves.range, ecosystem).some((alt) => {
    const bounds = rangeBounds(alt, ecosystem);
    if (!bounds) return true;
    return constraintBranches(constraint).some((branch) => {
      const affected = rangeBounds(branch, 'npm');
      return !affected || intervalsMeet(bounds, affected);
    });
  });
}

/**
 * Whether the release an unpinned spec installs is affected: the newest
 * release when the advisory has no fix and no upper bound, any release for a
 * moving tag only when the advisory covers them all, and a range when every
 * version it admits is affected — or, with no fix, when an open-ended affected
 * line starts inside it (the installer picks the newest release it admits:
 * `postmark-mcp@^1.0.0` gets the backdoored 1.0.16+). An advisory with a fixed
 * release the spec can still resolve to is not reported — the install may
 * well be fine, and MCP-010 already flags the missing pin. Malicious packages
 * are matched separately (maliciousPackage()).
 */
export function unpinnedSpecAffected(
  resolves: UnpinnedResolution,
  ecosystem: 'npm' | 'pypi',
  constraint: string,
  fixedVersion: string | undefined,
): boolean {
  const open = openEndedBranches(constraint);
  switch (resolves.kind) {
    case 'latest':
      return !fixedVersion && open.length > 0;
    case 'tag':
      return !fixedVersion && open.some((b) => satisfies('0.0.0', b));
    case 'range': {
      if (specEntirelyAffected(resolves.range, ecosystem, constraint, fixedVersion)) return true;
      if (newestAdmittedAffected(resolves.range, ecosystem, constraint, fixedVersion)) return true;
      const bounds = rangeBounds(resolves.range, ecosystem);
      if (!bounds) return false;
      return open.some((b) => satisfies(bounds.min, b) || (!fixedVersion && startsInside(b, bounds)));
    }
  }
}

/** An open-ended branch (`>=1.0.16`) whose lower bound falls below the range's top (`^1.0.0` → <2.0.0). */
function startsInside(branch: string, bounds: VersionBounds): boolean {
  let low: string | undefined;
  for (const token of branch.split(/\s+/)) {
    const m = /^>=?\s*(\S+)$/.exec(token);
    if (m) low = fullVersion(m[1]);
  }
  const lowParsed = low ? parseSemVer(low) : null;
  if (!lowParsed) return false;
  if (bounds.maxInclusive) {
    const top = parseSemVer(bounds.maxInclusive);
    return Boolean(top && compareSemVer(lowParsed, top) <= 0);
  }
  if (!bounds.maxExclusive) return true;
  const top = parseSemVer(bounds.maxExclusive);
  return Boolean(top && compareSemVer(lowParsed, top) < 0);
}

export const mcp027 = defineCheck({
  id: 'MCP-027',
  name: 'Vulnerable / Rolled-Back MCP Version',
  category: 'mcp',
  severity: 'warning',
  description:
    'Detect MCP server packages pinned to a known-vulnerable version, rolled back below a previously-seen version, or shipping a known-vulnerable or deprecated dependency such as an old MCP SDK',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    let maxSeverity: Severity = 'warning';

    const db = getAdvisoryDatabase();
    const depAdvisories = db.advisories.filter((a) => a.affectedDependency && advisoryAppliesToPlatform(a, ctx.platform));
    const store = ctx.mcpStateStore ?? defaultMcpStateStore();
    // Servers per package: a pre-1.3.0 history (keyed by package alone)
    // belongs to a server only when it is the one using that package.
    // Unpinned servers never record a version, so they don't count.
    const serversPerPackage = new Map<string, number>();
    for (const config of ctx.mcpConfigs ?? []) {
      for (const server of config.servers) {
        const pkg = pinnedRunnerPackage(server);
        if (!pkg?.version) continue;
        const name = stateName(pkg.name, pkg.ecosystem);
        serversPerPackage.set(name, (serversPerPackage.get(name) ?? 0) + 1);
      }
    }

    // Only non-info matches (and rollbacks) make the finding a warning or worse.
    let liveWarning = false;
    for (const config of ctx.mcpConfigs ?? []) {
      for (const server of config.servers) {
        const pkg = pinnedRunnerPackage(server);
        if (!pkg) continue;
        const { ecosystem, version, resolves } = pkg;
        // Unpinned specs (MCP-010 flags the missing pin) are matched only
        // against advisories covering every release they can install.
        if (!version && !resolves) continue;

        const name = packageKey(pkg.name, ecosystem);
        const shown = version ? `${name}@${version}` : unpinnedLabel(name, ecosystem, resolves!);

        // 1) Known-vulnerable version (advisory database).
        for (const adv of depAdvisories) {
          const dep = adv.affectedDependency!;
          const depEcosystem = dep.ecosystem ?? 'npm';
          if (depEcosystem !== ecosystem || packageKey(dep.name, depEcosystem) !== name) continue;
          // A package that has shipped malware: whatever an unpinned spec
          // resolves to may be a malicious release (only an exact pin to a
          // release outside the advisory is trusted)
          const malware = !version && maliciousPackage(adv);
          const outright = malwareFromFirstRelease(adv);
          const affected = !version && unpinnedSpecAffected(resolves!, ecosystem, dep.versionConstraint, adv.fixedVersion);
          // A range clear of every malicious release: noted, not live
          const excluded = malware && !outright && !affected && !canReachAffected(resolves!, ecosystem, dep.versionConstraint);
          // An exact pin of an all-releases-malicious package, prereleases too (`0.0.0-dev` escapes `>=0.0.0`)
          const pinnedHit = version !== undefined && (satisfies(version, dep.versionConstraint) || outright);
          if (version ? !pinnedHit : !malware && !affected) continue;
          if (!excluded) {
            if (adv.severity === 'critical') maxSeverity = 'critical';
            if (adv.severity !== 'info') liveWarning = true;
          }
          const what = version
            ? `${shown} is affected by "${adv.title}"`
            : malware && outright
              ? `${shown} installs a package published as malware, so no release of it is safe: "${adv.title}"`
              : affected
                ? `${unpinnedWhat(shown, resolves!, ecosystem, dep.versionConstraint, adv.fixedVersion)} affected by "${adv.title}"`
                : excluded
                  ? `${name} has published malicious releases (${dep.versionConstraint}); this spec (${shown}) excludes them — keep it pinned away from them: "${adv.title}"`
                  : `${name} has published malicious releases (${dep.versionConstraint}); run as ${shown} it can install one — pin a vetted version: "${adv.title}"`;
          evidence.push({
            file: config.filePath,
            snippet: `Server "${server.name}": ${shown}`,
            detail:
              `${adv.id}: ${what}` +
              ` (severity: ${excluded ? `info; the advisory is ${adv.severity}` : adv.severity}${adv.fixedVersion ? `, fix: ${adv.fixedVersion}` : ''})`,
          });
        }
        if (!version) continue; // no version to track for rollback

        const parsed = parseSemVer(version);

        // 2) Version rollback vs. the highest version previously seen.
        if (parsed) {
          // Per server, not per package: two servers pinning different
          // versions of one package would otherwise "roll back" every scan.
          const serverId = createHash('sha256').update(`${config.filePath}\0${server.name}`).digest('hex').slice(0, 12);
          const state = stateName(name, ecosystem);
          const key = `version-${state}-${serverId}`;
          let prev = await store.load<VersionState>(key);
          if (!prev && ecosystem === 'npm' && serversPerPackage.get(state) === 1) prev = await store.load<VersionState>(`version-${name}`);
          const prevParsed = prev?.highest ? parseSemVer(prev.highest) : null;

          if (prevParsed && compareSemVer(parsed, prevParsed) < 0) {
            liveWarning = true;
            evidence.push({
              file: config.filePath,
              snippet: `Server "${server.name}": ${name}@${version}`,
              detail: `${name} was rolled back from ${prev!.highest} to ${version} — a downgrade can silently re-introduce a fixed vulnerability`,
            });
          }

          const highest = prevParsed && compareSemVer(prevParsed, parsed) >= 0 ? prev!.highest : version;
          await store.save(key, { highest });
        }
      }
    }

    // 3) Packages a server ships with (its SDK and other dependencies), read
    // from the installed copy, lockfile or declared range of its project.
    // Bundled advisories first; then, with --audit-deps, what OSV.dev lists
    // (skipping advisories a bundled entry already reported); then packages
    // deprecated outright.
    for (const source of ctx.mcpServerSources ?? []) {
      for (const dep of source.dependencies ?? []) {
        const shown = dep.version ? `${dep.name}@${dep.version}` : `${dep.name} ${dep.range}`;
        const reported = new Set<string>();
        for (const adv of depAdvisories) {
          const target = adv.affectedDependency!;
          const targetEcosystem = target.ecosystem ?? 'npm';
          if (targetEcosystem !== dep.ecosystem || packageKey(target.name, targetEcosystem) !== packageKey(dep.name, dep.ecosystem)) continue;
          const affected = dep.version
            ? satisfies(fullVersion(dep.version), target.versionConstraint)
            : dep.range !== undefined && rangeEntirelyAffected(dep.range, dep.ecosystem, target.versionConstraint, adv.fixedVersion);
          if (!affected) continue;

          reported.add(adv.id);
          if (adv.reference) reported.add(adv.reference.split('/').pop()!);
          const notUsed = featureNotUsed(adv, source.sourceCode);
          if (!notUsed) {
            if (adv.severity === 'critical') maxSeverity = 'critical';
            if (adv.severity !== 'info') liveWarning = true;
          }
          evidence.push({
            file: dep.source,
            snippet: `Server "${source.serverName}": ${shown}`,
            detail:
              `${adv.id}: server "${source.serverName}" ships ${shown}, affected by "${adv.title}"` +
              ` (severity: ${adv.severity}${adv.fixedVersion ? `, fix: ${adv.fixedVersion}` : ''})` +
              (notUsed ? ` — applies to ${adv.appliesWhen!.usage}, which this server's code doesn't use` : ''),
            ...(notUsed ? { mitigated: true } : {}),
          });
        }

        for (const vuln of dep.vulnerabilities ?? []) {
          if ([vuln.id, ...vuln.aliases].some((id) => reported.has(id))) continue;
          if (vuln.severity === 'critical') maxSeverity = 'critical';
          if (vuln.severity !== 'info') liveWarning = true;
          evidence.push({
            file: dep.source,
            snippet: `Server "${source.serverName}": ${shown}`,
            detail:
              `${vuln.id}: server "${source.serverName}" ships ${shown}, affected by "${vuln.summary}"` +
              ` (severity: ${vuln.severity}${vuln.fixedVersion ? `, fix: ${vuln.fixedVersion}` : ''}; OSV.dev ${vuln.reference})`,
          });
        }

        const deprecated = dep.ecosystem === 'npm' ? DEPRECATED_NPM_PACKAGES[dep.name] : undefined;
        if (deprecated) {
          evidence.push({
            file: dep.source,
            snippet: `Server "${source.serverName}": ${shown}`,
            detail: `server "${source.serverName}" ships ${dep.name}, which is ${deprecated} — it gets no security fixes`,
          });
        }
      }
    }

    return h.result({
      passed: evidence.length === 0,
      // Only mitigated matches, low-severity advisories or deprecations: info.
      severity: liveWarning ? maxSeverity : 'info',
      message:
        evidence.length === 0
          ? 'No MCP server packages are on a known-vulnerable or rolled-back version'
          : evidence.every((e) => e.mitigated)
            ? `Found ${evidence.length} advisory match(es) in MCP server dependencies, none applicable — each needs a feature the server's code doesn't use`
            : `Found ${evidence.length} MCP server version issue(s) — known-vulnerable or rolled-back package(s)`,
      evidence,
      fixDescription:
        'Pin MCP servers to a current, non-vulnerable release; never roll a server back below a version that carried a security fix',
    });
  },
});

/**
 * The advisory needs a feature (an HTTP transport, the OAuth client) that the
 * server's own code shows no sign of using. Unknown when there is no source.
 */
function featureNotUsed(adv: Advisory, sourceCode: string | undefined): boolean {
  if (!adv.appliesWhen || !sourceCode) return false;
  try {
    return !new RegExp(adv.appliesWhen.sourcePattern).test(sourceCode);
  } catch {
    return false; // a malformed pattern from a feed proves nothing
  }
}
