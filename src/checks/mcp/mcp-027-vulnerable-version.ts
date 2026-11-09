import { createHash } from 'node:crypto';
import type { Evidence, Severity } from '../../core/types.js';
import type { MCPServerEntry } from '../../mcp/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getAdvisoryDatabase } from '../../advisory/database.js';
import { satisfies, parseSemVer, compareSemVer } from '../../core/semver.js';
import { defaultMcpStateStore } from '../../mcp/mcp-state-store.js';
import { fullVersion, rangeEntirelyAffected } from '../../core/version-range.js';
import type { Advisory } from '../../advisory/advisory-types.js';
import { DEPRECATED_NPM_PACKAGES } from '../../advisory/library-advisories.js';
import { advisoryAppliesToPlatform } from '../../advisory/applicability.js';
import { runnerPackage } from '../../mcp/package-pin.js';

/**
 * MCP-027 — Vulnerable / Rolled-Back MCP Version.
 *
 * Update-phase risks from Hou et al. arXiv 2503.23278 §5.3.2: re-deploying a
 * known-vulnerable MCP server version, or rolling a server back to an older
 * version (silently undoing a security fix). Three detections:
 *  - advisory match: the pinned `pkg@version` matches a dependency advisory.
 *  - rollback: the pinned version is lower than the highest version previously
 *    seen for that package (tracked in the cross-scan state store).
 *  - shipped dependency: a package the server's project ships with (the MCP
 *    SDK, …) matches an advisory — exact versions from the installed copy or
 *    lockfile, a declared range only when every version it admits is affected.
 *    An advisory scoped to a feature the server's code doesn't use is reported
 *    as mitigated.
 *
 * MCP-010 covers *unpinned* packages; this covers *pinned-but-bad* versions.
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
 * The package a server's runner installs (npx, bunx, `pnpm dlx`, `npm exec`,
 * uvx, `pipx run`, … — via runnerPackage()), with its version when the spec
 * pins one exactly (`pkg@1.2.3`, `pkg==1.2.3`, `--from pkg==1.2.3`).
 */
export function pinnedRunnerPackage(server: MCPServerEntry): { name: string; ecosystem: 'npm' | 'pypi'; version?: string } | undefined {
  const pkg = runnerPackage(server.command, server.args);
  if (!pkg || pkg.pin === 'local') return undefined;
  const base = { name: pkg.name, ecosystem: pkg.ecosystem };
  if (pkg.pin !== 'exact') return base;
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

    for (const config of ctx.mcpConfigs ?? []) {
      for (const server of config.servers) {
        const pkg = pinnedRunnerPackage(server);
        if (!pkg?.version) continue; // unpinned — MCP-010's job

        const { ecosystem, version } = pkg;
        const name = packageKey(pkg.name, ecosystem);
        const parsed = parseSemVer(version);

        // 1) Known-vulnerable version (advisory database).
        for (const adv of depAdvisories) {
          const dep = adv.affectedDependency!;
          const depEcosystem = dep.ecosystem ?? 'npm';
          if (depEcosystem !== ecosystem || packageKey(dep.name, depEcosystem) !== name) continue;
          if (!satisfies(version, dep.versionConstraint)) continue;
          if (adv.severity === 'critical') maxSeverity = 'critical';
          evidence.push({
            file: config.filePath,
            snippet: `Server "${server.name}": ${name}@${version}`,
            detail: `${adv.id}: ${name}@${version} is affected by "${adv.title}" (severity: ${adv.severity}${adv.fixedVersion ? `, fix: ${adv.fixedVersion}` : ''})`,
          });
        }

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
    let liveWarning = evidence.length > 0;
    for (const source of ctx.mcpServerSources ?? []) {
      for (const dep of source.dependencies ?? []) {
        const shown = dep.version ? `${dep.name}@${dep.version}` : `${dep.name} ${dep.range}`;
        const reported = new Set<string>();
        for (const adv of depAdvisories) {
          const target = adv.affectedDependency!;
          if (target.name !== dep.name || (target.ecosystem ?? 'npm') !== dep.ecosystem) continue;
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
