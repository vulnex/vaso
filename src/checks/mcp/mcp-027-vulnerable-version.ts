import type { Evidence, Severity } from '../../core/types.js';
import type { MCPServerEntry } from '../../mcp/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getAdvisoryDatabase } from '../../advisory/database.js';
import { satisfies, parseSemVer, compareSemVer } from '../../core/semver.js';
import { defaultMcpStateStore } from '../../mcp/mcp-state-store.js';

/**
 * MCP-027 — Vulnerable / Rolled-Back MCP Version.
 *
 * Update-phase risks from Hou et al. arXiv 2503.23278 §5.3.2: re-deploying a
 * known-vulnerable MCP server version, or rolling a server back to an older
 * version (silently undoing a security fix). Two detections:
 *  - advisory match: the pinned `pkg@version` matches a dependency advisory.
 *  - rollback: the pinned version is lower than the highest version previously
 *    seen for that package (tracked in the cross-scan state store).
 *
 * MCP-010 covers *unpinned* packages; this covers *pinned-but-bad* versions.
 */

const NPM_RUNNERS = new Set(['npx', 'npx.cmd']);
const SKIP_ARGS = new Set(['-y', '--yes']);

interface VersionState {
  highest: string;
}

function parsePackageSpec(spec: string): { name: string; version?: string } {
  const at = spec.lastIndexOf('@');
  if (at > 0) return { name: spec.slice(0, at), version: spec.slice(at + 1) };
  return { name: spec };
}

function npmInstallSpec(server: MCPServerEntry): string | undefined {
  const cmd = server.command ? basename(server.command) : undefined;
  if (!cmd || !NPM_RUNNERS.has(cmd)) return undefined;
  for (const arg of server.args ?? []) {
    if (arg.startsWith('-') || SKIP_ARGS.has(arg)) continue;
    return arg;
  }
  return undefined;
}

export const mcp027 = defineCheck({
  id: 'MCP-027',
  name: 'Vulnerable / Rolled-Back MCP Version',
  category: 'mcp',
  severity: 'warning',
  description:
    'Detect MCP server packages pinned to a known-vulnerable version or rolled back below a previously-seen version',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    let maxSeverity: Severity = 'warning';

    const db = getAdvisoryDatabase();
    const depAdvisories = db.advisories.filter((a) => a.affectedDependency);
    const store = ctx.mcpStateStore ?? defaultMcpStateStore();

    for (const config of ctx.mcpConfigs ?? []) {
      for (const server of config.servers) {
        const spec = npmInstallSpec(server);
        if (!spec) continue;

        const { name, version } = parsePackageSpec(spec);
        if (!version) continue; // unpinned — MCP-010's job

        const parsed = parseSemVer(version);

        // 1) Known-vulnerable version (advisory database).
        for (const adv of depAdvisories) {
          const dep = adv.affectedDependency!;
          if (dep.name !== name) continue;
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
          const key = `version-${name}`;
          const prev = await store.load<VersionState>(key);
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

    return h.result({
      passed: evidence.length === 0,
      severity: maxSeverity,
      message:
        evidence.length === 0
          ? 'No MCP server packages are on a known-vulnerable or rolled-back version'
          : `Found ${evidence.length} MCP server version issue(s) — known-vulnerable or rolled-back package(s)`,
      evidence,
      fixDescription:
        'Pin MCP servers to a current, non-vulnerable release; never roll a server back below a version that carried a security fix',
    });
  },
});

function basename(p: string): string {
  const idx = Math.max(p.lastIndexOf('/'), p.lastIndexOf('\\'));
  return idx >= 0 ? p.slice(idx + 1) : p;
}
