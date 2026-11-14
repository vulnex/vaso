import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { buildBroadPaths, isBroadPath } from '../../analyzers/broad-paths.js';
import { codexTrustedProjects, isCollectedProjectRoot } from '../../adapters/codex.js';

function extractTrustedPaths(data: Record<string, unknown>): string[] {
  const paths: string[] = [];

  // Form: trusted_projects = ["path1", "path2"]
  const arr = (data.trusted_projects ?? data.trustedProjects) as unknown;
  if (Array.isArray(arr)) {
    for (const p of arr) if (typeof p === 'string') paths.push(p);
  }

  // Form: [projects."/path"] trust_level = "trusted"
  const projects = data.projects as Record<string, unknown> | undefined;
  if (projects && typeof projects === 'object') {
    for (const [path, entry] of Object.entries(projects)) {
      if (!entry || typeof entry !== 'object') continue;
      const trust = (entry as Record<string, unknown>).trust_level
        ?? (entry as Record<string, unknown>).trustLevel;
      if (typeof trust === 'string' && trust.toLowerCase() === 'trusted') {
        paths.push(path);
      }
    }
  }

  return paths;
}

export const cdx006 = defineCheck({
  id: 'CDX-006',
  name: 'Codex Trusted Projects Too Broad',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect Codex trusted_projects entries that grant approval bypass over /, $HOME, /tmp, or /etc',
  supportedAgents: ['codex'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const home = ctx.fs.homedir();
    const broadPaths = buildBroadPaths(home);

    for (const config of ctx.configs) {
      const paths = extractTrustedPaths(config.data);
      for (const p of paths) {
        const broad = isBroadPath(p, broadPaths, home);
        if (broad) {
          evidence.push({
            file: config.filePath,
            snippet: p,
            detail: `Trusted project path "${p}" ${broad.reason} — defeats the approval prompt for any tool run inside it`,
          });
        }
      }
    }

    // A remote scan sees a trusted project's `.codex/` layer only in the
    // usual clone locations (the probe can't read the list before it runs)
    const unverified = ctx.fs.kind === 'snapshot' && ctx.installation.profile !== 'project'
      ? codexTrustedProjects(ctx.configs).filter(p => !isCollectedProjectRoot(p, home))
      : [];
    const note = unverified.length > 0
      ? `; .codex layer of trusted project(s) ${unverified.join(', ')} not verified — the probe doesn't collect it (checked on local scans)`
      : '';

    return h.fromEvidence(evidence, {
      passed: `Codex trusted projects scope is reasonable${note}`,
      failed: (n) => `Found ${n} overly broad trusted project path(s)`,
      fixDescription: 'Trust specific project directories (e.g. ~/code/myrepo), not /, $HOME, or /tmp',
    });
  },
});
