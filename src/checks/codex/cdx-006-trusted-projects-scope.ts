import { normalize } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

interface BroadPath {
  path: string;
  reason: string;
}

function buildBroadPaths(home: string): BroadPath[] {
  return [
    { path: '/', reason: 'covers the entire filesystem' },
    { path: home, reason: 'covers the entire home directory' },
    { path: '/tmp', reason: 'shared by all local users' },
    { path: '/var/tmp', reason: 'shared by all local users' },
    { path: '/etc', reason: 'system configuration directory' },
  ];
}

function expandHome(p: string, home: string): string {
  if (p === '~') return home;
  if (p.startsWith('~/')) return `${home}/${p.slice(2)}`;
  return p;
}

function isBroad(rawPath: string, broadPaths: BroadPath[], home: string): BroadPath | undefined {
  const normalized = normalize(expandHome(rawPath, home));
  return broadPaths.find(b => normalized === b.path);
}

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
        const broad = isBroad(p, broadPaths, home);
        if (broad) {
          evidence.push({
            file: config.filePath,
            snippet: p,
            detail: `Trusted project path "${p}" ${broad.reason} — defeats the approval prompt for any tool run inside it`,
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Codex trusted projects scope is reasonable',
      failed: (n) => `Found ${n} overly broad trusted project path(s)`,
      fixDescription: 'Trust specific project directories (e.g. ~/code/myrepo), not /, $HOME, or /tmp',
    });
  },
});
