import { homedir } from 'node:os';
import { normalize } from 'node:path';
import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';

const HOME = homedir();

interface BroadPath {
  path: string;
  reason: string;
}

const BROAD_PATHS: BroadPath[] = [
  { path: '/', reason: 'covers the entire filesystem' },
  { path: HOME, reason: 'covers the entire home directory' },
  { path: '/tmp', reason: 'shared by all local users' },
  { path: '/var/tmp', reason: 'shared by all local users' },
  { path: '/etc', reason: 'system configuration directory' },
];

function expandHome(p: string): string {
  if (p === '~') return HOME;
  if (p.startsWith('~/')) return `${HOME}/${p.slice(2)}`;
  return p;
}

function isBroad(rawPath: string): BroadPath | undefined {
  const normalized = normalize(expandHome(rawPath));
  return BROAD_PATHS.find(b => normalized === b.path);
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

export const cdx006: CheckModule = {
  id: 'CDX-006',
  name: 'Codex Trusted Projects Too Broad',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect Codex trusted_projects entries that grant approval bypass over /, $HOME, /tmp, or /etc',
  supportedAgents: ['codex'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const paths = extractTrustedPaths(config.data);
      for (const p of paths) {
        const broad = isBroad(p);
        if (broad) {
          evidence.push({
            file: config.filePath,
            snippet: p,
            detail: `Trusted project path "${p}" ${broad.reason} — defeats the approval prompt for any tool run inside it`,
          });
        }
      }
    }

    return {
      id: 'CDX-006',
      name: 'Codex Trusted Projects Too Broad',
      category: 'coding-agent',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'Codex trusted projects scope is reasonable'
        : `Found ${evidence.length} overly broad trusted project path(s)`,
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: false,
      fixDescription: 'Trust specific project directories (e.g. ~/code/myrepo), not /, $HOME, or /tmp',
    };
  },
};
