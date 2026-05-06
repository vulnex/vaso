import { join, normalize } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

interface SensitiveTarget {
  path: string;
  reason: string;
}

function buildSensitiveTargets(home: string): SensitiveTarget[] {
  return [
    { path: home, reason: 'entire user home directory — too broad' },
    { path: join(home, '.ssh'), reason: 'contains SSH private keys' },
    { path: join(home, '.aws'), reason: 'contains AWS credentials' },
    { path: join(home, '.gnupg'), reason: 'contains GPG private keys' },
    { path: join(home, '.kube'), reason: 'contains Kubernetes credentials' },
    { path: join(home, '.docker'), reason: 'contains Docker registry credentials' },
    { path: join(home, '.netrc'), reason: 'contains plaintext FTP/HTTP credentials' },
    { path: '/', reason: 'root of the filesystem — total exposure' },
    { path: '/etc', reason: 'system configuration directory' },
    { path: '/var', reason: 'system runtime/log directory' },
    { path: '/Library', reason: 'macOS system Library' },
  ];
}

const FILESYSTEM_SERVER_HINTS = ['filesystem', 'fs-mcp', 'mcp-filesystem'];

function expandHome(p: string, home: string): string {
  if (p === '~') return home;
  if (p.startsWith('~/')) return join(home, p.slice(2));
  return p;
}

function isFilesystemServer(name: string, command?: string, args?: string[]): boolean {
  const lower = name.toLowerCase();
  if (FILESYSTEM_SERVER_HINTS.some(h => lower.includes(h))) return true;
  // Filesystem MCP server typically wired up via `@modelcontextprotocol/server-filesystem`.
  const cmdLine = `${command ?? ''} ${(args ?? []).join(' ')}`;
  return /server-filesystem/i.test(cmdLine);
}

function matchesSensitive(dir: string, targets: SensitiveTarget[], home: string): SensitiveTarget | undefined {
  const normalized = normalize(expandHome(dir, home));
  return targets.find(t => normalized === t.path || normalized.startsWith(t.path + '/'));
}

export const cd007 = defineCheck({
  id: 'CD-007',
  name: 'Sensitive Filesystem Server Scope',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect MCP filesystem servers granted access to credential or system directories',
  supportedAgents: ['claude-desktop'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const home = ctx.fs.homedir();
    const sensitiveTargets = buildSensitiveTargets(home);

    for (const config of ctx.configs) {
      const mcpServers = config.data.mcpServers as Record<string, unknown> | undefined;
      if (!mcpServers || typeof mcpServers !== 'object') continue;

      for (const [name, srv] of Object.entries(mcpServers)) {
        if (!srv || typeof srv !== 'object') continue;
        const server = srv as Record<string, unknown>;
        const command = typeof server.command === 'string' ? server.command : undefined;
        const args = Array.isArray(server.args)
          ? (server.args as unknown[]).filter((a): a is string => typeof a === 'string')
          : [];
        if (!isFilesystemServer(name, command, args)) continue;

        // Filesystem server scope is the trailing positional path args.
        const pathArgs = args.filter(a => a.startsWith('/') || a.startsWith('~') || a.startsWith('./') || a.startsWith('../'));
        for (const p of pathArgs) {
          const match = matchesSensitive(p, sensitiveTargets, home);
          if (match) {
            evidence.push({
              file: config.filePath,
              snippet: `mcpServers.${name} → ${p}`,
              detail: `Filesystem server granted ${match.path} — ${match.reason}`,
            });
          }
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No MCP filesystem servers granted sensitive paths',
      failed: (n) => `Found ${n} filesystem server scope(s) covering sensitive paths`,
      fixDescription: 'Narrow filesystem server args to a dedicated working directory; never include $HOME, /etc, ~/.ssh, or ~/.aws',
    });
  },
});
