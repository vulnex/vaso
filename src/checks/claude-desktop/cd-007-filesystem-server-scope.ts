import { homedir } from 'node:os';
import { join, normalize } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const HOME = homedir();

interface SensitiveTarget {
  path: string;
  reason: string;
}

const SENSITIVE_TARGETS: SensitiveTarget[] = [
  { path: HOME, reason: 'entire user home directory — too broad' },
  { path: join(HOME, '.ssh'), reason: 'contains SSH private keys' },
  { path: join(HOME, '.aws'), reason: 'contains AWS credentials' },
  { path: join(HOME, '.gnupg'), reason: 'contains GPG private keys' },
  { path: join(HOME, '.kube'), reason: 'contains Kubernetes credentials' },
  { path: join(HOME, '.docker'), reason: 'contains Docker registry credentials' },
  { path: join(HOME, '.netrc'), reason: 'contains plaintext FTP/HTTP credentials' },
  { path: '/', reason: 'root of the filesystem — total exposure' },
  { path: '/etc', reason: 'system configuration directory' },
  { path: '/var', reason: 'system runtime/log directory' },
  { path: '/Library', reason: 'macOS system Library' },
];

const FILESYSTEM_SERVER_HINTS = ['filesystem', 'fs-mcp', 'mcp-filesystem'];

function expandHome(p: string): string {
  if (p === '~') return HOME;
  if (p.startsWith('~/')) return join(HOME, p.slice(2));
  return p;
}

function isFilesystemServer(name: string, command?: string, args?: string[]): boolean {
  const lower = name.toLowerCase();
  if (FILESYSTEM_SERVER_HINTS.some(h => lower.includes(h))) return true;
  // Filesystem MCP server typically wired up via `@modelcontextprotocol/server-filesystem`.
  const cmdLine = `${command ?? ''} ${(args ?? []).join(' ')}`;
  return /server-filesystem/i.test(cmdLine);
}

function matchesSensitive(dir: string): SensitiveTarget | undefined {
  const normalized = normalize(expandHome(dir));
  return SENSITIVE_TARGETS.find(t => normalized === t.path || normalized.startsWith(t.path + '/'));
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
          const match = matchesSensitive(p);
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
