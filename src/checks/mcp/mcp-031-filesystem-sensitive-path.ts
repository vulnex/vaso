import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

/**
 * MCP-031 — Filesystem Server Sensitive-Path Scope.
 *
 * MCP filesystem-style servers take the directories they may read/write as
 * arguments. When that scope reaches credential stores or shell startup files
 * (~/.ssh/authorized_keys, ~/.aws, ~/.bashrc, /etc), a tool-poisoning or
 * injected instruction turns into remote access / persistence / credential
 * theft — exactly the Malicious-Code-Execution, Remote-Access-Control and
 * Credential-Theft chains demonstrated in arXiv 2504.03767 (appsecco lab 1).
 *
 * This is the sharp, critical-severity sink detector; MCP-009 remains the
 * generic broad-scope (root/home) warning, so bare "/" or "~" grants are left
 * to it to avoid double-flagging.
 */

interface SinkPattern {
  re: RegExp;
  label: string;
}

const SENSITIVE_SINKS: SinkPattern[] = [
  { re: /(^|\/)\.ssh(\/|$)/i, label: 'SSH keys/config (~/.ssh)' },
  { re: /authorized_keys/i, label: 'SSH authorized_keys (remote-access persistence)' },
  { re: /(^|\/)\.aws(\/|$)/i, label: 'AWS credentials (~/.aws)' },
  { re: /(^|\/)\.gnupg(\/|$)/i, label: 'GnuPG keyring (~/.gnupg)' },
  { re: /(^|\/)\.kube(\/|$)/i, label: 'Kubernetes credentials (~/.kube)' },
  { re: /(^|\/)\.docker(\/|$)/i, label: 'Docker credentials (~/.docker)' },
  { re: /(^|\/)\.(bashrc|bash_profile|bash_login|bash_logout|profile|zshrc|zprofile|zshenv|zlogin)$/i, label: 'shell startup file (code-execution persistence)' },
  { re: /^\/etc(\/|$)/i, label: 'system configuration (/etc)' },
];

function classifyArg(arg: string): string[] {
  if (!arg || arg.startsWith('-')) return [];
  return SENSITIVE_SINKS.filter((s) => s.re.test(arg)).map((s) => s.label);
}

export const mcp031 = defineCheck({
  id: 'MCP-031',
  name: 'Filesystem Server Sensitive-Path Scope',
  category: 'mcp',
  severity: 'critical',
  description:
    'Detect MCP servers granted access to credential stores or shell startup files (~/.ssh, ~/.aws, ~/.bashrc, /etc)',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.mcpConfigs ?? []) {
      for (const server of config.servers) {
        const candidates: string[] = [];
        if (server.command) candidates.push(server.command);
        if (server.args) candidates.push(...server.args);

        const hits = new Map<string, Set<string>>(); // label -> args
        for (const arg of candidates) {
          for (const label of classifyArg(arg)) {
            if (!hits.has(label)) hits.set(label, new Set());
            hits.get(label)!.add(arg);
          }
        }

        for (const [label, args] of hits) {
          evidence.push({
            file: config.filePath,
            snippet: `Server "${server.name}": ${[...args].join(', ')}`,
            detail: `MCP server "${server.name}" is scoped to ${label} — a poisoned tool or injected instruction can use this to gain persistence, exfiltrate credentials, or achieve code execution`,
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No MCP servers are scoped to credential stores or shell startup files',
      failed: (n) => `Found ${n} MCP server path grant(s) reaching credential stores or shell startup files`,
      fixDescription:
        'Restrict the server to a dedicated project/workspace directory; never grant an MCP server access to ~/.ssh, ~/.aws, ~/.gnupg, shell rc files, or /etc',
    });
  },
});
