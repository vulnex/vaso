import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const PACKAGE_RUNNERS = new Set(['npx', 'pnpm', 'yarn', 'bunx', 'uvx', 'pipx']);
const PINNED_PACKAGE = /@\d+\.\d+\.\d+/;
const SHA_PINNED = /(?:@sha256:|#[a-f0-9]{7,40})/i;

interface LocalServer {
  type?: string;
  command?: unknown;
}

interface RemoteServer {
  type?: string;
  url?: unknown;
  oauth?: unknown;
}

function checkLocal(name: string, server: LocalServer, file: string, evidence: Evidence[]): void {
  const cmd = server.command;
  if (!Array.isArray(cmd) || cmd.length === 0) return;
  const exec = cmd[0];
  if (typeof exec !== 'string') return;

  const baseCmd = exec.split('/').pop() ?? exec;

  // (a) Bare runner with no version pin → supply chain risk
  if (PACKAGE_RUNNERS.has(baseCmd)) {
    const pkgArg = cmd.slice(1).find(a => typeof a === 'string' && !a.startsWith('-')) as string | undefined;
    if (pkgArg && !PINNED_PACKAGE.test(pkgArg) && !SHA_PINNED.test(pkgArg)) {
      evidence.push({
        file,
        snippet: `mcp.${name}.command = ${cmd.join(' ')}`,
        detail: `MCP server runs "${pkgArg}" via ${baseCmd} with no version pin — supply chain risk`,
      });
    }
    return;
  }

  // (b) Bare bin name (not absolute, not ./relative) → PATH injection risk
  if (!exec.startsWith('/') && !exec.startsWith('./') && !exec.startsWith('../') && !exec.startsWith('~')) {
    evidence.push({
      file,
      snippet: `mcp.${name}.command = ${exec}`,
      detail: `MCP server "${name}" launches bare binary "${exec}" — first match on PATH wins`,
    });
  }
}

function checkRemote(name: string, server: RemoteServer, file: string, evidence: Evidence[]): void {
  const url = server.url;
  if (typeof url !== 'string') return;
  if (url.startsWith('http://')) {
    evidence.push({
      file,
      snippet: `mcp.${name}.url = ${url}`,
      detail: `Remote MCP server uses plaintext HTTP — credentials and tool calls travel unencrypted`,
    });
  }
}

export const opc003 = defineCheck({
  id: 'OPC-003',
  name: 'OpenCode MCP Server Pinning & Transport',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect unpinned MCP packages, bare-binary MCP launchers, and plaintext-HTTP remote MCP endpoints',
  supportedAgents: ['opencode'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const mcp = config.data.mcp;
      if (!mcp || typeof mcp !== 'object') continue;

      for (const [name, srv] of Object.entries(mcp as Record<string, unknown>)) {
        if (!srv || typeof srv !== 'object') continue;
        const obj = srv as Record<string, unknown>;
        if (obj.type === 'local') {
          checkLocal(name, obj as LocalServer, config.filePath, evidence);
        } else if (obj.type === 'remote') {
          checkRemote(name, obj as RemoteServer, config.filePath, evidence);
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'OpenCode MCP servers are pinned and use safe transports',
      failed: (n) => `Found ${n} OpenCode MCP server issue(s)`,
      fixDescription: 'Use absolute paths for local MCP commands, pin npx/uvx packages, and prefer https:// for remote MCP URLs',
    });
  },
});
