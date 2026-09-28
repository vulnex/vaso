import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { queryPermissions } from '../../core/permissions.js';
import { asRecord, atomicConfigs, isEnabled, isLoopbackHost, mcpServers, serverName, urlHost } from './shared.js';

const PACKAGE_RUNNERS = new Set(['npx', 'pnpm', 'yarn', 'bunx', 'uvx', 'pipx']);
const PINNED = /@\d+\.\d+\.\d+/;
const SHA_PINNED = /(?:@sha256:|#[a-f0-9]{7,40})/i;
const PYPI_PINNED = /==\d/;
const SHELL_C = /^(?:bash|sh|zsh|fish|cmd|powershell|pwsh)$/i;

export const at007 = defineCheck({
  id: 'AT-007',
  name: 'Atomic Agent MCP Server Hardening',
  category: 'atomic-agent',
  severity: 'warning',
  description: 'Detect enabled mcp.servers[] launched via shell-c (`bash -c …`), running unpinned packages via npx/uvx/etc., invoking a world-writable command path, or reached over plaintext http:// to a non-loopback host (streamable_http / sse transports) — supply-chain, TOCTOU and interception vectors.',
  supportedAgents: ['atomic-agent'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of atomicConfigs(ctx.configs)) {
      const servers = mcpServers(config.data);
      for (let i = 0; i < servers.length; i++) {
        const server = servers[i];
        if (!isEnabled(server)) continue;
        const name = serverName(server, i);
        const transport = asRecord(server.transport);
        if (!transport) continue;

        if (transport.kind === 'streamable_http' || transport.kind === 'sse') {
          const url = typeof transport.url === 'string' ? transport.url : '';
          const host = urlHost(url);
          if (url.toLowerCase().startsWith('http://') && host && !isLoopbackHost(host)) {
            evidence.push({
              file: config.filePath,
              snippet: `mcp.servers[${name}].transport.url: ${url}`,
              detail: `MCP server "${name}" is reached over plaintext HTTP — tool calls, results and any auth headers can be read or altered in transit`,
            });
          }
          continue;
        }

        const command = transport.command;
        if (typeof command !== 'string') continue;
        const argList = Array.isArray(transport.args)
          ? (transport.args as unknown[]).filter((a): a is string => typeof a === 'string')
          : [];
        const baseCmd = command.split('/').pop() ?? command;
        const invocation = `${command} ${argList.join(' ')}`.trim();

        if (SHELL_C.test(baseCmd) && argList.includes('-c')) {
          evidence.push({
            file: config.filePath,
            snippet: `mcp.servers[${name}]: ${invocation}`,
            detail: `MCP server invoked via "${baseCmd} -c …" — argv injection becomes shell injection`,
          });
        }

        if (command.startsWith('/')) {
          try {
            const perms = await queryPermissions(ctx.fs, command);
            if (perms !== 'unsupported' && perms.worldWrite) {
              evidence.push({
                file: config.filePath,
                snippet: `${command} (mode 0${perms.octal})`,
                detail: 'MCP server command is world-writable — any local user can replace it before launch',
              });
            }
          } catch {
            // Path doesn't exist on host — skip
          }
        }

        if (PACKAGE_RUNNERS.has(baseCmd)) {
          const pkgArg = argList.find(a => !a.startsWith('-'));
          if (pkgArg && !PINNED.test(pkgArg) && !SHA_PINNED.test(pkgArg) && !PYPI_PINNED.test(pkgArg)) {
            evidence.push({
              file: config.filePath,
              snippet: `mcp.servers[${name}]: ${invocation}`,
              detail: `Runs "${pkgArg}" via ${baseCmd} with no version pin — every launch may fetch a different release`,
            });
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'Atomic Agent MCP servers use safe invocation, pinned packages and encrypted transport',
      failed: (n) => `Found ${n} Atomic Agent MCP server hygiene issue(s)`,
      fixDescription: 'Invoke server binaries directly (no `bash -c`), pin package versions (e.g. `@modelcontextprotocol/server-foo@1.2.3`), keep command paths non-world-writable, and use https:// for remote servers',
    });
  },
});
