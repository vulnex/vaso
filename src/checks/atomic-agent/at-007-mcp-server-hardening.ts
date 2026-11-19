import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { runnerPackage, isPinnedOrLocal, pinProblem } from '../../mcp/package-pin.js';
import { shellCommandWrapper, shellInvocation } from '../../mcp/shell-wrapper.js';
import { notCollectedNote } from '../../core/probe-coverage.js';
import { writableLaunchPaths, writableLaunchText } from '../../mcp/writable-command.js';
import { asRecord, atomicConfigs, isEnabled, isLoopbackHost, mcpServers, serverName, urlHost } from './shared.js';


export const at007 = defineCheck({
  id: 'AT-007',
  name: 'Atomic Agent MCP Server Hardening',
  category: 'atomic-agent',
  severity: 'warning',
  description: 'Detect enabled mcp.servers[] launched via shell-c (`bash -c …`), running unpinned packages via npx/uvx/etc., invoking a command any local user can replace (world-writable, or in a world-writable directory), or reached over plaintext http:// to a non-loopback host (streamable_http / sse transports) — supply-chain, TOCTOU and interception vectors.',
  supportedAgents: ['atomic-agent'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const unverified: string[] = [];
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
        const invocation = `${command} ${argList.join(' ')}`.trim();

        if (shellCommandWrapper(command, argList)) {
          evidence.push({
            file: config.filePath,
            snippet: `mcp.servers[${name}]: ${invocation}`,
            detail: `MCP server invoked via "${shellInvocation(shellCommandWrapper(command, argList)!, argList)} …" — argv injection becomes shell injection`,
          });
        }

        // A command (or the script an interpreter runs) any local user can
        // replace; on a snapshot, a path the probe didn't record: unknown, not safe
        for (const w of await writableLaunchPaths(ctx.fs, command, argList, unverified, { config: config.filePath })) {
          const { where, detail, mitigated } = writableLaunchText(w);
          evidence.push({
            file: config.filePath,
            snippet: `mcp.servers[${name}].transport.${w.role === 'command' ? 'command' : 'args'} = ${w.path}${where}`,
            detail,
            ...(mitigated ? { mitigated } : {}),
          });
        }

        const pkg = runnerPackage(command, argList);
        if (pkg && !isPinnedOrLocal(pkg)) {
          evidence.push({
            file: config.filePath,
            snippet: `mcp.servers[${name}]: ${invocation}`,
            detail: `${pinProblem(pkg)} — every launch may fetch a different release`,
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: unverified.length > 0
        ? `Atomic Agent MCP servers use safe invocation, pinned packages and encrypted transport; ${notCollectedNote('command path(s)', unverified)}`
        : 'Atomic Agent MCP servers use safe invocation, pinned packages and encrypted transport',
      failed: (n) => `Found ${n} Atomic Agent MCP server hygiene issue(s)${unverified.length > 0 ? `; ${notCollectedNote('command path(s)', unverified)}` : ''}`,
      fixDescription: 'Invoke server binaries directly (no `bash -c`), pin package versions (e.g. `@modelcontextprotocol/server-foo@1.2.3`), keep command paths non-world-writable, and use https:// for remote servers',
    });
  },
});
