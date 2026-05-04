import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const PACKAGE_RUNNERS = new Set(['npx', 'pnpm', 'yarn', 'bunx', 'uvx', 'pipx']);
const PINNED = /@\d+\.\d+\.\d+/;
const SHA_PINNED = /(?:@sha256:|#[a-f0-9]{7,40})/i;
const SHELL_C = /^(?:bash|sh|zsh|fish|cmd|powershell|pwsh)$/i;

export const hm010 = defineCheck({
  id: 'HM-010',
  name: 'Hermes MCP Server Stdio Hardening',
  category: 'hermes',
  severity: 'warning',
  description: 'Detect MCP servers in mcp_servers.<name> launched via shell-c (`bash -c …`), running unpinned packages via npx/uvx/etc., or invoking a world-writable command path — supply-chain and TOCTOU vectors.',
  supportedAgents: ['hermes'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of ctx.configs) {
      if (!config.filePath.endsWith('cli-config.yaml') && !config.filePath.endsWith('config.yaml')) continue;
      const servers = config.data.mcp_servers as Record<string, unknown> | undefined;
      if (!servers || typeof servers !== 'object') continue;

      for (const [name, serverRaw] of Object.entries(servers)) {
        if (!serverRaw || typeof serverRaw !== 'object') continue;
        const server = serverRaw as Record<string, unknown>;
        const command = server.command;
        const args = server.args;
        if (typeof command !== 'string') continue;

        const argList = Array.isArray(args)
          ? (args as unknown[]).filter((a): a is string => typeof a === 'string')
          : [];
        const baseCmd = command.split('/').pop() ?? command;

        // Shell-c invocation: `bash -c "..."` lets injected args run anything
        if (SHELL_C.test(baseCmd) && argList.includes('-c')) {
          evidence.push({
            file: config.filePath,
            snippet: `mcp_servers.${name}: ${command} ${argList.join(' ')}`,
            detail: `MCP server invoked via "${baseCmd} -c …" — argv injection becomes shell injection`,
          });
        }

        // World-writable command path
        if (command.startsWith('/')) {
          try {
            const stat = await ctx.fs.stat(command);
            const perms = stat.mode & 0o777;
            if ((perms & 0o002) !== 0) {
              evidence.push({
                file: config.filePath,
                snippet: `${command} (mode 0${perms.toString(8)})`,
                detail: `MCP server command is world-writable — any local user can replace it before launch`,
              });
            }
          } catch {
            // Path doesn't exist on host — skip
          }
        }

        // Unpinned package runner
        if (PACKAGE_RUNNERS.has(baseCmd)) {
          const pkgArg = argList.find(a => !a.startsWith('-'));
          if (pkgArg && !PINNED.test(pkgArg) && !SHA_PINNED.test(pkgArg)) {
            evidence.push({
              file: config.filePath,
              snippet: `mcp_servers.${name}: ${command} ${argList.join(' ')}`,
              detail: `Runs "${pkgArg}" via ${baseCmd} with no version pin — supply-chain risk`,
            });
          }
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'Hermes MCP servers use safe stdio invocation and pinned packages',
      failed: (n) => `Found ${n} Hermes MCP server hygiene issue(s)`,
      fixDescription: 'Drop `bash -c` wrappers (invoke the binary directly), pin package versions (e.g. `@modelcontextprotocol/server-foo@1.2.3`), and ensure command paths are not world-writable',
    });
  },
});
