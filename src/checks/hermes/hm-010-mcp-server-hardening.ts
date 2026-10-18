import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { runnerPackage, isPinnedOrLocal, pinProblem } from '../../mcp/package-pin.js';
import { shellCommandWrapper, shellInvocation } from '../../mcp/shell-wrapper.js';
import { queryPermissions } from '../../core/permissions.js';
import { managedOverride, markManagedOverride } from '../../adapters/hermes-managed.js';


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

        // The administrator-managed layer replacing this server's command or args launches something else
        const managed = managedOverride(ctx.configs, config, ['mcp_servers', name, 'command'])
          ?? managedOverride(ctx.configs, config, ['mcp_servers', name, 'args']);
        const push = (e: Evidence) => evidence.push(markManagedOverride(e, managed));

        const argList = Array.isArray(args)
          ? (args as unknown[]).filter((a): a is string => typeof a === 'string')
          : [];

        // Shell-c invocation: `bash -c "..."` lets injected args run anything
        if (shellCommandWrapper(command, argList)) {
          push({
            file: config.filePath,
            snippet: `mcp_servers.${name}: ${command} ${argList.join(' ')}`,
            detail: `MCP server invoked via "${shellInvocation(shellCommandWrapper(command, argList)!, argList)} …" — argv injection becomes shell injection`,
          });
        }

        // World-writable command path
        if (command.startsWith('/')) {
          try {
            const perms = await queryPermissions(ctx.fs, command);
            if (perms !== 'unsupported' && perms.worldWrite) {
              push({
                file: config.filePath,
                snippet: `${command} (mode 0${perms.octal})`,
                detail: `MCP server command is world-writable — any local user can replace it before launch`,
              });
            }
          } catch {
            // Path doesn't exist on host — skip
          }
        }

        // Unpinned package runner
        const pkg = runnerPackage(command, argList);
        if (pkg && !isPinnedOrLocal(pkg)) {
          push({
            file: config.filePath,
            snippet: `mcp_servers.${name}: ${command} ${argList.join(' ')}`,
            detail: `${pinProblem(pkg)} — supply-chain risk`,
          });
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
