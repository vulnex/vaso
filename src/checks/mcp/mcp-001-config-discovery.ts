import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { maskArgSecrets, maskUrlSecrets } from '../../mcp/config-secrets.js';
import { taintCoverage } from '../../analyzers/tool-input-taint.js';
import { join } from 'node:path';

export const mcp001 = defineCheck({
  id: 'MCP-001',
  name: 'MCP Config Discovery',
  category: 'mcp',
  severity: 'info',
  description: 'Inventory all configured MCP servers across all agent configs',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const mcpConfigs = ctx.mcpConfigs ?? [];

    for (const config of mcpConfigs) {
      for (const server of config.servers) {
        // The inventory quotes the URL and argv: a credential written there
        // (`/api/mcp/s/<secret>/`, `--token x`) is masked as MCP-003 finds it
        const detail = [
          `Transport: ${server.transport}`,
          server.command ? `Command: ${server.command}` : null,
          server.url ? `URL: ${maskUrlSecrets(server.url)}` : null,
          server.args?.length ? `Args: ${maskArgSecrets(server.args, server.command).join(' ')}` : null,
          server.env ? `Env vars: ${Object.keys(server.env).join(', ')}` : null,
        ].filter(Boolean).join(', ');

        evidence.push({
          file: config.filePath,
          snippet: `Server: ${server.name}`,
          detail,
        });
      }
    }

    const totalServers = mcpConfigs.reduce((sum, c) => sum + c.servers.length, 0);
    const found = totalServers === 0
      ? 'No MCP servers configured'
      : `Found ${totalServers} MCP server(s) across ${mcpConfigs.length} config(s)`;

    // Compiled servers (Go/Rust binaries): no source to analyze, so the
    // source checks pass them unseen. An info note — not an incomplete scan.
    const compiled = (ctx.mcpServerSources ?? []).filter((s) => s.compiledBinary);
    for (const s of compiled) {
      const kind = /executable|WebAssembly/.test(s.compiledBinary!) ? `compiled binary (${s.compiledBinary})` : s.compiledBinary!;
      evidence.push({
        file: s.localPath ?? s.serverName,
        snippet: `Server: ${s.serverName} (compiled binary, source not analysed)`,
        detail: `${kind} — source not analysed`,
      });
    }
    // Local code the source checks could not see: a missing entry file,
    // inline (`node -e`) or remote (`deno run https://…`) code
    const unanalyzed = (ctx.mcpServerSources ?? []).filter((s) => s.unanalyzed);
    for (const s of unanalyzed) {
      evidence.push({
        file: s.localPath ?? s.serverName,
        snippet: `Server: ${s.serverName} (source not analysed)`,
        detail: `${s.unanalyzed} — source not analysed`,
      });
    }
    // Modules a server's tool handlers import that cross-module tracing left
    // out (size limit): tool input reaching them is not traced (MCP-004/005/009)
    let incomplete = 0;
    for (const s of ctx.mcpServerSources ?? []) {
      if (!s.sourceCode || s.language === 'python') continue;
      const { untraced } = taintCoverage(s.sourceCode);
      if (untraced.length > 0) incomplete++;
      for (const m of untraced) {
        const file = s.sourceRoot ? join(s.sourceRoot, m.path) : s.packageName ? `${s.packageName}/${m.path}` : m.path;
        evidence.push({
          file,
          snippet: `Server: ${s.serverName} (cross-module analysis incomplete)`,
          detail: `cross-module analysis incomplete: ${m.path} not followed from ${m.from} (size limit) — tool input reaching it is not traced`,
        });
      }
    }
    if (compiled.length > 0 || unanalyzed.length > 0 || incomplete > 0) {
      const notes = [
        compiled.length > 0 ? `${compiled.length} run a compiled binary` : null,
        unanalyzed.length > 0 ? `${unanalyzed.length} name no source this scan could read` : null,
        incomplete > 0 ? `${incomplete} not traced across all their modules (size limit)` : null,
      ].filter(Boolean).join(', ');
      return h.result({
        passed: false,
        message: `${found}; ${notes} — source not ${compiled.length + unanalyzed.length > 0 ? 'analysed' : 'fully analysed'}`,
        evidence,
      });
    }

    return h.result({
      passed: true,
      message: found,
      evidence,
    });
  },
});
