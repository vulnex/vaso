import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { notCollectedNote } from '../../core/probe-coverage.js';
import { writableLaunchPaths, writableLaunchText } from '../../mcp/writable-command.js';

/**
 * MCP servers whose command (or the script an interpreter command runs) any
 * local user can replace before launch. Judged through the shared
 * `writableLaunchPaths` (as CD-009, HM-010 and AT-007 are): every interpreter
 * and wrapper (`python3.12 x.py`, `uv run x.py`, `env cmd`), the path as the
 * kernel reads it (`//tmp`, `/./tmp`, `..` through links), any world-writable
 * directory on the way (not only /tmp), sticky bits and owners.
 *
 * Severity: critical when any local user can swap or plant it; warning when
 * only one other user (owner of the file or of the sticky directory) can;
 * info when every finding sits behind a directory other users can't traverse.
 */
export const mcp022 = defineCheck({
  id: 'MCP-022',
  name: 'Server Command in World-Writable Path',
  category: 'mcp',
  severity: 'critical',
  description: 'Detect MCP servers whose command (or interpreter script) any local user can replace — world-writable, or in a world-writable directory such as /tmp or /var/tmp',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const unverified: string[] = [];
    let anyUser = false;

    for (const config of ctx.mcpConfigs ?? []) {
      for (const server of config.servers) {
        if (!server.command) continue;
        for (const w of await writableLaunchPaths(ctx.fs, server.command, server.args ?? [], unverified, { config: config.filePath })) {
          const { where, detail, mitigated } = writableLaunchText(w);
          const v = w.writable;
          if (!mitigated && !(v.kind === 'directory' && (v.foreignOwner || v.foreignDirOwner))) anyUser = true;
          evidence.push({
            file: config.filePath,
            snippet: `Server "${server.name}": ${w.role === 'command' ? 'command' : 'script'} ${w.path}${where}`,
            detail,
            ...(mitigated ? { mitigated } : {}),
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: unverified.length > 0
        ? notCollectedNote('MCP command path(s)', unverified)
        : 'No MCP servers run from world-writable paths',
      failed: (n) => `Found ${n} MCP server command(s) or script(s) on world-writable paths${unverified.length > 0 ? `; ${notCollectedNote('command path(s)', unverified)}` : ''}`,
      severity: anyUser ? 'critical' : 'warning',
      fixDescription: 'Move the server binary or script to a user-owned directory (e.g. ~/.local/bin or a project venv) and chmod o-w its directories; never run from /tmp',
    });
  },
});
