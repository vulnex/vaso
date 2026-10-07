import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { buildBroadPaths, isBroadPath } from '../../analyzers/broad-paths.js';
import { classifySensitivePath } from '../../analyzers/sensitive-paths.js';
import { markUntrustedProject, settingsConfigs } from './shared.js';

// Rules are `Tool` or `Tool(pattern)` — e.g. `Bash(git log *)`, `Read`, `Edit(src/**)`.
const RULE = /^([A-Za-z_]+)\s*(?:\((.*)\))?$/;
const WRITE_TOOLS = new Set(['Edit', 'Write', 'MultiEdit', 'NotebookEdit']);
const ANY = new Set(['', '*', '**']);

// Commands whose wildcard allowance hands the agent code execution or egress.
const RISKY_COMMANDS = new Set(['sh', 'bash', 'zsh', 'sudo', 'su', 'curl', 'wget', 'eval', 'python', 'python3', 'node', 'perl', 'ruby', 'ssh', 'nc', 'rm', 'chmod', 'npx']);

function firstToken(pattern: string): string {
  const first = pattern.trim().split(/[\s:]+/)[0] ?? '';
  return first.split('/').pop() ?? first;
}

export const aba002 = defineCheck({
  id: 'ABA-002',
  name: 'Abacus.AI Over-Broad Permission Rules',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect Abacus.AI permissions.allow rules granting unrestricted shell or write access (bare Bash, Bash(*), Edit/Write over the whole disk, home or a credential path) or wildcard allowances for shells, interpreters and network tools',
  supportedAgents: ['abacus'],

  async run(ctx, h) {
    const critical: Evidence[] = [];
    const warning: Evidence[] = [];
    const home = ctx.fs.homedir();
    const broadPaths = buildBroadPaths(home).filter(b => !b.path.endsWith('tmp'));

    for (const config of settingsConfigs(ctx.configs)) {
      const permissions = config.data.permissions as Record<string, unknown> | undefined;
      const allow = Array.isArray(permissions?.allow) ? permissions.allow : [];
      for (const entry of allow) {
        if (typeof entry !== 'string') continue;
        const m = RULE.exec(entry.trim());
        if (!m) continue;
        const [, tool, rawPattern] = m;
        const pattern = (rawPattern ?? '').trim();
        const snippet = `permissions.allow: "${entry}"`;

        if (tool === 'Bash') {
          if (ANY.has(pattern)) {
            critical.push({ file: config.filePath, snippet, detail: 'Allows any shell command without approval' });
          } else if (RISKY_COMMANDS.has(firstToken(pattern)) && /\*/.test(pattern)) {
            warning.push({ file: config.filePath, snippet, detail: `Wildcard allowance for "${firstToken(pattern)}" — runs arbitrary code or reaches the network without approval` });
          }
          continue;
        }

        if (WRITE_TOOLS.has(tool)) {
          // Bare Edit/Write is bounded by the workspace; an absolute or home
          // glob is not.
          if (!pattern || ANY.has(pattern)) continue;
          const base = pattern.replace(/(?:[\\/]\*{1,2})+$/, '') || '/';
          const broad = isBroadPath(base, broadPaths, home);
          const sinks = classifySensitivePath(base.replace(/^~/, home));
          if (broad) {
            critical.push({ file: config.filePath, snippet, detail: `Write access ${broad.reason}` });
          } else if (sinks.length > 0) {
            critical.push({ file: config.filePath, snippet, detail: `Write access to ${sinks.join(', ')}` });
          }
        }
      }
    }

    await markUntrustedProject(ctx, critical);
    await markUntrustedProject(ctx, warning);
    const liveCritical = critical.some(e => !e.mitigated);
    return h.fromEvidence([...critical, ...warning], {
      passed: 'No over-broad Abacus.AI permission rules',
      failed: (n) => `Found ${n} over-broad Abacus.AI permission rule(s)`,
      severity: liveCritical ? undefined : 'warning',
      fixDescription: 'Scope Bash() rules to specific commands (e.g. Bash(git log *)) and Edit()/Write() rules to project paths; deny shells, network tools and credential paths with permissions.deny',
    });
  },
});
