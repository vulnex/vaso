import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

// Commands whose bare approval grants network access or arbitrary execution.
const DANGEROUS_BARE = new Set([
  'curl', 'wget', 'nc', 'ncat', 'telnet', 'ssh', 'scp', 'rsync',
  'bash', 'sh', 'zsh', 'dash', 'ksh',
  'perl', 'python', 'python3', 'node', 'ruby', 'php', 'deno', 'bun',
  'npx', 'uvx', 'eval', 'exec', 'sudo', 'doas',
  'chmod', 'chown', 'dd', 'mkfs',
]);

const SHELLS = new Set(['bash', 'sh', 'zsh', 'dash', 'ksh']);
const INTERPRETERS = new Set(['perl', 'python', 'python3', 'node', 'ruby', 'php', 'deno', 'bun']);

function baseCommand(el: string): string {
  return el.includes('/') ? el.slice(el.lastIndexOf('/') + 1) : el;
}

/** Returns a reason string when an allow-rule prefix still permits arbitrary execution. */
export function classifyPrefixPattern(pattern: string[]): string | undefined {
  if (pattern.length === 0) return undefined;
  const cmd = baseCommand(pattern[0]);

  if (pattern.length === 1 && DANGEROUS_BARE.has(cmd)) {
    return `bare "${cmd}" prefix allows any ${cmd} invocation without approval`;
  }

  // Shell whose pattern ends at -c/-lc/-l: the actual command is unconstrained.
  if (SHELLS.has(cmd)) {
    const last = pattern[pattern.length - 1];
    if (/^-l?c$/.test(last) || (pattern.length > 1 && pattern.slice(1).every(p => p.startsWith('-')))) {
      return `"${pattern.join(' ')}" allows the shell to run any command without approval`;
    }
  }

  // Interpreter where everything after the binary is flags — payload is unconstrained
  // (e.g. ["perl", "-0pi"] approves rewriting any file with any expression).
  if (INTERPRETERS.has(cmd) && pattern.length > 1 && pattern.slice(1).every(p => p.startsWith('-'))) {
    return `"${pattern.join(' ')}" approves any ${cmd} payload — arbitrary code/file modification`;
  }

  return undefined;
}

const RULE_RE = /prefix_rule\(\s*pattern\s*=\s*(\[.*?\])\s*,\s*decision\s*=\s*"([a-z_]+)"/;

export const cdx010 = defineCheck({
  id: 'CDX-010',
  name: 'Codex Over-Broad Command Allow Rules',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect ~/.codex/rules/*.rules prefix_rule allow entries whose prefix still permits arbitrary execution (bare curl/shell/interpreter)',
  supportedAgents: ['codex'],

  async run(ctx, h) {
    const rulesDir = join(ctx.installation.installDir, 'rules');
    if (!(await ctx.fs.access(rulesDir))) return h.passed('No Codex rules directory present');

    const evidence: Evidence[] = [];

    let names: string[] = [];
    try {
      names = (await ctx.fs.readdir(rulesDir)).filter(n => n.endsWith('.rules'));
    } catch {
      return h.passed('No Codex rules directory present');
    }

    for (const name of names) {
      const file = join(rulesDir, name);
      let content: string;
      try {
        content = await ctx.fs.readFile(file);
      } catch {
        continue;
      }

      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const m = RULE_RE.exec(lines[i]);
        if (!m || m[2] !== 'allow') continue;

        let pattern: unknown;
        try {
          pattern = JSON.parse(m[1]);
        } catch {
          continue; // unparseable patterns are long/specific ones — prefix is constrained
        }
        if (!Array.isArray(pattern) || !pattern.every(p => typeof p === 'string')) continue;

        const reason = classifyPrefixPattern(pattern);
        if (reason) {
          evidence.push({
            file,
            line: i + 1,
            snippet: lines[i].trim().slice(0, 160),
            detail: reason,
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Codex command allow rules are scoped to specific commands',
      failed: (n) => `Found ${n} over-broad allow rule(s) in ~/.codex/rules/`,
      fixDescription: 'Narrow allow rules to full command prefixes (e.g. ["npm","run","build"]); remove bare network/shell/interpreter approvals',
    });
  },
});
