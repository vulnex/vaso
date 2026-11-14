import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { shellCommandWrapper, shellInvocation } from '../../mcp/shell-wrapper.js';
import { codexProfileName } from '../../adapters/codex.js';
import { hookCommandRisks } from '../../analyzers/hook-commands.js';

const INTERPRETERS = /^(?:python[\d.]*|node|bun|deno|ruby|perl|bash|sh|zsh|osascript)$/;
const EVAL_LIKE = new Set(['eval', 'exec']);
const WORLD_WRITABLE_DIRS = ['/tmp/', '/var/tmp/', '/private/tmp/'];

interface NotifyFinding {
  reason: string;
  critical?: boolean;
}

function basename(p: string): string {
  const idx = Math.max(p.lastIndexOf('/'), p.lastIndexOf('\\'));
  return idx >= 0 ? p.slice(idx + 1) : p;
}

function inspectNotify(notify: unknown): NotifyFinding[] {
  if (!Array.isArray(notify) || notify.length === 0) return [];
  const argv = notify.filter((v): v is string => typeof v === 'string');
  if (argv.length === 0) return [];

  const findings: NotifyFinding[] = [];
  const cmd = argv[0];
  const base = basename(cmd);

  const shell = shellCommandWrapper(cmd, argv.slice(1));
  if (shell) {
    // The script after -c runs at the end of every turn: judge it like a hook
    const script = argv.slice(1).filter(a => !a.startsWith('-')).join(' ');
    const critical = hookCommandRisks(script).filter(r => r.tier === 'critical');
    findings.push(critical.length > 0
      ? { critical: true, reason: `${shellInvocation(shell, argv.slice(1))} script ${critical[0].reason.replace(/ every time the hook fires$/, '')} at the end of every Codex turn` }
      : { reason: `invokes ${shellInvocation(shell, argv.slice(1))}, so any variable Codex injects is parsed as shell — same risk class as Claude Code unsafe hooks` });
  }

  if (EVAL_LIKE.has(base)) {
    findings.push({ reason: `top-level command is "${base}" — dynamic input becomes code` });
  }

  // A standard interpreter running an absolute script (`["python3", "/abs/notify.py"]`,
  // the form Codex documents) is as PATH-resolved as any command — not flagged.
  const interpreterWithScript = INTERPRETERS.test(base) && argv.slice(1).some(a => a.startsWith('/') || a.startsWith('~/'));
  if (cmd && !interpreterWithScript && !cmd.startsWith('/') && !cmd.startsWith('~') && !cmd.startsWith('./') && !cmd.startsWith('../')) {
    findings.push({
      reason: `relative command name "${cmd}" — resolved via $PATH at session-end, vulnerable to PATH hijack`,
    });
  }

  for (const a of argv) {
    for (const dir of WORLD_WRITABLE_DIRS) {
      if (a.startsWith(dir)) {
        findings.push({
          reason: `references ${dir} — world-writable on shared hosts, any local user can replace the script`,
        });
        break;
      }
    }
  }

  return findings;
}

export const cdx009 = defineCheck({
  id: 'CDX-009',
  name: 'Codex Unsafe Notify Command',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect Codex `notify` automation that invokes a shell (-c) — critical when the script downloads and runs code or sends secrets — uses a relative command name, or runs a script from a world-writable directory',
  supportedAgents: ['codex'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    let critical = false;
    // One finding per notify setting, naming every reason it is unsafe
    const add = (file: string, snippet: string, findings: NotifyFinding[]) => {
      if (findings.length === 0) return;
      if (findings.some(f => f.critical)) critical = true;
      evidence.push({ file, snippet, detail: findings.map(f => f.reason).join('; ') });
    };
    // Codex ignores `notify` in a project's .codex/config.toml
    if (ctx.installation.profile === 'project') return h.passed('Project config cannot set a Codex notify command');

    for (const config of ctx.configs) {
      const rootNotify = config.data.notify;
      // Profile files (`<name>.config.toml`) override notify under `codex -p <name>`
      const profile = codexProfileName(config.filePath);
      add(config.filePath, `${profile ? `${profile}.config.toml: ` : ''}notify = ${JSON.stringify(rootNotify)}`, inspectNotify(rootNotify));

      const profiles = config.data.profiles as Record<string, unknown> | undefined;
      if (profiles && typeof profiles === 'object') {
        for (const [name, profile] of Object.entries(profiles)) {
          if (!profile || typeof profile !== 'object') continue;
          const pn = (profile as Record<string, unknown>).notify;
          add(config.filePath, `[profiles.${name}] notify = ${JSON.stringify(pn)}`, inspectNotify(pn));
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Codex notify command is safely configured (or not set)',
      failed: (n) => `Found ${n} unsafe Codex notify configuration(s)`,
      severity: critical ? 'critical' : undefined,
      fixDescription: 'Use an absolute path to a non-shell script (e.g. notify = ["/usr/local/bin/codex-notify"]); avoid sh -c and /tmp scripts',
    });
  },
});
