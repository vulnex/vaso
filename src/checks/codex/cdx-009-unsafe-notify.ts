import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const SHELL_BINS = new Set(['sh', 'bash', 'zsh', 'fish', 'dash', 'ksh']);
const SHELL_EXEC_FLAGS = new Set(['-c', '-cu', '-uc']);
const EVAL_LIKE = new Set(['eval', 'exec']);
const WORLD_WRITABLE_DIRS = ['/tmp/', '/var/tmp/', '/private/tmp/'];

interface NotifyFinding {
  reason: string;
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

  if (SHELL_BINS.has(base) && argv.slice(1).some(a => SHELL_EXEC_FLAGS.has(a))) {
    findings.push({
      reason: `invokes ${base} -c, so any variable Codex injects is parsed as shell — same risk class as Claude Code unsafe hooks`,
    });
  }

  if (EVAL_LIKE.has(base)) {
    findings.push({ reason: `top-level command is "${base}" — dynamic input becomes code` });
  }

  if (cmd && !cmd.startsWith('/') && !cmd.startsWith('~') && !cmd.startsWith('./') && !cmd.startsWith('../')) {
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
  description: 'Detect Codex `notify` automation that invokes a shell (-c), uses a relative command name, or runs a script from a world-writable directory',
  supportedAgents: ['codex'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const rootNotify = config.data.notify;
      for (const f of inspectNotify(rootNotify)) {
        evidence.push({
          file: config.filePath,
          snippet: `notify = ${JSON.stringify(rootNotify)}`,
          detail: f.reason,
        });
      }

      const profiles = config.data.profiles as Record<string, unknown> | undefined;
      if (profiles && typeof profiles === 'object') {
        for (const [name, profile] of Object.entries(profiles)) {
          if (!profile || typeof profile !== 'object') continue;
          const pn = (profile as Record<string, unknown>).notify;
          for (const f of inspectNotify(pn)) {
            evidence.push({
              file: config.filePath,
              snippet: `[profiles.${name}] notify = ${JSON.stringify(pn)}`,
              detail: f.reason,
            });
          }
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Codex notify command is safely configured (or not set)',
      failed: (n) => `Found ${n} unsafe Codex notify configuration(s)`,
      fixDescription: 'Use an absolute path to a non-shell script (e.g. notify = ["/usr/local/bin/codex-notify"]); avoid sh -c and /tmp scripts',
    });
  },
});
