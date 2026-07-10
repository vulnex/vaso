import { isAbsolute, join, resolve, relative, dirname } from 'node:path';
import type { Evidence, Severity } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getAllSkillsDirs } from '../../core/utils.js';
import { classifySensitivePath } from '../../analyzers/sensitive-paths.js';

/**
 * SKL-013 — Workspace Symlink Escape (GhostApproval / CWE-61 + CWE-451).
 *
 * A malicious repository can plant a symlink disguised as an innocuous file
 * (e.g. `project_settings.json` → `~/.ssh/authorized_keys`) and, via a README
 * instruction, get an AI coding agent to "update" it. If the agent follows the
 * link without resolving and surfacing the true target, the user approves a
 * harmless-looking local edit while the write lands on a sensitive file outside
 * the workspace — SSH-key injection, shell-rc persistence, RCE. Wiz documented
 * this as GhostApproval across six coding assistants in July 2026.
 *
 * VASO can't fix an agent's runtime symlink handling, but it can detect the
 * attack *artifact* statically: any symlink inside a scanned skill/workspace
 * directory whose target resolves OUTSIDE that directory. We never follow the
 * link for reads — `readlink` returns the raw stored target, so even a dangling
 * link planted before its target exists is caught. Escapes that also reach a
 * known credential/persistence sink (shared catalogue with MCP-031) are
 * critical; escapes to any other out-of-workspace location are a warning.
 *
 * Runs for every agent and, notably, under `vaso skill audit <repo>` — point it
 * at a freshly cloned repository and it flags the escaping symlink before the
 * agent is ever asked to touch it.
 */

interface SymlinkFinding {
  linkPath: string;
  rawTarget: string;
  resolvedTarget: string;
  sensitiveLabels: string[];
}

function resolveTarget(rawTarget: string, linkDir: string, home: string): string {
  let t = rawTarget;
  if (t === '~' || t.startsWith('~/')) {
    t = join(home, t.slice(1));
  }
  if (isAbsolute(t)) return resolve(t);
  return resolve(linkDir, t);
}

function escapesRoot(root: string, resolvedTarget: string): boolean {
  const rel = relative(root, resolvedTarget);
  // Empty rel means the target IS the root; a leading '..' or an absolute
  // result means the target sits outside the walked directory tree.
  return rel === '' ? false : rel.startsWith('..') || isAbsolute(rel);
}

export const skl013 = defineCheck({
  id: 'SKL-013',
  name: 'Workspace Symlink Escape',
  category: 'skills',
  severity: 'critical',
  description:
    'Detect symlinks in a skill/workspace directory that resolve outside it (GhostApproval / CWE-61), especially to credential stores or shell startup files',

  async run(ctx, h) {
    const dirs = getAllSkillsDirs(ctx.installation);
    if (dirs.length === 0) return h.passed('No skills/workspace directory to scan for symlinks');

    // Providers that can't observe link status (snapshots, mocks) never set
    // isSymbolicLink and don't implement readlink — nothing to do there.
    if (typeof ctx.fs.readlink !== 'function') {
      return h.passed('Symlink status unavailable for this scan source');
    }

    const findings: SymlinkFinding[] = [];
    const seen = new Set<string>();

    for (const dir of dirs) {
      const root = resolve(dir);
      let entries;
      try {
        entries = await ctx.fs.readdirEntries(dir, { recursive: true });
      } catch {
        continue; // directory may not exist
      }

      for (const entry of entries) {
        if (!entry.isSymbolicLink) continue;
        const linkPath = entry.parentPath ? join(entry.parentPath, entry.name) : join(dir, entry.name);
        if (seen.has(linkPath)) continue;
        seen.add(linkPath);

        let rawTarget: string;
        try {
          rawTarget = await ctx.fs.readlink(linkPath);
        } catch {
          continue;
        }

        const resolvedTarget = resolveTarget(rawTarget, dirname(linkPath), ctx.fs.homedir());
        if (!escapesRoot(root, resolvedTarget)) continue; // link stays inside the workspace — benign

        const sensitiveLabels = [
          ...new Set([
            ...classifySensitivePath(resolvedTarget),
            ...classifySensitivePath(rawTarget),
          ]),
        ];
        findings.push({ linkPath, rawTarget, resolvedTarget, sensitiveLabels });
      }
    }

    if (findings.length === 0) {
      return h.passed('No symlinks escape the scanned workspace directory');
    }

    const anySensitive = findings.some((f) => f.sensitiveLabels.length > 0);
    const evidence: Evidence[] = findings.map((f) => ({
      file: f.linkPath,
      snippet: `${f.linkPath} → ${f.rawTarget}`,
      detail: f.sensitiveLabels.length > 0
        ? `Symlink resolves outside the workspace to ${f.sensitiveLabels.join(', ')} (${f.resolvedTarget}). An agent instructed to edit this "local" file writes to the sensitive target instead — GhostApproval-style informed-consent bypass.`
        : `Symlink resolves outside the workspace to ${f.resolvedTarget}. A write the user believes is workspace-local lands outside the project.`,
    }));

    const severity: Severity = anySensitive ? 'critical' : 'warning';
    const sensitiveCount = findings.filter((f) => f.sensitiveLabels.length > 0).length;

    return h.result({
      passed: false,
      severity,
      message: anySensitive
        ? `${findings.length} workspace symlink(s) escape the directory, ${sensitiveCount} reaching credential stores or shell startup files`
        : `${findings.length} workspace symlink(s) resolve outside the scanned directory`,
      evidence,
      fixDescription:
        'Remove or replace out-of-workspace symlinks; never let an agent write to a path it presents as workspace-local. Prefer a coding agent that resolves symlinks and warns before writing outside the project.',
    });
  },
});
