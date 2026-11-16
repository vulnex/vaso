import { isAbsolute, join, resolve, relative, dirname } from 'node:path';
import type { Evidence, Severity } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getAllSkillsDirs, relEscapes } from '../../core/utils.js';
import { classifySensitivePath } from '../../analyzers/sensitive-paths.js';
import { noSkillsDirResult } from './skill-files.js';
import { linkScope } from '../../core/skill-root-scope.js';
import { MAX_SKILL_TREE_ENTRIES } from '../../core/skill-tree-count.js';

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

async function isDirectory(fs: { stat(p: string): Promise<{ isDirectory(): boolean }> }, path: string): Promise<boolean> {
  try {
    return (await fs.stat(path)).isDirectory();
  } catch {
    return false;
  }
}

interface SymlinkFinding {
  linkPath: string;
  rawTarget: string;
  resolvedTarget: string;
  sensitiveLabels: string[];
  /** A whole skill linked into an installed agent's skills dir (`skills/x → ~/checkout/x`). */
  skillInstall: boolean;
  /** Its code is not scanned (SKL-002): linked to where no skills tree is
   *  walked, or to a tree over the entry limit. */
  unscanned?: 'outside' | 'limit';
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
  return rel === '' ? false : relEscapes(rel);
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
    const noDir = noSkillsDirResult(ctx, h, 'No skills/workspace directory to scan for symlinks');
    if (noDir) return noDir;

    // Providers that can't observe link status (mocks, snapshots from probes
    // before 1.1.0) never set isSymbolicLink — nothing to do there.
    if (typeof ctx.fs.readlink !== 'function') {
      return h.passed('Symlink status unavailable for this scan source');
    }

    const findings: SymlinkFinding[] = [];
    const seen = new Set<string>();
    // links the skill walk left out for the size of their tree (inventory)
    const overLimit = new Set((ctx.installation.unscannedSkillsDirs ?? []).filter(u => u.reason === 'limit').map(u => u.path));

    for (const dir of dirs) {
      const root = resolve(dir);
      const inScope = await linkScope(ctx.fs, dir);
      // A relative target is resolved where the link really is (its folder
      // may lie behind a link), and judged against the tree's either spelling
      const realOf = (p: string) => ctx.fs.realpath(p).catch(() => p);
      const rootReal = await realOf(root);
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

        const resolvedTarget = resolveTarget(rawTarget, await realOf(dirname(linkPath)), ctx.fs.homedir());
        // link stays inside the workspace — benign
        if (!escapesRoot(root, resolvedTarget) || !escapesRoot(rootReal, resolvedTarget)) continue;

        const sensitiveLabels = [
          ...new Set([
            ...classifySensitivePath(resolvedTarget),
            ...classifySensitivePath(rawTarget),
          ]),
        ];
        // Tools such as gstack install each skill as a link into their
        // checkout — the normal layout of an agent's skills dir, not a
        // workspace file in disguise. `vaso skill audit` keeps judging it.
        const skillInstall = ctx.installation.agent !== 'skill-audit' && sensitiveLabels.length === 0 &&
          resolve(dirname(linkPath)) === root && await isDirectory(ctx.fs, linkPath);
        const unscanned = !skillInstall ? undefined
          : !(await inScope(linkPath)) ? 'outside' as const
            : overLimit.has(linkPath) ? 'limit' as const : undefined;
        findings.push({ linkPath, rawTarget, resolvedTarget, sensitiveLabels, skillInstall, unscanned });
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
        : f.unscanned === 'outside'
          ? `Skill installed as a link to ${f.resolvedTarget} — a place no skills tree is walked, so its code is not scanned (see SKL-002); edits to it change what is there.`
        : f.unscanned === 'limit'
          ? `Skill installed as a link to ${f.resolvedTarget} — a tree over the ${MAX_SKILL_TREE_ENTRIES}-entry limit VASO walks, so its code is not scanned (see SKL-002); edits to it change what is there.`
        : f.skillInstall
          ? `Skill installed as a link to ${f.resolvedTarget} — its code is scanned there; edits to it change the source checkout.`
          : `Symlink resolves outside the workspace to ${f.resolvedTarget}. A write the user believes is workspace-local lands outside the project.`,
    }));

    const severity: Severity = anySensitive ? 'critical' : findings.every((f) => f.skillInstall) ? 'info' : 'warning';
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
