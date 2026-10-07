import { dirname, join } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { queryPermissions } from '../../core/permissions.js';
import type { PermissionFacts } from '../../core/fs-provider.js';
import { abacusDesktopDataDir } from '../../adapters/abacus.js';
import { abacusDir, isProjectInstall } from './shared.js';

async function facts(ctx: ScanContext, path: string): Promise<PermissionFacts | undefined> {
  if (!(await ctx.fs.access(path))) return undefined;
  try {
    const q = await queryPermissions(ctx.fs, path);
    return q === 'unsupported' ? undefined : q;
  } catch {
    return undefined;
  }
}

async function listFiles(ctx: ScanContext, dir: string): Promise<string[]> {
  try {
    return (await ctx.fs.readdirEntries(dir)).filter(e => !e.isDirectory).map(e => join(dir, e.name));
  } catch {
    return [];
  }
}

/**
 * Every finding here is about *world* access, so only a world barrier counts:
 * a 0750 home blocks other users even though its group can still traverse
 * (markUnreachable also weighs group access, which this check doesn't flag).
 */
async function markWorldUnreachable(ctx: ScanContext, evidence: Evidence[]): Promise<void> {
  for (const e of evidence) {
    for (let dir = dirname(e.file); ; dir = dirname(dir)) {
      const f = await facts(ctx, dir);
      if (f && !f.worldExec) {
        e.mitigated = true;
        e.detail = `${e.detail} — mitigated: ${dir} (${f.octal}) blocks other users`;
        break;
      }
      if (dirname(dir) === dir) break;
    }
  }
}

// Key stores are ABA-003's; everything else the desktop app writes with mode 0666.
const KEY_STORES = new Set(['provider-keys.json', 'cowork-provider-keys.json', 'Cookies']);

export const aba015 = defineCheck({
  id: 'ABA-015',
  name: 'Abacus.AI State World-Accessible',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect a world-writable ~/.abacusai or CLI binary directory (another user can replace the agent binary or its config), a world-readable prompt history (history.jsonl), session metadata and logs, and world-writable AbacusAI Desktop state files',
  supportedAgents: ['abacus'],

  async run(ctx, h) {
    if (isProjectInstall(ctx)) {
      return h.passed('Agent state is user-level — evaluated on the user installation');
    }
    const critical: Evidence[] = [];
    const warning: Evidence[] = [];
    const base = abacusDir(ctx);

    for (const path of [base, join(base, 'bin'), join(base, 'bin', 'abacusai'), join(base, 'config.json'), join(base, 'mcp.json'), join(base, 'desktop')]) {
      const f = await facts(ctx, path);
      if (f?.worldWrite) {
        critical.push({ file: path, snippet: `mode 0${f.octal}`, detail: 'World-writable — any local user can replace the Abacus.AI binary or rewrite its settings and MCP servers' });
      }
    }

    // Prompt history: every message typed, created world-readable under the default umask
    const history = join(base, 'history.jsonl');
    const hf = await facts(ctx, history);
    if (hf?.worldRead) {
      warning.push({ file: history, snippet: `mode 0${hf.octal}`, detail: 'World-readable prompt history — every message typed into the CLI (including pasted secrets) is visible to every local user' });
    }

    for (const dir of [join(base, 'logs'), join(base, 'projects')]) {
      const f = await facts(ctx, dir);
      if (f?.worldRead && f.worldExec) {
        warning.push({ file: dir, snippet: `mode 0${f.octal}`, detail: 'World-readable — session titles, tool activity and errors are visible to every local user' });
      }
    }

    const desktop = abacusDesktopDataDir(ctx.fs.homedir(), ctx.fs);
    for (const file of await listFiles(ctx, desktop)) {
      if (!file.endsWith('.json') || KEY_STORES.has(file.split(/[\\/]/).pop() ?? '')) continue;
      const f = await facts(ctx, file);
      if (f?.worldWrite) {
        warning.push({ file, snippet: `mode 0${f.octal}`, detail: 'World-writable desktop state — another user could rewrite workspaces, VM and update state' });
      }
    }

    await markWorldUnreachable(ctx, critical);
    await markWorldUnreachable(ctx, warning);
    const liveCritical = critical.some(e => !e.mitigated);
    return h.fromEvidence([...critical, ...warning], {
      passed: 'Abacus.AI state is not world-accessible',
      failed: (n) => `Found ${n} world-accessible Abacus.AI path(s)`,
      severity: liveCritical ? undefined : 'warning',
      fixDescription: 'chmod o-w ~/.abacusai ~/.abacusai/bin (and the files in them), chmod 600 ~/.abacusai/history.jsonl, chmod o-rwx ~/.abacusai/logs ~/.abacusai/projects, and chmod 600 the JSON files in the AbacusAI Desktop data directory',
    });
  },
});
