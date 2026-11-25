import { join } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { restrictFilesToOwner } from '../../remediation/config-writer.js';
import { permissionFixTargets } from '../../remediation/fix-refusal.js';
import { museDataDir } from '../../adapters/muse-code.js';
import { isProjectInstall, markWorldUnreachable, modeFacts } from './shared.js';

// Session trees nest sessions/YYYY/MM/DD/<id>/; bound the walk
const MAX_ENTRIES = 5000;

interface DataTarget {
  label: string;
  holds: string;
  files: string[];
}

async function walkFiles(ctx: ScanContext, root: string, out: string[], depth = 0): Promise<void> {
  if (depth > 6 || out.length >= MAX_ENTRIES) return;
  let entries;
  try {
    entries = await ctx.fs.readdirEntries(root);
  } catch {
    return;
  }
  for (const e of entries) {
    if (out.length >= MAX_ENTRIES) return;
    const p = join(root, e.name);
    if (e.isSymbolicLink) continue;
    if (e.isDirectory) await walkFiles(ctx, p, out, depth + 1);
    else out.push(p);
  }
}

/** Conversation data Muse Code keeps under its data directory. */
async function targets(ctx: ScanContext): Promise<DataTarget[]> {
  const data = museDataDir(ctx.fs.homedir(), ctx.fs);
  const sessions: string[] = [];
  await walkFiles(ctx, join(data, 'sessions'), sessions);
  const tracing: string[] = [];
  await walkFiles(ctx, join(data, 'local-tracing'), tracing);
  return [
    { label: 'session transcripts', holds: 'full session transcripts — prompts, tool output, file contents and any secret pasted into a session', files: sessions.filter(f => !f.endsWith('.lock')) },
    { label: 'session index', holds: 'the index of every session (titles, workspaces)', files: ['session-index.db', 'session-index.db-wal', 'session-index.db-shm'].map(f => join(data, f)) },
    { label: 'prompt history', holds: 'every prompt typed into the TUI', files: [join(data, 'tui-history.jsonl')] },
    { label: 'local traces', holds: 'local run traces', files: tracing },
  ];
}

export const msc008 = defineCheck({
  id: 'MSC-008',
  name: 'Muse Code Session Data World-Readable',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect Meta Muse Code session transcripts (sessions/**/session.jsonl, cron.db), the session index, prompt history and local traces readable by every local user — Muse creates transcripts and the index with the process umask (0664/0644 by default)',
  supportedAgents: ['muse-code'],
  supportedPlatforms: ['darwin', 'linux'],

  fixTargets: permissionFixTargets,

  async run(ctx, h) {
    if (isProjectInstall(ctx)) return h.passed('Session data is user-level — evaluated on the user installation');
    const evidence: Evidence[] = [];
    for (const t of await targets(ctx)) {
      const readable: string[] = [];
      let mode = '';
      for (const file of t.files) {
        const f = await modeFacts(ctx, file);
        if (!f?.worldRead) continue;
        readable.push(file);
        mode ||= f.octal ?? '';
      }
      if (readable.length === 0) continue;
      // Name a transcript when one is readable, not a marker file
      readable.sort((a, b) => Number(b.endsWith('session.jsonl')) - Number(a.endsWith('session.jsonl')));
      evidence.push({
        file: readable[0],
        snippet: readable.length > 1 ? `mode 0${mode} (+${readable.length - 1} more ${t.label} file(s))` : `mode 0${mode}`,
        detail: `World-readable ${t.label}: ${t.holds}`,
      });
    }
    await markWorldUnreachable(ctx, evidence);
    return h.fromEvidence(evidence, {
      passed: 'Muse Code session data is not world-readable',
      failed: (n) => `Found ${n} kind(s) of Muse Code session data readable by every local user`,
      fixable: true,
      fixDescription: 'chmod -R go-rwx ~/.local/share/muse (or $XDG_DATA_HOME/muse); set umask 077 for the shell Muse runs from so new sessions are created owner-only',
    });
  },

  async fix(ctx) {
    const data = museDataDir(ctx.fs.homedir(), ctx.fs);
    const files = (await targets(ctx)).flatMap(t => t.files);
    return restrictFilesToOwner('MSC-008', [data, join(data, 'sessions'), ...files]);
  },
});
