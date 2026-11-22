import { join } from 'node:path';
import { defineCheck } from '../../core/check-builder.js';
import { notCollectedNote } from '../../core/probe-coverage.js';
import type { ScanContext } from '../../core/types.js';
import { readableByOthersEvidence, workspaceDir } from './shared.js';

const HISTORY_FILE = /\.(?:jsonl|json)$/;

async function listFiles(ctx: ScanContext, dir: string): Promise<string[]> {
  try {
    return (await ctx.fs.readdirEntries(dir)).filter(e => !e.isDirectory).map(e => join(dir, e.name));
  } catch {
    return [];
  }
}

async function listDirs(ctx: ScanContext, dir: string): Promise<string[]> {
  try {
    return (await ctx.fs.readdirEntries(dir)).filter(e => e.isDirectory).map(e => join(dir, e.name));
  } catch {
    return [];
  }
}

export const nb009 = defineCheck({
  id: 'NB-009',
  name: 'Chat History Readable by Other Users',
  category: 'nanobot',
  severity: 'warning',
  description: 'nanobot stores conversation history in plaintext (there is no encryption option): ~/.nanobot/sessions/<workspace-id>/*.jsonl, <workspace>/memory/history.jsonl and ~/.nanobot/history/cli_history. They hold everything users and tools said — often pasted secrets and personal data — and must be owner-only.',
  supportedAgents: ['nanobot'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const dataDir = ctx.installation.installDir;
    const sessionsDir = join(dataDir, 'sessions');
    const files: string[] = [];
    // sessions/<workspace-id>/*.jsonl, plus legacy flat sessions/*.jsonl
    files.push(...(await listFiles(ctx, sessionsDir)).filter(f => HISTORY_FILE.test(f)));
    for (const sub of await listDirs(ctx, sessionsDir)) {
      files.push(...(await listFiles(ctx, sub)).filter(f => HISTORY_FILE.test(f)));
    }
    files.push(join(workspaceDir(ctx), 'memory', 'history.jsonl'));
    files.push(join(dataDir, 'history', 'cli_history'));

    const unverified: string[] = [];
    const evidence = await readableByOthersEvidence(ctx, files.map(path => ({ path, what: 'Chat history' })), unverified);
    return h.fromEvidence(evidence, {
      passed: unverified.length > 0 ? `Chat history files are owner-only (or absent); ${notCollectedNote('path(s)', unverified)}` : 'Chat history files are owner-only (or absent)',
      failed: (n) => `${n} chat history file(s) readable by other users${unverified.length > 0 ? `; ${notCollectedNote('path(s)', unverified)}` : ''}`,
      fixDescription: 'chmod 700 ~/.nanobot/sessions ~/.nanobot/history ~/.nanobot/workspace/memory and chmod 600 the history files',
    });
  },
});
