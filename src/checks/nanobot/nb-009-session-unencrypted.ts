import { join } from 'node:path';
import { defineCheck } from '../../core/check-builder.js';
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

    const evidence = await readableByOthersEvidence(ctx, files.map(path => ({ path, what: 'Chat history' })));
    return h.fromEvidence(evidence, {
      passed: 'Chat history files are owner-only (or absent)',
      failed: (n) => `${n} chat history file(s) readable by other users`,
      fixDescription: 'chmod 700 ~/.nanobot/sessions ~/.nanobot/history ~/.nanobot/workspace/memory and chmod 600 the history files',
    });
  },
});
