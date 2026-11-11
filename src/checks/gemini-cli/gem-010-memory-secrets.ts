import { dirname, isAbsolute, join, normalize, relative } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { memorySecretSeverity, scanMemorySecrets } from '../../analyzers/memory-secrets.js';
import { MemoryReader } from '../../analyzers/memory-read.js';
import { recordListFailure } from '../../core/config-loader.js';

// The save_memory tool and /memory write ~/.gemini/GEMINI.md; Gemini CLI
// never reads a ~/.gemini/memory.md (memoryTool.ts, memoryDiscovery.ts)
const MEMORY_FILES = ['GEMINI.md'];

/**
 * GEMINI.md plus the names `context.fileName` configures (a string or an
 * array; memoryTool.ts setGeminiMdFilename adds them to the default). The
 * CLI keeps a name with directories (`sub/notes.md`, `../shared/n.md`)
 * after path.normalize and loads the global file at path.join(~/.gemini,
 * name) — so does this. An absolute name would join to a path under
 * ~/.gemini that is not the file it names: skipped. Names that resolve to
 * a directory (`.`, `..`, `dir/`) name no file.
 */
function contextFileNames(ctx: ScanContext): string[] {
  const names = new Set(MEMORY_FILES);
  for (const config of ctx.configs) {
    const context = config.data.context;
    const fileName = context && typeof context === 'object' ? (context as Record<string, unknown>).fileName : undefined;
    for (const n of Array.isArray(fileName) ? fileName : [fileName]) {
      if (typeof n !== 'string' || !n.trim()) continue;
      const name = normalize(n.trim());
      if (isAbsolute(name) || name === '.' || name === '..' || /[\\/]$/.test(name) || /(?:^|[\\/])\.\.$/.test(name)) continue;
      names.add(name);
    }
  }
  return [...names];
}

/** Whether the probe manifest (`~/.gemini/*.md`) collects this context file. */
function collectedByProbe(ctx: ScanContext, file: string): boolean {
  return dirname(file) === ctx.installation.installDir && /\.md$/i.test(file);
}

/** Why the probe left a context file out: not markdown, below the top of ~/.gemini, or outside it. */
function notCollectedReason(ctx: ScanContext, file: string): string {
  if (!/\.md$/i.test(file)) return 'not a .md file';
  const rel = relative(ctx.installation.installDir, file);
  return rel.startsWith('..') ? 'outside ~/.gemini' : 'not at the top of ~/.gemini';
}

// The per-project memory index (memoryTool.ts getProjectMemoryIndexFilePath:
// <global temp dir>/<project id>/memory/MEMORY.md, storage.ts). The temp dir
// is <gemini home>/tmp, or ~/.cache/.gemini/tmp for a session run under the
// macOS seatbelt sandbox (getGlobalRuntimeDir). GEMINI_CLI_HOME moves both.
const PROJECT_INDEX = join('memory', 'MEMORY.md');

function tempDirs(installDir: string): string[] {
  return [join(installDir, 'tmp'), join(dirname(installDir), '.cache', '.gemini', 'tmp')];
}

/** `<tmp>/<project id>/memory/MEMORY.md` for every project dir (real dirs, as the probe's glob sees them). */
async function projectIndexes(ctx: ScanContext, tmp: string): Promise<string[]> {
  let entries;
  try {
    entries = await ctx.fs.readdirEntries(tmp);
  } catch (err) {
    // Absent is fine; there but unreadable hides every index in it
    await recordListFailure(tmp, ctx.fs, err);
    return [];
  }
  if (!Array.isArray(entries)) return [];
  return entries.filter(e => e.isDirectory).map(e => join(tmp, e.name, PROJECT_INDEX));
}

export const gem010 = defineCheck({
  id: 'GEM-010',
  name: 'Gemini Memory File Secret Leak',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Scan ~/.gemini/GEMINI.md (and any context.fileName) and the project memory indexes (~/.gemini/tmp/<project>/memory/MEMORY.md) for plaintext secrets and high-entropy strings',
  supportedAgents: ['gemini-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const reader = new MemoryReader(ctx.fs);
    const contextFiles = contextFileNames(ctx).map(f => join(ctx.installation.installDir, f));
    const files = [...contextFiles];
    // The indexes are per user, under the global temp dir: a project install
    // (<repo>/.gemini) has none of its own
    if (ctx.installation.profile !== 'project') {
      for (const tmp of tempDirs(ctx.installation.installDir)) files.push(...await projectIndexes(ctx, tmp));
    }
    for (const file of files) {
      // Present but unreadable: reported as CONFIG-LOAD
      const content = await reader.read(file);
      if (content !== undefined) {
        // One push per item: a spread of a huge result overflows the call stack
        for (const e of scanMemorySecrets(file, content)) evidence.push(e);
      } else if (ctx.fs.kind === 'snapshot' && contextFiles.includes(file) && !collectedByProbe(ctx, file)) {
        // The probe collects ~/.gemini/*.md only (it can't read context.fileName)
        reader.unverified.push(`${file} (not collected: ${notCollectedReason(ctx, file)})`);
      }
    }
    return h.fromEvidence(evidence, {
      severity: memorySecretSeverity(evidence),
      passed: `No secrets detected in Gemini memory files${reader.note()}`,
      failed: (n) => `Found ${n} potential secret(s) in Gemini memory files`,
      fixDescription: 'Remove the secret from the memory file and rotate the credential — these files often end up in git or shared workspaces',
    });
  },
});
