import { join } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const EXTENSIONS_DIR = 'Claude Extensions';

interface MCPBManifest {
  name?: unknown;
  display_name?: unknown;
  version?: unknown;
  author?: unknown;
}

// `mcpb sign` appends the signature to the archive itself (MCPB CLI.md
// "Signature Format"): [ZIP] MCPB_SIG_V1 [len] [DER PKCS#7] MCPB_SIG_END.
// The manifest has no signature field, and an installed extension is the
// unpacked bundle — whether it was signed shows only in a .mcpb on disk.
const SIG_START = 'MCPB_SIG_V1';
const SIG_END = 'MCPB_SIG_END';
// The signature block sits at the end; a certificate chain fits well inside this
const TRAILER_BYTES = 64 * 1024;

/** MCPB `author` is an object ({ name, email?, url? }); older bundles used a string. */
function authorName(author: unknown): string | undefined {
  if (typeof author === 'string') return author || undefined;
  if (author && typeof author === 'object') {
    const name = (author as Record<string, unknown>).name;
    return typeof name === 'string' && name ? name : undefined;
  }
  return undefined;
}

/** .mcpb archives kept for this extension: inside its dir, or `<id>.mcpb` beside it. */
async function archivesFor(ctx: ScanContext, extDir: string, id: string): Promise<string[]> {
  const found: string[] = [];
  try {
    for (const e of await ctx.fs.readdirEntries(join(extDir, id))) {
      if (e.isFile && e.name.toLowerCase().endsWith('.mcpb')) found.push(join(extDir, id, e.name));
    }
  } catch {
    // unreadable — nothing to judge
  }
  const sibling = join(extDir, `${id}.mcpb`);
  if (await ctx.fs.access(sibling)) found.push(sibling);
  return found;
}

/** true/false from the archive's trailer; undefined when it can't be read. */
async function archiveSigned(ctx: ScanContext, file: string): Promise<boolean | undefined> {
  try {
    const bytes = await ctx.fs.readBytes(file);
    const tail = Buffer.from(bytes.subarray(Math.max(0, bytes.length - TRAILER_BYTES))).toString('latin1');
    const start = tail.lastIndexOf(SIG_START);
    return start !== -1 && tail.indexOf(SIG_END, start) !== -1;
  } catch {
    return undefined;
  }
}

export const cd005 = defineCheck({
  id: 'CD-005',
  name: 'Unverified MCPB Desktop Extensions',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Inventory installed .mcpb Desktop Extensions and flag those whose bundle on disk carries no MCPB signature',
  supportedAgents: ['claude-desktop'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    let unsigned = 0;

    const extDir = join(ctx.installation.installDir, EXTENSIONS_DIR);
    if (!(await ctx.fs.access(extDir))) {
      return h.passed('No Claude Extensions directory present');
    }

    let entries;
    try {
      entries = await ctx.fs.readdirEntries(extDir);
    } catch {
      return h.passed('Claude Extensions directory not readable');
    }

    for (const entry of entries) {
      if (!entry.isDirectory) continue;
      const manifestPath = join(extDir, entry.name, 'manifest.json');
      if (!(await ctx.fs.access(manifestPath))) continue;

      let manifest: MCPBManifest = {};
      try {
        manifest = JSON.parse(await ctx.fs.readFile(manifestPath)) as MCPBManifest;
      } catch {
        evidence.push({
          file: manifestPath,
          detail: `Extension "${entry.name}" has an unparseable manifest.json`,
        });
        continue;
      }

      const name = typeof manifest.name === 'string' ? manifest.name : entry.name;
      const author = authorName(manifest.author);
      const snippet = `extension: ${name}${author ? ` (author: ${author})` : ''}`;
      const archives = await archivesFor(ctx, extDir, entry.name);
      const verdicts = await Promise.all(archives.map(a => archiveSigned(ctx, a)));
      const unsignedArchive = archives.find((_, i) => verdicts[i] === false);

      if (unsignedArchive) {
        unsigned++;
        evidence.push({
          file: unsignedArchive,
          snippet,
          detail: 'The extension\'s .mcpb bundle carries no MCPB signature — its origin and integrity were never verified',
        });
      } else if (!verdicts.includes(true)) {
        // Inventory only: without the bundle, signing can't be judged
        evidence.push({
          file: manifestPath,
          snippet,
          detail: `Installed extension${author ? '' : ' with no author'} — signature status unknown (the unpacked extension doesn't record it); review its source`,
          mitigated: true,
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'All installed Desktop Extensions with a bundle on disk carry an MCPB signature',
      failed: (n) => unsigned > 0
        ? `Found ${unsigned} unsigned Desktop Extension bundle(s)`
        : `${n} installed Desktop Extension(s) — signature status unknown`,
      fixDescription: 'Reinstall extensions from a trusted source that ships signed .mcpb bundles (`mcpb verify <file>`), or remove untrusted ones from the Extensions directory',
    });
  },
});
