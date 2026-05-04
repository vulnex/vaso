import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const EXTENSIONS_DIR = 'Claude Extensions';

interface MCPBManifest {
  name?: unknown;
  version?: unknown;
  author?: unknown;
  signature?: unknown;
  signed?: unknown;
}

export const cd005 = defineCheck({
  id: 'CD-005',
  name: 'Unverified MCPB Desktop Extensions',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Inventory installed .mcpb Desktop Extensions and flag those without a signature/author',
  supportedAgents: ['claude-desktop'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

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
        const raw = await ctx.fs.readFile(manifestPath);
        manifest = JSON.parse(raw) as MCPBManifest;
      } catch {
        evidence.push({
          file: manifestPath,
          detail: `Extension "${entry.name}" has an unparseable manifest.json`,
        });
        continue;
      }

      const hasSignature = manifest.signature != null || manifest.signed === true;
      const author = typeof manifest.author === 'string' ? manifest.author : undefined;

      if (!hasSignature) {
        const name = typeof manifest.name === 'string' ? manifest.name : entry.name;
        evidence.push({
          file: manifestPath,
          snippet: `extension: ${name}${author ? ` (author: ${author})` : ''}`,
          detail: 'MCPB extension has no signature in manifest — installed bundle was not verified at install time',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'All installed Desktop Extensions carry a signature',
      failed: (n) => `Found ${n} unsigned Desktop Extension(s)`,
      fixDescription: 'Reinstall extensions from a trusted source that ships signed .mcpb bundles, or remove untrusted ones from the Extensions directory',
    });
  },
});
