import { join } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

// Comet ships hidden built-in agentic extensions ("Comet Analytics", "Comet
// Agentic" — the latter exposed chrome.perplexity.mcp.addStdioServer, which
// SquareX showed could execute arbitrary host commands before Perplexity
// disabled the API, 2025-11). User-installed extensions share the agent's
// browser and can steer it (extension-stomping / AI-hijack research, 2026-09).
// This check inventories installed extensions so reviewers can spot
// unexpected ones; it is informational by design.
async function readManifestName(dir: string, fs: ScanContext['fs']): Promise<string | undefined> {
  try {
    const manifest = JSON.parse(await fs.readFile(join(dir, 'manifest.json'))) as Record<string, unknown>;
    const name = manifest.name;
    if (typeof name === 'string' && !name.startsWith('__MSG_')) return name;
    return typeof manifest.short_name === 'string' ? manifest.short_name : undefined;
  } catch {
    return undefined;
  }
}

export const pc002 = defineCheck({
  id: 'PC-002',
  name: 'Comet Extension Inventory',
  category: 'coding-agent',
  severity: 'info',
  description: 'Inventory browser extensions installed into the Comet profile — extensions share the agentic browser’s privileges and sessions',
  supportedAgents: ['comet'],

  async run(ctx, h) {
    const extensionsDir = join(ctx.installation.installDir, 'Default', 'Extensions');
    if (!(await ctx.fs.access(extensionsDir))) {
      return h.passed('No Comet extensions directory present');
    }

    const evidence: Evidence[] = [];
    let ids: string[] = [];
    try {
      ids = await ctx.fs.readdir(extensionsDir);
    } catch {
      return h.passed('Comet extensions directory not readable');
    }

    for (const id of ids) {
      if (id.startsWith('.')) continue;
      const extDir = join(extensionsDir, id);
      let versions: string[] = [];
      try {
        versions = (await ctx.fs.readdir(extDir)).filter(v => !v.startsWith('.'));
      } catch {
        continue;
      }
      const version = versions[versions.length - 1];
      const name = version ? await readManifestName(join(extDir, version), ctx.fs) : undefined;
      evidence.push({
        file: extDir,
        snippet: version ? `${id} @ ${version}` : id,
        detail: name
          ? `Extension "${name}" — verify it is expected; it shares Comet's agent sessions`
          : 'Extension with unreadable manifest — verify it is expected',
      });
    }

    return h.fromEvidence(evidence, {
      passed: 'No extensions installed in the Comet profile',
      failed: (n) => `${n} extension(s) installed in the Comet profile — review the inventory`,
      fixDescription: 'Remove extensions you do not recognize; treat extensions in an agentic browser as having access to everything the agent can do',
    });
  },
});
