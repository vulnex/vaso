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
/** Compare dotted numeric versions part by part (`9.0.0` < `10.0.0`). */
export function compareDottedVersions(a: string, b: string): number {
  const pa = a.split(/[._-]/);
  const pb = b.split(/[._-]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? '';
    const y = pb[i] ?? '';
    const nx = /^\d+$/.test(x) ? Number(x) : NaN;
    const ny = /^\d+$/.test(y) ? Number(y) : NaN;
    if (!Number.isNaN(nx) && !Number.isNaN(ny)) {
      if (nx !== ny) return nx - ny;
    } else if (x !== y) {
      return x < y ? -1 : 1;
    }
  }
  return 0;
}

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
        // Chromium version dirs (`10.0.1_0`): newest by number, not by name
        versions = (await ctx.fs.readdir(extDir)).filter(v => !v.startsWith('.')).sort(compareDottedVersions);
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
