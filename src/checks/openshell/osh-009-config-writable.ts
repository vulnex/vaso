import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { markUnreachable, writableByOthers } from '../../core/permissions.js';
import { facts, listDir, paths } from './shared.js';

export const osh009 = defineCheck({
  id: 'OSH-009',
  name: 'OpenShell Configuration Writable by Others',
  category: 'openshell',
  severity: 'critical',
  description: 'Detect OpenShell gateway and CLI configuration another user can modify: the gateway TOML and env file (TLS, auth, bind address), the CLI\'s active gateway and gateway metadata (redirects the CLI to another endpoint), and their directories',
  supportedAgents: ['openshell'],

  async run(ctx, h) {
    const p = paths(ctx);
    const candidates = [
      ...ctx.configs.map(c => c.filePath),
      p.configDir,
      join(p.configDir, 'gateways'),
      join(p.configDir, 'active_gateway'),
    ];
    for (const g of await listDir(ctx, join(p.configDir, 'gateways'))) {
      if (g.isDirectory) candidates.push(g.path, join(g.path, 'metadata.json'));
    }
    const evidence: Evidence[] = [];
    for (const path of [...new Set(candidates)]) {
      const f = await facts(ctx, path);
      if (!f || !writableByOthers(f)) continue;
      evidence.push({ file: path, snippet: `mode 0${f.octal ?? '?'}`, detail: `Writable by ${f.worldWrite ? 'all users' : 'group'} — can change gateway security settings or point the CLI at another gateway` });
    }
    await markUnreachable(ctx.fs, evidence);
    return h.fromEvidence(evidence, {
      passed: 'OpenShell configuration is not writable by other users',
      failed: (n) => `Found ${n} OpenShell configuration path(s) writable by other users`,
      fixDescription: 'chmod go-w the listed paths (600 for files, 700 for ~/.config/openshell and its gateway directories)',
    });
  },
});
