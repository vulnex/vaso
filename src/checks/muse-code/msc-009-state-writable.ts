import { dirname, join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { MUSE_CODE_SETTINGS, MUSE_CODE_TRUST, museConfigDir, museDataDir } from '../../adapters/muse-code.js';
import { isProjectInstall, markWorldUnreachable, modeFacts } from './shared.js';

export const msc009 = defineCheck({
  id: 'MSC-009',
  name: 'Muse Code Config or Launcher World-Writable',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect a world-writable Meta Muse Code config directory, settings.json or trust.json (another user could add hooks, MCP servers or an unrestricted default profile, or trust a workspace), data or skills directory, or a world-writable launcher / install directory (another user could replace the agent)',
  supportedAgents: ['muse-code'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    if (isProjectInstall(ctx)) return h.passed('Agent state is user-level — evaluated on the user installation');
    const home = ctx.fs.homedir();
    const config = museConfigDir(home, ctx.fs);
    const paths = [
      config,
      join(config, MUSE_CODE_SETTINGS),
      join(config, MUSE_CODE_TRUST),
      join(config, 'skills'),
      museDataDir(home, ctx.fs),
    ];
    const launcher = ctx.installation.cliBinary;
    if (launcher) paths.push(launcher, dirname(launcher), join(dirname(launcher), '.muse-version'));

    const evidence: Evidence[] = [];
    for (const path of paths) {
      const f = await modeFacts(ctx, path);
      if (!f?.worldWrite) continue;
      evidence.push({ file: path, snippet: `mode 0${f.octal}`, detail: 'World-writable — any local user can change what Muse Code runs, trusts or loads' });
    }
    await markWorldUnreachable(ctx, evidence);
    return h.fromEvidence(evidence, {
      passed: 'Muse Code config and launcher are not world-writable',
      failed: (n) => `Found ${n} world-writable Muse Code path(s)`,
      fixDescription: 'chmod o-w the Muse Code config directory, settings.json, trust.json, the data directory and the launcher directory',
    });
  },
});
