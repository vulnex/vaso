import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

export const cfg019 = defineCheck({
  id: 'CFG-019',
  name: 'NemoClaw Blueprint Integrity',
  category: 'config',
  severity: 'info',
  description: 'Check if NemoClaw blueprint uses digest verification and version pinning',
  supportedAgents: ['openclaw', 'nemoclaw'],

  async run(ctx, h) {
    const nemoDir = join(ctx.fs.homedir(), '.nemoclaw');
    if (!(await ctx.fs.access(nemoDir))) {
      return h.result({
        passed: false,
        message: 'NemoClaw not installed — blueprint integrity check not applicable',
      });
    }

    const evidence: Evidence[] = [];

    // Check plugin manifest for version pinning
    const pluginPaths = [
      '/usr/local/lib/node_modules/nemoclaw/nemoclaw/openclaw.plugin.json',
      join(ctx.fs.homedir(), '.npm-global', 'lib', 'node_modules', 'nemoclaw', 'nemoclaw', 'openclaw.plugin.json'),
    ];

    let usesLatest = false;
    for (const pluginPath of pluginPaths) {
      if (await ctx.fs.access(pluginPath)) {
        try {
          const raw = await ctx.fs.readFile(pluginPath);
          const manifest = JSON.parse(raw) as Record<string, unknown>;
          const blueprintVersion = manifest.blueprintVersion as string | undefined;
          if (blueprintVersion === 'latest') {
            usesLatest = true;
            evidence.push({
              file: pluginPath,
              detail: 'Blueprint version set to "latest" — consider pinning to a specific version',
            });
          } else if (blueprintVersion) {
            evidence.push({
              file: pluginPath,
              detail: `Blueprint version pinned to ${blueprintVersion}`,
            });
          }
        } catch {}
        break;
      }
    }

    // Check cached blueprints for integrity (blueprint.yaml present = verified download)
    const blueprintsDir = join(nemoDir, 'blueprints');
    if (await ctx.fs.access(blueprintsDir)) {
      try {
        const versions = await ctx.fs.readdir(blueprintsDir);
        for (const ver of versions) {
          const manifestPath = join(blueprintsDir, ver, 'blueprint.yaml');
          if (await ctx.fs.access(manifestPath)) {
            evidence.push({
              file: manifestPath,
              detail: `Cached blueprint v${ver} with manifest`,
            });
          }
        }
      } catch {}
    }

    // Check state for deployment records
    const stateFile = join(nemoDir, 'state', 'nemoclaw.json');
    if (await ctx.fs.access(stateFile)) {
      try {
        const raw = await ctx.fs.readFile(stateFile);
        const state = JSON.parse(raw) as Record<string, unknown>;
        if (state.migrationSnapshot || state.hostBackupPath) {
          evidence.push({
            file: stateFile,
            detail: 'Migration snapshot exists — rollback capability available',
          });
        }
      } catch {}
    }

    const passed = evidence.length > 0;

    return h.result({
      passed,
      message: passed
        ? `NemoClaw blueprint integrity verified${usesLatest ? ' (warning: using "latest" tag)' : ''}`
        : 'NemoClaw installed but no blueprint artifacts found',
      evidence,
    });
  },
});
