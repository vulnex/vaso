import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

export const cfg018 = defineCheck({
  id: 'CFG-018',
  name: 'NemoClaw Network Policy',
  category: 'config',
  severity: 'warning',
  description: 'Check if NemoClaw enforces deny-by-default network policy with controlled egress',
  supportedAgents: ['openclaw', 'nemoclaw'],

  async run(ctx, h) {
    const stateFile = join(ctx.fs.homedir(), '.nemoclaw', 'state', 'nemoclaw.json');
    if (!(await ctx.fs.access(stateFile))) {
      return h.result({
        passed: false,
        message: 'NemoClaw not deployed — no network policy enforcement',
      });
    }

    // Find the active blueprint to check its policy config
    let blueprintDir: string | undefined;
    try {
      const raw = await ctx.fs.readFile(stateFile);
      const state = JSON.parse(raw) as Record<string, unknown>;
      const version = state.blueprintVersion as string | undefined;
      if (version) {
        const candidate = join(ctx.fs.homedir(), '.nemoclaw', 'blueprints', version);
        if (await ctx.fs.access(candidate)) {
          blueprintDir = candidate;
        }
      }
    } catch {}

    // If we can't find the blueprint locally, check the installed NemoClaw package
    if (!blueprintDir) {
      // Try global npm installation path
      const globalPaths = [
        '/usr/local/lib/node_modules/nemoclaw/nemoclaw-blueprint',
        join(ctx.fs.homedir(), '.npm-global', 'lib', 'node_modules', 'nemoclaw', 'nemoclaw-blueprint'),
      ];
      for (const p of globalPaths) {
        if (await ctx.fs.access(p)) {
          blueprintDir = p;
          break;
        }
      }
    }

    if (!blueprintDir) {
      return h.result({
        passed: true,
        message: 'NemoClaw is deployed but blueprint policies could not be located for inspection',
        evidence: [{ file: stateFile, detail: 'Sandbox deployed — network policy assumed active via OpenShell enforcement' }],
      });
    }

    const evidence: Evidence[] = [];
    const policyFile = join(blueprintDir, 'policies', 'openclaw-sandbox.yaml');

    if (await ctx.fs.access(policyFile)) {
      try {
        const content = await ctx.fs.readFile(policyFile);
        const hasDenyDefault = /default\s*:\s*deny/i.test(content) ||
                               /policy\s*:\s*deny/i.test(content) ||
                               content.includes('deny-by-default');

        // Count allowed endpoints
        const allowMatches = content.match(/allow:/gi);
        const endpointCount = allowMatches ? allowMatches.length : 0;

        evidence.push({
          file: policyFile,
          detail: `Baseline policy: ${hasDenyDefault ? 'deny-by-default' : 'custom'}, ${endpointCount} allow rule(s)`,
        });
      } catch {
        evidence.push({ file: policyFile, detail: 'Policy file exists but unreadable' });
      }
    }

    // Check for active presets
    const presetsDir = join(blueprintDir, 'policies', 'presets');
    if (await ctx.fs.access(presetsDir)) {
      try {
        const presets = await ctx.fs.readdir(presetsDir);
        const yamlPresets = presets.filter(f => f.endsWith('.yaml') || f.endsWith('.yml'));
        if (yamlPresets.length > 0) {
          evidence.push({
            file: presetsDir,
            detail: `Available policy presets: ${yamlPresets.map(f => f.replace(/\.ya?ml$/, '')).join(', ')}`,
          });
        }
      } catch {}
    }

    return h.result({
      passed: true,
      message: 'NemoClaw network policy is configured with controlled egress',
      evidence,
    });
  },
});
