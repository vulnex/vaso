import { defineCheck } from '../../core/check-builder.js';
import { getNestedValue } from '../../core/utils.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';

const KNOWN_SANDBOXES = ['firejail', 'bubblewrap', 'bwrap', 'landlock', 'docker', 'podman', 'nsjail'];

export const zc014 = defineCheck({
  id: 'ZC-014',
  name: 'No OS Sandbox',
  category: 'zeroclaw',
  severity: 'warning',
  description: 'Detect runtime.kind=native without OS-level sandboxing (Firejail, Bubblewrap, Landlock)',
  supportedAgents: ['zeroclaw'],

  async run(ctx, h) {
    const evidence = [];

    for (const config of ctx.configs) {
      const runtimeKind = getNestedValue(config.data, 'runtime.kind');
      const runtimeSandbox = getNestedValue(config.data, 'runtime.sandbox');

      if (runtimeKind === 'native') {
        const hasSandbox =
          typeof runtimeSandbox === 'string' &&
          KNOWN_SANDBOXES.includes(runtimeSandbox.toLowerCase());

        if (!hasSandbox) {
          evidence.push({
            file: config.filePath,
            detail: `runtime.kind=native with runtime.sandbox=${runtimeSandbox ?? 'not set'} — no OS-level isolation`,
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Runtime has OS-level sandboxing or is not running in native mode',
      failed: () => 'Native runtime without OS-level sandboxing — process isolation is missing',
      fixable: true,
      fixDescription: 'Set runtime.sandbox to a supported sandbox (firejail, bubblewrap, landlock) or use runtime.kind=docker',
    });
  },

  async fix(ctx) {
    return fixFirstConfig(ctx.configs, {
      checkId: 'ZC-014',
      path: 'runtime.sandbox',
      value: 'firejail',
      message: 'Set runtime.sandbox=firejail',
      noConfigMessage: 'No TOML config file found',
    });
  },
});
