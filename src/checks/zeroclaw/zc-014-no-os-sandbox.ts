import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

const KNOWN_SANDBOXES = ['firejail', 'bubblewrap', 'bwrap', 'landlock', 'docker', 'podman', 'nsjail'];

export const zc014: CheckModule = {
  id: 'ZC-014',
  name: 'No OS Sandbox',
  category: 'zeroclaw',
  severity: 'warning',
  description: 'Detect runtime.kind=native without OS-level sandboxing (Firejail, Bubblewrap, Landlock)',
  supportedAgents: ['zeroclaw'],

  async run(ctx: ScanContext): Promise<CheckResult> {
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

    return {
      id: 'ZC-014',
      name: 'No OS Sandbox',
      category: 'zeroclaw',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'Runtime has OS-level sandboxing or is not running in native mode'
        : 'Native runtime without OS-level sandboxing — process isolation is missing',
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: true,
      fixDescription: 'Set runtime.sandbox to a supported sandbox (firejail, bubblewrap, landlock) or use runtime.kind=docker',
    };
  },
};
