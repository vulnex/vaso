import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';

function getNestedValue(obj: Record<string, unknown>, path: string): unknown {
  return path.split('.').reduce<unknown>((curr, key) => {
    if (curr && typeof curr === 'object') return (curr as Record<string, unknown>)[key];
    return undefined;
  }, obj);
}

export const cfg008: CheckModule = {
  id: 'CFG-008',
  name: 'Sandbox Disabled',
  category: 'config',
  severity: 'critical',
  description: 'Check if code sandbox/isolation is disabled',

  async run(ctx: ScanContext): Promise<CheckResult> {
    for (const config of ctx.configs) {
      const sandbox = getNestedValue(config.data, 'sandbox') ??
                      getNestedValue(config.data, 'security.sandbox') ??
                      getNestedValue(config.data, 'isolation');

      if (sandbox === false || sandbox === 'disabled' || sandbox === 'off' || sandbox === 'none') {
        return {
          id: 'CFG-008',
          name: 'Sandbox Disabled',
          category: 'config',
          severity: 'critical',
          passed: false,
          message: 'Code sandbox is explicitly disabled — skills run without isolation',
          evidence: [{ file: config.filePath, detail: `sandbox: ${String(sandbox)}` }],
          fixable: true,
          fixDescription: 'Enable sandbox mode',
        };
      }
    }

    return {
      id: 'CFG-008',
      name: 'Sandbox Disabled',
      category: 'config',
      severity: 'critical',
      passed: true,
      message: 'Sandbox is not explicitly disabled',
    };
  },
};
