import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

export const pol004: CheckModule = {
  id: 'POL-004',
  name: 'Sandbox Policy Enforcement',
  category: 'policy',
  severity: 'warning',
  description: 'Verify that enabled sandboxes have substantive constraints (exec, filesystem, network)',

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const sandbox = getNestedValue(config.data, 'sandbox') ??
                      getNestedValue(config.data, 'security.sandbox') ??
                      getNestedValue(config.data, 'isolation');

      // Skip if sandbox is disabled or not configured
      if (!sandbox || sandbox === false || sandbox === 'disabled' || sandbox === 'off' || sandbox === 'none') {
        continue;
      }

      // Sandbox is enabled — count substantive constraints
      let constraints = 0;
      const sandboxObj = typeof sandbox === 'object' ? sandbox as Record<string, unknown> : config.data;

      // 1. Exec restrictions
      const execRestriction = getNestedValue(sandboxObj, 'allowedExec') ??
                              getNestedValue(sandboxObj, 'safeBins') ??
                              getNestedValue(sandboxObj, 'restrictedExec') ??
                              getNestedValue(sandboxObj, 'execPolicy') ??
                              getNestedValue(config.data, 'sandbox.allowedExec') ??
                              getNestedValue(config.data, 'sandbox.execPolicy');
      if (execRestriction) constraints++;

      // 2. Filesystem boundaries
      const fsRestriction = getNestedValue(sandboxObj, 'filesystem') ??
                            getNestedValue(sandboxObj, 'allowedPaths') ??
                            getNestedValue(sandboxObj, 'workspace') ??
                            getNestedValue(sandboxObj, 'rootDir') ??
                            getNestedValue(config.data, 'sandbox.allowedPaths') ??
                            getNestedValue(config.data, 'sandbox.filesystem');
      if (fsRestriction) constraints++;

      // 3. Network restrictions
      const netRestriction = getNestedValue(sandboxObj, 'network') ??
                             getNestedValue(sandboxObj, 'allowedHosts') ??
                             getNestedValue(sandboxObj, 'networkPolicy') ??
                             getNestedValue(config.data, 'sandbox.allowedHosts') ??
                             getNestedValue(config.data, 'sandbox.networkPolicy');
      if (netRestriction) constraints++;

      if (constraints < 2) {
        evidence.push({
          file: config.filePath,
          detail: `Sandbox is enabled but has only ${constraints} constraint(s) (minimum 2 required: exec, filesystem, network)`,
        });
      }
    }

    return {
      id: 'POL-004',
      name: 'Sandbox Policy Enforcement',
      category: 'policy',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'Sandbox policies have sufficient constraints'
        : `Found ${evidence.length} sandbox config(s) with insufficient constraints`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};
