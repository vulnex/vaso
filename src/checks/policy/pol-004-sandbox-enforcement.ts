import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { CODING_AGENTS } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

export const pol004 = defineCheck({
  id: 'POL-004',
  name: 'Sandbox Policy Enforcement',
  category: 'policy',
  severity: 'warning',
  description: 'Verify that enabled sandboxes have substantive constraints (exec, filesystem, network)',
  excludedAgents: CODING_AGENTS,

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const sandbox = getNestedValue(config.data, 'sandbox') ??
                      getNestedValue(config.data, 'security.sandbox') ??
                      getNestedValue(config.data, 'isolation');

      if (!sandbox || sandbox === false || sandbox === 'disabled' || sandbox === 'off' || sandbox === 'none') {
        continue;
      }

      let constraints = 0;
      const sandboxObj = typeof sandbox === 'object' ? sandbox as Record<string, unknown> : config.data;

      const execRestriction = getNestedValue(sandboxObj, 'allowedExec') ??
                              getNestedValue(sandboxObj, 'safeBins') ??
                              getNestedValue(sandboxObj, 'restrictedExec') ??
                              getNestedValue(sandboxObj, 'execPolicy') ??
                              getNestedValue(config.data, 'sandbox.allowedExec') ??
                              getNestedValue(config.data, 'sandbox.execPolicy');
      if (execRestriction) constraints++;

      const fsRestriction = getNestedValue(sandboxObj, 'filesystem') ??
                            getNestedValue(sandboxObj, 'allowedPaths') ??
                            getNestedValue(sandboxObj, 'workspace') ??
                            getNestedValue(sandboxObj, 'rootDir') ??
                            getNestedValue(config.data, 'sandbox.allowedPaths') ??
                            getNestedValue(config.data, 'sandbox.filesystem');
      if (fsRestriction) constraints++;

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

    return h.fromEvidence(evidence, {
      passed: 'Sandbox policies have sufficient constraints',
      failed: (n) => `Found ${n} sandbox config(s) with insufficient constraints`,
    });
  },
});
