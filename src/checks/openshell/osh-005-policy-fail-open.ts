import { defineCheck } from '../../core/check-builder.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';
import { gateway, gatewayToml, settingEvidence } from './shared.js';

export const osh005 = defineCheck({
  id: 'OSH-005',
  name: 'OpenShell Keeps Last Policy on Validation Failure',
  category: 'openshell',
  severity: 'warning',
  description: 'Detect `policy_validation_failure_mode = "retain_last_valid"` — when a new policy generation fails validation, sandboxes keep enforcing the previous one instead of denying egress, so a tightening that breaks validation silently never takes effect',
  supportedAgents: ['openshell'],

  async run(ctx, h) {
    if (gateway(ctx).policy_validation_failure_mode !== 'retain_last_valid') {
      return h.passed('Invalid policy generations fail closed');
    }
    return h.fromEvidence([settingEvidence(gatewayToml(ctx), 'policy_validation_failure_mode = "retain_last_valid"',
      'An invalid policy update leaves the previous network policy active (default fail_closed denies egress until a valid generation loads)')], {
      passed: 'Invalid policy generations fail closed',
      failed: () => 'OpenShell keeps the last valid policy when an update fails validation',
      fixable: true,
      fixDescription: 'Set policy_validation_failure_mode = "fail_closed" (the default) and restart the gateway',
    });
  },

  async fix(ctx) {
    const toml = gatewayToml(ctx);
    return fixFirstConfig(toml ? [toml] : [], {
      checkId: 'OSH-005',
      path: 'openshell.gateway.policy_validation_failure_mode',
      value: 'fail_closed',
      message: 'Set policy_validation_failure_mode = "fail_closed" — restart the gateway to apply',
      noConfigMessage: 'No OpenShell gateway TOML found',
    });
  },
});
