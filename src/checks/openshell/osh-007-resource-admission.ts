import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { gatewayToml, record, root } from './shared.js';

export const osh007 = defineCheck({
  id: 'OSH-007',
  name: 'OpenShell Sandbox Resource Admission Disabled',
  category: 'openshell',
  severity: 'warning',
  description: 'Detect compute drivers with external-resource admission turned off (`resource_admission.enabled = false`) — sandboxes can then attach volumes, host mounts and other resources without operator approval labels; flagged as critical when caller-supplied driver config (`allow_driver_config = true`) is also enabled',
  supportedAgents: ['openshell'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    let critical = false;
    const file = gatewayToml(ctx)?.filePath ?? '';
    for (const [driver, value] of Object.entries(record(root(ctx).drivers) ?? {})) {
      const d = record(value);
      if (!d || record(d.resource_admission)?.enabled !== false) continue;
      const driverConfig = d.allow_driver_config === true;
      critical ||= driverConfig;
      evidence.push({
        file,
        snippet: `[openshell.drivers.${driver}.resource_admission] enabled = false${driverConfig ? ' + allow_driver_config = true' : ''}`,
        detail: driverConfig
          ? 'Sandbox callers can pass driver JSON (mounts, devices) and nothing requires operator approval for the resources it attaches'
          : 'External resources attached to sandboxes no longer need operator approval labels',
      });
    }
    return h.fromEvidence(evidence, {
      passed: 'Sandbox resource admission is enforced',
      failed: (n) => `Resource admission disabled on ${n} OpenShell compute driver(s)`,
      severity: critical ? 'critical' : undefined,
      fixDescription: 'Remove resource_admission.enabled = false (admission is on by default) and label approved resources instead; enable allow_driver_config only together with admission',
    });
  },
});
