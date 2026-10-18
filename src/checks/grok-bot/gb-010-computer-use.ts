import { defineCheck } from '../../core/check-builder.js';
import { DATA_FILES } from '../../adapters/grok-bot.js';
import { dataFile, effectivePermission, readJson, settingsConfig } from './shared.js';

export const gb010 = defineCheck({
  id: 'GB-010',
  name: 'Grok Bot Local Computer Use Available',
  category: 'coding-agent',
  severity: 'info',
  description: 'Report when Grok Bot\'s local computer-use gate is on (local-computer-use-gate.json isOn: true, mirrored from the server feature gate) — the cloud agent can take screenshots and drive the mouse and keyboard of this computer through the computer-use helper',
  supportedAgents: ['grok-bot'],

  async run(ctx, h) {
    const file = dataFile(ctx, DATA_FILES.computerUseGate);
    const gate = await readJson(ctx, file) as { isOn?: unknown } | undefined;
    if (!gate || gate.isOn !== true) return h.passed('Grok Bot local computer use is not enabled');

    const settings = settingsConfig(ctx)?.data ?? {};
    const local = effectivePermission(settings.localToolPermission, settings.localToolPermissionCeiling);
    return h.fromEvidence([{
      file,
      snippet: 'isOn: true',
      detail: local === 'never'
        ? 'Inactive while local execution is "never"'
        : 'Screen control is offered to the cloud agent; each app use asks first unless a standing approval exists (see GB-004)',
      mitigated: local === 'never' || undefined,
    }], {
      passed: '',
      failed: () => 'Grok Bot local computer use is available on this computer',
      fixDescription: 'Keep "Execution on Local Computer" on "Ask every time" and review app approvals; the gate itself is controlled by Grok Bot\'s server',
    });
  },
});
