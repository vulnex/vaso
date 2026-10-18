import { defineCheck } from '../../core/check-builder.js';
import { effectivePermission, settingsConfig } from './shared.js';

export const gb009 = defineCheck({
  id: 'GB-009',
  name: 'Grok Bot Messages Access Enabled',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect Grok Bot Messages access (messagesEnabled: true) — on macOS the cloud agent can read your Messages history and send iMessages from this computer; a message from a stranger becomes a prompt-injection path into an agent that can text your contacts',
  supportedAgents: ['grok-bot'],

  async run(ctx, h) {
    const config = settingsConfig(ctx);
    if (!config || config.data.messagesEnabled !== true) {
      return h.passed('Grok Bot Messages access is off');
    }
    const local = effectivePermission(config.data.localToolPermission, config.data.localToolPermissionCeiling);
    // Messages are read and sent through local execution, and only on macOS
    const inactive = ctx.fs.platform !== 'darwin' || local === 'never';
    return h.fromEvidence([{
      file: config.filePath,
      snippet: 'messagesEnabled: true',
      detail: inactive
        ? (ctx.fs.platform !== 'darwin' ? 'Messages access works only on macOS — no effect on this computer' : 'Inactive while local execution is "never"')
        : 'The cloud agent can read Messages history; sending asks first unless a standing approval exists (see GB-004)',
      mitigated: inactive || undefined,
    }], {
      passed: '',
      failed: () => 'Grok Bot can read and send Messages from this computer',
      fixDescription: 'Turn off Messages access in Grok Bot settings unless you need it — turning it off also revokes standing Messages approvals',
    });
  },
});
