import { defineCheck } from '../../core/check-builder.js';
import { effectivePermission, settingsConfig } from './shared.js';

export const gb009 = defineCheck({
  id: 'GB-009',
  name: 'Grok Bot Messages Access Enabled',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect Grok Bot Messages access (messagesEnabled: true) — on macOS the cloud agent can read your Messages history without asking (messagesReadEnabled, default on) and send iMessages from this computer (messagesSendEnabled, default on); a message from a stranger becomes a prompt-injection path into an agent that can text your contacts',
  supportedAgents: ['grok-bot'],

  async run(ctx, h) {
    const config = settingsConfig(ctx);
    const data = config?.data;
    // 0.78 split Messages into read and send capabilities, both on by default
    // (0.71 had only the master switch, which these defaults reproduce)
    const read = data?.messagesReadEnabled !== false;
    const send = data?.messagesSendEnabled !== false;
    if (!config || data?.messagesEnabled !== true) {
      return h.passed('Grok Bot Messages access is off');
    }
    if (!read && !send) {
      return h.passed('Grok Bot Messages access is on, but reading and sending are both turned off');
    }
    const local = effectivePermission(data.localToolPermission, data.localToolPermissionCeiling);
    // Messages are read and sent through local execution, and only on macOS
    const inactive = ctx.fs.platform !== 'darwin' || local === 'never';
    const snippet = ['messagesEnabled: true', ...(read ? [] : ['messagesReadEnabled: false']), ...(send ? [] : ['messagesSendEnabled: false'])].join(', ');
    const live = read
      // Reading is a setting-scoped action: Messages access is the approval
      ? `The cloud agent reads Messages history without asking${send ? '; sending asks first unless a standing approval exists (see GB-004)' : '; sending is off'}`
      : 'Reading Messages is off; sending asks first unless a standing approval exists (see GB-004)';
    return h.fromEvidence([{
      file: config.filePath,
      snippet,
      detail: inactive
        ? (ctx.fs.platform !== 'darwin' ? 'Messages access works only on macOS — no effect on this computer' : 'Inactive while local execution is "never"')
        : live,
      mitigated: inactive || undefined,
    }], {
      passed: '',
      failed: () => read
        ? `Grok Bot can read${send ? ' and send' : ''} Messages from this computer`
        : 'Grok Bot can send Messages from this computer',
      // Send-only still asks per recipient
      severity: read || inactive ? undefined : 'info',
      fixDescription: 'Turn off Messages access in Grok Bot settings unless you need it (or turn off reading) — turning it off also revokes standing Messages approvals',
    });
  },
});
