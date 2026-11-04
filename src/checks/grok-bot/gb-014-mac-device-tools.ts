import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { DATA_FILES } from '../../adapters/grok-bot.js';
import { dataFile, effectivePermission, readJson, settingsConfig } from './shared.js';

/**
 * Grok Bot 0.78 on macOS offers the cloud agent Reminders, Calendar, Contacts,
 * Notes and Mail through the local exec daemon. The app mirrors the server
 * flag that enables them into mac-device-tools-gate.json; sending mail also
 * needs the user's macMailSendEnabled (default off). Every device-tool call
 * asks first — "always" covers only command and file actions — and a mail
 * send spends a single-use approval; "never" refuses them.
 */
export const gb014 = defineCheck({
  id: 'GB-014',
  name: 'Grok Bot Mac Device Tools Available',
  category: 'coding-agent',
  severity: 'info',
  description: 'Report when Grok Bot offers its Mac device tools to the cloud agent (mac-device-tools-gate.json isOn: true, mirrored from the server flag) — Reminders, Calendar, Contacts, Notes and Mail on this computer, each call approved first — and when Mail sending is turned on (macMailSendEnabled: true), which lets the agent send email from your Mail accounts once you approve each message',
  supportedAgents: ['grok-bot'],

  async run(ctx, h) {
    if (ctx.fs.platform !== 'darwin') return h.passed('Grok Bot Mac device tools exist only on macOS');
    const file = dataFile(ctx, DATA_FILES.macDeviceToolsGate);
    const gate = await readJson(ctx, file) as { isOn?: unknown } | undefined;
    const gateOn = gate?.isOn === true;
    const config = settingsConfig(ctx);
    const mailSend = config?.data.macMailSendEnabled === true;
    if (!gateOn && !mailSend) return h.passed('Grok Bot Mac device tools are not enabled');

    const settings = config?.data ?? {};
    const never = effectivePermission(settings.localToolPermission, settings.localToolPermissionCeiling) === 'never';
    const evidence: Evidence[] = [];
    if (gateOn) {
      evidence.push({
        file,
        snippet: 'isOn: true',
        detail: never
          ? 'Inactive while local execution is "never"'
          : 'The cloud agent can use Reminders, Calendar, Contacts, Notes and Mail on this computer; each call asks first',
        mitigated: never || undefined,
      });
    }
    if (mailSend && config) {
      evidence.push({
        file: config.filePath,
        snippet: 'macMailSendEnabled: true',
        detail: !gateOn
          ? 'Inactive while the Mac device tools are off (mac-device-tools-gate.json)'
          : never
            ? 'Inactive while local execution is "never"'
            : 'The cloud agent can send email from your Mail accounts; each message needs its own approval',
        mitigated: !gateOn || never || undefined,
      });
    }
    return h.fromEvidence(evidence, {
      passed: '',
      failed: () => mailSend && gateOn
        ? 'Grok Bot can use Mail, Notes, Contacts, Calendar and Reminders, and send email, on this computer'
        : gateOn
          ? 'Grok Bot can use Mail, Notes, Contacts, Calendar and Reminders on this computer'
          : 'Grok Bot Mail sending is turned on',
      fixDescription: 'Keep "Execution on Local Computer" on "Ask every time", turn off Mail sending in Grok Bot settings unless you need it, and review the Automation and Contacts/Calendars/Reminders grants for Grok Bot in System Settings → Privacy & Security; the device-tools gate itself is controlled by Grok Bot\'s server',
    });
  },
});
