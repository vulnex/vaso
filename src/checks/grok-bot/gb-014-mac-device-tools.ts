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
 *
 * 1.2 moved Mail behind its own gate, mac-mail-tools-gate.json (server flag
 * sand_mac_mail_drafts): the daemon enables a Mail tool from that gate and
 * every other device tool from the device-tools gate. The app writes the
 * mail gate at every start, so when it exists it alone governs Mail.
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
    const mailFile = dataFile(ctx, DATA_FILES.macMailToolsGate);
    const mailGate = await readJson(ctx, mailFile) as { isOn?: unknown } | undefined;
    // 1.2+: a separate Mail gate; before it, Mail followed the device-tools gate
    const separateMail = mailGate !== undefined || await ctx.fs.access(mailFile);
    const mailOn = separateMail ? mailGate?.isOn === true : gateOn;
    const config = settingsConfig(ctx);
    const mailSend = config?.data.macMailSendEnabled === true;
    if (!gateOn && !mailOn && !mailSend) return h.passed('Grok Bot Mac device tools are not enabled');

    const settings = config?.data ?? {};
    const never = effectivePermission(settings.localToolPermission, settings.localToolPermissionCeiling) === 'never';
    const evidence: Evidence[] = [];
    const inactive = 'Inactive while local execution is "never"';
    if (gateOn) {
      evidence.push({
        file,
        snippet: 'isOn: true',
        detail: never
          ? inactive
          : separateMail
            ? 'The cloud agent can use Reminders, Calendar, Contacts and Notes on this computer; each call asks first'
            : 'The cloud agent can use Reminders, Calendar, Contacts, Notes and Mail on this computer; each call asks first',
        mitigated: never || undefined,
      });
    }
    if (separateMail && mailOn) {
      evidence.push({
        file: mailFile,
        snippet: 'isOn: true',
        detail: never ? inactive : 'The cloud agent can use Mail on this computer; each call asks first',
        mitigated: never || undefined,
      });
    }
    if (mailSend && config) {
      evidence.push({
        file: config.filePath,
        snippet: 'macMailSendEnabled: true',
        detail: !mailOn
          ? `Inactive while the Mac Mail tools are off (${separateMail ? DATA_FILES.macMailToolsGate : DATA_FILES.macDeviceToolsGate})`
          : never
            ? inactive
            : 'The cloud agent can send email from your Mail accounts; each message needs its own approval',
        mitigated: !mailOn || never || undefined,
      });
    }
    const apps = [...(mailOn ? ['Mail'] : []), ...(gateOn ? ['Notes', 'Contacts', 'Calendar', 'Reminders'] : [])];
    const appList = apps.length > 1 ? `${apps.slice(0, -1).join(', ')} and ${apps[apps.length - 1]}` : apps[0];
    return h.fromEvidence(evidence, {
      passed: '',
      failed: () => mailSend && mailOn
        ? `Grok Bot can use ${appList}, and send email, on this computer`
        : apps.length > 0
          ? `Grok Bot can use ${appList} on this computer`
          : 'Grok Bot Mail sending is turned on',
      fixDescription: 'Keep "Execution on Local Computer" on "Ask every time", turn off Mail sending in Grok Bot settings unless you need it, and review the Automation and Contacts/Calendars/Reminders grants for Grok Bot in System Settings → Privacy & Security; the device-tools gate itself is controlled by Grok Bot\'s server',
    });
  },
});
