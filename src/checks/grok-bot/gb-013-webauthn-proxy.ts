import { defineCheck } from '../../core/check-builder.js';
import { DATA_FILES } from '../../adapters/grok-bot.js';
import { dataFile, settingsConfig } from './shared.js';

// The app offers the proxy only where it can reach the platform
// authenticator (0.71.2: macOS and Windows)
const WEBAUTHN_PLATFORMS = new Set(['darwin', 'win32']);

export const gb013 = defineCheck({
  id: 'GB-013',
  name: 'Grok Bot Passkey Proxy Enabled',
  category: 'coding-agent',
  severity: 'info',
  description: 'Report when Grok Bot\'s WebAuthn proxy is on (webauthnProxyEnabled, default true; macOS and Windows only) — the cloud computer\'s browser can ask to sign in with this computer\'s passkeys and security keys. Each request asks for consent, showing the site, and for the PIN where the key needs one',
  supportedAgents: ['grok-bot'],

  async run(ctx, h) {
    if (!WEBAUTHN_PLATFORMS.has(ctx.fs.platform)) {
      return h.passed('Grok Bot\'s passkey proxy is not available on this platform');
    }
    // App-wide setting; a missing or rejected settings.json means the default
    const config = settingsConfig(ctx);
    if (config?.data.webauthnProxyEnabled === false) {
      return h.passed('Grok Bot\'s passkey proxy is off');
    }
    return h.fromEvidence([{
      file: config?.filePath ?? dataFile(ctx, DATA_FILES.settings),
      snippet: config?.data.webauthnProxyEnabled === true ? 'webauthnProxyEnabled: true' : 'webauthnProxyEnabled (default: true)',
      detail: 'Agents on the cloud computer can request sign-ins with this computer\'s passkeys and security keys; each one asks you first, naming the site',
    }], {
      passed: '',
      failed: () => 'Grok Bot\'s passkey proxy is on',
      fixDescription: 'Turn off the passkey and security-key proxy under Settings → Computer if agents should not sign in as you, and decline consent prompts for sites you did not ask the agent to use',
    });
  },
});
