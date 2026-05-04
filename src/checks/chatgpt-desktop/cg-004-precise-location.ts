import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const MAIN_PLIST = 'com.openai.chat.plist';

interface AccountSettingsResponse {
  settings?: {
    preciseLocationAllowed?: boolean;
  };
}

export const cg004 = defineCheck({
  id: 'CG-004',
  name: 'Precise Location Enabled',
  category: 'coding-agent',
  severity: 'info',
  description: 'Surface when the ChatGPT account has agreed to share precise location with the model',
  supportedAgents: ['chatgpt-desktop'],
  supportedPlatforms: ['darwin'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      if (!config.filePath.endsWith(MAIN_PLIST)) continue;

      for (const [key, value] of Object.entries(config.data)) {
        if (!key.startsWith('lastAccountSettingsResponse_')) continue;
        if (typeof value !== 'string') continue;
        try {
          const parsed = JSON.parse(value) as AccountSettingsResponse;
          if (parsed.settings?.preciseLocationAllowed === true) {
            evidence.push({
              file: config.filePath,
              snippet: `${key}.settings.preciseLocationAllowed = true`,
              detail: 'Precise location data may be sent to ChatGPT alongside prompts',
            });
          }
        } catch {}
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Precise location sharing is off',
      failed: () => 'ChatGPT account is configured to share precise location with the model',
      fixDescription: 'In ChatGPT → Settings → Data Controls, set Location to "Approximate" or off',
    });
  },
});
