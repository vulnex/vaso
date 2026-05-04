import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const MAIN_PLIST = 'com.openai.chat.plist';

interface AccountSettingsResponse {
  settings?: {
    trainingAllowed?: boolean;
  };
}

export const cg003 = defineCheck({
  id: 'CG-003',
  name: 'Training Data Opt-In Active',
  category: 'coding-agent',
  severity: 'info',
  description: 'Surface when the active ChatGPT account allows OpenAI to train on conversation data',
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
          if (parsed.settings?.trainingAllowed === true) {
            evidence.push({
              file: config.filePath,
              snippet: `${key}.settings.trainingAllowed = true`,
              detail: 'Conversations from this workspace may be used by OpenAI for model training',
            });
          }
        } catch {}
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Training-data opt-in is off (or not configurable in this account)',
      failed: () => 'ChatGPT is configured to allow conversation data to be used for training',
      fixDescription: 'In ChatGPT → Settings → Data Controls, disable "Improve the model for everyone" / training on chats',
    });
  },
});
