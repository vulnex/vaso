import { defineCheck } from '../../core/check-builder.js';
import { getNestedValue } from '../../core/utils.js';

export const zc009 = defineCheck({
  id: 'ZC-009',
  name: 'WhatsApp No App Secret',
  category: 'zeroclaw',
  severity: 'warning',
  description: 'Detect WhatsApp channel enabled without app_secret — webhooks accepted without HMAC verification',
  supportedAgents: ['zeroclaw'],

  async run(ctx, h) {
    const evidence = [];

    for (const config of ctx.configs) {
      const whatsappChannel =
        getNestedValue(config.data, 'channels.whatsapp') as Record<string, unknown> | undefined;

      if (!whatsappChannel || typeof whatsappChannel !== 'object') continue;

      const enabled = whatsappChannel.enabled;
      const appSecret = whatsappChannel.app_secret;

      if (enabled === true || enabled === 'true' || enabled === undefined) {
        if (!appSecret || (typeof appSecret === 'string' && appSecret.trim() === '')) {
          evidence.push({
            file: config.filePath,
            detail: 'WhatsApp channel enabled without app_secret — webhook payloads are not HMAC-verified',
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'WhatsApp channel has app_secret configured or is not enabled',
      failed: () => 'WhatsApp channel lacks app_secret — webhooks accepted without signature verification',
      fixDescription: 'Set channels.whatsapp.app_secret to your WhatsApp app secret for HMAC webhook verification',
    });
  },
});
