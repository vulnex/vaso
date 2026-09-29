import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { enabledChannels, picoMainConfigs, stringList } from './shared.js';

export const pcl005 = defineCheck({
  id: 'PCL-005',
  name: 'PicoClaw WebSocket Channel Weakly Guarded',
  category: 'picoclaw',
  severity: 'warning',
  description: 'The pico WebSocket channel accepts any browser origin when allow_origins is empty or "*" (cross-site WebSocket hijacking from a page the user visits), and allow_token_query puts its bearer token in URLs, where it lands in logs and history.',
  supportedAgents: ['picoclaw'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of picoMainConfigs(ctx.configs)) {
      for (const ch of enabledChannels(config.data).filter(c => c.type === 'pico')) {
        const origins = stringList(ch.settings.allow_origins);
        if (origins.length === 0 || origins.includes('*')) {
          evidence.push({
            file: config.filePath,
            snippet: `channel_list.${ch.name}.settings.allow_origins: ${JSON.stringify(origins)}`,
            detail: 'Any web origin may open the WebSocket — a malicious page can talk to the agent with the user\'s session',
          });
        }
        if (ch.settings.allow_token_query === true) {
          evidence.push({
            file: config.filePath,
            snippet: `channel_list.${ch.name}.settings.allow_token_query: true`,
            detail: 'The channel token is accepted as a URL query parameter',
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'PicoClaw WebSocket channel restricts origins and keeps its token out of URLs',
      failed: (n) => `${n} PicoClaw WebSocket channel weakness(es)`,
      fixDescription: 'Set settings.allow_origins to the launcher origin and allow_token_query to false',
    });
  },
});
