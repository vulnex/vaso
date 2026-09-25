import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

export const mm002 = defineCheck({
  id: 'MM-002',
  name: 'Muse Analytics Telemetry Active',
  category: 'coding-agent',
  severity: 'info',
  description: 'Report when Muse analytics/telemetry sessions are active on this machine (FBAnalytics + endo_analytics preference keys) or Sparkle auto-updates are disabled',
  supportedAgents: ['meta-muse'],
  supportedPlatforms: ['darwin'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      if (!config.filePath.endsWith('com.meta.endo.plist')) continue;
      const keys = Object.keys(config.data);

      const analyticsKeys = keys.filter(k =>
        k.startsWith('endo_analytics_') || k === 'FBAnalyticsCurrentLoggedInUserIdentityDict'
      );
      if (analyticsKeys.length > 0) {
        evidence.push({
          file: config.filePath,
          snippet: analyticsKeys.slice(0, 4).join(', '),
          detail: 'Analytics session state present — Muse reports telemetry to Meta (observed active even on unconfigured, region-locked installs)',
        });
      }

      // Sparkle auto-update disabled → security fixes stop arriving. Enabled
      // (the default) is the healthy state and is not reported.
      for (const key of ['SUEnableAutomaticChecks', 'SUAutomaticallyUpdate'] as const) {
        const value = config.data[key];
        if (value === 0 || value === false) {
          evidence.push({
            file: config.filePath,
            snippet: `${key} = 0`,
            detail: key === 'SUEnableAutomaticChecks'
              ? 'Sparkle update checks disabled — Muse will not learn about security updates'
              : 'Sparkle automatic install disabled — security updates wait for a manual install',
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No Muse analytics/telemetry state found',
      failed: (n) => `Found ${n} telemetry / disabled-update indicator(s) in Muse preferences`,
      fixDescription: 'Review Muse’s privacy settings once configurable; restrict analytics if organizational policy requires it; keep automatic updates enabled',
    });
  },
});
