import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

export const mm002 = defineCheck({
  id: 'MM-002',
  name: 'Muse Analytics Telemetry Active',
  category: 'coding-agent',
  severity: 'info',
  description: 'Report when Muse analytics/telemetry sessions are active on this machine (FBAnalytics + endo_analytics preference keys)',
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

      if (config.data.SUEnableAutomaticChecks === 1 || config.data.SUEnableAutomaticChecks === true) {
        evidence.push({
          file: config.filePath,
          snippet: 'SUEnableAutomaticChecks = 1',
          detail: 'Sparkle auto-update checks enabled (informational — verify the appcast host is expected)',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No Muse analytics/telemetry state found',
      failed: (n) => `Found ${n} telemetry/auto-update indicator(s) in Muse preferences`,
      fixDescription: 'Review Muse’s privacy settings once configurable; restrict analytics if organizational policy requires it',
    });
  },
});
