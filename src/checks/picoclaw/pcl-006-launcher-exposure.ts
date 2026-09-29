import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { picoLauncherConfigs, stringList } from './shared.js';

const ANY_NET = /^(?:0\.0\.0\.0\/0|::\/0)$/;

export const pcl006 = defineCheck({
  id: 'PCL-006',
  name: 'PicoClaw Web Launcher Exposed',
  category: 'picoclaw',
  severity: 'critical',
  description: 'A public web launcher (launcher-config.json public: true) listens on every interface. Until a dashboard password exists, anyone who reaches it can set one and take over the agent; without allowed_cidrs every network can reach it.',
  supportedAgents: ['picoclaw'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    let severity: 'critical' | 'warning' | 'info' = 'info';
    const raise = (s: 'critical' | 'warning') => {
      if (s === 'critical' || severity === 'info') severity = s;
    };
    for (const config of picoLauncherConfigs(ctx.configs)) {
      const d = config.data;
      const cidrs = stringList(d.allowed_cidrs);
      const openNet = cidrs.length === 0 || cidrs.some(c => ANY_NET.test(c));
      const hasPassword = typeof d.dashboard_password_hash === 'string' && d.dashboard_password_hash.trim() !== '';
      if (d.public === true) {
        if (!hasPassword) {
          raise('critical');
          evidence.push({
            file: config.filePath,
            snippet: 'public: true, no dashboard_password_hash',
            detail: 'Public launcher with no dashboard password — the first visitor can set it (POST /api/auth/setup) and control the agent',
          });
        } else if (openNet) {
          raise('warning');
          evidence.push({
            file: config.filePath,
            snippet: `public: true, allowed_cidrs: ${JSON.stringify(cidrs)}`,
            detail: 'Public launcher reachable from any network (password-protected)',
          });
        }
      }
      const proxies = stringList(d.trusted_proxy_cidrs);
      if (proxies.some(c => ANY_NET.test(c)) && d.allow_localhost_bypass !== false) {
        raise('warning');
        evidence.push({
          file: config.filePath,
          snippet: `trusted_proxy_cidrs: ${JSON.stringify(proxies)}`,
          detail: 'Every peer is a trusted proxy, so a forged X-Forwarded-For: 127.0.0.1 passes the localhost bypass',
        });
      }
      if (typeof d.launcher_token === 'string' && d.launcher_token.trim()) {
        evidence.push({
          file: config.filePath,
          snippet: 'launcher_token: (set)',
          detail: 'Legacy launcher token left in the config (the token login flow was removed)',
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'PicoClaw web launcher is not publicly exposed',
      failed: () => 'PicoClaw web launcher is exposed',
      severity,
      fixDescription: 'Set a dashboard password, restrict allowed_cidrs, or run the launcher without public',
    });
  },
});
