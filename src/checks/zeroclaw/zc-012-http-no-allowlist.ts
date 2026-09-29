import { defineCheck } from '../../core/check-builder.js';
import type { Evidence } from '../../core/types.js';
import { asRecord, hasWildcard, isFalse, isTrue, mainConfig, tomlLine, writeMainConfig } from './zc-config.js';

export const zc012 = defineCheck({
  id: 'ZC-012',
  name: 'Outbound Tools Reach Private Network',
  category: 'zeroclaw',
  severity: 'warning',
  description:
    'Detect SSRF protection turned off for agent network tools: [http_request] allow_private_hosts=true or allowed_private_hosts=["*"], and [web_fetch] / [text_browser] allowed_private_hosts=["*"]',
  supportedAgents: ['zeroclaw'],

  async run(ctx, h) {
    const config = mainConfig(ctx.configs);
    if (!config) return h.passed('No ZeroClaw config.toml found');
    const evidence: Evidence[] = [];
    let writable = false;

    const http = asRecord(config.data.http_request) ?? {};
    if (!isFalse(http.enabled)) {
      if (isTrue(http.allow_private_hosts)) {
        writable = true;
        evidence.push({
          file: config.filePath,
          ...tomlLine(config.raw, 'http_request', 'allow_private_hosts'),
          detail: 'http_request.allow_private_hosts = true — the agent can call RFC 1918 / loopback / .local services',
        });
      }
      if (hasWildcard(http.allowed_private_hosts)) {
        evidence.push({
          file: config.filePath,
          detail: 'http_request.allowed_private_hosts = ["*"] — every private/local host is reachable',
        });
      }
    }

    // web_fetch defaults to enabled; text_browser to disabled.
    const webFetch = asRecord(config.data.web_fetch) ?? {};
    if (!isFalse(webFetch.enabled) && hasWildcard(webFetch.allowed_private_hosts)) {
      evidence.push({
        file: config.filePath,
        detail: 'web_fetch.allowed_private_hosts = ["*"] — web_fetch (auto-approved by default) can reach any private/local host',
      });
    }
    const textBrowser = asRecord(config.data.text_browser) ?? {};
    if (isTrue(textBrowser.enabled) && hasWildcard(textBrowser.allowed_private_hosts)) {
      evidence.push({
        file: config.filePath,
        detail: 'text_browser.allowed_private_hosts = ["*"] — text browser can reach any private/local host',
      });
    }

    return h.fromEvidence(evidence, {
      passed: 'Agent network tools keep private hosts blocked',
      failed: (n) => `${n} network tool(s) can reach the private network (SSRF)`,
      fixable: writable,
      fixDescription:
        'Set [http_request] allow_private_hosts = false and replace "*" in allowed_private_hosts with the specific internal hosts the agent needs',
    });
  },

  async fix(ctx) {
    const config = mainConfig(ctx.configs);
    const http = asRecord(config?.data.http_request) ?? {};
    const updates: Array<[string, unknown]> = isTrue(http.allow_private_hosts)
      ? [['http_request.allow_private_hosts', false]]
      : [];
    return writeMainConfig(ctx, 'ZC-012', updates, 'Set http_request.allow_private_hosts=false');
  },
});
