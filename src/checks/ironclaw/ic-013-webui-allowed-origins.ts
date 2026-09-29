import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { isLegacy, isLoopbackHost, lineOf, rebornConfig, rebornSection, str, urlHost } from './layout.js';

/*
 * 1.x: [webui].allowed_origins is the WebChat v2 CORS allow-list, served with
 * `allow_credentials(true)` (ironclaw_webui/src/webui_serve.rs) and reused by
 * the WebSocket same-origin check. Empty (default) fails closed. Entries are
 * matched exactly, so risk comes from what an operator lists:
 *  - "null" — matches sandboxed iframes, file:// pages and data: URLs, i.e.
 *    any attacker page that opts into an opaque origin;
 *  - http:// origins on non-loopback hosts — a network attacker can inject
 *    script into that origin and ride the credentialed CORS grant;
 *  - "*" / patterns — never a wildcard here: tower-http panics at startup on
 *    "*", and "https://*.example.com" matches nothing (broken config).
 */

export const ic013 = defineCheck({
  id: 'IC-013',
  name: 'Permissive WebUI CORS Origins',
  category: 'ironclaw',
  severity: 'warning',
  description: 'Check [webui].allowed_origins (credentialed CORS + WebSocket origin allow-list) for "null", cleartext http:// remote origins, or wildcard entries',
  supportedAgents: ['ironclaw'],

  async run(ctx, h) {
    if (isLegacy(ctx)) return h.passed('Not applicable to IronClaw 0.x');
    const config = rebornConfig(ctx);
    const origins = rebornSection(ctx, 'webui')?.allowed_origins;
    if (!config || !Array.isArray(origins) || origins.length === 0) {
      return h.passed('WebUI CORS allow-list is empty (fails closed)');
    }

    const line = lineOf(config, 'allowed_origins');
    const at = line ? { line } : {};
    const evidence: Evidence[] = [];
    for (const raw of origins) {
      const origin = str(raw);
      if (!origin) continue;
      if (origin.toLowerCase() === 'null') {
        evidence.push({ file: config.filePath, ...at, snippet: origin, detail: 'Origin "null" is allowed — sandboxed iframes and file:// pages from any site match it and get credentialed access' });
        continue;
      }
      if (origin.includes('*')) {
        evidence.push({ file: config.filePath, ...at, snippet: origin, detail: `Wildcard origin "${origin}" — IronClaw matches origins exactly ("*" aborts serve at startup); list concrete origins` });
        continue;
      }
      const u = urlHost(origin);
      if (u && u.scheme === 'http' && !isLoopbackHost(u.host)) {
        evidence.push({ file: config.filePath, ...at, snippet: origin, detail: `Cleartext origin ${origin} gets credentialed CORS access — a network attacker who injects script into it can drive the WebUI API` });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'WebUI CORS allow-list contains only specific secure origins',
      failed: (n) => `${n} permissive WebUI CORS origin(s)`,
      fixDescription: 'Keep [webui].allowed_origins to the exact https:// origins that serve the WebUI (loopback http:// is fine); remove "null" and wildcard entries',
    });
  },
});
