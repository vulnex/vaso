import { defineCheck } from '../../core/check-builder.js';
import type { Evidence } from '../../core/types.js';
import { compareVersions } from '../../core/semver.js';
import {
  asRecord, asStringArray, effectiveProfiles, hasWildcard, isFalse, isTrue, mainConfig, profileLabel, writeMainConfig,
  type EffectiveProfile, type Rec,
} from './zc-config.js';
import type { KeyPath } from '../../core/utils.js';
import { mainConfigFixTargets } from './zc-config.js';

/** Last release where `[browser] enabled` (default true) also registers the
 *  full `browser` automation tool and `browser` is in the default
 *  auto_approve list. Later builds gate automation behind
 *  `browser.automation_enabled` (default false). */
const LAST_IMPLICIT_AUTOMATION = '0.8.5';

export function browserAutomationActive(data: Rec, version: string | undefined): boolean {
  const browser = asRecord(data.browser) ?? {};
  if ('automation_enabled' in browser) return isTrue(browser.automation_enabled);
  if (version && compareVersions(version, LAST_IMPLICIT_AUTOMATION) > 0) return false;
  return !isFalse(browser.enabled);
}

/** `default_auto_approve()` in zeroclaw ≤ 0.8.5 — applied when a profile omits
 *  auto_approve. It includes the full `browser` tool (removed upstream later). */
const DEFAULT_AUTO_APPROVE_085 = [
  'file_read', 'memory_recall', 'web_search_tool', 'web_fetch', 'calculator', 'glob_search',
  'content_search', 'image_info', 'weather', 'tool_search', 'browser', 'browser_open',
];

/** The profile's effective auto_approve list (upstream default when omitted). */
function autoApproveList(p: EffectiveProfile, implicitDefaults: boolean): string[] {
  if (Array.isArray(p.profile.auto_approve)) return asStringArray(p.profile.auto_approve).map(s => s.trim());
  return implicitDefaults ? DEFAULT_AUTO_APPROVE_085 : [];
}

/** Profiles under which a `browser` tool call skips approval. */
function autoApprovesBrowser(p: EffectiveProfile, implicitDefaults: boolean): boolean {
  const alwaysAsk = asStringArray(p.profile.always_ask).map(s => s.trim());
  if (alwaysAsk.includes('*') || alwaysAsk.includes('browser')) return false;
  const level = typeof p.profile.level === 'string' ? p.profile.level.trim().toLowerCase() : '';
  if (level === 'readonly') return false;
  if (level === 'full') return true;
  const auto = autoApproveList(p, implicitDefaults);
  return auto.includes('*') || auto.includes('browser');
}

export const zc011 = defineCheck({
  id: 'ZC-011',
  name: 'Browser Automation Without Approval',
  category: 'zeroclaw',
  severity: 'warning',
  description:
    'Detect the full `browser` automation tool (drives a possibly logged-in Chrome/Chromium) auto-approved by an agent risk profile, or [browser] allowed_private_hosts = ["*"] (reaches internal hosts and the cloud metadata endpoint)',
  supportedAgents: ['zeroclaw'],

  fixTargets: mainConfigFixTargets,

  async run(ctx, h) {
    const config = mainConfig(ctx.configs);
    if (!config) return h.passed('No ZeroClaw config.toml found');
    const browser = asRecord(config.data.browser) ?? {};
    const evidence: Evidence[] = [];
    const automation = browserAutomationActive(config.data, ctx.installation.version);
    // Only builds with implicit automation shipped "browser" in the default auto_approve.
    const implicit = !('automation_enabled' in browser);
    let writable = false;

    if (automation) {
      const domains = asStringArray(browser.allowed_domains);
      const scope = browser.allowed_domains === undefined || hasWildcard(domains)
        ? 'any domain (allowed_domains = ["*"])'
        : `${domains.length} allowed domain(s)`;
      for (const p of effectiveProfiles(config.data)) {
        if (!autoApprovesBrowser(p, implicit)) continue;
        const auto = autoApproveList(p, implicit);
        const viaAuto = auto.includes('browser') || auto.includes('*');
        if (auto.includes('browser')) writable = true;
        evidence.push({
          file: config.filePath,
          detail:
            `${profileLabel(p)}: browser automation runs without approval ` +
            `(${viaAuto ? (Array.isArray(p.profile.auto_approve) ? 'auto_approve' : 'default auto_approve') : 'level = "full"'}) on ${scope} — a prompt-injected message can act in the operator's browser sessions`,
        });
      }
    }

    if ((automation || !isFalse(browser.enabled)) && hasWildcard(browser.allowed_private_hosts)) {
      evidence.push({
        file: config.filePath,
        detail: 'browser.allowed_private_hosts = ["*"] — browser tools may reach any private/link-local host, including the cloud metadata endpoint',
      });
    }

    return h.fromEvidence(evidence, {
      passed: 'Browser automation requires approval and private hosts are not wildcarded',
      failed: (n) => `${n} browser exposure(s): automation without approval or wildcard private hosts`,
      fixable: writable,
      fixDescription:
        'Remove "browser" from auto_approve in the risk profile (keep "browser_open"), or disable [browser] if unused; list specific hosts in allowed_private_hosts',
    });
  },

  async fix(ctx) {
    const config = mainConfig(ctx.configs);
    const updates: Array<[KeyPath, unknown]> = [];
    if (config && browserAutomationActive(config.data, ctx.installation.version)) {
      const implicit = !('automation_enabled' in (asRecord(config.data.browser) ?? {}));
      for (const p of effectiveProfiles(config.data)) {
        const auto = autoApproveList(p, implicit);
        if (!auto.includes('browser')) continue;
        updates.push([[...p.path, 'auto_approve'], auto.filter(s => s !== 'browser')]);
      }
    }
    return writeMainConfig(ctx, 'ZC-011', updates, 'Removed "browser" from risk-profile auto_approve lists');
  },
});
