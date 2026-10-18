import { join } from 'node:path';
import type { Evidence, ScanContext, Severity } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { USER_DATA_FILES } from '../../adapters/grok-bot.js';
import { isOwnSession, userDataDir } from './shared.js';

/**
 * Endpoint overrides a packaged 0.71.2 build still honours (main-core
 * environment, read at every launch):
 * - SAND_BACKEND_URL, else CURSOR_API_BASE_URL — the backend. Sign-in polls
 *   it, every request carries the account's access token, and the local-exec
 *   channel is minted there and dialled by the exec daemon. A channel the
 *   backend marks server-authoritative has the daemon take that server's
 *   authorization for local tool use instead of this computer's "Execution on
 *   Local Computer" setting.
 * - SAND_HOST_GATEWAY_URL — replaces the cloud computer the app connects to
 *   (the dev-box control plane that also reads it is dev-only).
 * - SAND_CURSOR_WEBSITE_URL, else CURSOR_WEBSITE_URL — the sign-in page.
 * - SAND_HTTPS_PROXY — an explicit proxy (TLS still verified), unless
 *   SAND_SYSTEM_PROXY=0 or NODE_USE_ENV_PROXY=1 takes precedence.
 * SAND_UPDATE_FEED_BASE_URL is not here: packaged builds download updates
 * from the built-in feed whatever it says.
 */

// Hosts the vendor runs (api2.cursor.sh, cursor.com, *.cursorvm.com boxes)
const VENDOR_HOST = /(?:^|\.)(?:cursor\.sh|cursor\.com|cursorvm\.com)$/i;

interface Endpoint { origin: string; vendor: boolean }

/** Scheme, host and port only — never credentials, paths or query tokens. */
function endpoint(raw: string): Endpoint | undefined {
  try {
    const url = new URL(raw);
    const origin = url.host ? `${url.protocol}//${url.host}` : url.protocol;
    return { origin, vendor: VENDOR_HOST.test(url.hostname.replace(/\.$/, '')) };
  } catch {
    return undefined;
  }
}

/** The first variable that is set (even to ""), as the app's `a ?? b`. */
function firstSet(ctx: ScanContext, names: string[]): { name: string; value: string } | undefined {
  for (const name of names) {
    const value = ctx.fs.getEnv(name);
    if (value !== undefined) return { name, value };
  }
  return undefined;
}

/** SAND_HTTPS_PROXY as the app accepts it: http(s), a host, no path/query/fragment. */
function proxyEndpoint(raw: string): Endpoint | undefined {
  if (raw.includes('#')) return undefined;
  try {
    const url = new URL(raw);
    if ((url.protocol !== 'http:' && url.protocol !== 'https:') || !url.hostname || url.pathname !== '/' || url.search) return undefined;
  } catch {
    return undefined;
  }
  return endpoint(raw);
}

export const gb012 = defineCheck({
  id: 'GB-012',
  name: 'Grok Bot Backend Endpoints Redirected',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect Grok Bot pointed at endpoints other than its vendor\'s from the environment — SAND_BACKEND_URL / CURSOR_API_BASE_URL (the backend that receives the account token and issues the local-exec channel: critical), SAND_HOST_GATEWAY_URL (a substitute cloud computer) and SAND_CURSOR_WEBSITE_URL / CURSOR_WEBSITE_URL (the sign-in page: warning), and SAND_HTTPS_PROXY (info) — plus a past host-gateway override recorded in the user data',
  supportedAgents: ['grok-bot'],

  async run(ctx, h) {
    const critical: Evidence[] = [];
    const warning: Evidence[] = [];
    const info: Evidence[] = [];

    if (isOwnSession(ctx)) {
      // An unparseable value makes the app fail, not redirect
      const backend = firstSet(ctx, ['SAND_BACKEND_URL', 'CURSOR_API_BASE_URL']);
      const backendAt = backend && endpoint(backend.value);
      if (backend && backendAt && !backendAt.vendor) {
        critical.push({
          file: '<process env>',
          snippet: `${backend.name}=${backendAt.origin}`,
          detail: 'Grok Bot signs in against this host, sends it the account\'s access token on every request and takes the local-exec channel from it — a channel it marks server-authoritative lets it approve commands and file access on this computer itself',
        });
      }

      const gateway = ctx.fs.getEnv('SAND_HOST_GATEWAY_URL')?.trim();
      if (gateway) {
        const at = endpoint(gateway);
        if (!at?.vendor) {
          warning.push({
            file: '<process env>',
            snippet: `SAND_HOST_GATEWAY_URL=${at?.origin ?? '<set>'}`,
            detail: 'Replaces the cloud computer: that host receives what you send your agents and decides what they show you (the local-exec channel still comes from the backend)',
          });
        }
      }

      const website = firstSet(ctx, ['SAND_CURSOR_WEBSITE_URL', 'CURSOR_WEBSITE_URL']);
      const websiteAt = website && website.value.length > 0 ? endpoint(website.value) : undefined;
      if (website && websiteAt && !websiteAt.vendor) {
        warning.push({
          file: '<process env>',
          snippet: `${website.name}=${websiteAt.origin}`,
          detail: 'Sign-in opens this site in your browser instead of cursor.com — a page that can collect the account\'s credentials',
        });
      }

      const proxy = ctx.fs.getEnv('SAND_HTTPS_PROXY') ?? '';
      const proxyAt = proxy ? proxyEndpoint(proxy) : undefined;
      if (proxyAt && ctx.fs.getEnv('SAND_SYSTEM_PROXY') !== '0' && ctx.fs.getEnv('NODE_USE_ENV_PROXY') !== '1') {
        info.push({
          file: '<process env>',
          snippet: `SAND_HTTPS_PROXY=${proxyAt.origin}`,
          detail: 'The app\'s backend traffic goes through this proxy; TLS is still verified, so it sees which hosts are contacted, not the content',
        });
      }
    }

    // Written when the app first connects through SAND_HOST_GATEWAY_URL —
    // evidence of an override the scanning environment may no longer carry
    const bindings = join(await userDataDir(ctx), USER_DATA_FILES.gatewayBindings);
    if (await ctx.fs.access(bindings)) {
      info.push({
        file: bindings,
        detail: 'Grok Bot has connected through a host-gateway override (SAND_HOST_GATEWAY_URL) for this user — check how the app is launched',
      });
    }

    const severity: Severity | undefined = critical.length > 0 ? undefined : warning.length > 0 ? 'warning' : info.length > 0 ? 'info' : undefined;
    return h.fromEvidence([...critical, ...warning, ...info], {
      passed: 'Grok Bot uses its built-in endpoints',
      failed: () => critical.length > 0
        ? 'Grok Bot\'s backend is redirected to a non-vendor host'
        : warning.length > 0 ? 'Grok Bot endpoints are redirected to non-vendor hosts' : 'Grok Bot endpoint overrides worth reviewing',
      severity,
      fixDescription: 'Unset SAND_BACKEND_URL, CURSOR_API_BASE_URL, SAND_HOST_GATEWAY_URL, SAND_CURSOR_WEBSITE_URL, CURSOR_WEBSITE_URL and SAND_HTTPS_PROXY wherever the session sets them (shell profile, ~/.config/environment.d, launchctl setenv), then restart Grok Bot',
    });
  },
});
