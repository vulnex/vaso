import type { Evidence, FixResult } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { updateConfigValue, updateEnvFile } from '../../remediation/config-writer.js';
import {
  isLegacy, isLegacyUnused, isLoopbackHost, isWildcardHost, lineOf, legacySetting,
  rebornConfig, rebornSection, rebornServiceUnits, str,
} from './layout.js';
import { configFixTargets } from '../../remediation/fix-refusal.js';

/*
 * 1.x: the WebChat v2 listener (`ironclaw serve`) binds `[webui].listen_host`
 * (default 127.0.0.1:3000; `--host` overrides). It always requires the
 * env-bearer token, so a non-loopback bind is exposure of an authenticated
 * service — plain HTTP, and without `[webui].canonical_host` the WebSocket
 * same-origin check trusts the client-supplied Host header.
 * 0.x: the HTTP webhook (`HTTP_HOST`, requires HTTP_WEBHOOK_SECRET) and the web
 * gateway (`GATEWAY_HOST`, bearer token) both default to 127.0.0.1.
 */

function exposedBind(host: string): boolean {
  return !isLoopbackHost(host);
}

function bindLabel(host: string): string {
  return isWildcardHost(host) ? `${host} (all interfaces)` : host;
}

export const ic001 = defineCheck({
  id: 'IC-001',
  name: 'Listener Bound Beyond Loopback',
  category: 'ironclaw',
  severity: 'warning',
  description: 'Check whether the WebChat v2 listener (1.x [webui].listen_host / serve --host) or the 0.x HTTP webhook / web gateway is bound to a non-loopback interface',
  supportedAgents: ['ironclaw'],

  fixTargets: configFixTargets,

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    let fixable = false;

    if (!isLegacy(ctx)) {
      const config = rebornConfig(ctx);
      const webui = rebornSection(ctx, 'webui');
      const host = str(webui?.listen_host);
      if (config && host && exposedBind(host)) {
        fixable = true;
        const port = str(webui?.listen_port) ?? '3000';
        const pinned = str(webui?.canonical_host);
        const line = lineOf(config, 'listen_host');
        evidence.push({
          file: config.filePath,
          ...(line ? { line } : {}),
          snippet: `listen_host = "${host}"`,
          detail: `WebChat v2 listener bound to ${bindLabel(host)}:${port} — reachable from the network over plain HTTP`
            + (pinned ? '' : '; [webui].canonical_host is unset, so the WebSocket same-origin check trusts the client Host header'),
        });
      }
      for (const unit of await rebornServiceUnits(ctx)) {
        const lines = unit.raw.split('\n');
        for (let i = 0; i < lines.length; i++) {
          // systemd ExecStart=… serve --host 0.0.0.0 ; launchd <string>--host</string><string>0.0.0.0</string>
          const joined = lines[i] + (lines[i].includes('<string>--host</string>') ? (lines[i + 1] ?? '') : '');
          // `ironclaw service install` quotes each ExecStart argument
          // — an address or a hostname (`serve --host myserver.lan`)
          const m = /--host"?(?:=|\s+|<\/string>\s*<string>)"?([^\s"'<]+)/.exec(joined);
          const host = m?.[1].replace(/^\[(.*)\]$/, '$1');
          if (host && exposedBind(host)) {
            evidence.push({
              file: unit.file,
              line: i + 1,
              detail: `Service runs \`ironclaw serve --host ${host}\` — WebChat v2 listener reachable from the network`,
            });
          }
        }
      }
    } else if (!isLegacyUnused(ctx)) {
      const listeners = [
        { env: 'HTTP_HOST', toml: 'channels.http_host', label: 'HTTP webhook' },
        { env: 'GATEWAY_HOST', toml: 'channels.gateway_host', label: 'Web gateway' },
      ];
      for (const l of listeners) {
        for (const s of legacySetting(ctx, l.env, l.toml)) {
          const host = str(s.value);
          if (!host || !exposedBind(host)) continue;
          fixable = true;
          const line = lineOf(s.config, s.key.split('.').pop()!);
          evidence.push({
            file: s.file,
            ...(line ? { line } : {}),
            detail: `${l.label} bound to ${bindLabel(host)} (${s.key}) — reachable from the network`,
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'IronClaw listeners are bound to loopback',
      failed: (n) => `${n} IronClaw listener binding(s) reachable beyond loopback`,
      fixable,
      fixDescription: isLegacy(ctx)
        ? 'Set HTTP_HOST / GATEWAY_HOST to 127.0.0.1 and front the service with a TLS reverse proxy if remote access is needed'
        : 'Set [webui].listen_host = "127.0.0.1" (drop `serve --host`), and put a TLS reverse proxy with [webui].canonical_host in front for remote access',
    });
  },

  async fix(ctx): Promise<FixResult> {
    const changed: string[] = [];
    if (!isLegacy(ctx)) {
      const config = rebornConfig(ctx);
      const host = str(rebornSection(ctx, 'webui')?.listen_host);
      if (config && host && exposedBind(host)) {
        // [webui].listen_host is a string field of the deny_unknown_fields schema.
        await updateConfigValue(config, 'webui.listen_host', '127.0.0.1');
        changed.push(`${config.filePath}: webui.listen_host`);
      }
    } else if (!isLegacyUnused(ctx)) {
      for (const [env, toml] of [['HTTP_HOST', 'channels.http_host'], ['GATEWAY_HOST', 'channels.gateway_host']] as const) {
        for (const s of legacySetting(ctx, env, toml)) {
          const host = str(s.value);
          if (!host || !exposedBind(host)) continue;
          if (s.config.format === 'env') await updateEnvFile(s.file, env, '127.0.0.1');
          else await updateConfigValue(s.config, toml, '127.0.0.1');
          changed.push(`${s.file}: ${s.key}`);
        }
      }
    }
    return changed.length > 0
      ? { checkId: 'IC-001', applied: true, message: `Bound to 127.0.0.1 (${changed.join(', ')})` }
      : { checkId: 'IC-001', applied: false, message: 'No config-file listener binding to change (service-unit flags must be edited by hand)' };
  },
});
