import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import {
  isLegacy, isLoopbackHost, legacyEnv, legacyToml, lineOf, rebornConfig, rebornProviders, str, table, urlHost,
} from './layout.js';

/*
 * Neither generation terminates TLS itself (1.x WebChat v2 is plain HTTP; the
 * 0.x TLS env vars this check used to read never existed). The TLS risk that
 * is configurable is LLM egress: a `base_url` over http:// to a non-loopback
 * host sends the provider API key and every prompt/response in cleartext.
 * Upstream refuses public http:// endpoints but allows private-network ones
 * (self-hosted Ollama on the LAN), so those are what this flags in practice.
 */

function cleartext(url: string): string | undefined {
  const u = urlHost(url);
  if (!u || u.scheme !== 'http') return undefined;
  return isLoopbackHost(u.host) ? undefined : u.host;
}

export const ic002 = defineCheck({
  id: 'IC-002',
  name: 'Cleartext LLM Endpoint',
  category: 'ironclaw',
  severity: 'warning',
  description: 'Check for LLM provider base URLs (1.x [llm.*].base_url / providers.json default_base_url, 0.x *_BASE_URL) that use plain http:// to a non-loopback host',
  supportedAgents: ['ironclaw'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const flag = (file: string, line: number | undefined, key: string, url: string, host: string) =>
      evidence.push({
        file,
        ...(line ? { line } : {}),
        snippet: `${key} = ${url}`,
        detail: `${key} sends API keys and prompts to ${host} over unencrypted HTTP`,
      });

    if (!isLegacy(ctx)) {
      const config = rebornConfig(ctx);
      const llm = table(config?.data?.llm) ?? {};
      for (const [slot, raw] of Object.entries(llm)) {
        const url = str(table(raw)?.base_url);
        const host = url ? cleartext(url) : undefined;
        if (config && url && host) flag(config.filePath, lineOf(config, 'base_url'), `[llm.${slot}].base_url`, url, host);
      }
      const providers = rebornProviders(ctx);
      for (const entry of providers?.entries ?? []) {
        const url = str(entry.default_base_url);
        const host = url ? cleartext(url) : undefined;
        if (providers && url && host) {
          flag(providers.config.filePath, lineOf(providers.config, 'default_base_url'),
            `providers.json "${str(entry.id) ?? '?'}".default_base_url`, url, host);
        }
      }
    } else {
      const env = legacyEnv(ctx);
      for (const [key, value] of Object.entries(env?.data ?? {})) {
        if (!/_BASE_URL$|_API_URL$/.test(key)) continue;
        const url = str(value);
        const host = url ? cleartext(url) : undefined;
        if (env && url && host) flag(env.filePath, lineOf(env, key), key, url, host);
      }
      const toml = legacyToml(ctx);
      for (const key of ['ollama_base_url', 'openai_compatible_base_url']) {
        const url = str(toml?.data?.[key]);
        const host = url ? cleartext(url) : undefined;
        if (toml && url && host) flag(toml.filePath, lineOf(toml, key), key, url, host);
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'LLM endpoints use TLS or stay on loopback',
      failed: (n) => `${n} LLM endpoint(s) configured over cleartext HTTP`,
      fixDescription: 'Use https:// for remote LLM endpoints, or keep http:// endpoints on loopback (tunnel/VPN for LAN inference servers)',
    });
  },
});
