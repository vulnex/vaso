import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { asRecord, isLoopbackHost, nanobotConfigs, nonEmptyString, pick } from './shared.js';

/*
 * `nanobot serve` exposes an OpenAI-compatible HTTP API (api.host/api.port,
 * default 127.0.0.1:8900) that runs full agent turns — tools included. It has
 * no rate limiting or TLS of its own; api.apiKey is the only gate. The schema
 * rejects an unauthenticated 0.0.0.0 / :: bind, but a specific interface
 * address (e.g. a LAN IP) without apiKey loads and serves anyone.
 */

export const nb011 = defineCheck({
  id: 'NB-011',
  name: 'OpenAI-Compatible API Exposed Without Authentication',
  category: 'nanobot',
  severity: 'critical',
  description: 'Check the `nanobot serve` API (api.host / api.apiKey). nanobot has no request rate limiting, so authentication is the only abuse control: a non-loopback bind without api.apiKey lets anyone on the network run agent turns with shell and file tools (critical); a non-loopback bind with a key still sends it over plaintext HTTP (warning).',
  supportedAgents: ['nanobot'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    let critical = false;

    for (const config of nanobotConfigs(ctx.configs)) {
      const api = asRecord(config.data.api);
      const hostRaw = pick(api, 'host');
      const host = nonEmptyString(hostRaw) ? hostRaw.trim() : '127.0.0.1';
      if (isLoopbackHost(host)) continue;
      const port = typeof api?.port === 'number' ? api.port : 8900;

      if (!nonEmptyString(pick(api, 'apiKey'))) {
        critical = true;
        evidence.push({
          file: config.filePath,
          snippet: `api.host: "${host}", api.apiKey: ""`,
          detail: `nanobot serve on ${host}:${port} accepts unauthenticated requests that run agent turns with tools`,
        });
      } else {
        evidence.push({
          file: config.filePath,
          snippet: `api.host: "${host}"`,
          detail: `nanobot serve on ${host}:${port} is reachable from the network over plaintext HTTP — the API key can be sniffed; put it behind a TLS proxy`,
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'nanobot serve API is bound to loopback (default)',
      failed: (n) => `${n} nanobot serve API exposure issue(s)`,
      severity: evidence.length > 0 && !critical ? 'warning' : undefined,
      fixDescription: 'Keep api.host at 127.0.0.1 and reach it through an authenticated TLS reverse proxy; if it must listen on another interface, set api.apiKey (preferably as a ${VAR} reference)',
    });
  },
});
