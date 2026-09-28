import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { asRecord, atomicConfigs, isLoopbackHost, llmProviders, urlHost } from './shared.js';

function plaintextRemote(url: unknown): url is string {
  if (typeof url !== 'string' || !url.toLowerCase().startsWith('http://')) return false;
  const host = urlHost(url);
  return !!host && !isLoopbackHost(host);
}

export const at010 = defineCheck({
  id: 'AT-010',
  name: 'Atomic Agent Plaintext Inference Endpoint',
  category: 'atomic-agent',
  severity: 'warning',
  description: 'An external llama-server (localModels.url) or an llm.providers[] url/baseUrl uses http:// to a non-loopback host — every prompt (including file contents and tool output the agent read), every completion (including the tool calls the agent will execute) and any API key travel in cleartext and can be read or rewritten on the network.',
  supportedAgents: ['atomic-agent'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of atomicConfigs(ctx.configs)) {
      const local = asRecord(config.data.localModels);
      // Managed mode forces the URL to 127.0.0.1; only external mode dials out.
      if (local && local.mode !== 'managed' && plaintextRemote(local.url)) {
        evidence.push({
          file: config.filePath,
          snippet: `localModels.url: ${local.url}`,
          detail: 'External llama-server reached over plaintext HTTP on the network',
        });
      }
      llmProviders(config.data).forEach((p, i) => {
        const id = typeof p.id === 'string' ? p.id : `#${i}`;
        for (const key of ['url', 'baseUrl'] as const) {
          if (!plaintextRemote(p[key])) continue;
          evidence.push({
            file: config.filePath,
            snippet: `llm.providers[${id}].${key}: ${p[key]}`,
            detail: `Provider "${id}" is reached over plaintext HTTP on the network`,
          });
        }
      });
    }
    return h.fromEvidence(evidence, {
      passed: 'Atomic Agent inference endpoints are loopback or HTTPS',
      failed: (n) => `${n} Atomic Agent inference endpoint(s) use plaintext HTTP over the network`,
      fixDescription: 'Use https:// for remote inference servers (terminate TLS in front of llama-server / Ollama / LM Studio), or reach them over an SSH tunnel bound to 127.0.0.1',
    });
  },
});
