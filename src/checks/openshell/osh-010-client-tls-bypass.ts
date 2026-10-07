import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { listDir, ownInstall, paths, record } from './shared.js';

const TRUTHY = new Set(['1', 'true', 'yes', 'on']);
const LOOPBACK_URL = /^http:\/\/(?:localhost|127(?:\.\d+){3}|\[::1\])(?:[:/]|$)/i;

export const osh010 = defineCheck({
  id: 'OSH-010',
  name: 'OpenShell CLI Connects Without TLS Verification',
  category: 'openshell',
  severity: 'warning',
  description: 'Detect the OpenShell CLI skipping gateway TLS verification (OPENSHELL_GATEWAY_INSECURE) or registered against a remote gateway over plaintext http:// — a network attacker can impersonate the gateway and capture the CLI\'s credentials and every policy it pushes',
  supportedAgents: ['openshell'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    // The scanner's environment is the scanning user's own
    if (ownInstall(ctx) && TRUTHY.has((ctx.fs.getEnv('OPENSHELL_GATEWAY_INSECURE') ?? '').trim().toLowerCase())) {
      evidence.push({ file: 'environment', snippet: 'OPENSHELL_GATEWAY_INSECURE=true', detail: 'Every CLI call skips gateway certificate verification' });
    }
    for (const g of await listDir(ctx, join(paths(ctx).configDir, 'gateways'))) {
      if (!g.isDirectory) continue;
      const file = join(g.path, 'metadata.json');
      let meta: Record<string, unknown> | undefined;
      try {
        meta = record(JSON.parse(await ctx.fs.readFile(file)));
      } catch {
        continue;
      }
      const endpoint = meta?.gateway_endpoint;
      if (typeof endpoint === 'string' && /^http:\/\//i.test(endpoint) && !LOOPBACK_URL.test(endpoint)) {
        evidence.push({ file, snippet: `gateway_endpoint: ${endpoint}`, detail: `Gateway "${g.name}" is reached over plaintext HTTP` });
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'The OpenShell CLI verifies gateway TLS',
      failed: (n) => `Found ${n} OpenShell CLI connection(s) without TLS verification`,
      fixDescription: 'Unset OPENSHELL_GATEWAY_INSECURE and re-register remote gateways with an https:// endpoint (openshell gateway add https://…)',
    });
  },
});
