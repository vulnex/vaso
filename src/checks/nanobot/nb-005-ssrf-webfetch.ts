import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { asStringArray, getPath, nanobotConfigs } from './shared.js';

/*
 * nanobot blocks web_fetch / exec URLs that resolve to loopback, RFC 1918,
 * CGNAT, link-local (cloud metadata) and ULA ranges (security/network.py).
 * tools.ssrfWhitelist lists CIDRs exempted from that guard — intended for
 * narrow cases like a Tailscale range. Entries covering the metadata service,
 * loopback, or whole private blocks re-open SSRF.
 */

function parseV4(ip: string): number | undefined {
  const parts = ip.split('.');
  if (parts.length !== 4) return undefined;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return undefined;
    const v = Number(p);
    if (v > 255) return undefined;
    n = n * 256 + v;
  }
  return n;
}

function v4Contains(cidr: { base: number; prefix: number }, ip: number): boolean {
  if (cidr.prefix === 0) return true;
  const size = 2 ** (32 - cidr.prefix);
  const start = Math.floor(cidr.base / size) * size;
  return ip >= start && ip < start + size;
}

const METADATA_V4 = parseV4('169.254.169.254')!;
const LOOPBACK_V4 = parseV4('127.0.0.1')!;

/** Why a whitelist entry is dangerous, or undefined when it is narrow. */
export function riskyWhitelistEntry(entry: string): string | undefined {
  const raw = entry.trim();
  const [addr, prefixRaw] = raw.split('/');
  if (addr.includes(':')) {
    const prefix = prefixRaw === undefined ? 128 : Number(prefixRaw);
    const a = addr.toLowerCase();
    if (prefix === 0) return 'exempts every IPv6 address';
    if (a === '::1' || (a === '::' && prefix <= 127)) return 'exempts IPv6 loopback';
    if (/^fe[89ab]/.test(a) && prefix <= 10) return 'exempts all IPv6 link-local addresses';
    if (/^f[cd]/.test(a) && prefix <= 7) return 'exempts all IPv6 unique-local addresses';
    return undefined;
  }
  const base = parseV4(addr);
  const prefix = prefixRaw === undefined ? 32 : Number(prefixRaw);
  if (base === undefined || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return undefined;
  const cidr = { base, prefix };
  if (prefix === 0) return 'exempts every IPv4 address — the SSRF guard is off';
  if (v4Contains(cidr, METADATA_V4)) return 'exempts the cloud metadata service (169.254.169.254) — instance credentials become fetchable';
  if (v4Contains(cidr, LOOPBACK_V4)) return 'exempts loopback — local services (nanobot API, gateway, databases) become reachable';
  if (prefix <= 8) return `exempts a /${prefix} block — far broader than a single trusted network`;
  return undefined;
}

export const nb005 = defineCheck({
  id: 'NB-005',
  name: 'SSRF Guard Whitelist Too Broad',
  category: 'nanobot',
  severity: 'warning',
  description: 'Check tools.ssrfWhitelist, the CIDR exemptions from nanobot\'s built-in SSRF guard for web fetch and exec URLs. Entries covering 0.0.0.0/0, the 169.254.169.254 metadata service, loopback, or whole /8 blocks let a prompt-injected agent reach internal services and cloud credentials.',
  supportedAgents: ['nanobot'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of nanobotConfigs(ctx.configs)) {
      for (const entry of asStringArray(getPath(config.data, 'tools.ssrfWhitelist'))) {
        const why = riskyWhitelistEntry(entry);
        if (!why) continue;
        evidence.push({
          file: config.filePath,
          snippet: `tools.ssrfWhitelist: ${JSON.stringify(entry)}`,
          detail: `SSRF whitelist entry ${entry} ${why}`,
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'SSRF guard active with no broad whitelist exemptions',
      failed: (n) => `${n} broad SSRF whitelist exemption(s)`,
      fixDescription: 'Narrow tools.ssrfWhitelist to the specific trusted network (e.g. "100.64.0.0/10" for Tailscale); never include metadata, loopback or 0.0.0.0/0 ranges',
    });
  },
});
