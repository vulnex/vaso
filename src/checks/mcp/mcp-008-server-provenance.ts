import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { allowedTypoEdits, detectTyposquatting, typoDistance } from '../../ioc/typosquat.js';
import { WELL_KNOWN_MCP_SERVICES } from '../../ioc/mcp-services.js';
import { bareName, serviceCore } from '../../mcp/package-name.js';

/**
 * The well-known service a name imitates, if it is one typo away from it:
 * `twittter-mcp` → twitter, `githbu-server` → github. Same first letter (a
 * squat keeps the look of the brand), and for short services only the edits
 * squatters use — a doubled, dropped or swapped letter — not a substitution
 * (`stack` is a word, not a `slack` squat).
 */
function imitatedService(name: string): string | undefined {
  // A numeric suffix tells instances apart (`github2`, `postgres-1`); it is
  // not a typo of the service name.
  const known = WELL_KNOWN_MCP_SERVICES as readonly string[];
  // Whole numeric segments (`-13`, `_2`) are instance numbers; drop them first
  const raw = serviceCore(name.replace(/[-_.\s]\d+(?=$|[-_.\s])/g, ''));
  // …unless the digits are part of a known name (`context7`)
  if (known.includes(raw)) return undefined;
  const core = raw.replace(/\d+$/, '');
  if (core.length < 5 || known.includes(core)) return undefined;
  for (const service of WELL_KNOWN_MCP_SERVICES) {
    if (core[0] !== service[0]) continue;
    const distance = typoDistance(core, service);
    if (distance === 0 || distance > allowedTypoEdits(service.length)) continue;
    const substitution = core.length === service.length && [...core].sort().join('') !== [...service].sort().join('');
    if (substitution && service.length <= 6) continue;
    return service;
  }
  return undefined;
}
import { getIOCDatabase } from '../../ioc/database.js';

/**
 * A full-name typosquat whose difference also holds for the distinctive part:
 * two edits inside `mcp-server-…` boilerplate are tolerated by length, but
 * `mcp-server-sketch` is not a typo of `mcp-server-fetch` (cores sketch/fetch
 * differ by two in five letters).
 */
function confirmedTyposquat(packageName: string, trusted: string[]): ReturnType<typeof detectTyposquatting> {
  const match = detectTyposquatting(packageName, trusted);
  if (!match) return null;
  const core = serviceCore(packageName);
  const trustedCore = serviceCore(match.trustedName);
  if (core && trustedCore && typoDistance(core, trustedCore) > allowedTypoEdits(trustedCore.length)) return null;
  return match;
}

// Words a C2 domain label is often built from (npm-cache, js-mirror) — a label
// made only of them names no publisher and matches ordinary packages
const GENERIC_WORDS = new Set(['npm', 'js', 'node', 'cache', 'mirror', 'cdn', 'api', 'registry', 'proxy', 'update', 'updates',
  'cloud', 'static', 'assets', 'pkg', 'package', 'packages', 'mcp', 'server', 'servers', 'web', 'app', 'apps', 'dev', 'docs', 'files']);

function genericLabel(label: string): boolean {
  return label.split('-').every(part => GENERIC_WORDS.has(part));
}

/** `label` as a whole name segment (between /, @, ., _, - or the ends), not inside a word. */
function hasSegment(name: string, label: string): boolean {
  let from = 0;
  for (let i = name.indexOf(label, from); i >= 0; i = name.indexOf(label, from)) {
    const before = i === 0 ? '' : name[i - 1];
    const after = name[i + label.length] ?? '';
    if (/^[/@._-]?$/.test(before) && /^[/@._-]?$/.test(after)) return true;
    from = i + 1;
  }
  return false;
}

export const mcp008 = defineCheck({
  id: 'MCP-008',
  name: 'Server Provenance',
  category: 'mcp',
  severity: 'warning',
  description: 'Check MCP server package names for typosquatting, known-malicious publishers, and IOC matches',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const mcpConfigs = ctx.mcpConfigs ?? [];
    const sources = ctx.mcpServerSources ?? [];
    const ioc = getIOCDatabase();

    const trustedPackages = ioc.trustedMCPPackages ?? [];

    const reportedServers = new Set<string>();

    for (const source of sources) {
      // Compare the name, not the spec: `server-githbu@1.0.0` is a typo of
      // `server-github` whatever version it pins.
      const packageName = source.packageName ? bareName(source.packageName) : undefined;
      if (!packageName) continue;
      const before = evidence.length;

      const normalizedPkg = packageName.toLowerCase();
      for (const publisher of ioc.maliciousPublishers) {
        if (normalizedPkg.includes(publisher.toLowerCase())) {
          evidence.push({
            file: findConfigFile(mcpConfigs, source.serverName),
            snippet: `Server "${source.serverName}": package ${packageName}`,
            detail: `Package name matches known malicious publisher: ${publisher}`,
          });
        }
      }

      for (const domain of ioc.maliciousDomains) {
        // Only use the domain's first label when it is distinctive enough to
        // imply provenance (≥8 chars). Short/generic labels ("hub", "relay",
        // "claude", "canvas" — C2 hosts of the 2026 agent-remote-control
        // campaign) substring-match unrelated legitimate packages like
        // @modelcontextprotocol/server-github.
        const domainBase = domain.split('.')[0];
        if (domainBase.length >= 8 && !genericLabel(domainBase) && hasSegment(normalizedPkg, domainBase)) {
          evidence.push({
            file: findConfigFile(mcpConfigs, source.serverName),
            snippet: `Server "${source.serverName}": package ${packageName}`,
            detail: `Package name matches known malicious domain: ${domain}`,
          });
        }
      }

      const typosquat = trustedPackages.length > 0 ? confirmedTyposquat(packageName, trustedPackages) : null;
      if (typosquat) {
        evidence.push({
          file: findConfigFile(mcpConfigs, source.serverName),
          snippet: `Server "${source.serverName}": package ${packageName}`,
          detail: `Possible typosquat of "${typosquat.trustedName}" (distance: ${typosquat.distance})`,
        });
      } else if (!trustedPackages.includes(packageName)) {
        const service = imitatedService(packageName);
        if (service) {
          evidence.push({
            file: findConfigFile(mcpConfigs, source.serverName),
            snippet: `Server "${source.serverName}": package ${packageName}`,
            detail: `Package name imitates "${service}" with a typo — lookalike packages are a common way to get a malicious server installed; confirm this is the service's official package`,
          });
        }
      }

      for (const pattern of ioc.maliciousSkillPatterns) {
        if (pattern.test(packageName)) {
          evidence.push({
            file: findConfigFile(mcpConfigs, source.serverName),
            snippet: `Server "${source.serverName}": package ${packageName}`,
            detail: `Package name matches suspicious pattern: ${pattern.source}`,
          });
        }
      }
      if (evidence.length > before) reportedServers.add(source.serverName);
    }

    // Servers run from a local path have no package name — only the name the
    // user gave them in the config (the appsecco lab's "twittter-mcp").
    for (const config of mcpConfigs) {
      for (const server of config.servers) {
        if (reportedServers.has(server.name)) continue;
        const service = imitatedService(server.name);
        if (!service) continue;
        evidence.push({
          file: config.filePath,
          snippet: `Server "${server.name}"`,
          detail: `Server name imitates "${service}" with a typo — check that the server is the service's official one and not a lookalike`,
        });
      }
    }

    // Severity escalates to critical when an IOC publisher/domain matched
    const hasCritical = evidence.some(e =>
      e.detail?.includes('malicious publisher') || e.detail?.includes('malicious domain')
    );

    return h.fromEvidence(evidence, {
      passed: 'All MCP server packages pass provenance checks',
      failed: (n) => `Found ${n} provenance concern(s) for MCP server packages`,
      severity: hasCritical ? 'critical' : undefined,
    });
  },
});

function findConfigFile(configs: import('../../mcp/types.js').MCPConfig[], serverName: string): string {
  for (const config of configs) {
    if (config.servers.some(s => s.name === serverName)) {
      return config.filePath;
    }
  }
  return 'unknown';
}
