import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { detectTyposquatting } from '../../ioc/typosquat.js';
import { getIOCDatabase } from '../../ioc/database.js';

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

    for (const source of sources) {
      const packageName = source.packageName;
      if (!packageName) continue;

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
        const domainBase = domain.split('.')[0];
        if (normalizedPkg.includes(domainBase)) {
          evidence.push({
            file: findConfigFile(mcpConfigs, source.serverName),
            snippet: `Server "${source.serverName}": package ${packageName}`,
            detail: `Package name matches known malicious domain: ${domain}`,
          });
        }
      }

      if (trustedPackages.length > 0) {
        const typosquat = detectTyposquatting(packageName, trustedPackages);
        if (typosquat) {
          evidence.push({
            file: findConfigFile(mcpConfigs, source.serverName),
            snippet: `Server "${source.serverName}": package ${packageName}`,
            detail: `Possible typosquat of "${typosquat.trustedName}" (distance: ${typosquat.distance})`,
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
