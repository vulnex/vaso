import type { CheckModule, ScanContext, CheckResult, FixResult } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';
import { updateJsonFile } from '../../remediation/config-writer.js';

export const nb005: CheckModule = {
  id: 'NB-005',
  name: 'WebFetchTool SSRF Risk',
  category: 'nanobot',
  severity: 'warning',
  description: 'Check if WebFetchTool allows requests to localhost or private IPs (SSRF risk)',
  supportedAgents: ['nanobot'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence = [];
    for (const config of ctx.configs) {
      const webFetch = getNestedValue(config.data, 'tools.webFetch')
        ?? getNestedValue(config.data, 'webFetchTool');

      if (!webFetch || typeof webFetch !== 'object') continue;

      const toolConfig = webFetch as Record<string, unknown>;
      const blockedHosts = toolConfig.blockedHosts;
      const allowedHosts = toolConfig.allowedHosts;

      if (!blockedHosts && !allowedHosts) {
        evidence.push({
          file: config.filePath,
          detail: 'WebFetchTool has no blockedHosts or allowedHosts — SSRF to localhost/internal IPs is possible',
        });
      } else if (Array.isArray(blockedHosts) && blockedHosts.length === 0) {
        evidence.push({
          file: config.filePath,
          detail: 'WebFetchTool blockedHosts is empty — no host restrictions enforced',
        });
      } else if (Array.isArray(allowedHosts) && allowedHosts.length === 0) {
        evidence.push({
          file: config.filePath,
          detail: 'WebFetchTool allowedHosts is empty — no requests will succeed but config may be misconfigured',
        });
      }
    }
    return {
      id: 'NB-005', name: 'WebFetchTool SSRF Risk', category: 'nanobot',
      severity: 'warning', passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'WebFetchTool has host restrictions configured'
        : 'WebFetchTool lacks host restrictions — SSRF risk to localhost/private IPs',
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: true, fixDescription: 'Add blockedHosts with localhost, 127.0.0.1, 169.254.169.254, and private IP ranges to WebFetchTool config',
    };
  },

  async fix(ctx: ScanContext): Promise<FixResult> {
    const blockedHosts = ['localhost', '127.0.0.1', '0.0.0.0', '169.254.169.254', '10.*', '172.16.*', '192.168.*'];
    for (const config of ctx.configs) {
      if (config.format === 'json') {
        await updateJsonFile(config.filePath, 'tools.webFetch.blockedHosts', blockedHosts);
        return { checkId: 'NB-005', applied: true, message: 'Added SSRF-blocking host list to WebFetchTool' };
      }
    }
    return { checkId: 'NB-005', applied: false, message: 'No JSON config file found' };
  },
};
