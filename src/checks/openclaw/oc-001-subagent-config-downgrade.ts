import type { Evidence, ParsedConfig } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { extractPosture, findDowngrades, mergeConfigData } from './posture.js';
import { containerEnvironment } from '../../adapters/openclaw-bind.js';

export const oc001 = defineCheck({
  id: 'OC-001',
  name: 'Sub-Agent Config Security Downgrade',
  category: 'openclaw',
  severity: 'critical',
  description: 'Detect when an OpenClaw sub-agent (agents/<name>/agent.{yaml,json,env}, or its agents.entries.<name> entry) overrides the global config to weaken security: disable TLS or sandbox, re-bind the gateway publicly, drop tool approval, or downgrade auth.',
  supportedAgents: ['openclaw'],

  async run(ctx, h) {
    const installation = ctx.installation;
    if (!installation.agentName) {
      return h.passed('Not a sub-agent installation; OC-001 does not apply');
    }

    const subAgentDir = installation.installDir;
    const globalConfigs: ParsedConfig[] = [];
    const subAgentConfigs: ParsedConfig[] = [];
    for (const c of ctx.configs) {
      if (c.filePath.startsWith(subAgentDir + '/') || c.filePath.startsWith(subAgentDir + '\\')) {
        subAgentConfigs.push(c);
      } else {
        globalConfigs.push(c);
      }
    }

    if (subAgentConfigs.length === 0 || globalConfigs.length === 0) {
      return h.passed('No sub-agent override configs to compare against global');
    }

    // The override side also applies the agent's own agents.entries.<name>
    // entry (2026.x per-agent sandbox / tools.exec overrides)
    const inContainer = await containerEnvironment(ctx.fs);
    const basePosture = extractPosture(mergeConfigData(globalConfigs), undefined, inContainer);
    const overridePosture = extractPosture(mergeConfigData([...globalConfigs, ...subAgentConfigs]), installation.agentName, inContainer);
    const issues = findDowngrades(basePosture, overridePosture);

    const evidence: Evidence[] = issues.map(detail => ({
      file: subAgentConfigs[0].filePath,
      detail: `Sub-agent "${installation.agentName}": ${detail}`,
    }));

    return h.fromEvidence(evidence, {
      passed: `Sub-agent "${installation.agentName}" config does not weaken global security posture`,
      failed: (n) => `Sub-agent "${installation.agentName}" weakens ${n} global security setting${n === 1 ? '' : 's'}`,
    });
  },
});
