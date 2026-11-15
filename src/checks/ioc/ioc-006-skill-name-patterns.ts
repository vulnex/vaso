import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getAllSkillsDirs } from '../../core/utils.js';
import { namedSkills, nameSegments } from './skill-names.js';
import { getIOCDatabase } from '../../ioc/database.js';
import { noSkillsDirResult } from '../skills/skill-files.js';

/**
 * Security tooling is named after what it hunts (`backdoor-detector`,
 * `keylogger-detector`, `stealer-scanner`); the malware word next to one of
 * these is the tool's subject, not its nature. What such a skill does is
 * judged by the SKL content checks.
 */
const DEFENSIVE_WORDS = new Set([
  'detector', 'detection', 'detect', 'scanner', 'scan', 'finder', 'hunter', 'hunting', 'checker', 'check',
  'guard', 'defender', 'defense', 'monitor', 'auditor', 'audit', 'analyzer', 'analysis', 'protection',
  'protector', 'remover', 'removal', 'cleaner', 'blocker', 'sentinel', 'shield', 'yara', 'sigma',
]);

function isDefensiveName(name: string): boolean {
  return nameSegments(name).some(seg => DEFENSIVE_WORDS.has(seg));
}

export const ioc006 = defineCheck({
  id: 'IOC-006',
  name: 'Skill Name Patterns',
  category: 'ioc',
  severity: 'warning',
  description: 'Match skill names against known malicious naming patterns',

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const db = getIOCDatabase();
    const noDir = noSkillsDirResult(ctx, h);
    if (noDir) return noDir;

    for (const skill of await namedSkills(ctx)) {
      const hit = skill.names
        .filter(name => !isDefensiveName(name))
        .map(name => ({ name, pattern: db.maliciousSkillPatterns.find(p => p.test(name)) }))
        .find(m => m.pattern);
      if (!hit) continue;
      evidence.push({
        file: skill.dir,
        detail: `Skill "${hit.name}" matches malicious name pattern: ${hit.pattern!.source}`,
      });
    }

    return h.fromEvidence(evidence, {
      passed: 'No malicious skill name patterns detected',
      failed: (n) => `Found ${n} skill(s) with suspicious names`,
    });
  },
});
