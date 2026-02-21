import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

const PUBLIC_URL_PATTERNS = [
  /https?:\/\/github\.com\//,
  /https?:\/\/gitlab\.com\//,
  /https?:\/\/bitbucket\.org\//,
  /git:\/\//,
  /https?:\/\/.*\.git$/,
];

export const zc008: CheckModule = {
  id: 'ZC-008',
  name: 'Open Skills',
  category: 'zeroclaw',
  severity: 'warning',
  description: 'Detect open skills enabled — skills installed from public repos via git clone',
  supportedAgents: ['zeroclaw'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence = [];

    for (const config of ctx.configs) {
      const openInstall = getNestedValue(config.data, 'skills.open_install');

      if (openInstall === true || openInstall === 'true') {
        evidence.push({
          file: config.filePath,
          detail: 'skills.open_install=true — skills can be installed from any public repository',
        });
      }

      const sources = getNestedValue(config.data, 'skills.sources') as string[] | undefined;

      if (Array.isArray(sources)) {
        for (const source of sources) {
          if (typeof source === 'string') {
            for (const pattern of PUBLIC_URL_PATTERNS) {
              if (pattern.test(source)) {
                evidence.push({
                  file: config.filePath,
                  detail: `skills.sources contains public URL: ${source}`,
                });
                break;
              }
            }
          }
        }
      }
    }

    return {
      id: 'ZC-008',
      name: 'Open Skills',
      category: 'zeroclaw',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'Open skill installation is not enabled'
        : `Found ${evidence.length} open skill configuration(s) — unvetted code may be installed`,
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: true,
      fixDescription: 'Set skills.open_install=false and restrict skills.sources to trusted private repositories',
    };
  },
};
