import { defineCheck } from '../../core/check-builder.js';
import { getNestedValue } from '../../core/utils.js';
import { updateTomlFile } from '../../remediation/config-writer.js';

const PUBLIC_URL_PATTERNS = [
  /https?:\/\/github\.com\//,
  /https?:\/\/gitlab\.com\//,
  /https?:\/\/bitbucket\.org\//,
  /git:\/\//,
  /https?:\/\/.*\.git$/,
];

export const zc008 = defineCheck({
  id: 'ZC-008',
  name: 'Open Skills',
  category: 'zeroclaw',
  severity: 'warning',
  description: 'Detect open skills enabled — skills installed from public repos via git clone',
  supportedAgents: ['zeroclaw'],

  async run(ctx, h) {
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

    return h.fromEvidence(evidence, {
      passed: 'Open skill installation is not enabled',
      failed: (n) => `Found ${n} open skill configuration(s) — unvetted code may be installed`,
      fixable: true,
      fixDescription: 'Set skills.open_install=false and restrict skills.sources to trusted private repositories',
    });
  },

  async fix(ctx) {
    for (const config of ctx.configs) {
      if (config.format === 'toml') {
        await updateTomlFile(config.filePath, 'skills.open_install', false);
        return { checkId: 'ZC-008', applied: true, message: 'Set skills.open_install=false' };
      }
    }
    return { checkId: 'ZC-008', applied: false, message: 'No TOML config file found' };
  },
});
