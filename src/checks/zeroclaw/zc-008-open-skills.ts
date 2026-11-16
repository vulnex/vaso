import { defineCheck } from '../../core/check-builder.js';
import type { Evidence } from '../../core/types.js';
import { asRecord, isFalse, isTrue, mainConfig, tomlLine, writeMainConfig } from './zc-config.js';
import { configFixTargets } from '../../remediation/fix-refusal.js';

function insecureUrl(url: string): boolean {
  return /^(http|git):\/\//i.test(url.trim());
}

export const zc008 = defineCheck({
  id: 'ZC-008',
  name: 'Unvetted Skill Sources',
  category: 'zeroclaw',
  severity: 'warning',
  description:
    'Detect [skills] open_skills_enabled=true (community open-skills repo synced into the prompt), allow_scripts=true (skills may ship shell scripts), or skill registries fetched over plaintext http:// / git://',
  supportedAgents: ['zeroclaw'],

  fixTargets: configFixTargets,

  async run(ctx, h) {
    const config = mainConfig(ctx.configs);
    if (!config) return h.passed('No ZeroClaw config.toml found');
    const skills = asRecord(config.data.skills) ?? {};
    const evidence: Evidence[] = [];
    let writable = false;

    if (isTrue(skills.open_skills_enabled)) {
      writable = true;
      evidence.push({
        file: config.filePath,
        ...tomlLine(config.raw, 'skills', 'open_skills_enabled'),
        detail: 'skills.open_skills_enabled = true — unreviewed community skills are cloned and loaded into every agent',
      });
    }
    if (isTrue(skills.allow_scripts)) {
      writable = true;
      evidence.push({
        file: config.filePath,
        ...tomlLine(config.raw, 'skills', 'allow_scripts'),
        detail: 'skills.allow_scripts = true — skills may bundle .sh/.ps1/shebang scripts',
      });
    }
    if (typeof skills.registry_url === 'string' && insecureUrl(skills.registry_url)) {
      evidence.push({
        file: config.filePath,
        detail: `skills.registry_url = ${skills.registry_url} — skill registry fetched over an unauthenticated transport`,
      });
    }
    if (Array.isArray(skills.extra_registries)) {
      for (const raw of skills.extra_registries) {
        const r = asRecord(raw);
        if (!r || isFalse(r.enabled) || typeof r.url !== 'string') continue;
        if (insecureUrl(r.url)) {
          evidence.push({
            file: config.filePath,
            detail: `skills.extra_registries "${String(r.name ?? '?')}" = ${r.url} — skill registry fetched over an unauthenticated transport`,
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Skill sources are restricted',
      failed: (n) => `${n} unvetted skill source setting(s)`,
      fixable: writable,
      fixDescription:
        'Set [skills] open_skills_enabled = false and allow_scripts = false; use https:// URLs for registry_url / extra_registries',
    });
  },

  async fix(ctx) {
    const config = mainConfig(ctx.configs);
    const skills = asRecord(config?.data.skills) ?? {};
    const updates: Array<[string, unknown]> = [];
    if (isTrue(skills.open_skills_enabled)) updates.push(['skills.open_skills_enabled', false]);
    if (isTrue(skills.allow_scripts)) updates.push(['skills.allow_scripts', false]);
    return writeMainConfig(ctx, 'ZC-008', updates, 'Disabled open-skills sync and skill scripts');
  },
});
