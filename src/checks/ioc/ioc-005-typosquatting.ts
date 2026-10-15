import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getIOCDatabase } from '../../ioc/database.js';
import { getAllSkillsDirs } from '../../core/utils.js';
import { namedSkills, nameSegments } from './skill-names.js';
import { detectTyposquatting } from '../../ioc/typosquat.js';

/**
 * Ordinary words of tool names. A lookalike misspells the trusted name
 * (`weathr`, `githb-helper`); a name whose differing part is another real
 * word (`pdf-render` vs `pdf-reader`, `email-reader` vs `email-sender`,
 * `image-generation` vs `image-generator`) names a different tool.
 */
const TOOL_WORDS = new Set([
  'agent', 'analysis', 'analyzer', 'assistant', 'audio', 'backup', 'bot', 'browser', 'build', 'builder',
  'calendar', 'canvas', 'chart', 'chat', 'checker', 'cli', 'client', 'cloud', 'code', 'coder', 'compose',
  'converter', 'crawler', 'creator', 'database', 'debugger', 'deploy', 'design', 'diagram', 'doc', 'docs',
  'document', 'downloader', 'editor', 'email', 'exporter', 'extractor', 'fetcher', 'file', 'files', 'filler',
  'finder', 'formatter', 'generation', 'generator', 'helper', 'helpers', 'image', 'images', 'importer', 'inbox',
  'kit', 'lab', 'linter', 'loader', 'logger', 'mail', 'maker', 'manager', 'map', 'maps', 'merger', 'monitor',
  'notes', 'parser', 'planner', 'player', 'reader', 'reading', 'receiver', 'recorder', 'render', 'renderer',
  'rendering', 'report', 'review', 'reviewer', 'runner', 'scanner', 'scheduler', 'scraper', 'search', 'searcher',
  'sender', 'server', 'service', 'sheet', 'sheets', 'signer', 'slides', 'splitter', 'studio', 'summarizer',
  'sync', 'task', 'tasks', 'terminal', 'test', 'tester', 'testing', 'text', 'theme', 'tool', 'toolkit', 'tools',
  'tracker', 'translate', 'translation', 'translator', 'uploader', 'utils', 'video', 'viewer', 'voice', 'web',
  'writer', 'writing',
]);

function isOtherWord(name: string, trusted: string): boolean {
  const a = nameSegments(name);
  const b = nameSegments(trusted);
  if (a.length !== b.length) return false;
  const differing = a.filter((seg, i) => seg !== b[i]);
  return differing.length > 0 && differing.every(seg => TOOL_WORDS.has(seg));
}

export const ioc005 = defineCheck({
  id: 'IOC-005',
  name: 'Typosquatting',
  category: 'ioc',
  severity: 'warning',
  description: 'Detect skills with names similar to trusted ones (Levenshtein distance <= 2)',

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const db = getIOCDatabase();
    if (getAllSkillsDirs(ctx.installation).length === 0) return h.passed('No skills directory found');

    for (const skill of await namedSkills(ctx)) {
      for (const name of skill.names) {
        const match = detectTyposquatting(name, db.trustedSkillNames);
        if (!match || isOtherWord(name, match.trustedName)) continue;
        evidence.push({
          file: skill.dir,
          detail: `Skill "${match.skillName}" is similar to trusted "${match.trustedName}" (distance: ${match.distance})`,
        });
        break;
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No typosquatting detected',
      failed: (n) => `Found ${n} potential typosquat(s)`,
    });
  },
});
