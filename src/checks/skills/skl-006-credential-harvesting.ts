import { extname } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { analyzeCode } from '../../analyzers/ast-analyzer.js';
import { analyzePythonDataFlow } from '../../analyzers/python-sinks.js';
import { scanWithPatterns, SECURITY_PATTERNS } from '../../analyzers/pattern-engine.js';
import { isSourceFile, readSkillText, skillFilesOf, skillsDirsOf } from './skill-files.js';
import { markTestCode } from '../../analyzers/test-paths.js';

const CRED_HARVEST_RULES = SECURITY_PATTERNS.filter(r => r.category === 'credential-harvest');

/**
 * `echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys` in setup docs: the key is
 * a placeholder, so nothing is planted. A real key body (hundreds of base64
 * characters) appended there is persistence and stays critical.
 */
function placeholderKeyLine(line: string): boolean {
  if (!/authorized_keys/.test(line)) return false;
  const key = /\b(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-[\w-]+|sk-ssh-[\w@.-]+)\s+(\S+)/.exec(line);
  if (!key) return /<[^<>\n]{0,100}key[^<>\n]{0,100}>|your[_-]?(?:public[_-]?)?key/i.test(line);
  const body = key[1].replace(/["'`]+$/, '');
  // A variable or anything else unknown stays critical: it may be the attacker's key
  return body.includes('...') || body.includes('…') || /^<.*>$/.test(body) || /^AAAA[A-Za-z0-9+/]{0,59}$/.test(body);
}

export const skl006 = defineCheck({
  id: 'SKL-006',
  name: 'Credential Harvesting',
  category: 'skills',
  severity: 'critical',
  description: 'Detect access to .ssh, .aws, .env, and other credential stores',

  async run(ctx, h) {
    if (skillsDirsOf(ctx).length === 0) return h.passed('No skills directory found');

    const evidence: Evidence[] = [];
    const files = await skillFilesOf(ctx);

    for (const file of files) {
      try {
        const code = await readSkillText(ctx.fs, file, 'patterns');
        if (code === undefined) continue;

        // Pattern-based detection
        const matches = scanWithPatterns(code, CRED_HARVEST_RULES);
        const lines = code.split('\n');
        for (const match of matches) {
          const placeholder = placeholderKeyLine(lines[match.line - 1] ?? '');
          evidence.push({
            file,
            line: match.line,
            snippet: match.snippet,
            detail: placeholder ? `${match.description} — placeholder key written to authorized_keys (setup instructions)` : match.description,
            ...(placeholder ? { mitigated: true } : {}),
          });
        }

        // AST-based detection (source files only — not SKILL.md code blocks)
        if (!isSourceFile(file)) continue;
        // Python skill scripts go through the Python analyzer; Babel can't read them.
        const flows = extname(file).toLowerCase() === '.py' ? analyzePythonDataFlow(code) : analyzeCode(code, file);
        const fsAccess = flows.filter(f => f.type === 'fs-access');
        for (const flow of fsAccess) {
          evidence.push({
            file,
            line: flow.line,
            snippet: flow.snippet,
            detail: flow.description,
          });
        }
      } catch {}
    }

    await markTestCode(evidence, ctx.installation, ctx.fs);
    return h.fromEvidence(evidence, {
      passed: 'No credential harvesting patterns detected',
      failed: (n) => `Found ${n} credential harvesting indicator(s)`,
    });
  },
});
