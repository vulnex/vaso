import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { scanWithPatterns, SECURITY_PATTERNS } from '../../analyzers/pattern-engine.js';
import { skillFilesOf, skillsDirsOf, noSkillsDirResult } from './skill-files.js';
import { analyzeSkillSource, readSkillSource } from './skill-source.js';
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

/**
 * A documentation code line that does something with the path: a command
 * word first (after a `$ ` prompt, `sudo`, `VAR=x`), shell plumbing (a pipe,
 * redirect or substitution), a call (`open(…)`, `readFileSync(…)`) or an
 * assignment. Sample output and notes in a block ("cause: token in
 * ~/.docker/config.json expired") are none of these.
 */
const COMMAND_WORD = /^\s*(?:[$#>]\s+)?(?:sudo\s+(?:-\S+\s+)*)?(?:[A-Za-z_]\w*=\S*\s+)*(?:cat|cp|mv|ln|scp|rsync|sftp|tar|zip|7z|gzip|base64|xxd|od|curl|wget|nc|ncat|netcat|socat|openssl|gpg|ssh(?:-add|-copy-id|-keygen)?|head|tail|less|more|grep|rg|awk|sed|find|ls|stat|chmod|chown|echo|printf|tee|dd|security|aws|gcloud|az|kubectl|docker|python[\d.]*|node|deno|bun|ruby|perl|php|bash|sh|zsh|pwsh|eval|source|export|cd|vi|vim|nano)\b/;
const CODE_SHAPE = /\||>{1,2}|<\s*[~/$"']|\$\(|`|[\w$\]]\(|[\w$\]]\s*=[^=]/;

function commandLine(line: string): boolean {
  return COMMAND_WORD.test(line) || CODE_SHAPE.test(line);
}

export const skl006 = defineCheck({
  id: 'SKL-006',
  name: 'Credential Harvesting',
  category: 'skills',
  severity: 'critical',
  description: 'Detect access to .ssh, .aws, .env, and other credential stores',

  async run(ctx, h) {
    const noDir = noSkillsDirResult(ctx, h);
    if (noDir) return noDir;

    const evidence: Evidence[] = [];
    const files = await skillFilesOf(ctx);

    for (const file of files) {
      try {
        const src = await readSkillSource(ctx, file, 'patterns', 'code', { data: false });
        // A data file naming a credential path (a list of paths an SSH
        // skill manages) reads nothing
        if (src === undefined || src.kind === 'data') continue;

        // Pattern-based detection
        const matches = scanWithPatterns(src.text, CRED_HARVEST_RULES);
        const lines = src.text.split('\n');
        for (const match of matches) {
          const placeholder = placeholderKeyLine(lines[match.line - 1] ?? '');
          // In documentation, a path in inline code is a mention ("keys live
          // in `~/.ssh/id_rsa`"); a code block is a command to run, and a
          // `!`cmd`` span runs when Claude Code loads the skill
          const onLoad = src.loadCommands?.get(match.line)?.some(cmd => scanWithPatterns(cmd, CRED_HARVEST_RULES).length > 0);
          // …and a code block line that isn't a command (sample output, a
          // note: "cause: token in ~/.docker/config.json expired") names one
          const mention = !onLoad && src.kind === 'markdown'
            && (src.inlineLines?.has(match.line) === true || !commandLine(lines[match.line - 1] ?? ''));
          evidence.push({
            file,
            line: match.line,
            snippet: match.snippet,
            detail: placeholder ? `${match.description} — placeholder key written to authorized_keys (setup instructions)`
              : onLoad ? `${match.description} in a !\`…\` command — Claude Code runs it when it loads the skill, and its output goes into the conversation`
                : mention ? `${match.description} — path named in inline code in skill documentation` : match.description,
            ...(placeholder || mention ? { mitigated: true } : {}),
          });
        }

        // AST-based detection (JavaScript and Python scripts only — not SKILL.md code blocks)
        const flows = src.kind === 'script' ? analyzeSkillSource(src) : [];
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
