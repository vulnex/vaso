import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { scanWithPatterns, SECURITY_PATTERNS } from '../../analyzers/pattern-engine.js';
import { readSkillText, skillFilesOf, skillsDirsOf, noSkillsDirResult } from './skill-files.js';
import { markTestCode } from '../../analyzers/test-paths.js';

const CURL_PIPE_RULES = SECURITY_PATTERNS.filter(r => r.category === 'curl-pipe');

/** Skill documentation (SKILL.md, references): instructions, not code that runs on its own. */
const DOC_FILE = /\.(?:md|mdx|markdown|txt|rst)$/i;
/** Hosts that hide where a script really comes from. */
const OPAQUE_HOSTS = /^(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|goo\.gl|cutt\.ly|rb\.gy|pastebin\.com|paste\.ee|hastebin\.com|termbin\.com|transfer\.sh|0x0\.st|ngrok(?:-free)?\.(?:io|app|dev)|[\w-]+\.ngrok(?:-free)?\.(?:io|app|dev)|[\w-]+\.trycloudflare\.com)$/i;
/** Official installers of widely used developer tools. */
const KNOWN_INSTALLERS = /^(?:sh\.rustup\.rs|astral\.sh|bun\.sh|deno\.land|get\.docker\.com|ollama\.com|get\.pnpm\.io|install\.python-poetry\.org|foundry\.paradigm\.xyz|starship\.rs|tailscale\.com|fly\.io|claude\.ai|opencode\.ai|mise\.run|sdk\.cloud\.google\.com)$/i;

/**
 * How serious a pipe-to-shell line in skill documentation is. The agent may
 * follow these instructions, so an opaque source (plain http, an IP, a
 * shortener or paste site) stays critical; an https installer from a named
 * vendor is the usual way a skill says "install the tool I wrap" (warning,
 * info for well-known installers); a line with no download URL is prose
 * (`never run curl | sh lines`).
 */
function docTier(line: string): 'critical' | 'warning' | 'info' {
  const raw = /https?:\/\/[^\s"'`|)<>]+/.exec(line)?.[0];
  if (!raw) return 'info';
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return 'critical';
  }
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (url.protocol !== 'https:' || /^[\d.]+$/.test(host) || host.includes(':') || OPAQUE_HOSTS.test(host)) return 'critical';
  return KNOWN_INSTALLERS.test(host) ? 'info' : 'warning';
}

export const skl004 = defineCheck({
  id: 'SKL-004',
  name: 'Curl-Pipe Execution',
  category: 'skills',
  severity: 'critical',
  description: 'Detect curl|sh, wget|bash, and similar pipe-to-shell execution',

  async run(ctx, h) {
    const noDir = noSkillsDirResult(ctx, h);
    if (noDir) return noDir;

    const evidence: Evidence[] = [];
    const files = await skillFilesOf(ctx);
    let critical = false;

    for (const file of files) {
      try {
        const code = await readSkillText(ctx.fs, file, 'patterns');
        if (code === undefined) continue;
        const matches = scanWithPatterns(code, CURL_PIPE_RULES);

        const doc = DOC_FILE.test(file);
        const lines = doc ? code.split('\n') : [];
        for (const match of matches) {
          const tier = doc ? docTier(lines[match.line - 1] ?? match.snippet) : 'critical';
          if (tier === 'critical') critical = true;
          evidence.push({
            file,
            line: match.line,
            snippet: match.snippet,
            detail: doc && tier !== 'critical'
              ? `${match.description} in skill documentation${tier === 'info' ? ' (no download URL, or a well-known vendor installer)' : ' — installer from a named https host'}`
              : match.description,
            ...(tier === 'info' ? { mitigated: true } : {}),
          });
        }
      } catch {}
    }

    await markTestCode(evidence, ctx.installation, ctx.fs);
    return h.fromEvidence(evidence, {
      passed: 'No curl-pipe execution patterns detected',
      failed: (n) => `Found ${n} curl-pipe execution pattern(s)`,
      // Only a named-host https installer in documentation: warning
      severity: critical ? 'critical' : 'warning',
    });
  },
});
