import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { recordListFailure } from '../../core/config-loader.js';
import { pathPresent, readTextIfPresent } from '../../adapters/load-if-present.js';

// Commands whose bare approval grants network access or arbitrary execution.
const DANGEROUS_BARE = new Set([
  'curl', 'wget', 'nc', 'ncat', 'telnet', 'ssh', 'scp', 'rsync',
  'bash', 'sh', 'zsh', 'dash', 'ksh',
  'perl', 'python', 'python3', 'node', 'ruby', 'php', 'deno', 'bun',
  'npx', 'uvx', 'eval', 'exec', 'sudo', 'doas',
  'chmod', 'chown', 'dd', 'mkfs',
]);

const SHELLS = new Set(['bash', 'sh', 'zsh', 'dash', 'ksh']);
const INTERPRETERS = new Set(['perl', 'python', 'python3', 'node', 'ruby', 'php', 'deno', 'bun']);

function baseCommand(el: string): string {
  return el.includes('/') ? el.slice(el.lastIndexOf('/') + 1) : el;
}

/** Returns a reason string when an allow-rule prefix still permits arbitrary execution. */
export function classifyPrefixPattern(pattern: string[]): string | undefined {
  if (pattern.length === 0) return undefined;
  const cmd = baseCommand(pattern[0]);

  if (pattern.length === 1 && DANGEROUS_BARE.has(cmd)) {
    return `bare "${cmd}" prefix allows any ${cmd} invocation without approval`;
  }

  // Shell whose pattern ends at -c/-lc/-l: the actual command is unconstrained.
  if (SHELLS.has(cmd)) {
    const last = pattern[pattern.length - 1];
    if (/^-l?c$/.test(last) || (pattern.length > 1 && pattern.slice(1).every(p => p.startsWith('-')))) {
      return `"${pattern.join(' ')}" allows the shell to run any command without approval`;
    }
  }

  // Interpreter where everything after the binary is flags — payload is unconstrained
  // (e.g. ["perl", "-0pi"] approves rewriting any file with any expression).
  if (INTERPRETERS.has(cmd) && pattern.length > 1 && pattern.slice(1).every(p => p.startsWith('-'))) {
    return `"${pattern.join(' ')}" approves any ${cmd} payload — arbitrary code/file modification`;
  }

  return undefined;
}

/**
 * A Starlark list literal of strings (or nested lists of alternatives) at
 * `src[i]` — either quote style, trailing commas. Returns the value and the
 * index after it, or undefined when it is anything else.
 */
function parseList(src: string, i: number): { value: Array<string | string[]>; end: number } | undefined {
  const skip = () => { while (i < src.length && /[\s,]/.test(src[i])) i++; };
  if (src[i] !== '[') return undefined;
  i++;
  const out: Array<string | string[]> = [];
  for (;;) {
    skip();
    if (src[i] === ']') return { value: out, end: i + 1 };
    if (src[i] === '[') {
      const inner = parseList(src, i);
      if (!inner || inner.value.some(v => typeof v !== 'string')) return undefined;
      out.push(inner.value as string[]);
      i = inner.end;
      continue;
    }
    const q = src[i];
    if (q !== '"' && q !== "'") return undefined;
    let str = '';
    for (i++; i < src.length && src[i] !== q; i++) {
      if (src[i] === '\\') i++;
      str += src[i] ?? '';
    }
    if (i >= src.length) return undefined;
    out.push(str);
    i++;
  }
}

/** Every concrete prefix a pattern with alternatives stands for (capped). */
function expandAlternatives(pattern: Array<string | string[]>): string[][] {
  let out: string[][] = [[]];
  for (const el of pattern) {
    const alts = typeof el === 'string' ? [el] : el;
    out = out.flatMap(prefix => alts.map(a => [...prefix, a])).slice(0, 64);
  }
  return out;
}

interface PrefixRule { line: number; text: string; patterns: string[][]; decision: string }

/**
 * `prefix_rule(pattern = [...], decision = "...", …)` calls in a .rules
 * (Starlark) file, in any argument order, across lines. `decision` defaults
 * to "allow" (Codex execpolicy).
 */
export function parsePrefixRules(content: string): PrefixRule[] {
  const rules: PrefixRule[] = [];
  const call = /\bprefix_rule\s*\(/g;
  for (let m = call.exec(content); m; m = call.exec(content)) {
    // the call's argument text, up to its balanced closing paren
    let depth = 1;
    let j = m.index + m[0].length;
    let quote: string | undefined;
    for (; j < content.length && depth > 0; j++) {
      const c = content[j];
      if (quote) {
        if (c === '\\') j++;
        else if (c === quote) quote = undefined;
      } else if (c === '"' || c === "'") quote = c;
      else if (c === '(') depth++;
      else if (c === ')') depth--;
    }
    const args = content.slice(m.index + m[0].length, j - 1);
    const pat = /\bpattern\s*=\s*/.exec(args);
    const list = pat ? parseList(args, pat.index + pat[0].length) : undefined;
    if (!list) continue;
    const decision = /\bdecision\s*=\s*["']([a-z_]+)["']/.exec(args)?.[1] ?? 'allow';
    const line = content.slice(0, m.index).split('\n').length;
    rules.push({ line, text: content.slice(m.index, j).replace(/\s+/g, ' '), patterns: expandAlternatives(list.value), decision });
  }
  return rules;
}

export const cdx010 = defineCheck({
  id: 'CDX-010',
  name: 'Codex Over-Broad Command Allow Rules',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect ~/.codex/rules/*.rules prefix_rule allow entries whose prefix still permits arbitrary execution (bare curl/shell/interpreter)',
  supportedAgents: ['codex'],

  async run(ctx, h) {
    const rulesDir = join(ctx.installation.installDir, 'rules');
    if (!(await pathPresent(rulesDir, ctx.fs))) return h.passed('No Codex rules directory present');

    const evidence: Evidence[] = [];

    let names: string[] = [];
    try {
      names = (await ctx.fs.readdir(rulesDir)).filter(n => n.endsWith('.rules'));
    } catch (err) {
      // Present but unlistable: reported as CONFIG-LOAD
      if (await recordListFailure(rulesDir, ctx.fs, err)) {
        return h.passed(`Codex rules directory ${rulesDir} could not be listed — not inspected (see CONFIG-LOAD)`);
      }
    }

    for (const name of names) {
      const file = join(rulesDir, name);
      // Unreadable: reported as CONFIG-LOAD
      const content = await readTextIfPresent(file, ctx.fs);
      if (content === undefined) continue;

      for (const rule of parsePrefixRules(content)) {
        if (rule.decision !== 'allow') continue;
        const reason = rule.patterns.map(classifyPrefixPattern).find(Boolean);
        if (reason) {
          evidence.push({
            file,
            line: rule.line,
            snippet: rule.text.slice(0, 160),
            detail: reason,
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Codex command allow rules are scoped to specific commands',
      failed: (n) => `Found ${n} over-broad allow rule(s) in ${rulesDir}`,
      fixDescription: 'Narrow allow rules to full command prefixes (e.g. ["npm","run","build"]); remove bare network/shell/interpreter approvals',
    });
  },
});
