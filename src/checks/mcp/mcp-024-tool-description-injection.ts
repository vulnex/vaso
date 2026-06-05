import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { extractToolDefinitions } from '../../mcp/tool-baseline.js';

/**
 * MCP-024 — Tool Description Injection (toolflow hijacking).
 *
 * An MCP tool's `description` is fed to the client LLM verbatim when it decides
 * which tool to call. A malicious or compromised server can embed directives in
 * that description ("always prefer this tool", "ignore previous instructions",
 * "do not mention this to the user") or hide them in invisible/bidi Unicode, so
 * the model is steered without the user ever seeing it. See Hou et al.
 * (arXiv 2503.23278 §5.2.1) and OWASP MCP03.
 */

interface DirectivePattern {
  re: RegExp;
  label: string;
}

// Imperative / priority-manipulation phrases that have no business in a neutral
// tool description. Kept tight to avoid flagging ordinary prose.
const DIRECTIVE_PATTERNS: DirectivePattern[] = [
  { re: /\bignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\b/i, label: 'instruction-override ("ignore previous")' },
  { re: /\bdisregard\s+(?:all\s+)?(?:previous|prior|above|earlier|the)\b/i, label: 'instruction-override ("disregard…")' },
  { re: /\b(?:always|must)\s+(?:prefer|use|call|choose|select)\s+this\b/i, label: 'tool-priority directive ("always use this")' },
  { re: /\bprefer(?:red)?\s+(?:to\s+)?(?:use\s+)?this\s+tool\b/i, label: 'tool-priority directive ("prefer this tool")' },
  { re: /\bthis\s+tool\s+should\s+be\s+(?:prioriti[sz]ed|preferred|used\s+first)\b/i, label: 'tool-priority directive ("should be prioritized")' },
  { re: /\buse\s+this\s+tool\s+first\b/i, label: 'tool-priority directive ("use this tool first")' },
  { re: /\b(?:instead\s+of|rather\s+than)\s+(?:any\s+)?other\s+tools?\b/i, label: 'tool-priority directive ("instead of other tools")' },
  { re: /\bdo\s+not\s+(?:mention|tell|inform|reveal|disclose|notify)\b/i, label: 'concealment directive ("do not mention")' },
  { re: /\bdon'?t\s+(?:mention|tell|inform|reveal|disclose|notify)\b/i, label: 'concealment directive ("don\'t tell")' },
  { re: /\bwithout\s+(?:telling|informing|notifying|alerting)\s+(?:the\s+)?user\b/i, label: 'concealment directive ("without telling the user")' },
  { re: /(?:^|[.!?]\s+|\n)\s*(?:system|assistant|developer)\s*:/i, label: 'role-spoofing prefix ("system:" / "assistant:")' },
  { re: /<\/?(?:important|system|instructions?|secret|hidden)\b[^>]*>/i, label: 'hidden-instruction tag (<important>/<system>)' },
  { re: /\byou\s+must\s+(?:always|first|immediately|secretly)\b/i, label: 'coercive directive ("you must always…")' },
];

// Invisible / bidi / smuggling code-point ranges, expressed as numeric ranges so
// no literal invisible character ever appears in this source file: soft hyphen,
// Mongolian vowel sep, zero-width space-joiners, LTR/RTL marks, bidi embeddings
// & overrides, word joiner, invisible math operators, bidi isolates, BOM, and
// the entirely-invisible Unicode "tag" block (a known prompt-smuggling channel).
const INVISIBLE_RANGES: ReadonlyArray<readonly [number, number]> = [
  [0x00ad, 0x00ad],
  [0x180e, 0x180e],
  [0x200b, 0x200f],
  [0x202a, 0x202e],
  [0x2060, 0x2064],
  [0x2066, 0x2069],
  [0xfeff, 0xfeff],
  [0xe0000, 0xe007f],
];

function isInvisibleCodePoint(cp: number): boolean {
  return INVISIBLE_RANGES.some(([lo, hi]) => cp >= lo && cp <= hi);
}

function describeChar(cp: number): string {
  return `U+${cp.toString(16).toUpperCase().padStart(4, '0')}`;
}

function analyzeDescription(description: string): string[] {
  const reasons: string[] = [];

  for (const { re, label } of DIRECTIVE_PATTERNS) {
    if (re.test(description)) reasons.push(label);
  }

  const invisible = new Set<string>();
  for (const ch of description) {
    const cp = ch.codePointAt(0) ?? 0;
    if (isInvisibleCodePoint(cp)) invisible.add(describeChar(cp));
  }
  if (invisible.size > 0) {
    reasons.push(`invisible/bidi characters (${[...invisible].join(', ')})`);
  }

  return reasons;
}

export const mcp024 = defineCheck({
  id: 'MCP-024',
  name: 'Tool Description Injection',
  category: 'mcp',
  severity: 'critical',
  description:
    'Detect prompt-injection / toolflow-hijacking directives and hidden Unicode embedded in MCP tool descriptions',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const sources = ctx.mcpServerSources ?? [];

    for (const source of sources) {
      const tools = source.tools ?? (source.sourceCode ? extractToolDefinitions(source.sourceCode) : []);
      if (tools.length === 0) continue;

      for (const tool of tools) {
        if (!tool.description) continue;
        const reasons = analyzeDescription(tool.description);
        if (reasons.length === 0) continue;

        evidence.push({
          file: source.localPath ?? source.packageName ?? source.serverName,
          snippet: `Tool "${tool.name}" in server "${source.serverName}"`,
          detail: `Tool description contains ${reasons.join('; ')} — the client LLM reads this verbatim when selecting tools, so it can be steered or kept silent without the user's knowledge`,
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No MCP tool descriptions contain injection directives or hidden characters',
      failed: (n) => `Found ${n} MCP tool description(s) with injection directives or hidden Unicode — toolflow-hijacking risk`,
      fixDescription:
        'Remove imperative/priority directives and any invisible characters from tool descriptions; descriptions should neutrally state what the tool does, not how the model must behave',
    });
  },
});
