/**
 * Shared prompt-injection / toolflow-hijacking directive detection.
 *
 * The same imperative directives are dangerous in two different places:
 *  - an MCP tool's `description`, read by the client LLM at tool-selection time
 *    (MCP-024), and
 *  - the content an MCP server returns as a tool *result*, read by the LLM at
 *    execution time (MCP-034).
 *
 * Both checks share this pattern set so detection stays consistent. See Hou et
 * al. (arXiv 2503.23278 §5.2.1) and OWASP MCP03 / MCP06.
 */

interface DirectivePattern {
  re: RegExp;
  label: string;
}

// Imperative / priority-manipulation phrases that have no business in a neutral
// tool description or in legitimately-returned tool output. Kept tight to avoid
// flagging ordinary prose.
export const DIRECTIVE_PATTERNS: DirectivePattern[] = [
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
  { re: /\[\s*(?:system|admin|important|developer)\s+(?:instruction|prompt|note|message)\b/i, label: 'injected-instruction marker ("[SYSTEM INSTRUCTION…]")' },
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

export function isInvisibleCodePoint(cp: number): boolean {
  return INVISIBLE_RANGES.some(([lo, hi]) => cp >= lo && cp <= hi);
}

export function describeChar(cp: number): string {
  return `U+${cp.toString(16).toUpperCase().padStart(4, '0')}`;
}

/**
 * Return the list of directive/invisible-character reasons found in `text`.
 * Empty array means the text is clean.
 */
export function analyzeText(text: string, opts: { checkInvisible?: boolean } = {}): string[] {
  const reasons: string[] = [];

  for (const { re, label } of DIRECTIVE_PATTERNS) {
    if (re.test(text)) reasons.push(label);
  }

  if (opts.checkInvisible) {
    const invisible = new Set<string>();
    for (const ch of text) {
      const cp = ch.codePointAt(0) ?? 0;
      if (isInvisibleCodePoint(cp)) invisible.add(describeChar(cp));
    }
    if (invisible.size > 0) {
      reasons.push(`invisible/bidi characters (${[...invisible].join(', ')})`);
    }
  }

  return reasons;
}
