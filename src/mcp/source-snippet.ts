/**
 * Source text quoted in an MCP finding. A credential MCP-003 flags in a
 * server's source is masked wherever another check quotes that source —
 * prose (`"use password <pw>"`), an argument, a URL — not just where a
 * `key: value` shape lets the report masker see it. Masking happens before
 * the cut; a value an earlier cut left at the end of the text is masked too.
 */

import { findSourceSecretValues } from '../analyzers/source-secrets.js';
import { truncateSnippet } from '../core/patterns.js';
import type { MCPServerSource } from './types.js';

const valuesBySource = new WeakMap<object, string[]>();
const valuesByCode = new Map<string, string[]>();
/** A cut-off value shorter than this is too little to identify it. */
const MIN_CUT_PREFIX = 6;

function secretValues(source: Pick<MCPServerSource, 'sourceCode'>): string[] {
  const cached = valuesBySource.get(source);
  if (cached) return cached;
  const code = source.sourceCode ?? '';
  let values = valuesByCode.get(code);
  if (!values) {
    values = findSourceSecretValues(code).sort((a, b) => b.length - a.length);
    // one entry: checks run source by source
    valuesByCode.clear();
    valuesByCode.set(code, values);
  }
  valuesBySource.set(source, values);
  return values;
}

function maskValue(value: string): string {
  return `${value.slice(0, 4)}… (${value.length} chars)`;
}

/** `text` with every secret value flagged in `source` masked. */
export function maskSourceSecrets(source: Pick<MCPServerSource, 'sourceCode'>, text: string): string {
  const values = secretValues(source);
  if (values.length === 0) return text;
  let out = text;
  for (const value of values) {
    if (out.includes(value)) out = out.split(value).join(maskValue(value));
  }
  // a value cut off by an earlier truncation: `… Tr0ub4dor-Ze` / `… Tr0ub4dor-Ze ...`
  const tail = /([^\s"'`,;:=(){}[\]<>]+)((?: ?\.\.\.|…)?\s*)$/.exec(out);
  if (tail && tail[1].length >= MIN_CUT_PREFIX) {
    const cut = tail[1];
    const value = values.find((v) => v.length > cut.length && v.startsWith(cut));
    if (value) out = `${out.slice(0, tail.index)}${maskValue(value)}${tail[2]}`;
  }
  return out;
}

/** A source line or statement quoted in a finding: secrets masked, then cut to `max`. */
export function sourceSnippet(source: Pick<MCPServerSource, 'sourceCode'>, text: string, max = 120): string {
  return truncateSnippet(maskSourceSecrets(source, text.trim()), max);
}
