import { parse } from 'smol-toml';
import { scrubParseError } from './parse-error.js';

/**
 * Parse TOML from a scanned file. TOML integers are 64-bit, so a valid
 * `max_bytes = 9223372036854775807` makes a plain smol-toml parse throw
 * ("cannot be represented losslessly") and the whole config would go unread.
 * Integers beyond 2^53 are parsed exactly and then handed to checks as the
 * nearest Number — no check needs the exact value, and every consumer
 * (JSON.stringify, numeric comparisons) keeps working. Writers edit the raw
 * text, so a fix never rewrites such a value.
 */
export function parseTomlSafe(raw: string): Record<string, unknown> {
  let data: unknown;
  try {
    data = parse(raw, { integersAsBigInt: 'asNeeded' });
  } catch (err) {
    // smol-toml's message (and `codeblock`) quote the lines around the error
    throw scrubParseError(err);
  }
  return toNumbers(data) as Record<string, unknown>;
}

function toNumbers(value: unknown): unknown {
  if (typeof value === 'bigint') return Number(value);
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) value[i] = toNumbers(value[i]);
    return value;
  }
  if (value && typeof value === 'object' && isPlainTable(value)) {
    const obj = value as Record<string, unknown>;
    for (const k of Object.keys(obj)) obj[k] = toNumbers(obj[k]);
  }
  return value;
}

/** smol-toml tables are null-prototype objects; dates are class instances and stay as they are. */
function isPlainTable(value: object): boolean {
  const proto = Object.getPrototypeOf(value);
  return proto === null || proto === Object.prototype;
}
