import { getNestedValue } from '../core/utils.js';

/**
 * Atomic Agent's `coerceIntLike`: a number as is, or a string holding an
 * integer ("5", " 5 ", "5.0", "+5"); undefined otherwise.
 */
export function coerceIntLike(v: unknown): number | undefined {
  if (typeof v === 'number') return v;
  if (typeof v !== 'string') return undefined;
  const t = v.trim();
  if (!/^[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$/.test(t)) return undefined;
  const n = Number(t);
  return Number.isSafeInteger(n) ? n : undefined;
}

/** Atomic Agent's `parseBool`: booleans and 1/true/yes/on, 0/false/no/off (any case). */
export function parseAtomicBool(v: unknown): boolean | undefined {
  if (typeof v === 'boolean') return v;
  if (typeof v !== 'string') return undefined;
  const t = v.toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(t)) return true;
  if (['0', 'false', 'no', 'off'].includes(t)) return false;
  return undefined;
}

export type AtomicApproval =
  | { level: number; snippet: string }
  /** Atomic refuses to load config.json ("invalid config: …"). */
  | { rejected: string };

/**
 * `resolveApprovalLevel`: agent.approvalLevel when set (`parseApprovalLevel`:
 * an integer 1–5 after `coerceIntLike`), else legacy agent.approvalRequired
 * (`parseBool`: true → 1, false → 5). Any other value throws, and Atomic
 * refuses to start with the file. undefined: neither is set (default 1).
 */
export function atomicApproval(data: Record<string, unknown>): AtomicApproval | undefined {
  const raw = getNestedValue(data, 'agent.approvalLevel');
  if (raw != null) {
    const level = coerceIntLike(raw);
    return level !== undefined && Number.isInteger(level) && level >= 1 && level <= 5
      ? { level, snippet: `agent.approvalLevel: ${JSON.stringify(raw)}` }
      : { rejected: `agent.approvalLevel: expected an integer between 1 and 5, got ${JSON.stringify(raw)}` };
  }
  const legacy = getNestedValue(data, 'agent.approvalRequired');
  if (legacy == null) return undefined;
  const required = parseAtomicBool(legacy);
  return required === undefined
    ? { rejected: `agent.approvalRequired: expected boolean, got ${JSON.stringify(legacy)}` }
    : { level: required ? 1 : 5, snippet: `agent.approvalRequired: ${JSON.stringify(legacy)}` };
}
