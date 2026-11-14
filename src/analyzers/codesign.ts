import type { ExecResult } from '../core/fs-provider.js';

/**
 * What `codesign -dv <bundle>` said about a macOS bundle. Only codesign's own
 * words make a bundle unsigned: a run that did not happen or ended abnormally
 * (command missing, refused, timed out, not collected in a snapshot, an
 * unexpected error) says nothing about the signature and is `unknown` —
 * reported as not verified, never as an unsigned app.
 */
export type CodesignInfo =
  | { state: 'signed'; team: string; identifier: string }
  /** Signed without a developer identity (ad hoc): no Team ID to match. */
  | { state: 'adhoc'; identifier?: string }
  | { state: 'unsigned' }
  | { state: 'broken'; detail: string }
  | { state: 'unknown'; reason: string };

const TEAM_RE = /^TeamIdentifier=(.*)$/m;
const IDENTIFIER_RE = /^Identifier=([\w.-]+)$/m;
const UNSIGNED_RE = /code object is not signed at all/i;
const BROKEN_RE = /invalid signature|signature (?:is )?(?:invalid|malformed|corrupt)/i;

/** First line of codesign's error output, bounded (it may come from a scanned host). */
function firstLine(text: string): string {
  const line = text.trim().split('\n')[0]?.trim() ?? '';
  return line.length > 160 ? `${line.slice(0, 160)}…` : line;
}

export function readCodesign(result: ExecResult): CodesignInfo {
  // codesign writes its metadata to stderr by design
  const text = `${result.stdout}\n${result.stderr}`;
  if (UNSIGNED_RE.test(text)) return { state: 'unsigned' };
  if (result.exitCode !== 0) {
    if (BROKEN_RE.test(text)) return { state: 'broken', detail: firstLine(result.stderr || result.stdout) };
    const said = firstLine(result.stderr || result.stdout);
    return { state: 'unknown', reason: `codesign exited ${result.exitCode}${said ? `: ${said}` : ''}` };
  }
  const team = TEAM_RE.exec(text)?.[1]?.trim().slice(0, 64);
  const identifier = IDENTIFIER_RE.exec(text)?.[1];
  if (identifier && /^Signature=adhoc$/m.test(text)) return { state: 'adhoc', identifier };
  // `not set` on a real signature: an Apple platform binary — still not the vendor's Team ID
  if (identifier && team) return { state: 'signed', team, identifier };
  return { state: 'unknown', reason: 'codesign printed no signing identity' };
}
