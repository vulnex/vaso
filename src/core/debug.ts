import { escapeControlChars } from '../reporting/text-safety.js';

let debugEnabled = false;

export function setDebug(enabled: boolean): void {
  debugEnabled = enabled;
}

export function isDebug(): boolean {
  return debugEnabled;
}

/**
 * Log an error consistently across commands. With --debug, prints the full
 * stack trace; otherwise just the message. Always uses console.error.
 * Error text can quote hostile input (a scan file, a file name), so control
 * characters are shown escaped; newlines are kept for stack traces.
 */
export function logError(prefix: string, err: unknown): void {
  if (err instanceof Error) {
    if (debugEnabled && err.stack) {
      console.error(prefix, escapeControlChars(err.stack));
    } else {
      console.error(prefix, escapeControlChars(err.message));
    }
  } else {
    console.error(prefix, escapeControlChars(String(err)));
  }
}
