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
 */
export function logError(prefix: string, err: unknown): void {
  if (err instanceof Error) {
    if (debugEnabled && err.stack) {
      console.error(prefix, err.stack);
    } else {
      console.error(prefix, err.message);
    }
  } else {
    console.error(prefix, String(err));
  }
}
