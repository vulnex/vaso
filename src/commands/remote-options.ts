export interface RemoteOptionValues {
  concurrency: number;
  retries: number;
  sshTimeoutSec: number;
}

/** Longest --ssh-timeout accepted, in seconds. */
export const MAX_SSH_TIMEOUT_SEC = 86400;

function parseNonNegativeInt(raw: string | undefined, fallback: number, label: string): number {
  if (raw === undefined) return fallback;
  const n = Number(raw);
  if (!/^\d+$/.test(raw.trim()) || !Number.isSafeInteger(n)) {
    throw new Error(`Invalid ${label} value "${raw}": expected a non-negative integer`);
  }
  return n;
}

/**
 * `--parallel`, `--ssh-retries` and `--ssh-timeout`, validated up front for
 * every scan/detect — local ones included — so a typo is a usage error
 * (exit 2) wherever it appears, not something only a remote run notices.
 */
export function parseRemoteOptions(options: { parallel?: string; sshRetries?: string; sshTimeout?: string }): RemoteOptionValues {
  const concurrency = parseNonNegativeInt(options.parallel, 5, '--parallel');
  if (concurrency === 0) throw new Error('--parallel must be at least 1');
  const retries = parseNonNegativeInt(options.sshRetries, 0, '--ssh-retries');
  const sshTimeoutSec = parseNonNegativeInt(options.sshTimeout, 60, '--ssh-timeout');
  if (sshTimeoutSec === 0) throw new Error('--ssh-timeout must be at least 1');
  // Node timers overflow past 2^31-1 ms (~24.8 days) and fire after 1 ms instead
  if (sshTimeoutSec > MAX_SSH_TIMEOUT_SEC) throw new Error(`--ssh-timeout must be at most ${MAX_SSH_TIMEOUT_SEC} (24 hours)`);
  return { concurrency, retries, sshTimeoutSec };
}
