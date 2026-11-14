export interface RemoteOptionValues {
  concurrency: number;
  retries: number;
  sshTimeoutSec: number;
}

/** Longest --ssh-timeout accepted, in seconds. */
export const MAX_SSH_TIMEOUT_SEC = 86400;

/** Most --ssh-retries accepted: backoff caps at 8 s, so 10 retries already wait over a minute per host. */
export const MAX_SSH_RETRIES = 10;

function parseNonNegativeInt(raw: string | undefined, fallback: number, label: string): number {
  if (raw === undefined) return fallback;
  const n = Number(raw);
  if (!/^\d+$/.test(raw.trim()) || !Number.isSafeInteger(n)) {
    throw new Error(`Invalid ${label} value "${raw}": expected a non-negative integer`);
  }
  return n;
}

export interface RemoteOptionInput {
  parallel?: string;
  sshRetries?: string;
  sshTimeout?: string;
  host?: string[];
  inventory?: string;
  snapshot?: string;
  saveSnapshot?: string;
  sshKey?: string;
  sudo?: boolean;
}

/**
 * Options that only make sense together (or apart). A scan reads one source:
 * this machine, a snapshot, or remote hosts — `--snapshot` with `--host` used
 * to scan the hosts in `scan` and the snapshot in `detect`. Remote-only
 * options given to a local or snapshot scan were silently ignored.
 */
function assertOptionCombination(options: RemoteOptionInput): void {
  const remote = !!options.host?.length || !!options.inventory;
  if (options.snapshot !== undefined && remote) {
    throw new Error('--snapshot and --host/--inventory are mutually exclusive (a scan reads one snapshot or scans remote hosts)');
  }
  // Snapshots are what a remote scan collects; a local scan has none to save
  if (options.saveSnapshot !== undefined && !remote) {
    throw new Error('--save-snapshot applies to remote scans only (use with --host or --inventory)');
  }
  if (options.sshKey !== undefined && options.sshKey.trim() === '') {
    throw new Error('--ssh-key needs a key file path');
  }
  if (!remote) {
    const unused = [options.sshKey !== undefined && '--ssh-key', options.sudo && '--sudo'].filter(Boolean);
    if (unused.length > 0) throw new Error(`${unused.join(' and ')} appl${unused.length > 1 ? 'y' : 'ies'} to remote scans only (use with --host or --inventory)`);
  }
}

/**
 * `--parallel`, `--ssh-retries` and `--ssh-timeout`, validated up front for
 * every scan/detect — local ones included — so a typo is a usage error
 * (exit 2) wherever it appears, not something only a remote run notices.
 * Also rejects option combinations that can't apply (see
 * assertOptionCombination).
 */
export function parseRemoteOptions(options: RemoteOptionInput): RemoteOptionValues {
  assertOptionCombination(options);
  const concurrency = parseNonNegativeInt(options.parallel, 5, '--parallel');
  if (concurrency === 0) throw new Error('--parallel must be at least 1');
  const retries = parseNonNegativeInt(options.sshRetries, 0, '--ssh-retries');
  if (retries > MAX_SSH_RETRIES) throw new Error(`--ssh-retries must be at most ${MAX_SSH_RETRIES}`);
  const sshTimeoutSec = parseNonNegativeInt(options.sshTimeout, 60, '--ssh-timeout');
  if (sshTimeoutSec === 0) throw new Error('--ssh-timeout must be at least 1');
  // Node timers overflow past 2^31-1 ms (~24.8 days) and fire after 1 ms instead
  if (sshTimeoutSec > MAX_SSH_TIMEOUT_SEC) throw new Error(`--ssh-timeout must be at most ${MAX_SSH_TIMEOUT_SEC} (24 hours)`);
  return { concurrency, retries, sshTimeoutSec };
}
