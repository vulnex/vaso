/**
 * SSH target parsing and remote probe execution for network scanning.
 *
 * Uses SSH ControlMaster multiplexing: authenticates once (supporting
 * password prompts), then reuses the connection for all subsequent
 * ssh/scp commands without re-authenticating.
 */

import { spawn, execFileSync, type ChildProcess, type SpawnOptions } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { writeFile, unlink, access, stat } from 'node:fs/promises';
import { isIP } from 'node:net';
import { openSync, readFileSync, closeSync, unlinkSync, constants } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ProbeSnapshot, ProbeManifest } from '../core/snapshot-types.js';
import { resolveProbeBinary } from './probe-fetch.js';
import { escapeControlChars } from '../reporting/text-safety.js';
import { isDebug } from '../core/debug.js';
import { MAX_REMOTE_OUTPUT_BYTES, parseSnapshot, SnapshotLoadError } from '../core/snapshot-load.js';
import { safeHostname } from './host-files.js';

export interface SSHTarget {
  user: string;
  host: string;
  port: number;
  label?: string;
  identity?: string;
  sudo?: boolean;
}

export interface SSHTransportOptions {
  probeBinDir: string;
  manifest: ProbeManifest;
  timeout?: number;
  /**
   * --silent: ssh's own stderr (host-key notices, connection errors) is
   * captured instead of reaching the terminal, and printed only with --debug.
   * Password prompts still work — ssh writes and reads them on /dev/tty.
   * VASO's own error for a failed host is unaffected.
   */
  quiet?: boolean;
}

/**
 * Parse a target string like "user@host[:port]" into an SSHTarget.
 */
export function parseSSHTarget(target: string): SSHTarget {
  const atIdx = target.indexOf('@');
  if (atIdx === -1) {
    throw new Error(`Invalid SSH target "${target}": expected user@host[:port]`);
  }

  const user = target.slice(0, atIdx);
  const rest = target.slice(atIdx + 1);

  let host: string;
  let port = 22;

  const colonIdx = rest.lastIndexOf(':');
  if (rest.startsWith('[')) {
    // IPv6 with a port: user@[::1]:2222 (ssh's own bracket syntax)
    const m = /^\[([^\]]*)\](?::(\d+))?$/.exec(rest);
    if (!m) throw new Error(`Invalid SSH target "${target}": expected user@[ipv6-address][:port]`);
    host = m[1];
    if (m[2] !== undefined) port = Number(m[2]);
  } else if (rest.indexOf(':') !== colonIdx) {
    // A bare IPv6 address (user@::1, user@fe80::1) has no port; `::1` is not
    // host `:` on port 1
    host = rest;
  } else if (colonIdx !== -1) {
    const maybePart = rest.slice(colonIdx + 1);
    // `host:` names no port; ssh would get a host called `host:`
    if (maybePart === '') throw new Error(`Invalid SSH target "${target}": missing port after ":"`);
    if (/^\d+$/.test(maybePart)) {
      // `host:99999` names a port, just not a valid one — not a host called that
      host = rest.slice(0, colonIdx);
      port = Number(maybePart);
    } else {
      host = rest;
    }
  } else {
    host = rest;
  }

  if (!host) {
    throw new Error(`Invalid SSH target "${target}": missing hostname`);
  }
  assertSSHTargetParts(target, user, host, port);

  return { user, host, port, label: targetLabel(user, host, port) };
}

/** `user@host[:port]`, an IPv6 host bracketed when a port follows. */
export function targetLabel(user: string, host: string, port: number): string {
  if (port === 22) return `${user}@${host}`;
  return `${user}@${host.includes(':') ? `[${host}]` : host}:${port}`;
}

/** An inventory host written `[::1]` is the address inside the brackets. */
export function unbracketHost(host: string): string {
  const m = /^\[([^\]]*)\]$/.exec(host);
  return m ? m[1] : host;
}

/**
 * User, host and port as ssh will receive them. The user@host word is passed
 * as one argv entry, so a leading `-` would be read as an ssh option, and an
 * empty user or a port outside 1–65535 only fails later, as an unreachable host.
 */
export function assertSSHTargetParts(target: string, user: string, host: string, port: number): void {
  const bad = (why: string) => new Error(`Invalid SSH target "${target}": ${why}`);
  if (!user) throw bad('missing user (expected user@host[:port])');
  if (user.startsWith('-') || host.startsWith('-')) throw bad('user and host may not start with "-"');
  // `user:password@host` — ssh takes no password in the target, and a ':' in
  // the user would be passed on as part of the login name
  if (user.includes(':')) throw bad('the user may not contain ":" (ssh takes no password in the target)');
  if (/[\s\u0000-\u001f\u007f]/.test(user + host)) throw bad('whitespace or control characters');
  // What's left of a malformed [ipv6]:port, or a second user@
  if (/[[\]@/]/.test(host)) throw bad(`invalid host "${host}"`);
  // A host name, an IPv4 or IPv6 address (with a %zone): nothing else reaches ssh
  if (!/^[A-Za-z0-9._:%-]+$/.test(host)) throw bad(`invalid host "${host}"`);
  // Only an IPv6 address has colons (`h:22:22` is not one), and only an
  // address carries a %zone
  const [address, zone] = host.split('%', 2);
  if (host.includes(':') && isIP(address) !== 6) throw bad(`invalid host "${host}" (a colon is only valid in an IPv6 address)`);
  if (zone !== undefined && (isIP(address) !== 6 || zone === '')) throw bad(`invalid host "${host}"`);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw bad(`port must be 1–65535 (got ${String(port)})`);
}

/**
 * Every --ssh-key / inventory `identity` is a readable file. ssh only warns
 * about a missing one and goes on with the agent's or default keys, so a
 * mistyped path would scan with credentials nobody chose.
 */
export async function assertIdentityFiles(targets: SSHTarget[]): Promise<void> {
  for (const identity of new Set(targets.map(t => t.identity).filter((i): i is string => !!i))) {
    const path = identity === '~' || identity.startsWith('~/') ? join(homedir(), identity.slice(1)) : identity;
    try {
      await access(path, constants.R_OK);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code ?? 'unreadable';
      throw new Error(`SSH key "${identity}" is not readable (${code})`);
    }
    // ssh warns about a directory or an empty file and goes on with other keys
    const info = await stat(path);
    if (!info.isFile()) throw new Error(`SSH key "${identity}" is not a file`);
    if (info.size === 0) throw new Error(`SSH key "${identity}" is empty`);
  }
}

/**
 * Targets without repeats (same user, host and port — host names are
 * case-insensitive, `Host` and `host` are one machine); returns the dropped labels.
 */
export function uniqueTargets(targets: SSHTarget[]): { targets: SSHTarget[]; duplicates: string[] } {
  const seen = new Set<string>();
  const out: SSHTarget[] = [];
  const duplicates: string[] = [];
  for (const t of targets) {
    const key = `${t.user}@${t.host.toLowerCase()}:${t.port}`;
    if (seen.has(key)) duplicates.push(t.label ?? key);
    else { seen.add(key); out.push(t); }
  }
  return { targets: out, duplicates };
}

/**
 * A target's label names its baseline (and its report and snapshot files when
 * hostnames repeat), sanitised to a file name on a file system that may
 * ignore case. Two targets whose labels come out the same would overwrite
 * each other's — rejected before anything is scanned.
 */
export function assertDistinctLabels(targets: SSHTarget[]): void {
  const owners = new Map<string, string>();
  for (const t of targets) {
    const label = t.label ?? targetLabel(t.user, t.host, t.port);
    const key = safeHostname(label).toLowerCase();
    const other = owners.get(key);
    if (other !== undefined) {
      throw new Error(other === label
        ? `Label "${label}" is used by more than one host — give each host its own label`
        : `Labels "${other}" and "${label}" would name the same files (baselines and reports) — give each host a distinct label`);
    }
    owners.set(key, label);
  }
}

/**
 * Human-readable reason an `ssh` connection attempt ended. `elapsedMs` tells
 * ssh's own `ConnectTimeout` (exit 255 once the timeout has passed — it races
 * the spawn timer, and wins when the event loop is busy scanning another
 * host) apart from a refusal or a rejected key, which fail fast.
 */
export function describeConnectFailure(
  target: Pick<SSHTarget, 'user' | 'host'>,
  code: number | null,
  signal: NodeJS.Signals | null,
  timeoutMs: number,
  elapsedMs = 0,
): string {
  const who = `${target.user}@${target.host}`;
  const timedOut = code === 255 && elapsedMs >= timeoutMs - CONNECT_TIMEOUT_SLACK_MS;
  if (code === null || timedOut) {
    // spawn()'s timeout kills ssh with a signal and reports no exit code
    return signal === 'SIGTERM' || signal === null || timedOut
      ? `SSH connection to ${who} timed out after ${Math.round(timeoutMs / 1000)}s (host unreachable or not answering; raise --ssh-timeout if it is just slow)`
      : `SSH connection to ${who} was terminated by ${signal}`;
  }
  if (code === 255) {
    return `SSH connection to ${who} failed (ssh exit 255: connection refused, unknown host, or authentication rejected — check the host, user and --ssh-key)`;
  }
  return `SSH connection to ${who} failed (ssh exit ${code})`;
}

/**
 * spawn() with its own kill timer. Node's `timeout` option leaves its timer
 * running when the command can't start at all (ssh not installed), so the
 * process sat out the whole --ssh-timeout after the error.
 */
function spawnTimed(cmd: string, args: string[], options: SpawnOptions, timeout?: number): ChildProcess {
  const child = spawn(cmd, args, options);
  if (timeout && timeout > 0) {
    const timer = setTimeout(() => child.kill('SIGTERM'), timeout);
    const clear = () => clearTimeout(timer);
    child.once('exit', clear);
    child.once('close', clear);
    child.once('error', clear);
  }
  return child;
}

/**
 * The error for a command that could not be started. A missing client
 * stays missing: it is marked `permanent`, so --ssh-retries doesn't retry it.
 */
function startError(cmd: string, err: Error): Error {
  return (err as NodeJS.ErrnoException).code === 'ENOENT'
    ? Object.assign(new Error(`${cmd} is not installed or not on PATH — remote scans need the OpenSSH client (${cmd})`), { permanent: true })
    : err;
}

/** An error no retry can fix (startError). */
function isPermanent(err: unknown): boolean {
  return typeof err === 'object' && err !== null && (err as { permanent?: unknown }).permanent === true;
}

/** ssh's ConnectTimeout fires on whole seconds; allow for timer and start-up skew. */
const CONNECT_TIMEOUT_SLACK_MS = 500;

/**
 * Establish a ControlMaster SSH connection. This is the only step that
 * may prompt for a password — all subsequent ssh/scp commands multiplex
 * over this connection and never prompt again.
 *
 * Uses stdio: 'inherit' so the SSH password prompt works interactively;
 * `quiet` captures stderr only (the prompt goes through /dev/tty).
 */
function establishControlMaster(target: SSHTarget, controlPath: string, timeout: number, quiet = false): Promise<void> {
  return new Promise((resolve, reject) => {
    const args = [
      '-o', 'ControlMaster=yes',
      '-o', `ControlPath=${controlPath}`,
      '-o', 'ControlPersist=120',
      '-o', 'StrictHostKeyChecking=accept-new',
      // Honor --ssh-timeout for the TCP/handshake phase too (was fixed at 10 s)
      '-o', `ConnectTimeout=${Math.max(1, Math.ceil(timeout / 1000))}`,
      '-p', String(target.port),
    ];
    if (target.identity) args.push('-i', target.identity);
    args.push(`${target.user}@${target.host}`, '-N'); // -N: no remote command, just connect

    // Quiet: stderr to a private temp file, not a pipe — the backgrounded
    // master inherits it, and a pipe would hold 'close' open for
    // ControlPersist's 120 s (or SIGPIPE the master once read and closed).
    const log = quiet ? openQuietLog() : undefined;
    const started = Date.now();
    const child = spawnTimed('ssh', args, {
      stdio: log ? ['inherit', 'inherit', log.fd] : 'inherit', // Full terminal access for password prompts
    }, timeout);

    // ControlPersist keeps the connection alive in the background after
    // the master process exits, so we wait for it to fork and return.
    child.on('close', (code, signal) => {
      log?.finish();
      if (code === 0) return resolve();
      reject(new Error(describeConnectFailure(target, code, signal, timeout, Date.now() - started)));
    });
    child.on('error', (err) => { log?.finish(); reject(startError('ssh', err)); });
  });
}

/**
 * A 0600 temp file for ssh's stderr under --silent. `finish` prints what ssh
 * wrote when --debug is on (escaped: it can quote the host's banner), then
 * closes and removes the file; the background master keeps writing to the
 * removed inode harmlessly.
 */
function openQuietLog(): { fd: number; finish: () => void } {
  const path = join(tmpdir(), `vaso-ssh-${randomUUID()}.log`);
  const fd = openSync(path, 'wx+', 0o600);
  let done = false;
  return {
    fd,
    finish: () => {
      if (done) return;
      done = true;
      try {
        if (isDebug()) {
          const text = readFileSync(path, 'utf-8').slice(0, 64 * 1024);
          if (text) process.stderr.write(escapeControlChars(text));
        }
      } catch { /* debug output only */ }
      try { closeSync(fd); } catch { /* already closed */ }
      try { unlinkSync(path); } catch { /* already gone */ }
    },
  };
}

export { MAX_REMOTE_OUTPUT_BYTES };

/**
 * Run ssh/scp over an existing ControlMaster socket.
 * No password prompt — the connection is already authenticated.
 */
function runOverControl(
  cmd: string,
  args: string[],
  options: { timeout?: number } = {},
): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawnTimed(cmd, args, { stdio: ['pipe', 'pipe', 'pipe'] }, options.timeout);

    const chunks: Buffer[] = [];
    const errChunks: Buffer[] = [];
    let received = 0;
    let oversized = false;
    child.stdout!.on('data', (d: Buffer) => {
      received += d.length;
      if (received > MAX_REMOTE_OUTPUT_BYTES) {
        if (!oversized) {
          oversized = true;
          chunks.length = 0;
          child.kill();
        }
        return;
      }
      chunks.push(d);
    });
    child.stderr!.on('data', (d: Buffer) => errChunks.push(d));

    child.on('close', (code, signal) => {
      if (oversized) {
        reject(new Error(
          `Remote probe output exceeded ${Math.round(MAX_REMOTE_OUTPUT_BYTES / 1024 / 1024)} MiB and was aborted — ` +
          'the host has unusually large agent data; update to the current vaso-probe, which budgets its output.'));
        return;
      }
      const stdout = Buffer.concat(chunks).toString('utf-8');
      const stderr = Buffer.concat(errChunks).toString('utf-8');
      if (code === 0) {
        resolve({ stdout, stderr });
      } else if (code === null && signal && options.timeout) {
        // spawn()'s timeout kills the child with a signal and no exit code
        reject(new Error(`${cmd === 'scp' ? 'Upload' : 'Remote command'} did not finish within ${Math.round(options.timeout / 1000)}s and was stopped: ${args.slice(-1).join(' ')}`));
      } else {
        reject(new Error(`Command failed: ${cmd} ${args.slice(-1).join(' ')}\n${stderr || stdout}`.trim()));
      }
    });
    child.on('error', (err) => reject(startError(cmd, err)));
  });
}

function controlSSHArgs(target: SSHTarget, controlPath: string, remoteCmd: string[]): string[] {
  const args = [
    '-o', `ControlPath=${controlPath}`,
    '-o', 'StrictHostKeyChecking=accept-new',
    '-p', String(target.port),
  ];
  if (target.identity) args.push('-i', target.identity);
  args.push(`${target.user}@${target.host}`, ...remoteCmd);
  return args;
}

function controlSCPArgs(target: SSHTarget, controlPath: string, localPath: string, remotePath: string): string[] {
  const args = [
    '-o', `ControlPath=${controlPath}`,
    '-o', 'StrictHostKeyChecking=accept-new',
    '-P', String(target.port),
  ];
  if (target.identity) args.push('-i', target.identity);
  // scp splits host:path at the first colon, so an IPv6 host needs brackets
  const host = target.host.includes(':') ? `[${target.host}]` : target.host;
  args.push(localPath, `${target.user}@${host}:${remotePath}`);
  return args;
}

function closeControlMaster(target: SSHTarget, controlPath: string): void {
  try {
    execFileSync('ssh', [
      '-o', `ControlPath=${controlPath}`,
      '-O', 'exit',
      `${target.user}@${target.host}`,
    ], { timeout: 5000, stdio: 'pipe' });
  } catch {
    // Best effort cleanup
  }
}

interface RemotePlatform {
  os: string;
  arch: string;
}

async function detectRemotePlatform(
  target: SSHTarget,
  controlPath: string,
  timeout: number,
): Promise<RemotePlatform> {
  const { stdout } = await runOverControl(
    'ssh',
    controlSSHArgs(target, controlPath, ['uname -s && uname -m']),
    { timeout },
  );
  const lines = stdout.trim().split('\n');
  if (lines.length < 2) throw new Error(`Unexpected uname output from ${target.host}: ${stdout}`);

  const os = lines[0].trim().toLowerCase();
  const rawArch = lines[1].trim().toLowerCase();

  let arch: string;
  switch (rawArch) {
    case 'x86_64': arch = 'amd64'; break;
    case 'aarch64': case 'arm64': arch = 'arm64'; break;
    default: throw new Error(`Unsupported architecture on ${target.host}: ${rawArch}`);
  }

  if (os !== 'linux' && os !== 'darwin') {
    throw new Error(
      `Unsupported platform on ${target.host}: ${os}/${arch}\n` +
      `  vaso-probe binaries are available for Linux and macOS (amd64/arm64).`
    );
  }

  return { os, arch };
}

export interface RetryOptions {
  retries: number;
  onRetry?: (target: SSHTarget, attempt: number, err: Error) => void;
}

interface WithRetryOptions<T> {
  retries: number;
  fn: () => Promise<T>;
  onRetry?: (attempt: number, err: Error) => void;
  /** Test seam — defaults to setTimeout-based exponential backoff. */
  sleep?: (attempt: number) => Promise<void>;
}

const defaultSleep = (attempt: number): Promise<void> =>
  new Promise(r => setTimeout(r, Math.min(1000 * 2 ** (attempt - 1), 8000)));

/**
 * Run an async function with exponential backoff retry.
 * `retries` is the number of *additional* attempts after the first (so retries=2
 * means up to 3 attempts total).
 */
export async function withRetry<T>(opts: WithRetryOptions<T>): Promise<T> {
  const sleep = opts.sleep ?? defaultSleep;
  let lastErr: unknown;
  for (let attempt = 0; attempt <= opts.retries; attempt++) {
    if (attempt > 0) {
      await sleep(attempt);
      opts.onRetry?.(attempt, lastErr as Error);
    }
    try {
      return await opts.fn();
    } catch (err) {
      if (isPermanent(err)) throw err;
      lastErr = err;
    }
  }
  throw lastErr;
}

/**
 * Run executeRemoteProbe with exponential backoff retry.
 * Cleanup of remote /tmp files happens in executeRemoteProbe's finally block,
 * so retries are safe — each attempt uses a fresh UUID.
 */
export async function executeRemoteProbeWithRetry(
  target: SSHTarget,
  options: SSHTransportOptions,
  retry: RetryOptions,
): Promise<ProbeSnapshot> {
  return withRetry({
    retries: retry.retries,
    fn: () => executeRemoteProbe(target, options),
    onRetry: retry.onRetry ? (attempt, err) => retry.onRetry!(target, attempt, err) : undefined,
  });
}

/**
 * The probe's stdout as a snapshot, held to the shape and size checks a
 * `--snapshot` file gets: the host may be hostile or compromised, and a
 * malformed snapshot would otherwise crash or mislead the scan. Throws a
 * one-line error, so the host is reported unscanned (exit 3).
 */
export function parseProbeOutput(stdout: string, target: Pick<SSHTarget, 'user' | 'host'>): ProbeSnapshot {
  try {
    return parseSnapshot(stdout, 'Probe output');
  } catch (err) {
    if (!(err instanceof SnapshotLoadError)) throw err;
    const problems = err.problems.length > 3
      ? [...err.problems.slice(0, 3), `${err.problems.length - 3} more`]
      : err.problems;
    const detail = problems.length > 0 ? `${err.message.replace(/:$/, '')}: ${problems.join('; ')}` : err.message;
    // Paths and the JSON error's excerpt come from the host: one escaped, bounded line
    const line = escapeControlChars(detail, { lineBreaks: true });
    throw new Error(`${target.user}@${target.host} returned unusable probe output, host not scanned — ${line.length > 500 ? `${line.slice(0, 500)}…` : line}`);
  }
}

/** Upper bound for uploading and running the probe (independent of --ssh-timeout). */
export const PROBE_RUN_TIMEOUT_MS = 10 * 60 * 1000;

export async function executeRemoteProbe(
  target: SSHTarget,
  options: SSHTransportOptions,
): Promise<ProbeSnapshot> {
  // --ssh-timeout bounds connecting (handshake, platform detection). Uploading
  // and running the probe take longer on large hosts and get their own limit.
  const timeout = options.timeout ?? 60000;
  const runTimeout = Math.max(timeout, PROBE_RUN_TIMEOUT_MS);
  const uuid = randomUUID().slice(0, 8);
  const controlPath = `/tmp/vaso-ssh-${uuid}`;
  const remoteProbePath = `/tmp/vaso-probe-${uuid}`;
  const remoteManifestPath = `/tmp/vaso-manifest-${uuid}.json`;
  const localManifestPath = `/tmp/vaso-manifest-local-${uuid}.json`;
  let connected = false;

  try {
    // 1. Establish authenticated connection (may prompt for password once)
    await establishControlMaster(target, controlPath, timeout, options.quiet);
    connected = true;

    // All subsequent commands reuse the authenticated connection — no more prompts

    // 2. Detect remote platform
    const platform = await detectRemotePlatform(target, controlPath, timeout);

    // 3. Select correct binary — resolves a locally-built probe, a cached one,
    //    or lazily downloads + verifies the matching release asset on first use.
    const localBinary = await resolveProbeBinary(platform.os, platform.arch, {
      probeBinDir: options.probeBinDir,
    });

    // 4. Write manifest locally
    await writeFile(localManifestPath, JSON.stringify(options.manifest), 'utf-8');

    // 5. Push binary + manifest to remote
    await runOverControl('scp', controlSCPArgs(target, controlPath, localBinary, remoteProbePath), { timeout: runTimeout });
    await runOverControl('scp', controlSCPArgs(target, controlPath, localManifestPath, remoteManifestPath), { timeout: runTimeout });

    // 6. Make probe executable
    await runOverControl('ssh', controlSSHArgs(target, controlPath, [`chmod +x ${remoteProbePath}`]), { timeout: 10000 });

    // 7. Execute probe
    const probeCmd = `${remoteProbePath} --manifest ${remoteManifestPath}${target.sudo ? ' --escalate' : ''}`;
    const { stdout } = await runOverControl('ssh', controlSSHArgs(target, controlPath, [probeCmd]), { timeout: runTimeout });

    // 8. Parse snapshot
    return parseProbeOutput(stdout, target);
  } finally {
    // Clean up local temp file
    await unlink(localManifestPath).catch(() => {});
    // Remote cleanup needs the control connection; without it ssh would dial
    // the (unreachable) host again and stall the failure by up to 10 s.
    if (connected) {
      try {
        await runOverControl('ssh', controlSSHArgs(target, controlPath, [`rm -f ${remoteProbePath} ${remoteManifestPath}`]), { timeout: 10000 });
      } catch { /* best effort */ }
      closeControlMaster(target, controlPath);
    }
  }
}
