/**
 * SSH target parsing and remote probe execution for network scanning.
 *
 * Uses SSH ControlMaster multiplexing: authenticates once (supporting
 * password prompts), then reuses the connection for all subsequent
 * ssh/scp commands without re-authenticating.
 */

import { spawn, execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { writeFile, unlink } from 'node:fs/promises';
import type { ProbeSnapshot, ProbeManifest } from '../core/snapshot-types.js';
import { resolveProbeBinary } from './probe-fetch.js';

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
  if (colonIdx !== -1) {
    const maybePart = rest.slice(colonIdx + 1);
    const parsed = parseInt(maybePart, 10);
    if (!isNaN(parsed) && parsed > 0 && parsed <= 65535) {
      host = rest.slice(0, colonIdx);
      port = parsed;
    } else {
      host = rest;
    }
  } else {
    host = rest;
  }

  if (!host) {
    throw new Error(`Invalid SSH target "${target}": missing hostname`);
  }

  const label = port === 22 ? `${user}@${host}` : `${user}@${host}:${port}`;
  return { user, host, port, label };
}

/**
 * Establish a ControlMaster SSH connection. This is the only step that
 * may prompt for a password — all subsequent ssh/scp commands multiplex
 * over this connection and never prompt again.
 *
 * Uses stdio: 'inherit' so the SSH password prompt works interactively.
 */
function establishControlMaster(target: SSHTarget, controlPath: string, timeout: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const args = [
      '-o', 'ControlMaster=yes',
      '-o', `ControlPath=${controlPath}`,
      '-o', 'ControlPersist=120',
      '-o', 'StrictHostKeyChecking=accept-new',
      '-o', 'ConnectTimeout=10',
      '-p', String(target.port),
    ];
    if (target.identity) args.push('-i', target.identity);
    args.push(`${target.user}@${target.host}`, '-N'); // -N: no remote command, just connect

    const child = spawn('ssh', args, {
      stdio: 'inherit', // Full terminal access for password prompts
      timeout,
    });

    // ControlPersist keeps the connection alive in the background after
    // the master process exits, so we wait for it to fork and return.
    child.on('close', (code) => {
      if (code === 0) resolve();
      else reject(new Error(`SSH connection to ${target.user}@${target.host} failed (exit ${code})`));
    });
    child.on('error', reject);
  });
}

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
    const child = spawn(cmd, args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: options.timeout,
    });

    const chunks: Buffer[] = [];
    const errChunks: Buffer[] = [];
    child.stdout.on('data', (d: Buffer) => chunks.push(d));
    child.stderr.on('data', (d: Buffer) => errChunks.push(d));

    child.on('close', (code) => {
      const stdout = Buffer.concat(chunks).toString('utf-8');
      const stderr = Buffer.concat(errChunks).toString('utf-8');
      if (code === 0) {
        resolve({ stdout, stderr });
      } else {
        reject(new Error(`Command failed: ${cmd} ${args.slice(-1).join(' ')}\n${stderr || stdout}`.trim()));
      }
    });
    child.on('error', reject);
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
  args.push(localPath, `${target.user}@${target.host}:${remotePath}`);
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

export async function executeRemoteProbe(
  target: SSHTarget,
  options: SSHTransportOptions,
): Promise<ProbeSnapshot> {
  const timeout = options.timeout ?? 60000;
  const uuid = randomUUID().slice(0, 8);
  const controlPath = `/tmp/vaso-ssh-${uuid}`;
  const remoteProbePath = `/tmp/vaso-probe-${uuid}`;
  const remoteManifestPath = `/tmp/vaso-manifest-${uuid}.json`;
  const localManifestPath = `/tmp/vaso-manifest-local-${uuid}.json`;

  try {
    // 1. Establish authenticated connection (may prompt for password once)
    await establishControlMaster(target, controlPath, timeout);

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
    await runOverControl('scp', controlSCPArgs(target, controlPath, localBinary, remoteProbePath), { timeout });
    await runOverControl('scp', controlSCPArgs(target, controlPath, localManifestPath, remoteManifestPath), { timeout });

    // 6. Make probe executable
    await runOverControl('ssh', controlSSHArgs(target, controlPath, [`chmod +x ${remoteProbePath}`]), { timeout: 10000 });

    // 7. Execute probe
    const probeCmd = `${remoteProbePath} --manifest ${remoteManifestPath}${target.sudo ? ' --escalate' : ''}`;
    const { stdout } = await runOverControl('ssh', controlSSHArgs(target, controlPath, [probeCmd]), { timeout });

    // 8. Parse snapshot
    return JSON.parse(stdout) as ProbeSnapshot;
  } finally {
    // Clean up local temp file
    await unlink(localManifestPath).catch(() => {});
    // Clean up remote temp files (best effort)
    try {
      await runOverControl('ssh', controlSSHArgs(target, controlPath, [`rm -f ${remoteProbePath} ${remoteManifestPath}`]), { timeout: 10000 });
    } catch { /* best effort */ }
    // Close the control master connection
    closeControlMaster(target, controlPath);
  }
}
