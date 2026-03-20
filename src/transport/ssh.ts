/**
 * SSH target parsing and remote probe execution for network scanning.
 */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import { writeFile, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import type { ProbeSnapshot, ProbeManifest } from '../core/snapshot-types.js';

const execFileAsync = promisify(execFile);

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

  return { user, host, port };
}

interface RemotePlatform {
  os: string;
  arch: string;
}

function buildSSHArgs(target: SSHTarget, remoteCmd: string[]): string[] {
  const args = [
    '-o', 'BatchMode=yes',
    '-o', 'StrictHostKeyChecking=accept-new',
    '-o', 'ConnectTimeout=10',
    '-p', String(target.port),
  ];
  if (target.identity) args.push('-i', target.identity);
  args.push(`${target.user}@${target.host}`, ...remoteCmd);
  return args;
}

function buildSCPArgs(target: SSHTarget, localPath: string, remotePath: string): string[] {
  const args = [
    '-o', 'BatchMode=yes',
    '-o', 'StrictHostKeyChecking=accept-new',
    '-o', 'ConnectTimeout=10',
    '-P', String(target.port),
  ];
  if (target.identity) args.push('-i', target.identity);
  args.push(localPath, `${target.user}@${target.host}:${remotePath}`);
  return args;
}

async function detectRemotePlatform(target: SSHTarget, timeout: number): Promise<RemotePlatform> {
  const { stdout } = await execFileAsync('ssh', buildSSHArgs(target, ['uname -s && uname -m']), {
    timeout, encoding: 'utf-8',
  });
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

export async function executeRemoteProbe(
  target: SSHTarget,
  options: SSHTransportOptions,
): Promise<ProbeSnapshot> {
  const timeout = options.timeout ?? 60000;
  const uuid = randomUUID().slice(0, 8);
  const remoteProbePath = `/tmp/vaso-probe-${uuid}`;
  const remoteManifestPath = `/tmp/vaso-manifest-${uuid}.json`;
  const localManifestPath = `/tmp/vaso-manifest-local-${uuid}.json`;

  try {
    // 1. Detect remote platform
    const platform = await detectRemotePlatform(target, timeout);

    // 2. Select correct binary
    const localBinary = join(options.probeBinDir, `vaso-probe-${platform.os}-${platform.arch}`);

    // 3. Write manifest locally
    await writeFile(localManifestPath, JSON.stringify(options.manifest), 'utf-8');

    // 4. Push binary + manifest to remote
    await execFileAsync('scp', buildSCPArgs(target, localBinary, remoteProbePath), { timeout, encoding: 'utf-8' });
    await execFileAsync('scp', buildSCPArgs(target, localManifestPath, remoteManifestPath), { timeout, encoding: 'utf-8' });

    // 5. Make probe executable
    await execFileAsync('ssh', buildSSHArgs(target, [`chmod +x ${remoteProbePath}`]), { timeout: 10000, encoding: 'utf-8' });

    // 6. Execute probe
    const probeCmd = `${remoteProbePath} --manifest ${remoteManifestPath}${target.sudo ? ' --escalate' : ''}`;
    const { stdout } = await execFileAsync('ssh', buildSSHArgs(target, [probeCmd]), {
      timeout, encoding: 'utf-8', maxBuffer: 50 * 1024 * 1024,
    });

    // 7. Parse snapshot
    return JSON.parse(stdout) as ProbeSnapshot;
  } finally {
    // Clean up local temp file
    await unlink(localManifestPath).catch(() => {});
    // Clean up remote temp files (best effort)
    await execFileAsync('ssh', buildSSHArgs(target, [`rm -f ${remoteProbePath} ${remoteManifestPath}`]), {
      timeout: 10000, encoding: 'utf-8',
    }).catch(() => {});
  }
}
