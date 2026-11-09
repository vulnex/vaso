import type { FSProvider } from '../core/fs-provider.js';

/**
 * OpenClaw `gateway.bind` as its gateway resolves it (resolveGatewayBindHost,
 * src/gateway/net.ts, verified at 2026.9.4 and 2026.11.2):
 *
 *   loopback   127.0.0.1 (also an unset bind outside containers)
 *   lan        0.0.0.0
 *   tailnet    the tailnet address, else loopback
 *   custom     gateway.customBindHost
 *   auto       0.0.0.0 inside a container (Docker/Podman/Kubernetes/Fly, for
 *              port forwarding), loopback everywhere else — nothing prefers
 *              the tailnet
 *
 * "auto" therefore depends on where the gateway runs. VASO can tell only for
 * a local scan, from the same markers OpenClaw uses (isContainerEnvironment).
 * A remote snapshot doesn't carry them, so there "auto" stays undecided and
 * checks report it as informational with the container caveat.
 */

/** Markers OpenClaw's isContainerEnvironment() looks for (2026.11.2). */
const CONTAINER_SENTINELS = ['/.dockerenv', '/run/.containerenv', '/var/run/.containerenv'];
const CONTAINER_CGROUP = /\/docker\/|cri-containerd-[0-9a-f]|containerd\/[0-9a-f]{64}|\/kubepods[/.]|\blxc\b/;

const cache = new WeakMap<FSProvider, Promise<boolean | undefined>>();

/**
 * Whether the scanned host is a container, as OpenClaw would decide it:
 * true / false on a local scan, undefined when it can't be known (a remote
 * snapshot, which doesn't collect the markers).
 */
export function containerEnvironment(fs: FSProvider): Promise<boolean | undefined> {
  let pending = cache.get(fs);
  if (!pending) {
    pending = detectContainer(fs);
    cache.set(fs, pending);
  }
  return pending;
}

async function detectContainer(fs: FSProvider): Promise<boolean | undefined> {
  if (fs.kind === 'snapshot') return undefined;
  try {
    if (fs.getEnv('FLY_MACHINE_ID')?.trim() && fs.getEnv('FLY_APP_NAME')?.trim()) return true;
    for (const sentinel of CONTAINER_SENTINELS) {
      if (await fs.access(sentinel)) return true;
    }
  } catch {
    // a provider that can't answer: unknown
    return undefined;
  }
  if (fs.platform === 'linux') {
    try {
      if (CONTAINER_CGROUP.test(await fs.readFile('/proc/1/cgroup'))) return true;
    } catch {
      // no procfs, or unreadable
    }
  }
  return false;
}

export function isOpenclawAutoBind(bind: unknown): boolean {
  return typeof bind === 'string' && bind.trim().toLowerCase() === 'auto';
}

/** The address "auto" resolves to: 0.0.0.0 in a container, loopback outside, undefined when unknown. */
export function openclawAutoBindHost(inContainer: boolean | undefined): string | undefined {
  return inContainer === undefined ? undefined : inContainer ? '0.0.0.0' : '127.0.0.1';
}

/** Detail line for a "auto" bind: what it does, and what VASO could tell about this host. */
export function openclawAutoBindDetail(inContainer: boolean | undefined): string {
  const rule = 'Gateway bind mode "auto" — loopback (127.0.0.1) outside containers, 0.0.0.0 (every interface) inside Docker/Podman/Kubernetes';
  if (inContainer === true) return `${rule}; this host is a container, so it listens on 0.0.0.0`;
  if (inContainer === false) return `${rule}; no container detected here, so it listens on loopback — set "loopback" to keep it local if the gateway also runs in a container`;
  return `${rule}; whether the remote host is a container can't be verified from a snapshot — set "loopback" to keep it local`;
}
