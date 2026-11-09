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
 * "auto" therefore depends on where the gateway runs. VASO decides it from
 * the same markers OpenClaw uses (isContainerEnvironment); the probe manifest
 * collects them (OPENCLAW_CONTAINER_MARKERS), so a remote scan decides it
 * like a local one. A snapshot that doesn't carry them (saved by an older
 * VASO) leaves "auto" undecided: checks report it as informational with the
 * container caveat.
 *
 * An unset bind is not always loopback either: with Tailscale serve/funnel
 * off, OpenClaw defaults it to "auto" inside a container and to "loopback"
 * elsewhere (server-runtime-config.ts resolveGatewayRuntimeConfig,
 * defaultGatewayBindMode in net.ts, 2026.11.2) — see openclawEffectiveBind.
 */

/** Markers OpenClaw's isContainerEnvironment() looks for (2026.11.2,
 *  src/infra/container-environment.ts): both Fly variables set, a sentinel
 *  file present, or a container cgroup for PID 1. */
const FLY_ENV = ['FLY_MACHINE_ID', 'FLY_APP_NAME'];
const CONTAINER_SENTINELS = ['/.dockerenv', '/run/.containerenv', '/var/run/.containerenv'];
const PID1_CGROUP = '/proc/1/cgroup';
const CONTAINER_CGROUP = /\/docker\/|cri-containerd-[0-9a-f]|containerd\/[0-9a-f]{64}|\/kubepods[/.]|\blxc\b/;

/**
 * What the probe collects so a remote scan decides "auto" as a local one does:
 * whether the two Fly variables are set (envPresence: a placeholder, never the
 * app name or machine id — OpenClaw only tests them non-empty), the
 * sentinels as existence only (an old Docker's /.dockerenv held the
 * container's environment; Podman's /run/.containerenv names the image), and
 * PID 1's cgroup list — a few short lines of cgroup paths. The cgroup file is
 * a system path, recorded even when absent, which is how a snapshot shows
 * that the markers were collected at all.
 */
export const OPENCLAW_CONTAINER_MARKERS = {
  envNames: FLY_ENV,
  existenceOnly: CONTAINER_SENTINELS,
  content: [PID1_CGROUP],
} as const;

const cache = new WeakMap<FSProvider, Promise<boolean | undefined>>();

/**
 * Whether the scanned host is a container, as OpenClaw would decide it:
 * true / false on a local scan and on a snapshot that collected the markers,
 * undefined when it can't be known (a snapshot without them).
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
  if (fs.kind === 'snapshot' && !markersCollected(fs)) return undefined;
  try {
    if (FLY_ENV.every(name => fs.getEnv(name)?.trim())) return true;
    for (const sentinel of CONTAINER_SENTINELS) {
      if (await fs.access(sentinel)) return true;
    }
  } catch {
    // a provider that can't answer: unknown
    return undefined;
  }
  if (fs.platform === 'linux') {
    try {
      if (CONTAINER_CGROUP.test(await fs.readFile(PID1_CGROUP))) return true;
    } catch {
      // no procfs, or unreadable
    }
  }
  return false;
}

/** A snapshot carries the markers when the probe was asked for PID 1's cgroup
 *  (recorded present or absent; older manifests didn't ask). */
function markersCollected(fs: FSProvider): boolean {
  const collected = (fs as FSProvider & { collected?: (path: string) => boolean }).collected;
  return typeof collected === 'function' && collected.call(fs, PID1_CGROUP);
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

/**
 * The bind mode OpenClaw runs a config's gateway with: `gateway.bind` when
 * set; unset, "loopback" when Tailscale serve/funnel is on (any mode but
 * "off"), else "auto" inside a container and "loopback" outside
 * (resolveGatewayRuntimeConfig + defaultGatewayBindMode, 2026.11.2). Unset
 * on a host whose container question is open stays "loopback", the default
 * nearly every host gets.
 */
export function openclawEffectiveBind(data: Record<string, unknown>, inContainer: boolean | undefined): unknown {
  const gw = data.gateway && typeof data.gateway === 'object' && !Array.isArray(data.gateway)
    ? data.gateway as Record<string, unknown>
    : undefined;
  if (gw?.bind !== undefined && gw.bind !== null) return gw.bind;
  const ts = gw?.tailscale && typeof gw.tailscale === 'object' ? (gw.tailscale as Record<string, unknown>).mode : undefined;
  if (ts && ts !== 'off') return 'loopback';
  return inContainer ? 'auto' : 'loopback';
}
