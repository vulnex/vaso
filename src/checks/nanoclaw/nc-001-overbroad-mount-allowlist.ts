import { posix } from 'node:path';
import { defineCheck } from '../../core/check-builder.js';
import type { ScanContext, Severity } from '../../core/types.js';
import { allowlistConfig, checkoutDir, Findings } from './shared.js';

/**
 * NanoClaw v2 mount allowlist (`~/.config/nanoclaw/mount-allowlist.json`):
 *
 *   { "allowedRoots": [{ "path": "~/projects", "allowReadWrite": true, "description"?: "…" }],
 *     "blockedPatterns": ["…"], "nonMainReadOnly": true }
 *
 * Upstream (src/modules/mount-security) lets a group mount any host path that
 * resolves under an allowed root. Blocked patterns (built-in: .ssh, .gnupg,
 * .aws, .kube, .docker, .config/nanoclaw, .local/bin, .env, credentials, …)
 * are matched ONLY against the mount root — never the subtree — so allowing
 * `~` (or `/`) makes every credential beneath it mountable. `allowReadWrite`
 * is per root; a legacy `readOnly` key is translated (`allowReadWrite =
 * !readOnly`), and neither key means read-only. `nonMainReadOnly` is ignored.
 *
 * loadMountAllowlist() refuses the whole file — and so blocks every additional
 * mount — unless it is strict JSON with both `allowedRoots` and
 * `blockedPatterns` arrays (a null root entry makes it throw too). Roots are
 * compared after realpath(), so a symlinked root is judged by its target; an
 * entry without a string `path` becomes "" — the host process's cwd, the
 * checkout.
 */

/** Credential stores whose mounts upstream's built-in blocked patterns already refuse. */
const BUILTIN_BLOCKED = ['.ssh', '.gnupg', '.gpg', '.aws', '.azure', '.gcloud', '.kube', '.docker',
  '.config/nanoclaw', '.local/bin', 'credentials', '.env', '.netrc', '.npmrc', '.pypirc'];

/** System trees: RW → host takeover; RO still leaks host config. */
const SYSTEM_DIRS = ['/etc', '/root', '/usr', '/boot', '/Library', '/System', '/private/etc'];
/** The Docker socket: a root at or above it lets an agent drive the host's Docker (escape). */
const DOCKER_SOCKETS = ['/var/run/docker.sock', '/run/docker.sock', '/private/var/run/docker.sock'];
/** Kernel interfaces: any root inside or above them. */
const KERNEL_DIRS = ['/proc', '/sys', '/dev'];

interface Root { path: string; readWrite: boolean }

/** Upstream normalizeRoot(): a non-object entry or a missing path is "". */
function normalizeRoot(entry: unknown): Root {
  const r = (entry && typeof entry === 'object' ? entry : {}) as Record<string, unknown>;
  const readWrite = typeof r.allowReadWrite === 'boolean'
    ? r.allowReadWrite
    : typeof r.readOnly === 'boolean' ? !r.readOnly : false;
  return { path: typeof r.path === 'string' ? r.path : '', readWrite };
}

/** Why NanoClaw refuses the file (and blocks all additional mounts), if it does. */
function rejectedBy(raw: string): string | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return 'is not strict JSON';
  }
  const data = (parsed && typeof parsed === 'object' ? parsed : {}) as Record<string, unknown>;
  if (!Array.isArray(data.allowedRoots)) return 'has no allowedRoots array';
  if (!Array.isArray(data.blockedPatterns)) return 'has no blockedPatterns array';
  if (data.allowedRoots.some(e => e === null)) return 'has a null allowedRoots entry';
  return undefined;
}

function expand(p: string, home: string, base: string): string {
  if (p === '~') return home;
  if (p.startsWith('~/')) return posix.join(home, p.slice(2));
  // Upstream path.resolve()s relative roots against the host's cwd — the checkout.
  return posix.resolve(base, p);
}

/** a === b or a is an ancestor of b. */
function contains(a: string, b: string): boolean {
  if (a === '/') return true;
  return b === a || b.startsWith(a + '/');
}

async function real(fs: ScanContext['fs'], p: string): Promise<string> {
  try {
    return await fs.realpath(p);
  } catch {
    return p; // not there (or not collected): judged as written
  }
}

function classify(root: Root, abs: string, home: string, checkout: string | undefined): { detail: string; severity: Severity } | undefined {
  const mode = root.readWrite ? 'read-write' : 'read-only';
  const label = `allowedRoots "${root.path}"${abs !== expand(root.path, home, checkout ?? home) ? ` (→ ${abs})` : ''} (${mode})`;

  if (abs === '/') {
    return { severity: 'critical', detail: `${label} grants the entire host filesystem to agent containers` };
  }
  if (contains(abs, home)) {
    return {
      severity: 'critical',
      detail: abs === home
        ? `${label} grants the whole home directory — blocked patterns are checked only against the mount root, so ~/.ssh, cloud credentials and shell profiles beneath it are all mountable${root.readWrite ? ' and writable (host code execution)' : ''}`
        : `${label} contains the user home directory — every credential beneath it is mountable`,
    };
  }
  if (DOCKER_SOCKETS.some(s => contains(abs, s))) {
    return { severity: 'critical', detail: `${label} contains the Docker socket — an agent can drive the host's Docker daemon (container escape)` };
  }
  if (KERNEL_DIRS.some(d => contains(abs, d) || contains(d, abs))) {
    return { severity: 'critical', detail: `${label} exposes kernel interface ${abs} (container escape)` };
  }
  // Paths inside the user's home are judged below, even when home itself is
  // under a system directory (root's home is /root).
  if (!contains(home, abs) && SYSTEM_DIRS.some(d => contains(d, abs))) {
    return {
      severity: root.readWrite ? 'critical' : 'warning',
      detail: `${label} exposes system directory ${abs}${root.readWrite ? ' writable — host takeover' : ''}`,
    };
  }
  if (checkout && contains(abs, checkout)) {
    return {
      severity: 'critical',
      detail: `${label} contains the NanoClaw checkout ${checkout} — agents can read its .env secrets${root.readWrite ? ' and rewrite the host code that runs them' : ''}`,
    };
  }
  const rel = contains(home, abs) ? abs.slice(home.length + 1) : undefined;
  if (rel !== undefined) {
    // Roots inside a built-in blocked credential store can never be mounted.
    if (BUILTIN_BLOCKED.some(b => rel === b || rel.startsWith(b + '/'))) return undefined;
    if (rel === '.config' || rel === '.local' || rel === '.local/share') {
      return {
        severity: root.readWrite ? 'critical' : 'warning',
        detail: `${label} exposes ~/${rel} — app tokens (gh, gcloud, …) are mountable${root.readWrite ? '; writable autostart/systemd/bin paths give host code execution' : ''}`,
      };
    }
  }
  return undefined;
}

export const nc001 = defineCheck({
  id: 'NC-001',
  name: 'Overbroad Mount Allowlist',
  category: 'nanoclaw',
  severity: 'critical',
  description: 'Detect mount-allowlist.json allowedRoots that let agent containers mount the whole filesystem, the user home (every credential beneath it — blocked patterns only guard the mount root), Docker-socket/kernel trees, system directories, or the NanoClaw checkout itself.',
  supportedAgents: ['nanoclaw'],

  async run(ctx, h) {
    const config = allowlistConfig(ctx);
    if (!config) return h.passed('No mount allowlist (additional mounts are blocked)');

    const rejected = rejectedBy(config.raw);
    if (rejected) {
      return h.passed(`Mount allowlist ${rejected} — NanoClaw rejects it and blocks additional mounts`);
    }
    const roots = config.data.allowedRoots as unknown[];

    // Upstream compares realpaths: a symlinked root, home or checkout is judged by its target
    const lexicalHome = ctx.fs.homedir();
    const home = await real(ctx.fs, lexicalHome);
    const lexicalCheckout = checkoutDir(ctx);
    const checkout = lexicalCheckout ? await real(ctx.fs, lexicalCheckout) : undefined;
    const findings = new Findings();
    for (const entry of roots) {
      const root = normalizeRoot(entry);
      const abs = await real(ctx.fs, expand(root.path, lexicalHome, lexicalCheckout ?? lexicalHome));
      const hit = classify(root, abs, home, checkout);
      if (hit) findings.add({ file: config.filePath, detail: hit.detail }, hit.severity);
    }

    return h.fromEvidence(findings.evidence, {
      passed: 'Mount allowlist roots are scoped to project directories',
      failed: (n) => `Mount allowlist grants ${n} overbroad root${n === 1 ? '' : 's'} to agent containers`,
      severity: findings.severity('critical'),
      fixable: false,
      fixDescription: 'Replace broad allowedRoots with specific project directories (e.g. ~/projects/<repo>), set allowReadWrite: false unless agents must write, and re-run `setup --step mounts --force` or edit ~/.config/nanoclaw/mount-allowlist.json',
    });
  },
});
