import { posix } from 'node:path';
import { defineCheck } from '../../core/check-builder.js';
import type { Severity } from '../../core/types.js';
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

function normalizeRoot(entry: unknown): Root | undefined {
  if (typeof entry === 'string') return { path: entry, readWrite: false };
  if (!entry || typeof entry !== 'object') return undefined;
  const r = entry as Record<string, unknown>;
  if (typeof r.path !== 'string' || !r.path.trim()) return undefined;
  const readWrite = typeof r.allowReadWrite === 'boolean'
    ? r.allowReadWrite
    : typeof r.readOnly === 'boolean' ? !r.readOnly : false;
  return { path: r.path.trim(), readWrite };
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

function classify(root: Root, home: string, checkout: string | undefined): { detail: string; severity: Severity } | undefined {
  const abs = expand(root.path, home, checkout ?? home);
  const mode = root.readWrite ? 'read-write' : 'read-only';
  const label = `allowedRoots "${root.path}" (${mode})`;

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
  if (SYSTEM_DIRS.some(d => contains(d, abs))) {
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

    const roots = config.data?.allowedRoots;
    if (!Array.isArray(roots)) {
      return h.passed('Mount allowlist has no allowedRoots array (NanoClaw rejects it and blocks additional mounts)');
    }

    const home = ctx.fs.homedir();
    const checkout = checkoutDir(ctx);
    const findings = new Findings();
    for (const entry of roots) {
      const root = normalizeRoot(entry);
      if (!root) continue;
      const hit = classify(root, home, checkout);
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
