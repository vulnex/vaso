import { defineCheck } from '../../core/check-builder.js';
import type { FSProvider } from '../../core/fs-provider.js';
import type { AgentInstallation } from '../../core/types.js';

/**
 * CVE-2026-21636 (OSV; Node.js January 2026 security release): with the
 * permission model on (`--permission`), Unix domain socket connections skip
 * the network restriction. Affected: 25.0.0 ≤ v < 25.3.0 — no LTS line.
 */
const AFFECTED = { major: 25, fixedMinor: 3 };

/** A CLI installed into a Node version manager's per-version tree runs on that Node. */
export const MANAGER_VERSION = /\/(?:\.nvm\/versions\/node|fnm\/node-versions|\.asdf\/installs\/nodejs|mise\/installs\/node|n\/versions\/node)\/v?(\d+\.\d+\.\d+)\//;

/**
 * Volta runs a global package on the Node it was installed with, recorded
 * per binary in `$VOLTA_HOME/tools/user/bins/<bin>.json` (`platform.node`;
 * volta-core `BinConfig`). The CLI path (`~/.volta/bin/<bin>` shim or the
 * package image) doesn't name it.
 */
async function voltaNodeVersion(cliBinary: string, fs: FSProvider): Promise<{ version: string; source: string } | undefined> {
  const m = /^(.*\/\.volta)\/(?:bin\/([^/]+)$|tools\/image\/packages\/(?:@[^/]+\/)?[^/]+\/bin\/([^/]+)$)/.exec(cliBinary);
  if (!m) return undefined;
  const file = `${m[1]}/tools/user/bins/${m[2] ?? m[3]}.json`;
  try {
    const node = (JSON.parse(await fs.readFile(file)) as { platform?: { node?: unknown } }).platform?.node;
    const v = typeof node === 'string' ? /^v?(\d+\.\d+\.\d+)$/.exec(node.trim()) : null;
    return v ? { version: v[1], source: file } : undefined;
  } catch {
    return undefined;
  }
}

/**
 * The Node.js the agent runs on: the version-manager tree its CLI sits in
 * (the same on local and remote scans), else — locally — the `node` on PATH
 * (the scanned host's, not necessarily the one running VASO). A snapshot
 * collects no `node --version`, so a CLI outside a version manager is unknown.
 */
async function agentNodeVersion(installation: AgentInstallation, fs: FSProvider): Promise<{ version: string; source: string } | undefined> {
  const fromPath = installation.cliBinary ? MANAGER_VERSION.exec(installation.cliBinary) : null;
  if (fromPath) return { version: fromPath[1], source: installation.cliBinary! };
  const volta = installation.cliBinary ? await voltaNodeVersion(installation.cliBinary, fs) : undefined;
  if (volta) return volta;
  if (fs.kind === 'snapshot') return undefined;
  try {
    const out = fs.execSync('node', ['--version'], { timeout: 5000 }).trim();
    const m = /^v?(\d+\.\d+\.\d+)/.exec(out);
    return m ? { version: m[1], source: '`node` on PATH' } : undefined;
  } catch {
    return undefined;
  }
}

export const cfg011 = defineCheck({
  id: 'CFG-011',
  name: 'Node.js CVE-2026-21636',
  category: 'config',
  severity: 'warning',
  description: 'Check if the Node.js runtime of a Node-based agent is vulnerable to CVE-2026-21636 (permission-model bypass via Unix domain sockets, Node.js 25.0–25.2)',
  // The frameworks that run on Node.js (Lyrie runs on Bun, Atomic Agent is a
  // single executable with its own runtime, the rest are Go/Rust/Python)
  supportedAgents: ['openclaw', 'nanoclaw', 'nemoclaw'],

  async run(ctx, h) {
    const runtime = await agentNodeVersion(ctx.installation, ctx.fs);
    if (!runtime) {
      return h.passed(ctx.fs.kind === 'snapshot'
        ? 'Not checked on remote/snapshot scans — the scanned host\'s Node.js version is not collected'
        : 'Could not determine the agent\'s Node.js version');
    }
    const [major, minor] = runtime.version.split('.').map(n => parseInt(n, 10));
    const vulnerable = major === AFFECTED.major && minor < AFFECTED.fixedMinor;
    return h.result({
      passed: !vulnerable,
      message: vulnerable
        ? `Node.js v${runtime.version} (${runtime.source}) is vulnerable to CVE-2026-21636 — with --permission, Unix socket connections bypass the network restriction; update to 25.3.0 or later`
        : `Node.js v${runtime.version} (${runtime.source}) is not affected by CVE-2026-21636`,
      evidence: vulnerable ? [{ file: runtime.source.startsWith('/') ? runtime.source : '<node on PATH>', detail: `Node.js v${runtime.version}; affected 25.0.0–25.2.x, fixed in 25.3.0` }] : undefined,
    });
  },
});
