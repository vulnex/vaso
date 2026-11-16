import { basename, join } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { accessibleByOthers, markUnreachable, queryPermissions, readableByOthers, writableByOthers } from '../../core/permissions.js';
import { configHoldsSecret, CREDENTIAL_FILE_NAME } from '../../core/secret-values.js';
import { ghc003 } from './ghc-003-plaintext-token.js';
import { restrictFilesToOwner } from '../../remediation/config-writer.js';
import { foreignAgentDir, foreignStoreTarget, storeHomeOf, withinDir as within, type ForeignReason } from '../../core/store-links.js';

const PROTECTED_FILES = [
  'config.json',
  'settings.json',
  'lsp-config.json',
  'providers.json',
  'command-history-state.json',
  'session-store.db',
];
/** Always private whatever they hold: the user's own history and session data. */
const PRIVATE_FILES = new Set(['command-history-state.json', 'session-store.db']);
/**
 * Directories of private files (config-dir reference): session transcripts,
 * command history (a directory since it replaced command-history-state.json),
 * and the MCP OAuth token / secret fallback stores used when no keychain is
 * available. Listed most sensitive first — tokens and secrets before history
 * and transcripts.
 */
export const PRIVATE_DIRS: Array<{ dir: string; what: string }> = [
  { dir: 'mcp-oauth-config', what: 'MCP OAuth token/registration file' },
  { dir: 'mcp-secrets', what: 'MCP secret fallback file' },
  { dir: 'command-history-state', what: 'Command history file' },
  { dir: 'session-state', what: 'Session transcript' },
];
const PROTECTED_DIRS = ['.', ...PRIVATE_DIRS.map(d => d.dir)];
/**
 * Open store files listed per store; the rest are counted in one line (all
 * are judged, and the fix changes all). Four stores of 40 plus the top-level
 * paths stay under the engine's evidence cap (MAX_EVIDENCE in core/engine.ts),
 * so no item is cut from the reports.
 */
const MAX_LISTED_PER_STORE = 40;
/** Files judged per store at most — a bound on a pathological history, far above a real one. */
const MAX_JUDGED_PER_STORE = 20_000;
/** Store links outside the store and the home listed at most; the rest are counted in one line. */
const MAX_LISTED_OUTSIDE = 10;

/** Where a store link leads: see ForeignReason; `file` — a store folder that is a link to a file in the home. */
type LinkKind = ForeignReason['why'] | 'file';

interface Findings {
  evidence: Evidence[];
  /** Paths found open — the listed ones plus those counted in a "+N more" line. */
  total: number;
  /** Store links leaving the store and the home, or folders linked into a sensitive location (judged apart). */
  outside: Evidence[];
  /** How many such links there are (`outside` lists at most MAX_LISTED_OUTSIDE, then a "+N more" line). */
  outsideTotal: number;
  /** Where they lead (the message names each kind present). */
  kinds: Set<LinkKind>;
  /** Store files a remote scan couldn't judge (the probe didn't collect their metadata). */
  unverified: string[];
  /** Stores with more files than MAX_JUDGED_PER_STORE: only that many were judged. */
  truncated: string[];
  /** The agent folder itself leads to a place that isn't the agent's: nothing behind it is judged. */
  agentLink?: ForeignReason;
  /** The agent folder resolves outside the home: vaso fix can't change it (it writes only where rollback can restore). */
  outsideHome?: boolean;
}

interface StoreLink {
  path: string;
  target: string;
  /** A folder link (not walked), and why. */
  folder?: ForeignReason;
  /** The store folder is a link to a file (or another non-folder): why it isn't the agent's (undefined: a file in the home), and its mode. */
  file?: { why?: ForeignReason; mode?: string };
  /** The store folder itself is the link (~/.copilot/session-state → ~/.aws). */
  self?: boolean;
}

interface StoreListing {
  files: string[];
  /** Links leaving the store and the home, or folders linked into a sensitive location, the home or a folder holding the store. */
  outside: StoreLink[];
  /** Linked subdirectories whose files a remote scan doesn't have (the probe doesn't follow links). */
  linkedDirs: string[];
  truncated: boolean;
  /** The store folder itself links to such a place: nothing in it is the agent's (not walked, its mode not judged). */
  foreignSelf?: boolean;
}

/** The home holding the store: the parent of ~/.copilot, else the scanning user's. */
function storeHome(ctx: ScanContext): string {
  return storeHomeOf(ctx.installation.installDir, ctx.fs.homedir());
}

/** `root` as written and resolved (a snapshot also gives the spelling the probe recorded for it). */
async function spellingsOf(ctx: ScanContext, root: string): Promise<string[]> {
  const out = [root];
  try {
    const real = await ctx.fs.realpath(root);
    if (typeof real === 'string' && real !== root) out.push(real);
  } catch {
    // the written spelling only
  }
  // A snapshot holds no link for a linked home: the probe records where it resolves
  const recorded = (ctx.fs as { resolvedDir?(p: string): string }).resolvedDir?.(root);
  if (recorded !== undefined && !out.includes(recorded)) out.push(recorded);
  return out;
}

/** The snapshot holds an entry under `dir` (the probe followed the link to it). */
async function snapshotHolds(ctx: ScanContext, dir: string): Promise<boolean> {
  try {
    return (await ctx.fs.readdirEntries(dir)).length > 0;
  } catch {
    return false;
  }
}

/** What a symlink resolves to: a directory or a file (with its real path when known), or nothing (dangling). */
async function linkTarget(ctx: ScanContext, path: string): Promise<{ kind: 'dir' | 'file'; target?: string } | undefined> {
  let st: Awaited<ReturnType<ScanContext['fs']['stat']>>;
  try {
    st = await ctx.fs.stat(path);
  } catch {
    return undefined;
  }
  const kind = st.isDirectory() ? 'dir' : 'file';
  let target: string | undefined;
  try {
    target = await ctx.fs.realpath(path);
  } catch {
    target = undefined;
  }
  return { kind, target };
}

/**
 * A store's files: its entries and the entries of its subdirectories, one
 * level deep (session-state/<session id>/events.jsonl). Symlinks count — a
 * store file's data is wherever it points, and its mode is the target's; a
 * link to a directory is a subdirectory like any other (its own mode is not a
 * store file's). A link leaving the store and the home for a file that isn't
 * a credential store (`mcp-secrets/x.json → /etc/hosts`) is set apart: its
 * mode says nothing about the agent's data. So is a linked folder that leaves
 * the home, lands in a sensitive location (`session-state/abc → ~/.aws`) or
 * holds the store itself: it is not walked — its files aren't the agent's,
 * and the fix must not change them.
 */
async function storeFiles(ctx: ScanContext, storeDir: string): Promise<StoreListing> {
  const files: string[] = [];
  const outside: StoreListing['outside'] = [];
  const linkedDirs: string[] = [];
  // Both spellings of the home and the store: a target is compared by its real path
  const homeRoots = await spellingsOf(ctx, storeHome(ctx));
  const storeRoots = await spellingsOf(ctx, ctx.installation.installDir);
  const roots = [...homeRoots, ...storeRoots];
  const full = () => files.length > MAX_JUDGED_PER_STORE;
  const add = (path: string) => { if (!full()) files.push(path); };
  const addLink = (path: string, target: string | undefined) => {
    if (target !== undefined && !roots.some(root => within(target, root)) && !CREDENTIAL_FILE_NAME.test(basename(target))) {
      outside.push({ path, target });
    } else {
      add(path);
    }
  };
  /**
   * Why a linked folder resolving to `target` isn't walked: it lands in a
   * sensitive location, leaves the home (a folder above it too), is the home,
   * or holds the store; undefined for an ordinary folder of the home. The
   * probe applies the same rule (privateStores) and ships nothing behind one.
   */
  const foreignDir = (target: string): ForeignReason | undefined =>
    foreignStoreTarget(target, { homeRoots, storeRoots, storeDir });

  // The store folder itself a link to such a place: its files aren't the
  // agent's — not walked, and the fix changes nothing behind it
  let selfLink = false;
  try {
    await ctx.fs.readlink(storeDir);
    selfLink = true;
  } catch {
    // not a link (or a provider that can't tell)
  }
  if (selfLink) {
    const link = await linkTarget(ctx, storeDir);
    const folder = link?.kind === 'dir' && link.target !== undefined ? foreignDir(link.target) : undefined;
    if (link?.target !== undefined && folder !== undefined) {
      return { files: [], outside: [{ path: storeDir, target: link.target, folder, self: true }], linkedDirs: [], truncated: false, foreignSelf: true };
    }
    // A store folder that is a link to a file is no store of the agent's:
    // reported as a link (with its target's mode), never walked or changed
    if (link?.kind === 'file') {
      const target = link.target ?? await ctx.fs.readlink(storeDir).catch(() => '?');
      let mode: string | undefined;
      try {
        const perms = await queryPermissions(ctx.fs, storeDir);
        if (perms !== 'unsupported') mode = perms.octal;
      } catch {
        // mode unknown
      }
      const why = link.target !== undefined ? foreignStoreTarget(link.target, { homeRoots, storeRoots, storeDir }) : undefined;
      return { files: [], outside: [{ path: storeDir, target, file: { why, mode }, self: true }], linkedDirs: [], truncated: false, foreignSelf: true };
    }
  }

  const subdirFiles = async (dir: string) => {
    let entries: Awaited<ReturnType<ScanContext['fs']['readdirEntries']>>;
    try {
      entries = await ctx.fs.readdirEntries(dir);
    } catch {
      return;
    }
    for (const sub of entries) {
      if (full()) return;
      const path = join(dir, sub.name);
      if (sub.isFile) {
        add(path);
      } else if (sub.isSymbolicLink) {
        const link = await linkTarget(ctx, path);
        // a directory two levels down is not judged (like a real one)
        if (link?.kind === 'file') addLink(path, link.target);
        else if (!link) add(path);
      }
    }
  };

  for (const e of await ctx.fs.readdirEntries(storeDir)) {
    const path = join(storeDir, e.name);
    if (e.isFile) {
      add(path);
    } else if (e.isSymbolicLink) {
      const link = await linkTarget(ctx, path);
      const folder = link?.kind === 'dir' && link.target !== undefined ? foreignDir(link.target) : undefined;
      if (link?.target !== undefined && folder !== undefined) {
        outside.push({ path, target: link.target, folder });
      } else if (link?.kind === 'dir') {
        // The probe records the files behind a link that stays inside the
        // home and outside credential stores (probes newer than 1.4.1); for any other, a
        // remote scan has the link, not the files behind it
        if (ctx.fs.kind === 'snapshot' && !(await snapshotHolds(ctx, path))) linkedDirs.push(path);
        else await subdirFiles(path);
      } else if (link?.kind === 'file') {
        addLink(path, link.target);
      } else {
        add(path);
      }
    } else if (e.isDirectory) {
      await subdirFiles(path);
    }
    if (full()) break;
  }
  return { files: files.slice(0, MAX_JUDGED_PER_STORE), outside, linkedDirs, truncated: files.length > MAX_JUDGED_PER_STORE };
}

/** The paths readable or writable beyond the owner; `maxListed` caps the files listed per private store. */
async function findings(ctx: ScanContext, maxListed: number): Promise<Findings> {
  const evidence: Evidence[] = [];
  const outside: Evidence[] = [];
  let outsideTotal = 0;
  const kinds: Findings['kinds'] = new Set();
  const unverified: string[] = [];
  const truncated: string[] = [];
  let total = 0;

  // Listed first: a store folder linked out of the store has no mode of the agent's to judge
  // The agent folder itself (or a folder above it) linked to a place that
  // isn't the agent's: nothing behind it is judged — reported once, as a link
  const installDir = ctx.installation.installDir;
  const homeRoots = await spellingsOf(ctx, storeHome(ctx));
  let agentReal: string | undefined;
  try {
    agentReal = await ctx.fs.realpath(installDir);
  } catch {
    // judged as written
  }
  const agentLink = agentReal !== undefined ? foreignAgentDir(installDir, agentReal, homeRoots) : undefined;
  if (agentLink) {
    kinds.add(agentLink.why);
    return {
      evidence, total, unverified, truncated, kinds, agentLink, outsideTotal: 1,
      outside: [{
        file: installDir,
        snippet: `-> ${agentReal}`,
        detail: `${installDir} is a link to the folder ${agentReal}${placeText(agentLink)} — its session, history and MCP secret stores there are not the agent's own files (neither checked nor changed here), but the agent reads and writes through it`,
      }],
    };
  }
  // A folder relocated outside the home (COPILOT_HOME=/data/copilot) is the
  // agent's own, but vaso fix changes nothing there: it writes only inside
  // the home, where its backups can restore what it changed
  const outsideHome = !homeRoots.some(root => within(agentReal ?? installDir, root));

  const listings = new Map<string, StoreListing>();
  for (const { dir } of PRIVATE_DIRS) {
    try {
      listings.set(dir, await storeFiles(ctx, join(ctx.installation.installDir, dir)));
    } catch {
      // store absent
    }
  }

  for (const subdir of PROTECTED_DIRS) {
    const path = subdir === '.' ? ctx.installation.installDir : join(ctx.installation.installDir, subdir);
    if (listings.get(subdir)?.foreignSelf) continue;
    if (!(await ctx.fs.access(path))) continue;
    try {
      const perms = await queryPermissions(ctx.fs, path);
      if (perms !== 'unsupported' && writableByOthers(perms)) {
        evidence.push({
          file: path,
          snippet: `mode 0${perms.octal}`,
          detail: `${subdir === '.' ? '~/.copilot/' : `${subdir}/`} is writable by group/other — its auth and session files can be replaced`,
        });
        total++;
      }
    } catch {}
  }

  for (const filename of PROTECTED_FILES) {
    const filePath = join(ctx.installation.installDir, filename);
    if (!(await ctx.fs.access(filePath))) continue;
    if (!PRIVATE_FILES.has(filename)) {
      const config = ctx.configs.find(c => c.filePath === filePath);
      if (config && !configHoldsSecret(config.data) && (await ghc003.run({ ...ctx, configs: [config] })).passed) continue;
    }
    try {
      const perms = await queryPermissions(ctx.fs, filePath);
      if (perms !== 'unsupported' && accessibleByOthers(perms)) {
        evidence.push({
          file: filePath,
          snippet: `mode 0${perms.octal}`,
          detail: `${filename} is readable or writable by group/other`,
        });
        total++;
      }
    } catch {}
  }

  for (const { dir, what } of PRIVATE_DIRS) {
    const storeDir = join(ctx.installation.installDir, dir);
    const listing = listings.get(dir);
    if (!listing) continue; // store absent
    if (listing.truncated) truncated.push(storeDir);
    const open: Evidence[] = [];
    let missing = 0;
    for (const filePath of listing.files) {
      let perms: Awaited<ReturnType<typeof queryPermissions>>;
      try {
        perms = await queryPermissions(ctx.fs, filePath);
      } catch {
        if (ctx.fs.kind === 'snapshot') missing++;
        continue;
      }
      if (perms !== 'unsupported' && readableByOthers(perms)) {
        open.push({ file: filePath, snippet: `mode 0${perms.octal}`, detail: `${what} readable by group/other` });
      }
    }
    if (missing > 0) unverified.push(`${missing} file(s) in ${dir}/`);
    if (listing.linkedDirs.length > 0) {
      unverified.push(`the files behind ${listing.linkedDirs.length} linked folder(s) in ${dir}/ (${listing.linkedDirs.map(p => basename(p)).join(', ')})`);
    }
    for (const { path, target, folder, file, self } of listing.outside) {
      outsideTotal++;
      kinds.add(file ? (file.why?.why ?? 'file') : (folder?.why ?? 'outside'));
      if (outside.length >= MAX_LISTED_OUTSIDE) continue;
      const where = folder ? placeText(folder) : '';
      outside.push(file
        ? {
          file: path,
          snippet: `-> ${target}${file.mode ? ` mode 0${file.mode}` : ''}`,
          detail: `${dir}/ itself is a link to the file ${target}${file.why ? placeText(file.why) : ', in the home'}, not a folder — not the agent's own store (neither checked nor changed here), but the agent reads and writes through it`,
        }
        : {
          file: path,
          snippet: `-> ${target}`,
          detail: self
            ? `${dir}/ itself is a link to the folder ${target}${where} — not the agent's own files (neither checked nor changed here), but the agent reads and writes through it`
            : folder
              ? `${dir}/ holds a link to the folder ${target}${where} — not the agent's own files (neither checked nor changed here), but the agent reads and writes through it`
              : `${what} is a link to ${target}, outside the store and the home — not the agent's own file, but the agent reads and writes through it`,
        });
    }
    // Which files are listed must not depend on walk order (local vs snapshot)
    open.sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : 0));
    total += open.length;
    evidence.push(...open.slice(0, maxListed));
    if (open.length > maxListed) {
      evidence.push({
        file: storeDir,
        snippet: `+${open.length - maxListed} more file(s)`,
        detail: `${open.length - maxListed} more ${what.toLowerCase()}(s) in ${dir}/ readable by group/other (not listed)`,
      });
    }
  }

  if (outsideTotal > outside.length) {
    outside.push({
      file: ctx.installation.installDir,
      snippet: `+${outsideTotal - outside.length} more link(s)`,
      detail: `${outsideTotal - outside.length} more store link(s) ${linkPlaces(kinds)} (not listed)`,
    });
  }
  return { evidence, total, outside, outsideTotal, kinds, unverified, truncated, outsideHome };
}

/** Where a link leads, after its target: " (AWS credentials (~/.aws))", " — the home itself", … */
function placeText(reason: ForeignReason): string {
  return reason.why === 'sensitive' ? ` (${reason.label})`
    : reason.why === 'home' ? ' — the home itself'
      : reason.why === 'store' ? ' — a folder holding the store'
        : ', outside the store and the home';
}

/** Where the agent folder's link leads, for the message. */
function agentPlace(reason: ForeignReason): string {
  return reason.why === 'sensitive' ? `into a sensitive location (${reason.label})`
    : reason.why === 'home' ? 'to the home or a folder above it'
      : 'out of the home';
}

/** Where store links lead, for the message: "point outside the store and the home or into a sensitive location". */
function linkPlaces(kinds: Findings['kinds']): string {
  const places = [
    ...(kinds.has('outside') ? ['outside the store and the home'] : []),
    ...(kinds.has('sensitive') ? ['into a sensitive location'] : []),
    ...(kinds.has('home') ? ['to the home itself'] : []),
    ...(kinds.has('store') ? ['to a folder holding the store'] : []),
    ...(kinds.has('file') ? ['to a file instead of a folder'] : []),
  ];
  return `point ${places.join(' or ')}`;
}

export const ghc001 = defineCheck({
  id: 'GHC-001',
  name: 'Copilot CLI Directory Permissions',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Verify ~/.copilot/, its session/history/MCP-secret stores, session-store.db and credential files (incl. providers.json) are not group/world readable',
  supportedAgents: ['copilot-cli'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    if (ctx.installation.profile === 'project') return h.passed('Project configuration — ~/.copilot permissions are checked on the user install');
    const { evidence, total, outside, outsideTotal, kinds, unverified, truncated, agentLink, outsideHome } = await findings(ctx, MAX_LISTED_PER_STORE);
    if (agentLink) {
      return h.result({
        passed: false,
        severity: 'warning',
        message: `Copilot CLI folder ${ctx.installation.installDir} is a link ${agentPlace(agentLink)} — its private stores there are not checked`,
        evidence: outside,
        fixable: false,
        fixDescription: 'Keep the Copilot folder in the home (or set COPILOT_HOME to the folder you want) unless you linked it on purpose',
      });
    }
    await markUnreachable(ctx.fs, evidence);
    const notes = [
      ...(unverified.length > 0 ? [`${unverified.join(', ')} not verified — the probe didn't collect them (checked on local scans)`] : []),
      ...(truncated.length > 0 ? [`only the first ${MAX_JUDGED_PER_STORE} files of ${truncated.join(', ')} checked`] : []),
    ];
    const noteText = notes.length > 0 ? `; ${notes.join('; ')}` : '';
    const outsideText = outsideTotal > 0
      ? `${outsideTotal} store link(s) ${linkPlaces(kinds)}`
      : '';
    if (evidence.length === 0 && outside.length > 0) {
      // Not an exposure of the agent's data: worth a look, nothing to chmod
      return h.result({
        passed: false,
        severity: 'warning',
        message: `Copilot CLI directory and store files are owner-only, but ${outsideText}${noteText}`,
        evidence: outside,
        fixable: false,
        fixDescription: 'Replace the link with a file of the agent\'s own (or remove it) unless you made it on purpose',
      });
    }
    const result = h.fromEvidence(evidence, {
      // Something the probe didn't collect: say so first, like other checks' "Not verified"
      passed: unverified.length > 0
        ? `Not verified — ${notes.join('; ')}; the rest of ~/.copilot is owner-only`
        : `Copilot CLI directory and config files are owner-only${noteText}`,
      failed: () => `Found ${total} Copilot CLI path(s) with overly permissive mode${outsideText ? `; ${outsideText}` : ''}${noteText}${outsideHome ? `; not changed by vaso fix: ${ctx.installation.installDir} is outside the home` : ''}`,
      fixable: !outsideHome,
      fixDescription: outsideHome
        ? `Remove group/other access yourself: \`chmod -R go-rwx ${ctx.installation.installDir}\` — the folder is outside the home, and vaso fix changes files only inside it (where it can restore them)`
        : 'Remove group/other access (chmod go-rwx) from the listed ~/.copilot paths — `chmod -R go-rwx ~/.copilot` covers everything',
    });
    return outside.length > 0 ? { ...result, evidence: [...(result.evidence ?? []), ...outside] } : result;
  },

  async fix(ctx) {
    if (ctx.installation.profile === 'project') return { checkId: 'GHC-001', applied: false, alreadyDone: true, message: 'Project configuration — nothing to change' };
    return restrictFilesToOwner('GHC-001', (await findings(ctx, Infinity)).evidence.flatMap(e => (e.file ? [e.file] : [])));
  },
});
