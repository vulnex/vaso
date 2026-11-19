import { basename, dirname, extname, join, normalize, relative, sep } from 'node:path';

/**
 * Which files of a skill tree the skill and IOC checks read, beyond the walk
 * itself. Shared with the remote probe: SKILL_ASSET_EXTENSIONS mirrors
 * metadataOnlyExtensions minus skillBinaryExtensions in probe/collector.go,
 * and VENDOR_REFERENCE mirrors vendorReference in probe/skill_refs.go (both
 * kept equal by Go tests), so a remote scan reads the files a local one does.
 */

/**
 * Images, fonts, media, archives and other assets: no skill check reads them
 * as text, and the probe ships them as metadata only. Compiled helpers
 * (BINARY_EXTENSIONS) are not among them — IOC-003/007 read those.
 */
export const SKILL_ASSET_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.bmp',
  '.woff', '.woff2', '.ttf', '.otf', '.eot',
  '.mp3', '.mp4', '.mov', '.wav', '.webm',
  '.zip', '.gz', '.tgz', '.tar', '.jar', '.7z', '.pdf',
  '.wasm',
  '.pyc', '.db', '.sqlite', '.sqlite3',
  '.icns', '.tiff', '.tif', '.heic', '.avif',
  '.bz2', '.xz', '.zst', '.lz4', '.dmg', '.iso',
]);

/** An asset file by name (SKILL_ASSET_EXTENSIONS). */
export function isSkillAsset(name: string): boolean {
  return SKILL_ASSET_EXTENSIONS.has(extname(name).toLowerCase());
}

/**
 * A relative path in a SKILL.md that goes through a vendor-named folder
 * (`node node_modules/helper/index.js`, `bash .cache/run.sh`,
 * `python3 venv/bin/sync.py`): the walks skip those folders, so the file the
 * skill runs from one is read by name. The token starts after whitespace,
 * a quote, a backtick, `(`, `=` or `:` — never after `/` or `~` (an absolute
 * or home path is not the skill's own file). Group 1 is the path.
 */
export const VENDOR_REFERENCE = /(?:^|[\s`'"(=:])(?:\.\/)?((?:[\w.@+-]+\/)*(?:node_modules|\.git|\.next|\.cache|\.venv|venv|__pycache__)\/(?:[\w.@+-]+\/)*[\w.@+-]+)/g;

/** References read from one SKILL.md at most (the probe stops at the same count). */
export const MAX_VENDOR_REFERENCES = 64;

/**
 * Paths (relative to the SKILL.md's folder, normalized) of the vendor-folder
 * files a SKILL.md names, in order, without duplicates, at most
 * MAX_VENDOR_REFERENCES. A path with a `.` or `..` segment is dropped: it
 * names nothing inside the skill (or is written to look like it does).
 */
export function vendorReferences(text: string): string[] {
  const out: string[] = [];
  VENDOR_REFERENCE.lastIndex = 0;
  for (let m = VENDOR_REFERENCE.exec(text); m && out.length < MAX_VENDOR_REFERENCES; m = VENDOR_REFERENCE.exec(text)) {
    const ref = m[1];
    if (ref.split('/').some(s => s === '.' || s === '..')) continue;
    if (!out.includes(ref)) out.push(ref);
  }
  return out;
}

/**
 * Where a SKILL.md's vendor references lead, as paths under `root` — those
 * that stay inside it. `skillMd` is the SKILL.md's path under `root`.
 */
export function vendorReferencePaths(root: string, skillMd: string, text: string): string[] {
  const out: string[] = [];
  for (const ref of vendorReferences(text)) {
    const path = normalize(join(dirname(skillMd), ...ref.split('/')));
    const rel = relative(root, path);
    if (!rel || rel === '..' || rel.startsWith(`..${sep}`)) continue;
    out.push(path);
  }
  return out;
}

/**
 * A relative module a script loads: `require('../node_modules/helper')`,
 * `import x from './.cache/boot.js'`, `import('../venv/x.mjs')`. Group 1 or 2
 * is the specifier. (RE2 syntax: probe/skill_refs.go relativeLoad is the same
 * pattern, kept equal by a Go test.)
 */
export const RELATIVE_LOAD = /(?:\brequire\s*\(\s*|\bimport\s*\(\s*|\bfrom\s+|\bimport\s+)(?:'(\.\.?\/[^'\n]{1,256})'|"(\.\.?\/[^"\n]{1,256})")/g;

/**
 * A module path built from the script's own folder out of literal segments:
 * `path.join(__dirname, '..', '.cache', 'lib.js')`, `resolve(import.meta.dirname, '../x')`
 * (group 1: the segment list); `new URL('../.cache/x.js', import.meta.url)`
 * (group 2 or 3); Python's `os.path.join(os.path.dirname(__file__), '..', 'lib.py')`
 * (group 4) and `sys.path.insert(0, '<dir>')` / `.append('<dir>')` (group 5,
 * or a dirname join in group 6) — a folder the script then imports modules
 * from. Folded into relative paths (foldedLoads). RE2 syntax, kept equal to
 * probe/skill_refs.go builtLoad by a Go test.
 */
export const BUILT_LOAD = /\b(?:path\.)?(?:join|resolve)\s*\(\s*(?:__dirname|import\.meta\.dirname)\s*((?:,\s*(?:'[^'\n]*'|"[^"\n]*")\s*)+)\)|\bnew\s+URL\s*\(\s*(?:'([^'\n]{1,256})'|"([^"\n]{1,256})")\s*,\s*import\.meta\.url\s*\)|\bos\.path\.join\s*\(\s*os\.path\.dirname\s*\(\s*(?:os\.path\.(?:abspath|realpath)\s*\(\s*__file__\s*\)|__file__)\s*\)\s*((?:,\s*(?:'[^'\n]*'|"[^"\n]*")\s*)+)\)|\bsys\.path\.(?:insert\s*\(\s*\d+\s*,|append\s*\()\s*(?:'([^'\n]{1,256})'|"([^"\n]{1,256})"|os\.path\.join\s*\(\s*os\.path\.dirname\s*\(\s*(?:os\.path\.(?:abspath|realpath)\s*\(\s*__file__\s*\)|__file__)\s*\)\s*((?:,\s*(?:'[^'\n]*'|"[^"\n]*")\s*)+)\))/g;

/** A quoted literal in a BUILT_LOAD segment list. */
const SEGMENT = /'([^'\n]*)'|"([^"\n]*)"/g;

/** A Python import's top-level module name (`import x`, `import x.y as z, w`, `from x.y import z`). */
const PY_IMPORT = /^[ \t]*(?:import[ \t]+([\w.]+(?:[ \t]+as[ \t]+\w+)?(?:[ \t]*,[ \t]*[\w.]+(?:[ \t]+as[ \t]+\w+)?)*)|from[ \t]+(\w[\w.]*)[ \t]+import\b)/gm;

/** Files whose loads are followed: JavaScript and Python by extension, and package.json (its scripts' files). */
export const LOAD_SOURCE_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.mts', '.cts', '.py']);

/** Vendor-folder files a tree's loads add at most, and how many loads deep they are followed. */
export const MAX_VENDOR_LOADS = 64;
export const MAX_VENDOR_LOAD_DEPTH = 3;

/** A file whose loads are followed (LOAD_SOURCE_EXTENSIONS, or a package.json). */
export function isLoadSource(path: string): boolean {
  return basename(path) === 'package.json' || LOAD_SOURCE_EXTENSIONS.has(extname(path).toLowerCase());
}

/**
 * What a source file loads, as relative paths in its own folder's terms (in
 * order, no duplicates, at most MAX_VENDOR_REFERENCES): a package.json's
 * vendor references (`"start": "node .cache/boot.js"`), a script's relative
 * require/import specifiers.
 */
export function loadReferences(path: string, text: string): string[] {
  if (basename(path) === 'package.json') return vendorReferences(text);
  const found: Array<[number, string]> = [];
  RELATIVE_LOAD.lastIndex = 0;
  for (let m = RELATIVE_LOAD.exec(text); m; m = RELATIVE_LOAD.exec(text)) found.push([m.index, m[1] ?? m[2]]);
  const folded = foldedLoads(text);
  found.push(...folded.loads);
  // a sys.path folder: the modules the script imports from it
  if (folded.dirs.length > 0) {
    const modules = pythonImports(text);
    for (const [at, dir] of folded.dirs) {
      for (const mod of modules) found.push([at, `${dir}/${mod}.py`], [at, `${dir}/${mod}/__init__.py`]);
    }
  }
  // in source order (a stable sort keeps a sys.path folder's modules together)
  found.sort((a, b) => a[0] - b[0]);
  const out: string[] = [];
  for (const [, spec] of found) {
    if (out.length >= MAX_VENDOR_REFERENCES) break;
    if (!out.includes(spec)) out.push(spec);
  }
  return out;
}

/** A path from literal segments as a relative specifier, or undefined (an absolute or empty one). */
function relativeSpec(segs: string[]): string | undefined {
  const parts = segs.flatMap(s => s.split('/')).filter(s => s !== '' && s !== '.');
  if (parts.length === 0 || segs.length > 16 || segs.some(s => s.length > 256 || s.startsWith('/') || s.startsWith('~') || s.includes('\\') || s.includes(':'))) return undefined;
  return `./${parts.join('/')}`;
}

function segments(list: string): string[] {
  const out: string[] = [];
  SEGMENT.lastIndex = 0;
  for (let m = SEGMENT.exec(list); m; m = SEGMENT.exec(list)) out.push(m[1] ?? m[2]);
  return out;
}

/**
 * BUILT_LOAD matches as relative specifiers, with their offsets: module
 * paths (`loads`) and Python sys.path folders (`dirs`).
 */
export function foldedLoads(text: string): { loads: Array<[number, string]>; dirs: Array<[number, string]> } {
  const loads: Array<[number, string]> = [];
  const dirs: Array<[number, string]> = [];
  BUILT_LOAD.lastIndex = 0;
  for (let m = BUILT_LOAD.exec(text); m; m = BUILT_LOAD.exec(text)) {
    const list = m[1] ?? m[4] ?? m[7];
    const single = m[2] ?? m[3] ?? m[5] ?? m[6];
    const spec = relativeSpec(list !== undefined ? segments(list) : [single as string]);
    if (spec === undefined) continue;
    (m[5] !== undefined || m[6] !== undefined || m[7] !== undefined ? dirs : loads).push([m.index, spec]);
  }
  return { loads, dirs };
}

/** The top-level module names a Python file imports, in order, without duplicates. */
function pythonImports(text: string): string[] {
  const out: string[] = [];
  PY_IMPORT.lastIndex = 0;
  for (let m = PY_IMPORT.exec(text); m; m = PY_IMPORT.exec(text)) {
    const names = m[1] !== undefined ? m[1].split(',').map(n => n.trim().split(/[ \t]/)[0]) : [m[2]];
    for (const name of names) {
      const top = name.split('.')[0];
      if (top && !out.includes(top)) out.push(top);
    }
  }
  return out;
}

/**
 * Where Node looks for a module at `p` (no extension resolution beyond the
 * common ones): a folder's package.json `main` (and it with `.js` or as a
 * folder), then `p` itself, with `.js`/`.mjs`/`.cjs`, and its `index`
 * files. `main` is the folder's package.json's, when given.
 */
export function loadCandidates(p: string, main?: string): string[] {
  const out: string[] = [];
  if (main !== undefined) {
    const m = normalize(join(p, main));
    out.push(m, `${m}.js`, join(m, 'index.js'));
  }
  out.push(p, `${p}.js`, `${p}.mjs`, `${p}.cjs`, join(p, 'index.js'), join(p, 'index.mjs'), join(p, 'index.cjs'));
  return out;
}

/** The language a skill file runs as (by extension, interpreter or `#!` line). */
export type SkillLang = 'js' | 'python' | 'shell' | 'ruby' | 'perl' | 'php' | 'powershell' | 'lua' | 'batch';

/** The interpreter a `#!` line names (`#!/usr/bin/env -S node --flag`, `#!/bin/bash`). */
export function shebangLang(text: string): SkillLang | undefined {
  const m = /^#!\s*(\S+)(?:[ \t]+(.*))?/.exec(text.slice(0, 512));
  if (!m) return undefined;
  let prog = basename(m[1]);
  if (prog === 'env') {
    const words = (m[2] ?? '').split(/\s+/).filter(w => w && !w.startsWith('-') && !/^\w+=/.test(w));
    prog = words[0] ? basename(words[0]) : '';
  }
  return interpreterLang(prog);
}

function interpreterLang(prog: string): SkillLang | undefined {
  if (/^(?:node(?:js)?|bun|deno|tsx|ts-node)$/.test(prog)) return 'js';
  if (/^(?:python[\d.]*|pypy[\d.]*)$/.test(prog)) return 'python';
  if (/^(?:ba|z|k|da|a|fi)?sh$|^source$|^\.$/.test(prog)) return 'shell';
  if (prog === 'ruby') return 'ruby';
  if (prog === 'perl') return 'perl';
  if (/^php[\d.]*$/.test(prog)) return 'php';
  if (/^lua[\d.]*$/.test(prog)) return 'lua';
  if (/^(?:pwsh|powershell)$/i.test(prog)) return 'powershell';
  return undefined;
}

/**
 * `<interpreter> [options] <relative path>` in a SKILL.md: what it runs and
 * with what (`node scripts/tool.data`, `python3 -u scripts/helper.txt`,
 * `uv run scripts/x.py`, `bun run x.ts`, `bash "${CLAUDE_SKILL_DIR}/scripts/run.bin"`
 * — Claude Code's variable for the skill's own folder).
 */
const RUN_REFERENCE = /(?:^|[\s`'"(;&|$])((?:[\w./-]*\/)?(?:node(?:js)?|bun|deno|tsx|ts-node|python[\d.]*|pypy[\d.]*|bash|sh|zsh|ksh|dash|source|ruby|perl|php[\d.]*|lua[\d.]*|pwsh|powershell))(?:\s+(?:run|-[\w-]+(?:=\S*)?))*\s+["']?(?:\.\/|\$\{?CLAUDE_SKILL_DIR\}?\/)?((?:[\w.@+-]+\/)*[\w.@+-]+)/g;

/** A code fence's opening marker and info string (```` ```bash ````, `~~~ sh`). */
const FENCE_INFO = /^([ \t]*(?:`{3,}|~{3,}))[ \t]*[^\s`]*/gm;

/** The skill files a SKILL.md runs through an interpreter, and the language it runs them as. */
export function runReferences(skillMd: string, text: string): Array<[string, SkillLang]> {
  const out: Array<[string, SkillLang]> = [];
  // a fence's info string names the block's language, not a command: in
  // ```` ```bash\nnode x.dat ```` the command is `node x.dat`
  text = text.replace(FENCE_INFO, '$1');
  RUN_REFERENCE.lastIndex = 0;
  for (let m = RUN_REFERENCE.exec(text); m; m = RUN_REFERENCE.exec(text)) {
    const lang = interpreterLang(basename(m[1]));
    const ref = m[2];
    if (!lang || ref.split('/').some(s => s === '.' || s === '..')) continue;
    out.push([normalize(join(dirname(skillMd), ...ref.split('/'))), lang]);
  }
  return out;
}
