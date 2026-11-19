import { dirname, extname, join, normalize, relative, sep } from 'node:path';

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
