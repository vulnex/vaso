import { join } from 'node:path';

/**
 * Package roots of a legacy (early 2026) npm-global NemoClaw install, in
 * lookup order. Shared by the checks that read its bundled blueprint and
 * plugin manifest (CFG-018/019) and by the probe manifest, so a remote scan
 * collects exactly what a local one reads.
 */
export function nemoclawLegacyRoots(home: string): string[] {
  return [
    '/usr/local/lib/node_modules/nemoclaw',
    '/usr/lib/node_modules/nemoclaw',
    '/opt/homebrew/lib/node_modules/nemoclaw',
    join(home, '.npm-global', 'lib', 'node_modules', 'nemoclaw'),
  ];
}

/** Files of a blueprint directory the checks read. */
export const BLUEPRINT_FILES = ['blueprint.yaml', join('policies', 'openclaw-sandbox.yaml')];
/** Directories of a blueprint directory the checks list. */
export const BLUEPRINT_DIRS = ['', 'policies', join('policies', 'presets')];
/** The plugin manifest inside a legacy package root (CFG-019 version pin). */
export const PLUGIN_MANIFEST = join('nemoclaw', 'openclaw.plugin.json');
