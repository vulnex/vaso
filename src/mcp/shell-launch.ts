import { dirname, extname, isAbsolute, resolve } from 'node:path';

/**
 * The script a shell launcher starts: `exec node "$(dirname "$0")/real.js"`.
 * A server configured as `launch.sh` keeps its code in the file the launcher
 * hands to an interpreter; reading only the launcher analyzed none of it.
 */

const SHELL_EXTENSIONS = new Set(['.sh', '.bash', '.zsh', '.ksh', '.dash', '.command']);
const SHELL_SHEBANG = /^#![^\n]*\b(?:sh|bash|zsh|dash|ksh)\b/;

/** `$(dirname "$0")`, `$(cd "$(dirname "$0")" && pwd)`, `` `dirname $0` ``, `${0%/*}` (also via BASH_SOURCE). */
const SCRIPT_REF = String.raw`\$(?:0|\{0\}|\{BASH_SOURCE(?:\[0\])?\}|BASH_SOURCE)`;
const SCRIPT_DIR = new RegExp(
  [
    String.raw`\$\(\s*cd\s+"?\$\(\s*dirname\s+(?:--\s+)?"?${SCRIPT_REF}"?\s*\)"?\s*(?:&&|;)\s*pwd(?:\s+-P)?\s*\)`,
    String.raw`\$\(\s*dirname\s+(?:--\s+)?"?${SCRIPT_REF}"?\s*\)`,
    String.raw`\`dirname\s+(?:--\s+)?"?${SCRIPT_REF}"?\``,
    String.raw`\$\{0%/\*\}`,
  ].join('|'),
  'g',
);
const DIR_MARK = '\u0000DIR\u0000';
/** `exec node --flag x.js`, `/usr/bin/env python3 server.py` — the interpreter and the file it runs. */
const LAUNCH = /^(?:exec\s+)?(?:\S*\/)?(?:env\s+(?:-\S+\s+)*)?(?:node|nodejs|bun|tsx|ts-node|python(?:\d+(?:\.\d+)?)?)\s+(?:-\S+\s+)*(\S+)/;
const SCRIPT_TARGET = new Set(['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.py']);
const MAX_LINES = 200;

export function isShellScript(path: string, code: string): boolean {
  return SHELL_EXTENSIONS.has(extname(path).toLowerCase()) || SHELL_SHEBANG.test(code);
}

/** The file a shell launcher runs with node/python/…, resolved against the launcher's directory; undefined when none. */
export function shellLaunchTarget(launcher: string, code: string): string | undefined {
  if (!isShellScript(launcher, code)) return undefined;
  const dirVars = new Set<string>();
  for (const raw of code.split('\n').slice(0, MAX_LINES)) {
    let line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    line = line.replace(SCRIPT_DIR, DIR_MARK);
    // DIR="$(cd "$(dirname "$0")" && pwd)" — a variable holding the launcher's directory
    const assign = /^(?:export\s+|local\s+|readonly\s+)?([A-Za-z_]\w*)=["']?\u0000DIR\u0000["']?;?$/.exec(line);
    if (assign) {
      dirVars.add(assign[1]);
      continue;
    }
    for (const name of dirVars) line = line.split(`\${${name}}`).join(DIR_MARK).split(`$${name}`).join(DIR_MARK);
    const m = LAUNCH.exec(line.replace(/["']/g, ''));
    if (!m) continue;
    const target = m[1];
    if (!SCRIPT_TARGET.has(extname(target).toLowerCase()) || /\$/.test(target.replace(DIR_MARK, ''))) continue;
    const base = dirname(launcher);
    const path = target.split(DIR_MARK).join(base);
    return isAbsolute(path) ? resolve(path) : resolve(base, path);
  }
  return undefined;
}
