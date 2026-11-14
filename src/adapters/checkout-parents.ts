/**
 * Common parent directories people clone into (one level below home), in
 * lower case: any spelling on disk matches (~/GitHub, ~/Projects, ~/SRC).
 */
export const CHECKOUT_PARENTS = [
  'src', 'code', 'projects', 'dev', 'developer', 'git', 'repos', 'workspace',
  'work', 'github',
];

/** Every-case glob for one name: `src` → `[sS][rR][cC]`. */
export function anyCaseGlob(name: string): string {
  return [...name].map(c => (c.toLowerCase() === c.toUpperCase() ? c : `[${c.toLowerCase()}${c.toUpperCase()}]`)).join('');
}

/**
 * `~/{<every-case parent>,…}` for probe globs. Each parent is an every-case
 * class: it matches any spelling, and the probe matches it against the
 * directory listing — a literal is stat'ed, and on a case-insensitive file
 * system `projects` would then also collect ~/Projects under the wrong case.
 */
export function checkoutParentsGlob(): string {
  return `~/{${CHECKOUT_PARENTS.map(anyCaseGlob).join(',')}}`;
}
