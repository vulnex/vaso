/**
 * Whether the command line turns colour off. chalk reads `--no-color` itself
 * but lets `FORCE_COLOR` override it (CI runners set FORCE_COLOR), so an
 * explicit `--no-color` — or `NO_COLOR` (no-color.org) — is applied here.
 * Only arguments before a `--` separator count.
 */
export function colorDisabled(argv: readonly string[], env: NodeJS.ProcessEnv): boolean {
  const end = argv.indexOf('--');
  const args = end === -1 ? argv : argv.slice(0, end);
  return args.includes('--no-color') || (env.NO_COLOR !== undefined && env.NO_COLOR !== '');
}
