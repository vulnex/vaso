/**
 * Command stems that run whatever they are given, shared by the permission
 * checks that judge a saved or configured command allowance (GHC-002,
 * CUR-003, DEV-001): approving one of these for any arguments approves every
 * command. Kept in one place so `python3`, `/usr/bin/node` or `osascript`
 * count the same on every agent.
 */

/** Shells: `bash -c …` runs any script. */
export const SHELL_COMMANDS: ReadonlySet<string> = new Set([
  'bash', 'sh', 'zsh', 'fish', 'dash', 'ksh', 'pwsh', 'powershell', 'cmd',
]);

/** Interpreters and package runners: `python -c …`, `node -e …`, `npx <any package>`. */
export const INTERPRETER_COMMANDS: ReadonlySet<string> = new Set([
  'python', 'node', 'deno', 'bun', 'perl', 'ruby', 'php', 'osascript', 'npx', 'bunx', 'uvx',
]);

/** Wrappers that run the command after them: `sudo x`, `env x`, `xargs x`. */
export const WRAPPER_COMMANDS: ReadonlySet<string> = new Set([
  'sudo', 'su', 'doas', 'env', 'xargs', 'eval', 'exec', 'nohup', 'timeout', 'command',
]);

/** Versioned interpreter names map to their family: python3, python3.12 → python. */
export function commandFamily(cmd: string): string {
  return cmd.replace(/^(python|ruby|perl|php|node)\d+(?:\.\d+)*$/, '$1');
}

/** The family of a command word, path dropped: `/usr/bin/python3` → `python`. */
export function commandStem(word: string): string {
  return commandFamily((word.split(/[/\\]/).pop() ?? word).toLowerCase());
}
