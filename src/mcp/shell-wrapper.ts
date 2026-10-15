import { commandName, windowsCmdTarget } from './package-pin.js';

/**
 * Whether `command args…` runs its arguments through a shell interpreter
 * (`bash -c "…"`): argv injection becomes shell injection. Covers combined
 * flags (`-lc`, `-ec`, `-xc`), `/usr/bin/env [-S] bash -c`, `cmd /c`, and
 * PowerShell `-Command`/`-c`. Returns the shell's name, or undefined.
 */
export function shellCommandWrapper(command: unknown, rawArgs: unknown): string | undefined {
  if (typeof command !== 'string' || !command) return undefined;
  let args = Array.isArray(rawArgs) ? rawArgs.filter((a): a is string => typeof a === 'string') : [];
  let shell = commandName(command).toLowerCase();

  // `env [VAR=x …] [-S] bash -c …`
  if (shell === 'env') {
    const at = args.findIndex(a => !a.startsWith('-') && !/^\w+=/.test(a));
    if (at < 0) return undefined;
    shell = commandName(args[at]).toLowerCase();
    args = args.slice(at + 1);
  }

  if (POSIX_SHELLS.has(shell)) {
    // Options before the script: a short-flag cluster containing c (-c, -lc, -ec, -cu)
    for (const a of args) {
      if (!a.startsWith('-') || a === '-' || a === '--') break;
      if (/^-[a-zA-Z]*c[a-zA-Z]*$/.test(a)) return shell;
      if (a === '-o' || a === '+o' || a === '--rcfile' || a === '--init-file') continue;
    }
    return undefined;
  }
  if (shell === 'cmd' && args.some(a => /^\/[ck]$/i.test(a))) {
    // `cmd /c npx -y pkg` is how MCP servers are documented to start on
    // Windows: a program invocation, not a shell script. Only cmd syntax
    // (&, |, <, >, ^) or an unparseable wrapped command makes it one.
    const target = windowsCmdTarget(command, args);
    return target?.plain ? undefined : shell;
  }
  if ((shell === 'powershell' || shell === 'pwsh') && args.some(a => /^-(?:c|command|encodedcommand|e|ec)$/i.test(a))) return shell;
  return undefined;
}

/** How the wrapper is written for `shell`, for messages: `bash -c`, `cmd /c` (or `/k`), `powershell -Command`. */
export function shellInvocation(shell: string, args: readonly string[] = []): string {
  if (shell === 'cmd') return args.some(a => /^\/k$/i.test(a)) ? 'cmd /k' : 'cmd /c';
  if (shell === 'powershell' || shell === 'pwsh') return `${shell} -Command`;
  return `${shell} -c`;
}

const POSIX_SHELLS = new Set(['sh', 'bash', 'zsh', 'fish', 'dash', 'ksh', 'mksh', 'ash', 'busybox']);
