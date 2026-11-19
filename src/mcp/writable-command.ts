import { dirname } from 'node:path';
import type { FSProvider } from '../core/fs-provider.js';
import { queryPermissions } from '../core/permissions.js';
import { uncollectedPath } from '../core/probe-coverage.js';

/** Where any local user can replace an MCP server's command before it launches. */
export type WritableCommandPath =
  | { kind: 'binary'; path: string; octal?: string }
  | { kind: 'directory'; path: string; octal?: string };

/**
 * An absolute MCP command that is world-writable, or that sits in a
 * world-writable directory (anyone can swap it). `uncollected`: on a
 * snapshot, the command is outside what the probe collected — unknown, not
 * safe. A remote scan answers like a local one: the probe stats a command a
 * config names and records the modes of its parent directories.
 */
export async function worldWritableCommandPath(fs: FSProvider, command: string): Promise<WritableCommandPath | 'uncollected' | undefined> {
  try {
    const perms = await queryPermissions(fs, command);
    if (perms !== 'unsupported' && perms.worldWrite) return { kind: 'binary', path: command, octal: perms.octal };
  } catch {
    return (await uncollectedPath(fs, command)) ? 'uncollected' : undefined;
  }
  try {
    const parent = dirname(command);
    const perms = await queryPermissions(fs, parent);
    if (perms !== 'unsupported' && perms.worldWrite) return { kind: 'directory', path: parent, octal: perms.octal };
  } catch {
    // parent mode unknown: nothing to report
  }
  return undefined;
}
