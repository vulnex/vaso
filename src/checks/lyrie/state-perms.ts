import type { Evidence } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { queryPermissions } from '../../core/permissions.js';

/**
 * World (other-user) access to a Lyrie state file. Group bits alone are not
 * reported: on user-private-group systems the group is the owner, and Lyrie
 * creates its state dirs with the default umask (e.g. 0775/0664).
 * Returns an evidence item, or undefined when the path is absent, private,
 * or its permissions cannot be evaluated on this platform.
 */
export async function worldAccessEvidence(
  fs: FSProvider,
  path: string,
  what: string,
): Promise<Evidence | undefined> {
  try {
    if (!(await fs.access(path))) return undefined;
    const perms = await queryPermissions(fs, path);
    if (perms === 'unsupported') return undefined;
    if (!perms.worldRead && !perms.worldWrite) return undefined;
    const access = perms.worldWrite ? 'readable and writable' : 'readable';
    return {
      file: path,
      snippet: perms.description,
      detail: `${what} is ${access} by any local user`,
    };
  } catch {
    return undefined;
  }
}
