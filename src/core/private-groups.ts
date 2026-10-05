/**
 * User-private groups (UPG). Debian/Ubuntu and most Linux distributions give
 * every user a group of the same name that only that user is in, and default
 * to umask 002 — so their files are 664 and dirs 775. Group access to such a
 * file reaches nobody but its owner, yet it was reported as exposure (several
 * agent checks rate a group-readable credential file critical).
 *
 * A group is private to a user when the group has that user's name, exactly
 * one local account has it as primary group (that user), and it lists no
 * other members. Only local /etc files are read: a directory-service user
 * sharing the gid is not visible here, which is why the name must also match.
 */
export function parsePrivateGroups(passwd: string, group: string): Map<number, number> {
  const primary = new Map<number, { name: string; uid: number }[]>();
  for (const line of passwd.split('\n')) {
    const [name, , uid, gid] = line.split(':');
    if (!name || uid === undefined || gid === undefined || name.startsWith('#')) continue;
    const g = Number(gid);
    const u = Number(uid);
    if (!Number.isInteger(g) || !Number.isInteger(u)) continue;
    primary.set(g, [...(primary.get(g) ?? []), { name, uid: u }]);
  }

  const result = new Map<number, number>();
  for (const line of group.split('\n')) {
    const [name, , gid, members = ''] = line.split(':');
    if (!name || gid === undefined || name.startsWith('#')) continue;
    const g = Number(gid);
    const users = primary.get(g);
    if (!Number.isInteger(g) || users?.length !== 1) continue;
    const [user] = users;
    const listed = members.split(',').map(m => m.trim()).filter(m => m.length > 0);
    if (user.name === name && listed.every(m => m === user.name)) result.set(g, user.uid);
  }
  return result;
}
