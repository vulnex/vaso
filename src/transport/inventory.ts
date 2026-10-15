/**
 * YAML inventory file parser for multi-host scanning.
 *
 * Inventory format:
 *   hosts:
 *     - user: deploy
 *       host: 10.0.1.5
 *       port: 22
 *       label: prod-1
 *       identity: ~/.ssh/id_prod
 *       sudo: true
 *     - host: ops@10.0.1.6:2222   # user@host[:port], as with --host
 */

import { readFile } from 'node:fs/promises';
import { parse as parseYAML } from 'yaml';
import { parseSSHTarget, assertSSHTargetParts } from './ssh.js';
import type { SSHTarget } from './ssh.js';

interface InventoryFile {
  hosts: Array<{
    user?: string;
    host: string;
    port?: number;
    label?: string;
    identity?: string;
    sudo?: boolean;
  }>;
}

const INVENTORY_KEYS = new Set(['host', 'user', 'port', 'label', 'identity', 'sudo']);

/**
 * Parse a YAML inventory file and return an array of SSHTarget objects.
 */
export async function parseInventory(path: string): Promise<SSHTarget[]> {
  const raw = await readFile(path, 'utf-8');
  const doc = parseYAML(raw) as InventoryFile;

  if (!doc || !Array.isArray(doc.hosts)) {
    throw new Error(`Invalid inventory file "${path}": expected a "hosts" array`);
  }

  return doc.hosts.map((entry, idx) => {
    if (!entry || typeof entry !== 'object') {
      throw new Error(`Inventory entry #${idx + 1} must be a mapping with a "host" field`);
    }
    // A misspelt key (`sshKey:` for `identity:`) would otherwise be dropped
    // silently and the scan would run with a different key, user or port.
    const unknown = Object.keys(entry).filter((k) => !INVENTORY_KEYS.has(k));
    if (unknown.length > 0) {
      throw new Error(
        `Inventory entry #${idx + 1}: unknown field${unknown.length > 1 ? 's' : ''} ${unknown.map((k) => `"${k}"`).join(', ')} ` +
        `(expected ${[...INVENTORY_KEYS].join(', ')})`,
      );
    }
    if (!entry.host) {
      throw new Error(`Inventory entry #${idx + 1} missing required "host" field`);
    }
    // `host: user@host[:port]` is read like `--host`; it used to become
    // `root@user@host`, which ssh can only reject.
    let host = String(entry.host);
    let user = entry.user;
    let port = entry.port;
    if (host.includes('@')) {
      const parsed = parseSSHTarget(host);
      if (user !== undefined && user !== parsed.user) {
        throw new Error(`Inventory entry #${idx + 1}: host "${host}" names user "${parsed.user}" but "user" is "${user}"`);
      }
      if (port !== undefined && parsed.port !== 22 && port !== parsed.port) {
        throw new Error(`Inventory entry #${idx + 1}: host "${host}" names port ${parsed.port} but "port" is ${port}`);
      }
      host = parsed.host;
      user = parsed.user;
      port = port ?? parsed.port;
    }
    user = user ?? 'root';
    port = port ?? 22;
    assertSSHTargetParts(`inventory entry #${idx + 1}`, String(user), host, port);
    const defaultLabel = port === 22 ? `${user}@${host}` : `${user}@${host}:${port}`;
    return {
      user,
      host,
      port,
      label: entry.label ?? defaultLabel,
      identity: entry.identity,
      sudo: entry.sudo,
    };
  });
}
