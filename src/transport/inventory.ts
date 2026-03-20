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
 */

import { readFile } from 'node:fs/promises';
import { parse as parseYAML } from 'yaml';
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
    if (!entry.host) {
      throw new Error(`Inventory entry #${idx + 1} missing required "host" field`);
    }
    return {
      user: entry.user ?? 'root',
      host: entry.host,
      port: entry.port ?? 22,
      label: entry.label,
      identity: entry.identity,
      sudo: entry.sudo,
    };
  });
}
