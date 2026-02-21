#!/usr/bin/env node
/**
 * Generate an Ed25519 keypair for signing IOC threat feeds.
 *
 * Usage: node scripts/generate-feed-keypair.mjs
 *
 * Outputs:
 *   feed-signing-key.pem     — Private key (KEEP SECRET, never commit)
 *   feed-signing-key.pub.pem — Public key (embed in src/ioc/public-key.ts)
 */

import { generateKeyPairSync } from 'node:crypto';
import { writeFileSync } from 'node:fs';

const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

writeFileSync('feed-signing-key.pem', privateKey, { mode: 0o600 });
writeFileSync('feed-signing-key.pub.pem', publicKey);

console.log('Generated Ed25519 keypair:');
console.log('  Private: feed-signing-key.pem (KEEP SECRET)');
console.log('  Public:  feed-signing-key.pub.pem');
console.log('');
console.log('Embed the public key in src/ioc/public-key.ts:');
console.log(publicKey);
