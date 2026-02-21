#!/usr/bin/env node
/**
 * Sign an IOC feed JSON file with an Ed25519 private key.
 *
 * Usage: node scripts/sign-feed.mjs <feed.json> <private-key.pem>
 *
 * Produces: <feed.json>.sig (base64-encoded 64-byte Ed25519 signature)
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { sign, createPrivateKey } from 'node:crypto';

const [,, feedPath, keyPath] = process.argv;

if (!feedPath || !keyPath) {
  console.error('Usage: node scripts/sign-feed.mjs <feed.json> <private-key.pem>');
  process.exit(1);
}

const feedBytes = readFileSync(feedPath);
const privateKeyPem = readFileSync(keyPath, 'utf-8');
const privateKey = createPrivateKey(privateKeyPem);

const signature = sign(null, feedBytes, privateKey);
const sigBase64 = signature.toString('base64');

const sigPath = feedPath + '.sig';
writeFileSync(sigPath, sigBase64);

console.log(`Signed ${feedPath} → ${sigPath}`);
console.log(`Signature (${signature.length} bytes): ${sigBase64}`);
