import { describe, expect, it } from 'vitest';
import { isCredentialReference, isPathValue, isSecretReference } from './patterns.js';

describe('isPathValue / isCredentialReference — dt21 g8-F15', () => {
  it('reads paths as paths', () => {
    for (const p of ['/', '~/.ssh/id_rsa', '/home/u/.config/gcloud/creds.json', './secrets/token.txt', '../keys/deploy.pem', 'C:\\Users\\me\\key.pem',
      '/run/secrets/db_password', '/tmp/tmp.Xk3j9ZQwLp', '/Users/me/.keys/Xq7Lk2Pz9Rt4Vw8Y.pem', '/nix/store/0123456789abcdfghijklmnpqrsvwxyz-node/bin/node']) {
      expect(isPathValue(p), p).toBe(true);
      expect(isCredentialReference(p), p).toBe(true);
    }
  });

  it('reads base64 secrets that start with a slash as secrets', () => {
    for (const s of ['/Xq7Lk2Pz9Rt4Vw8Ym3Nb6Hc1Jd5Fg0Sa+Ke', './Hk4Lm8Np2Qr6St0Uv3Wx7Yz1Ab5Cd9Ef', '~/Gh5Ij9Kl3Mn7Op1Qr4St8Uv2Wx6Yz0Ab', '/K7MDENG/bPxRfiCYq9Zr2Lm7Vb3Xc9Zr2Lm7V']) {
      expect(isPathValue(s), s).toBe(false);
      expect(isSecretReference(s), s).toBe(false); // the probe's Go copy judges the same shape
      expect(isCredentialReference(s), s).toBe(false);
    }
  });

  it('keeps every other reference form', () => {
    for (const r of ['${GITHUB_TOKEN}', 'op://Private/GitHub/credential', 'service-account-key.json', 'production-us-east-2', 'Bearer ${TOKEN}']) {
      expect(isCredentialReference(r), r).toBe(true);
    }
  });
});
