import { describe, it, expect } from 'vitest';
import { isKnownSecretValue, isSecretNamedValue } from './secret-values.js';

// dt21 g6-F8: a Microsoft identity authority URL names the tenant (public);
// it is not a credential under any name.
const TENANT = '72f988bf-86f1-41af-91ab-2d7cd011db47';

describe('identity authority URLs (dt21 g6-F8)', () => {
  it('does not treat the tenant id in an authority URL as a secret', () => {
    for (const url of [
      `https://login.microsoftonline.com/${TENANT}/v2.0`,
      `https://login.microsoftonline.us/${TENANT}`,
      `https://sts.windows.net/${TENANT}/`,
    ]) {
      expect(isKnownSecretValue(url), url).toBe(false);
      expect(isSecretNamedValue('AZURE_AUTHORITY', url), url).toBe(false);
      expect(isSecretNamedValue('AZURE_AUTH_URL', url), url).toBe(false);
    }
  });

  it('still reports a credential carried in such a URL, and a token in a capability URL', () => {
    expect(isKnownSecretValue(`https://login.microsoftonline.com/${TENANT}/oauth2?client_secret=Zq8wLm3vT9kR2pN7aY4cB6dF`)).toBe(true);
    expect(isKnownSecretValue('https://actions.zapier.com/mcp/sk-ak-Zq8wLm3vT9kR2pN7aY4cB6dFhJ2k/sse')).toBe(true);
  });
});

describe('AWS temporary key ids are exactly ASIA + 16', () => {
  it('matches the 20-character id, not a longer all-caps word', () => {
    expect(isKnownSecretValue('ASIAQ7RT2MZ9KLP4WN1X')).toBe(true);
    expect(isKnownSecretValue('ASIAPACIFICNORTHEAST1')).toBe(false);
  });
});
