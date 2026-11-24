import { describe, it, expect } from 'vitest';
import { envSecretKeys } from './secret-values.js';
import { isDotenvReference } from '../core/patterns.js';

// dt25 g2-HA-3: python-dotenv (Hermes) and Node's dotenv parser (Atomic
// Agent) read a value literally, so a bare variable name or a profile-like
// word under a password key is the password — HM-002/AT-005 must see it.
describe('envSecretKeys: dotenv values are read literally', () => {
  it.each([
    ['EMAIL_PASSWORD', 'admin-2024'],
    ['DB_PASSWORD', 'MY_DB_PASS_2024'],
    ['API_TOKEN', 'production'],
    ['TELEGRAM_BOT_TOKEN', '123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11'],
  ])('%s=%s holds a secret', (key, value) => {
    expect(envSecretKeys({ [key]: value })).toEqual([key]);
  });

  it.each([
    ['OPENAI_API_KEY', ''],
    ['OPENAI_API_KEY', 'sk-...'],
    ['OPENAI_API_KEY', 'your-api-key-here'],
    ['OPENAI_API_KEY', '<your key>'],
    ['OPENAI_API_KEY', '${OPENAI_API_KEY}'], // python-dotenv expands it
    ['OPENAI_API_KEY', 'op://Private/OpenAI/credential'], // `op run --env-file`
    ['GOOGLE_KEY', '~/.config/gcloud/key.json'],
    ['SSH_KEY', 'id_ed25519.pem'],
  ])('%s=%s holds none', (key, value) => {
    expect(envSecretKeys({ [key]: value })).toEqual([]);
  });

  it('isDotenvReference keeps variable, manager and file references only', () => {
    expect(isDotenvReference('${DB_PASS}')).toBe(true);
    expect(isDotenvReference('"op://vault/item/field"')).toBe(true);
    expect(isDotenvReference('/run/secrets/db_password')).toBe(true);
    expect(isDotenvReference('DB_PASS')).toBe(false);
    expect(isDotenvReference('staging-eu')).toBe(false);
    expect(isDotenvReference('/Xq7Lk2Pz9Rt4Vw8Yb3Nc')).toBe(false);
  });

  it('only ${VAR} / ${VAR:-default} are references, not $VAR (dt25 g2 5a)', () => {
    expect(isDotenvReference('${DB_PASS:-}')).toBe(true);
    for (const v of ['$Hunter2024', '$uperSecretPw', '$DB_PASS', '${DB_PASS:?unset}', '$env:DB_PASS', '%DB_PASS%', '${env:DB_PASS}']) {
      expect(isDotenvReference(v), v).toBe(false);
    }
    expect(envSecretKeys({ EMAIL_PASSWORD: '$Hunter2024' })).toEqual(['EMAIL_PASSWORD']);
    expect(envSecretKeys({ EMAIL_PASSWORD: '$uperSecretPw' })).toEqual(['EMAIL_PASSWORD']);
  });
});
