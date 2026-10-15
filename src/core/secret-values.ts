import { basename } from 'node:path';
import { shannonEntropy } from '../analyzers/entropy.js';
import { API_KEY_PATTERNS, isEnvReference, isPlaceholderSecret } from './patterns.js';

/**
 * Whether a parsed config holds a credential — what makes a settings file a
 * credential file for the permission checks. A settings file most agents
 * write with their default umask (Gemini CLI, Qwen Code, Claude Code: 0644)
 * exposes nothing secret unless a key, token or password was put in it; a
 * group-readable `{}` is not a leak.
 *
 * A value counts when it matches a known key format, or sits under a
 * secret-sounding key and looks random (length ≥ 20, high entropy). Env
 * references (`${VAR}`, `{env:VAR}`) and documentation placeholders don't.
 */
const SECRET_KEY_NAME = /(?:api[_-]?key|apikey|token|secret|password|passwd|credential|private[_-]?key|auth(?:orization)?$)/i;
const AUTH_SCHEME = /^(?:bearer|basic|token)\s+/i;
const MIN_LENGTH = 20;
const HIGH_ENTROPY = 4.5;
const MAX_NODES = 5000;

export function isSecretLikeValue(value: string, keyName = ''): boolean {
  const v = value.trim().replace(AUTH_SCHEME, '');
  if (!v || isEnvReference(v) || isPlaceholderSecret(v)) return false;
  if (API_KEY_PATTERNS.some(({ pattern }) => pattern.test(v))) return true;
  return SECRET_KEY_NAME.test(keyName) && v.length >= MIN_LENGTH && !/\s/.test(v) && shannonEntropy(v) > HIGH_ENTROPY;
}

export function configHoldsSecret(data: unknown): boolean {
  let seen = 0;
  const walk = (node: unknown, key: string): boolean => {
    if (++seen > MAX_NODES) return false;
    if (typeof node === 'string') return isSecretLikeValue(node, key);
    if (Array.isArray(node)) return node.some(v => walk(v, key));
    if (node && typeof node === 'object') {
      return Object.entries(node as Record<string, unknown>).some(([k, v]) => walk(v, k));
    }
    return false;
  };
  return walk(data, '');
}

/** Files that are credentials by what they are, whatever they hold right now. */
// PicoClaw's .security.yml is its secret store (the place api keys move to)
export const CREDENTIAL_FILE_NAME = /(?:^\.env(?:\.|$)|^\.security\.ya?ml$|credential|auth|token|secret|keystore|\.key$|\.pem$)/i;

/**
 * A declared credential path that is ordinary settings (an agent's
 * settings.json, written with the default umask) exposes something only when
 * it holds a secret; a group-readable settings file with none is not a leak.
 */
export function exposesCredentials(config: { filePath: string; data: unknown }): boolean {
  return CREDENTIAL_FILE_NAME.test(basename(config.filePath)) || configHoldsSecret(config.data);
}
