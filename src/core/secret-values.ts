import { basename } from 'node:path';
import type { FSProvider } from './fs-provider.js';
import { shannonEntropy } from '../analyzers/entropy.js';
import { API_KEY_PATTERNS, isPlaceholderSecret, isSecretReference } from './patterns.js';

/**
 * Whether a parsed config holds a credential — what makes a settings file a
 * credential file for the permission checks. A settings file most agents
 * write with their default umask (Gemini CLI, Qwen Code, Claude Code: 0644)
 * exposes nothing secret unless a key, token or password was put in it; a
 * group-readable `{}` is not a leak.
 *
 * A value counts when it matches a known key format, or sits under a
 * secret-sounding key and looks random (length ≥ 20, high entropy). Env
 * references (`${VAR}`, `{env:VAR}`), secret manager references, file and
 * profile names (`isSecretReference`) and documentation placeholders don't.
 */
const SECRET_KEY_NAME = /(?:api[_-]?key|apikey|token|secret|password|passwd|credential|private[_-]?key|auth(?:orization)?$)/i;
const AUTH_SCHEME = /^(?:bearer|basic|token)\s+/i;
const MIN_LENGTH = 20;
const HIGH_ENTROPY = 4.5;
const MAX_NODES = 5000;

export function isSecretLikeValue(value: string, keyName = ''): boolean {
  const v = value.trim().replace(AUTH_SCHEME, '');
  if (!v || isSecretReference(v) || isPlaceholderSecret(v)) return false;
  if (API_KEY_PATTERNS.some(({ pattern }) => pattern.test(v))) return true;
  return SECRET_KEY_NAME.test(keyName) && v.length >= MIN_LENGTH && !/\s/.test(v) && shannonEntropy(v) > HIGH_ENTROPY;
}

export function configHoldsSecret(data: unknown): boolean {
  // Depth-first, first MAX_NODES nodes in document order; an explicit stack,
  // so a config nested thousands of levels deep can't exhaust the call stack
  const stack: Array<[unknown, string]> = [[data, '']];
  let seen = 0;
  while (stack.length > 0) {
    if (++seen > MAX_NODES) return false;
    const [node, key] = stack.pop()!;
    if (typeof node === 'string') {
      if (isSecretLikeValue(node, key)) return true;
    } else if (Array.isArray(node)) {
      for (let i = node.length - 1; i >= 0; i--) stack.push([node[i], key]);
    } else if (node && typeof node === 'object') {
      const entries = Object.entries(node as Record<string, unknown>);
      for (let i = entries.length - 1; i >= 0; i--) stack.push([entries[i][1], entries[i][0]]);
    }
  }
  return false;
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

/** An agent's ordinary settings file (as opposed to a token store). */
const SETTINGS_FILE_NAME = /^(?:\.claude|settings(?:\.local)?|config|cli-config)\.(?:json[c5]?|toml|ya?ml)$/i;

/**
 * A declared credential path that isn't a loaded config: token stores and
 * auth files always count. A settings file that is there but didn't load
 * (unparseable — reported as CONFIG-LOAD) counts only when its text contains
 * a known key format, so a broken, secret-free settings.json is no leak. When
 * the text can't be read either, it counts (nothing shows it is harmless).
 */
export async function unloadedFileExposes(fs: FSProvider, path: string): Promise<boolean> {
  const name = basename(path);
  if (CREDENTIAL_FILE_NAME.test(name) || !SETTINGS_FILE_NAME.test(name)) return true;
  let text: string;
  try {
    text = await fs.readFile(path);
  } catch {
    return true;
  }
  return API_KEY_PATTERNS.some(({ pattern }) => {
    const m = pattern.exec(text);
    return !!m && !isPlaceholderSecret(m[0]);
  });
}
