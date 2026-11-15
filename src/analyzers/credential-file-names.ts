import type { FSProvider } from '../core/fs-provider.js';

/**
 * A file name that marks the file as a credential (a token or key file, a
 * Vault token, a shell or client history, a keyring, a browser cookie or
 * login store). The remote probe ships such files from a config-derived
 * skill tree as metadata only (`credentialName` in probe/config_roots.go,
 * kept equal by TestCredentialNamesMatchTS) unless they are programs.
 */
export const CREDENTIAL_FILE_NAME = /^(?:\.?(?:tokens?|secrets?|credentials?|passwords?|api[_-]?keys?|access[_-]?tokens?|auth[_-]?tokens?)(?:\.(?:json|toml|ya?ml|txt|ini|cfg|conf|env|dat))?|.*\.(?:key|pem|p12|pfx|jks|keystore|keyring|kdbx|token|secret|gpg|asc)|id_(?:rsa|dsa|ecdsa|ed25519)|client_secret[\w.-]*\.json|\.htpasswd|\.vault-token|\.[\w-]*history|\.histfile|\.lesshst|[._]netrc|\.pgpass|\.my\.cnf|\.git-credentials|\.Xauthority|Cookies(?:-journal)?|Login Data(?: For Account)?(?:-journal)?|Web Data(?:-journal)?|key[34]\.db|logins\.json|cookies\.sqlite(?:-wal|-journal)?|signons\.sqlite)$/i;

const PROGRAM_MAGIC: readonly number[][] = [
  [0x7f, 0x45, 0x4c, 0x46], // ELF
  [0xfe, 0xed, 0xfa, 0xce], [0xfe, 0xed, 0xfa, 0xcf], [0xce, 0xfa, 0xed, 0xfe], [0xcf, 0xfa, 0xed, 0xfe], // Mach-O
  [0xca, 0xfe, 0xba, 0xbe], // Mach-O universal
];

/** The file starts like a program: a `#!` script, ELF, Mach-O or PE (`MZ`). Mirrors programHeader in the probe. */
export async function startsLikeProgram(fs: FSProvider, path: string): Promise<boolean> {
  let head: Uint8Array;
  try {
    head = fs.readHead ? await fs.readHead(path, 4) : (await fs.readBytes(path)).subarray(0, 4);
  } catch {
    return false;
  }
  if (head.length >= 2 && ((head[0] === 0x23 && head[1] === 0x21) || (head[0] === 0x4d && head[1] === 0x5a))) return true;
  return head.length === 4 && PROGRAM_MAGIC.some(m => m.every((b, i) => head[i] === b));
}

/**
 * An executable whose name marks it as a credential and whose content
 * doesn't start like a program: a key or token with an execute bit, not a
 * script — skill checks don't read it as code (and the remote probe never
 * ships it from a config-derived tree).
 */
export async function isCredentialNotProgram(fs: FSProvider, path: string, name: string): Promise<boolean> {
  return CREDENTIAL_FILE_NAME.test(name) && !(await startsLikeProgram(fs, path));
}
