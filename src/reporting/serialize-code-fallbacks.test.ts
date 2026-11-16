import { describe, it, expect } from 'vitest';
import { maskCredentialsInLine, maskCredentialsInText } from './serialize.js';

/** A credential assigned from code with a literal fallback or branch. */
const CASES: Array<[string, string, string[]]> = [
  ['password = os.getenv("DB_PASSWORD") or "SkPyPwE333!x"', 'SkPyPwE333', ['DB_PASSWORD', 'os.getenv']],
  ['api_key = load_key() or "SkPyKeyF444abcd"', 'SkPyKeyF444', ['load_key()']],
  ['DB_PASSWORD = os.environ.get("A") or os.environ.get("B") or "SkPyPwG555xyz"', 'SkPyPwG555', ['"A"', '"B"']],
  ['client_secret = os.environ["CS"] if os.environ.get("CS") else "SkTernary777abc"', 'SkTernary777', ['"CS"']],
  ['const apiKey = getKey() || "SkJsKeyB999qwert";', 'SkJsKeyB999', ['getKey()']],
  ['const token = process.env.T ? process.env.T : "SkJsTokC111asdfg";', 'SkJsTokC111', ['process.env.T']],
  ['let secret = cfg.secret ?? "SkJsSecD222zxcvb";', 'SkJsSecD222', ['cfg.secret']],
  ["    self.password = get_pw() or 'SkSelfPw333zz'", 'SkSelfPw333', ['get_pw()']],
  ['connect(password=lookup("x") or "SkKwarg444qq")', 'SkKwarg444', []],
];

describe('credentials assigned from code with literal fallbacks (g3-R6-2)', () => {
  it.each(CASES)('%s', (line, secret, kept) => {
    for (const masked of [maskCredentialsInLine(line), maskCredentialsInText(line)]) {
      expect(masked).not.toContain(secret);
      for (const k of kept) expect(masked).toContain(k);
    }
  });

  it('leaves non-credential names alone', () => {
    expect(maskCredentialsInLine('name = get_name() or "default-name"')).toContain('"default-name"');
  });
});
