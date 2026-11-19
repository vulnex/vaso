import { describe, it, expect } from 'vitest';
import { continuationMasker, maskCredentialsInLine, maskCredentialsInText } from './serialize.js';

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

describe('every credential-named position on a line has its value literals masked', () => {
  const MASKED: Array<[string, string]> = [
    ['conn = connect(host, password=getpw() or "KwPw01xq", user="u")', 'KwPw01xq'],
    ['db = {"password": os.getenv("X") or "DkPw02xq"}', 'DkPw02xq'],
    ['const cfg = { password: process.env.PW || "JsPw03xq" };', 'JsPw03xq'],
    ['config["password"] = os.getenv("X") or "SubPw04xq"', 'SubPw04xq'],
    ['opts["apiKey"] = env.K || "SubKey05xq";', 'SubKey05xq'],
    ['const apiKey = getKey() || `BtKey06xq`;', 'BtKey06xq'],
    ['password ||= "OrEq07xq";', 'OrEq07xq'],
    ['PASSWORD=${DB_PW:-ShDef08xq}', 'ShDef08xq'],
    ['export API_KEY="${KEY:-ShDef09xq}"', 'ShDef09xq'],
    ['password = os.getenv("X") or os.getenv("Y", "ArgDef10xq")', 'ArgDef10xq'],
    ['secret_key = settings.get("secret_key", "ArgDef11xq")', 'ArgDef11xq'],
    ["$db = ['password' => getenv('X') ?: 'PhpKey12xq'];", 'PhpKey12xq'],
  ];
  it.each(MASKED)('%s', (line, secret) => {
    expect(maskCredentialsInLine(line)).not.toContain(secret);
    expect(maskCredentialsInText(line)).not.toContain(secret);
  });

  it('keeps names readable: env lookups, indexes, keys, prompts, the code around', () => {
    const out = maskCredentialsInLine('conn = connect(host, password=getpw() or "KwPw01xq", user="u")');
    expect(out).toContain('user="u"');
    expect(out).toContain('conn = connect(host, ');
    expect(maskCredentialsInLine('password = os.getenv("DB_PASSWORD") or "x9Lk2Pq7"')).toContain('os.getenv("DB_PASSWORD")');
    expect(maskCredentialsInText('token = headers["x-token"]')).toBe('token = headers["x-token"]');
    expect(maskCredentialsInLine('password = getpass("Password: ")')).toBe('password = getpass("Password: ")');
    expect(maskCredentialsInLine('export API_KEY="${KEY:-ShDef09xq}"')).toContain('${KEY:-');
    // a list is a value, not an index
    expect(maskCredentialsInLine('tokens = env.T || ["LsTok13xq"]')).not.toContain('LsTok13xq');
  });

  it('masks a value continued on the next lines', () => {
    for (const [text, secret] of [
      ['token = os.getenv("X") or \\\n    "Cont14xq"', 'Cont14xq'],
      ['const apiKey2 = getKey() ||\n  "Cont15xq";', 'Cont15xq'],
      ['client = Client(\n    api_key=os.getenv("K") or\n        "Cont16xq",\n)', 'Cont16xq'],
      ['db = {"password": os.getenv("X") or\n  "Cont17xq"}', 'Cont17xq'],
    ]) {
      const lines = text.split('\n');
      const c = continuationMasker(lines);
      const out = lines.map((l, i) => maskCredentialsInLine(c(i, l))).join('\n');
      expect(out, text).not.toContain(secret);
    }
    // a line after a closed value is left alone
    const lines = ['password = os.getenv("X") or "a1b2c3d4"', 'name = "visible"'];
    expect(continuationMasker(lines)(1, lines[1])).toBe('name = "visible"');
  });

  it('stays linear on long lines', () => {
    for (const unit of ['password="a" ', 'token=x or "y" ', '"password": ', 'a["token"]=', 'x(password=', 'password="${A:-', '`token=`']) {
      const line = unit.repeat(Math.ceil(100000 / unit.length));
      const t = performance.now();
      maskCredentialsInLine(line);
      maskCredentialsInText(line);
      expect(performance.now() - t, unit).toBeLessThan(2000);
    }
  });
});

describe('addresses under address names', () => {
  it('keeps a plain URL built under a *_URL / *Endpoint / *Uri name readable', () => {
    for (const line of [
      'TOKEN_URL = f"{AUTH_HOST}/oauth/token"',
      'TOKEN_URL = f"http://auth.example.com/oauth/token"',
      'const tokenEndpoint = new URL("http://auth.example.com/oauth/token");',
      'const tokenUrl = new URL("/oauth/token", AUTH_HOST);',
      'const tokenUri = `${AUTH_HOST}/oauth/token`;',
    ]) expect(maskCredentialsInLine(line)).toBe(line);
  });

  it('still masks what a credential could be: queries, userinfo, other literals, other names', () => {
    expect(maskCredentialsInLine('TOKEN_URL = f"{x}?access_token=SkQueryTok12345"')).not.toContain('SkQueryTok12345');
    expect(maskCredentialsInLine('TOKEN_URL = f"{AUTH_HOST}/oauth/token" + "SkTailLit67890"')).not.toContain('SkTailLit67890');
    expect(maskCredentialsInLine('token_url = "http://user:SkUserPw4321@h/x"')).not.toContain('SkUserPw4321');
    expect(maskCredentialsInLine('PASSWORD_URL = f"SkNotAUrl24680"')).not.toContain('SkNotAUrl24680');
    expect(maskCredentialsInLine('api_token = f"{AUTH}/SkPathTok13579"')).not.toContain('SkPathTok13579');
    expect(maskCredentialsInLine('TOKEN_URL = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"')).not.toContain('ghp_abcdef');
  });
});
