import { describe, it, expect } from 'vitest';
import { parsePythonDotenv } from './dotenv-python.js';
import { expandBunDotenvLayers, parseBunDotenvRaw } from './dotenv-bun.js';

// Expected values were produced by the real loaders on the same text:
// python-dotenv 1.2.2 (`dotenv_values`, the parser Hermes uses) and Bun 1.3.11
// (`process.env` after auto-loading `.env`), except where noted — an
// unresolvable reference is kept as written instead of becoming "".
const SAMPLE = [
  'A=v#c',
  'A2=v #c',
  'A3="v" # c',
  'A4="x\\"y\\nz"',
  "A5='x' #c",
  'B=${A2}',
  'C=${UNSET_X:-def}',
  'D=$A2',
  "E='${A2}'",
  'export F=1',
  'G',
  'H = spaced  ',
  'I="multi',
  'line"',
  'J=${A2}${C}',
  'A2=later',
  'L=${A2}',
  'M="${A2}"',
  'N=a b c',
  'O=#nocomment',
  'P= #x',
].join('\n');

describe('python-dotenv dialect (Hermes)', () => {
  it('matches python-dotenv 1.2.2 on comments, quotes, escapes and ${VAR} expansion', () => {
    expect(parsePythonDotenv(SAMPLE)).toEqual({
      A: 'v#c', A2: 'later', A3: 'v', A4: 'x"y\nz', A5: 'x',
      // expansion runs in file order: B saw the first A2
      B: 'v', C: 'def', D: '$A2', E: 'v', F: '1', H: 'spaced', I: 'multi\nline',
      J: 'vdef', L: 'later', M: 'later', N: 'a b c', O: '#nocomment', P: '#x',
    });
  });

  it('drops statements python-dotenv cannot parse, keeps the next line', () => {
    expect(parsePythonDotenv('Z="q" junk\n\'QK\'=1\nFOO BAR=1\nNEXT=ok\nSQ=\'it\\\'s\'\n  IND=1\nEMPTY=\nE2=""\nDOL=$\nDOLB=${'))
      .toEqual({ QK: '1', NEXT: 'ok', SQ: "it's", IND: '1', EMPTY: '', E2: '', DOL: '$', DOLB: '${' });
  });

  it('expands from the file first, then the environment; ${X:-d} only when X is absent', () => {
    const env: Record<string, string> = { HOME: '/home/u', EMPTY_ENV: '' };
    expect(parsePythonDotenv('K=${HOME}\nHOME=/file\nK2=${HOME}\nX=${EMPTY_ENV:-d}\nY=${NOPE:-d}', n => env[n]))
      .toEqual({ K: '/home/u', HOME: '/file', K2: '/file', X: '', Y: 'd' });
  });

  it('keeps a reference nothing visible defines as written', () => {
    expect(parsePythonDotenv('API_SERVER_KEY=${SERVICE_ONLY_SECRET}')).toEqual({ API_SERVER_KEY: '${SERVICE_ONLY_SECRET}' });
  });
});

describe('Bun dialect (Lyrie)', () => {
  const bun = (raw: string, env: Record<string, string> = {}) =>
    expandBunDotenvLayers([parseBunDotenvRaw(raw)], n => env[n])[0];

  it('matches Bun 1.3.11 on comments, quotes and $VAR expansion', () => {
    expect(bun(SAMPLE, { HOME: '/tmp' })).toEqual({
      A: 'v', A2: 'later', A3: 'v', A4: 'x\\"y\nz', A5: 'x',
      // expansion sees the final value
      B: 'later', C: 'def', D: 'later', E: 'later', F: '1', H: 'spaced', I: 'multi\nline',
      J: 'laterdef', L: 'later', M: 'later', N: 'a b c', O: '', P: '',
    });
  });

  it('closes a quote only where blanks or a comment follow; otherwise reads the line unquoted', () => {
    expect(bun('A=one\nN="q"#c\nO="a"b"  # c\nS="${A}" junk\nT=a\\\\#b\nU=\\$A\nK==eq\nexport  L=sp\n M =  v w  # c\nD=`x#y` # c\nQ\nR=${Q}r'))
      .toEqual({ A: 'one', N: 'q', O: 'a"b', S: '"one" junk', T: 'a\\\\', U: '$A', K: '=eq', L: 'sp', M: 'v w', D: 'x#y', R: '${Q}r' });
  });

  it('a quote never closed on a later line swallows the rest of the file', () => {
    expect(bun('A=one\nE="unterminated\nF=after\nN="q"#c')).toEqual({ A: 'one', E: 'unterminated\nF=after\nN="q' });
  });

  it('expands against the process environment first, then the merged layers (a later layer wins)', () => {
    const [base, local] = expandBunDotenvLayers(
      [parseBunDotenvRaw('A=one\nB=${A}x\nG=${PE}\nPE=file'), parseBunDotenvRaw('N=${A}local\nA=fromlocal')],
      n => ({ PE: 'proc' } as Record<string, string>)[n],
    );
    // Each file keeps its own value; references see the final environment
    expect(base).toEqual({ A: 'one', B: 'fromlocalx', G: 'proc', PE: 'file' });
    expect(local).toEqual({ N: 'fromlocallocal', A: 'fromlocal' });
  });

  it('survives self-reference', () => {
    expect(bun('A=${A}x')).toEqual({ A: '${A}x' });
  });
});
