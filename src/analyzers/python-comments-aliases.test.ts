import { describe, it, expect } from 'vitest';
import { analyzePythonSinks, stripComment } from './python-sinks.js';

const HEAD = 'from mcp.server.fastmcp import FastMCP\nmcp = FastMCP("x")\n';
const tool = (body: string): string => `@mcp.tool()\ndef t(cmd: str) -> str:\n    """t"""\n${body}\n`;
const severe = (code: string) => analyzePythonSinks(code).filter((f) => f.kind === 'injection' || f.toolInput);

describe('trailing comments are not code', () => {
  it.each([
    ['a removed shell call', 'import subprocess\n' + HEAD + tool('    x = cmd  # subprocess.run(cmd, shell=True) was removed\n    return x')],
    ['a removed os.system', 'import os\n' + HEAD + tool('    x = cmd  # os.system(cmd)\n    return x')],
    ['an alias named in a comment', 'import subprocess as sp\n' + HEAD + tool('    x = cmd  # sp.run(cmd, shell=True) was removed\n    return x')],
  ])('%s', (_label, code) => {
    expect(analyzePythonSinks(code)).toEqual([]);
  });

  it('code before the comment is still analysed', () => {
    const code = 'import os\n' + HEAD + tool('    os.system(cmd)  # runs the command\n    return "ok"');
    expect(severe(code).length).toBeGreaterThan(0);
  });

  it('a # inside a string is text', () => {
    expect(stripComment('x = "a # b"  # c')).toBe('x = "a # b"');
    expect(stripComment("os.system(f'echo {cmd} #1')")).toBe("os.system(f'echo {cmd} #1')");
    expect(stripComment('y = 1')).toBe('y = 1');
  });

  it('a line opening or closing a triple-quoted string is kept whole', () => {
    expect(stripComment('X = """body # not a comment')).toBe('X = """body # not a comment');
    expect(stripComment('end # still text""")')).toBe('end # still text""")');
    expect(stripComment('X = """a""" + y  # c')).toBe('X = """a""" + y');
  });
});

describe('a module-level def shadows a from-imported sink', () => {
  it('`from subprocess import run` then `def run(x)` calls the local function', () => {
    const code = HEAD + 'from subprocess import run\ndef run(x):\n    return x.upper()\n' + tool('    return run(cmd)');
    expect(analyzePythonSinks(code)).toEqual([]);
  });

  it('a def before the import does not', () => {
    const code = HEAD + 'def run(x):\n    return x\nfrom subprocess import run\n' + tool('    return run(cmd, shell=True)');
    expect(severe(code).length).toBeGreaterThan(0);
  });
});

describe('functools.partial(..., shell=True) aliases', () => {
  it('nested calls are rewritten in linear time with the same verdict', () => {
    const n = 150000;
    const code = 'import functools, subprocess\n' + HEAD + 'sh = functools.partial(subprocess.run, shell=True)\n'
      + tool(`    return ${'sh('.repeat(n)}cmd${')'.repeat(n)}`);
    const start = Date.now();
    const findings = analyzePythonSinks(code);
    expect(Date.now() - start).toBeLessThan(5000);
    expect(findings.some((f) => f.kind === 'injection')).toBe(true);
  });

  it('shell=True goes in before the call\'s own closing parenthesis', () => {
    const code = 'import functools, subprocess\n' + HEAD + 'sh = functools.partial(subprocess.run, shell=True)\n'
      + tool('    return sh(f"echo {cmd}", text=(1, 2)).stdout');
    expect(severe(code).length).toBeGreaterThan(0);
  });
});
