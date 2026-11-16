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

describe('the last binding of a from-imported name wins', () => {
  it.each([
    ['re-import after a def', 'from subprocess import run\ndef run(*a, **k):\n    return None\nfrom subprocess import run\n'],
    ['re-import under an alias after a def', 'from subprocess import run\ndef run(*a, **k):\n    return None\nfrom subprocess import Popen as run\n'],
  ])('%s is the sink again', (_label, prelude) => {
    const code = HEAD + prelude + tool('    return run(cmd, shell=True).stdout');
    expect(severe(code).length).toBeGreaterThan(0);
  });

  it('import, def, import, class: the local definition', () => {
    const code = HEAD + 'from subprocess import run\ndef run(x):\n    return x\nfrom subprocess import run\nclass run:\n    pass\n'
      + tool('    return run(cmd)');
    expect(analyzePythonSinks(code)).toEqual([]);
  });
});

describe('alias lines with a trailing comment', () => {
  it.each([
    ['partial with a comment', 'import functools, subprocess\nsh = functools.partial(subprocess.run, shell=True)  # always shell\n', '    return sh(cmd).stdout'],
    ['partial with a comment, no space', 'import functools, subprocess\nsh = functools.partial(subprocess.run, shell=True)#always shell\n', '    return sh(cmd).stdout'],
    ['an assigned alias with a comment', 'import subprocess\nr = subprocess.run  # alias\n', '    return r(cmd, shell=True).stdout'],
    ['partial imported under another name', 'import subprocess\nfrom functools import partial as P\nsh = P(subprocess.run, shell=True)\n', '    return sh(cmd).stdout'],
    ['functools imported under another name', 'import subprocess\nimport functools as ft\nsh = ft.partial(subprocess.run, shell=True)\n', '    return sh(cmd).stdout'],
  ])('%s is a sink', (_label, prelude, body) => {
    expect(severe(HEAD + prelude + tool(body)).length).toBeGreaterThan(0);
  });

  it('an alias only named in a comment is not one', () => {
    const code = 'import subprocess\n' + HEAD + 'r = str  # was subprocess.run\n' + tool('    return r(cmd)');
    expect(analyzePythonSinks(code)).toEqual([]);
  });
});

describe('function-local imports and method definitions', () => {
  it('an import inside a function does not rebind the module-level def', () => {
    const code = HEAD + 'from subprocess import run\ndef run(x, shell=False):\n    return "safe"\ndef other():\n    from subprocess import run\n    return run(["ls"])\n'
      + tool('    return run(cmd, shell=True)');
    expect(severe(code)).toEqual([]);
  });

  it('a re-import inside a module-level try block still rebinds the name', () => {
    const code = HEAD + 'from subprocess import run\ndef run(*a, **k):\n    return None\ntry:\n    from subprocess import run\nexcept ImportError:\n    pass\n'
      + tool('    return run(cmd, shell=True).stdout');
    expect(severe(code).length).toBeGreaterThan(0);
  });

  it('a function-local import with no module-level binding is still a sink alias', () => {
    const code = HEAD + tool('    from subprocess import run\n    return run(cmd, shell=True).stdout');
    expect(severe(code).length).toBeGreaterThan(0);
  });

  it.each([
    ['a module-level def of the same name', 'def run(x, shell=False):\n    return "safe"\n' + tool('    from subprocess import run\n    return run(cmd, shell=True).stdout')],
    ['a module-level assignment of the same name', 'run = print\n' + tool('    from subprocess import run\n    return run(cmd, shell=True).stdout')],
    ['a module-level import of the same name', 'from os import system as run\n' + tool('    from subprocess import run\n    return run(cmd, shell=True).stdout')],
    ['os.system with a module-level def system', 'def system(x):\n    return 0\n' + tool('    from os import system\n    return str(system(cmd))')],
    ['a method-local Popen with a module-level def Popen', 'def Popen(*a, **k):\n    return None\nclass W:\n    def go(self, cmd):\n        from subprocess import Popen\n        return Popen(cmd, shell=True)\n' + tool('    return str(W().go(cmd))')],
    ['tab indentation', 'def run(x, shell=False):\n\treturn x\n@mcp.tool()\ndef t(cmd: str) -> str:\n\t"""t"""\n\tfrom subprocess import run\n\treturn run(cmd, shell=True).stdout\n'],
  ])('a function-local import is the sink inside its function despite %s', (_label, code) => {
    const found = analyzePythonSinks(HEAD + code);
    expect(found.some((f) => f.kind === 'exec' && /subprocess\.(?:run|Popen)|os\.system/.test(f.description))).toBe(true);
    expect(found.some((f) => f.kind === 'injection')).toBe(true);
  });

  it('a function-local import reaches a function nested in it', () => {
    const code = HEAD + 'def run(x, shell=False):\n    return "safe"\n' + tool('    from subprocess import run\n    def inner():\n        return run(cmd, shell=True)\n    return inner().stdout');
    expect(severe(code).length).toBeGreaterThan(0);
  });

  it('a function-local import stays inside its function when the module binds the name', () => {
    const code = HEAD + 'def run(x, shell=False):\n    return "safe"\ndef other():\n    from subprocess import run\n    return run(["ls"])\n'
      + tool('    return run(cmd, shell=True)');
    const found = analyzePythonSinks(code);
    expect(found.filter((f) => f.kind === 'exec').map((f) => f.snippet)).toEqual(['return run(["ls"])']);
    expect(severe(code)).toEqual([]);
  });

  it('`def run(self)` is not reported as a subprocess.run() call', () => {
    const code = HEAD + 'from subprocess import run\nclass Job:\n    def run(self, job):\n        return job\n' + tool('    return Job().run(cmd)');
    expect(analyzePythonSinks(code).filter((f) => /def run/.test(f.snippet))).toEqual([]);
  });
});
