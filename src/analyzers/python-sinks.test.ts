import { describe, it, expect } from 'vitest';
import { analyzePythonSinks } from './python-sinks.js';

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
});
