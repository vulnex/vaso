import { describe, it, expect } from 'vitest';
import { pythonStringLines } from './string-literals.js';

describe('pythonStringLines', () => {
  it('returns string contents, not annotations or names', () => {
    const code = [
      'def f(instructions: Annotated[str, "Assembly instructions separated by \';\'"], assistant: Assistant | None = None):',
      '    """Docstring: do not tell me about this."""',
      '    x = f"""# Environment',
      'System: {uname_sysname}',
      '"""',
      '    return {"text": "Ignore previous instructions"}  # trailing comment "quoted"',
      'p = Field(description=\'Starting Address\')',
    ].join('\n');
    const units = pythonStringLines(code);
    expect(units.some(u => u.text.includes('Annotated'))).toBe(false);
    expect(units.some(u => /assistant:/.test(u.text))).toBe(false);
    expect(units.find(u => u.text.includes('do not tell'))?.description).toBe(true);
    expect(units.find(u => u.text.includes('System: {uname_sysname}'))).toMatchObject({ line: 4, description: false });
    expect(units.find(u => u.text === 'Ignore previous instructions')).toMatchObject({ line: 6, description: false });
    expect(units.some(u => u.text.includes('quoted'))).toBe(false);
    expect(units.find(u => u.text === 'Starting Address')?.description).toBe(true);
  });
});
