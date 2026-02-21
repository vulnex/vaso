import { describe, it, expect, vi, beforeEach, afterAll } from 'vitest';
import type { CheckResult } from '../core/types.js';

// Use vi.hoisted to create mocks that are available in vi.mock factory
const { mockQuestion, mockClose } = vi.hoisted(() => ({
  mockQuestion: vi.fn(),
  mockClose: vi.fn(),
}));

vi.mock('node:readline', () => ({
  createInterface: vi.fn().mockReturnValue({
    question: mockQuestion,
    close: mockClose,
  }),
}));

import { promptForFix } from './prompt.js';

const baseFinding: CheckResult = {
  id: 'CFG-001',
  name: 'Gateway Binding',
  category: 'config',
  severity: 'critical',
  passed: false,
  message: 'Gateway bound to 0.0.0.0',
  evidence: [
    { file: '/etc/openclaw/config.json', line: 5, snippet: '"host": "0.0.0.0"' },
  ],
  fixable: true,
  fixDescription: 'Change gateway host to 127.0.0.1',
};

let consoleLogs: string[];
const originalLog = console.log;

beforeEach(() => {
  consoleLogs = [];
  console.log = (...args: unknown[]) => {
    consoleLogs.push(args.map(String).join(' '));
  };
  vi.clearAllMocks();
});

afterAll(() => {
  console.log = originalLog;
});

function simulateInput(answer: string) {
  mockQuestion.mockImplementation((_prompt: string, callback: (answer: string) => void) => {
    callback(answer);
  });
}

describe('promptForFix', () => {
  it('returns "yes" for "y" input', async () => {
    simulateInput('y');
    const result = await promptForFix(baseFinding);
    expect(result).toBe('yes');
    expect(mockClose).toHaveBeenCalled();
  });

  it('returns "yes" for "yes" input', async () => {
    simulateInput('yes');
    const result = await promptForFix(baseFinding);
    expect(result).toBe('yes');
  });

  it('returns "no" for "n" input', async () => {
    simulateInput('n');
    const result = await promptForFix(baseFinding);
    expect(result).toBe('no');
  });

  it('returns "no" for "no" input', async () => {
    simulateInput('no');
    const result = await promptForFix(baseFinding);
    expect(result).toBe('no');
  });

  it('returns "all" for "a" input', async () => {
    simulateInput('a');
    const result = await promptForFix(baseFinding);
    expect(result).toBe('all');
  });

  it('returns "all" for "all" input', async () => {
    simulateInput('all');
    const result = await promptForFix(baseFinding);
    expect(result).toBe('all');
  });

  it('returns "quit" for "q" input', async () => {
    simulateInput('q');
    const result = await promptForFix(baseFinding);
    expect(result).toBe('quit');
  });

  it('returns "quit" for "quit" input', async () => {
    simulateInput('quit');
    const result = await promptForFix(baseFinding);
    expect(result).toBe('quit');
  });

  it('returns "no" for empty input (safe default)', async () => {
    simulateInput('');
    const result = await promptForFix(baseFinding);
    expect(result).toBe('no');
  });

  it('returns "no" for unrecognized input', async () => {
    simulateInput('maybe');
    const result = await promptForFix(baseFinding);
    expect(result).toBe('no');
  });

  it('closes readline after response', async () => {
    simulateInput('y');
    await promptForFix(baseFinding);
    expect(mockClose).toHaveBeenCalledTimes(1);
  });

  it('displays severity, check ID, message, evidence, and fixDescription', async () => {
    simulateInput('n');
    await promptForFix(baseFinding);

    const output = consoleLogs.join('\n');
    expect(output).toContain('CFG-001');
    expect(output).toContain('critical');
    expect(output).toContain('Gateway bound to 0.0.0.0');
    expect(output).toContain('/etc/openclaw/config.json:5');
    expect(output).toContain('Change gateway host to 127.0.0.1');
  });

  it('handles finding without evidence or fixDescription', async () => {
    simulateInput('y');
    const minimal: CheckResult = {
      id: 'TST-001',
      name: 'Test',
      category: 'config',
      severity: 'warning',
      passed: false,
      message: 'Test issue',
      fixable: true,
    };
    const result = await promptForFix(minimal);
    expect(result).toBe('yes');
  });
});
