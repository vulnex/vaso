import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { setDebug, isDebug, logError } from './debug.js';

describe('debug', () => {
  let consoleErrors: string[];

  beforeEach(() => {
    consoleErrors = [];
    vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
      consoleErrors.push(args.map(String).join(' '));
    });
    setDebug(false);
  });

  afterEach(() => {
    setDebug(false);
    vi.restoreAllMocks();
  });

  it('isDebug reflects setDebug', () => {
    expect(isDebug()).toBe(false);
    setDebug(true);
    expect(isDebug()).toBe(true);
    setDebug(false);
    expect(isDebug()).toBe(false);
  });

  it('logError prints just the message without --debug', () => {
    const err = new Error('boom');
    logError('Scan failed:', err);
    expect(consoleErrors[0]).toBe('Scan failed: boom');
  });

  it('logError prints the stack trace with --debug', () => {
    setDebug(true);
    const err = new Error('boom');
    logError('Scan failed:', err);
    expect(consoleErrors[0]).toContain('Scan failed:');
    expect(consoleErrors[0]).toContain('Error: boom');
    expect(consoleErrors[0]).toContain('debug.test.ts');
  });

  it('logError handles non-Error values', () => {
    logError('Scan failed:', 'string error');
    expect(consoleErrors[0]).toBe('Scan failed: string error');
  });

  it('logError handles undefined', () => {
    logError('Scan failed:', undefined);
    expect(consoleErrors[0]).toBe('Scan failed: undefined');
  });
});
