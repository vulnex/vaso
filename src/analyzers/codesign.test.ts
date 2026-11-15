import { describe, it, expect } from 'vitest';
import { readCodesign } from './codesign.js';
import type { ExecResult } from '../core/fs-provider.js';

describe('readCodesign', () => {
  it('says so when a recorded result has no exit status', () => {
    const result = { stdout: '', stderr: '' } as unknown as ExecResult;
    expect(readCodesign(result)).toEqual({ state: 'unknown', reason: 'codesign reported no exit status' });
  });

  it('names the exit code and first line otherwise', () => {
    expect(readCodesign({ stdout: '', stderr: 'boom\nmore', exitCode: 3 })).toEqual({ state: 'unknown', reason: 'codesign exited 3: boom' });
  });
});
