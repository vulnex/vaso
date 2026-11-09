import type { FSProvider } from '../core/fs-provider.js';
import { pathPresent, readTextIfPresent } from '../adapters/load-if-present.js';

/**
 * Reads memory/instruction files for the memory-secret checks and remembers
 * the ones a snapshot holds without content (the probe left a 40 MB CLAUDE.md
 * out for size): a local scan reads those, so a remote "No secrets detected"
 * must say they were not verified instead of reading as clean.
 */
export class MemoryReader {
  /** `<path> (omitted: <reason>)` for each file present without content. */
  readonly unverified: string[] = [];

  constructor(private readonly fs: FSProvider) {}

  /**
   * readTextIfPresent (unreadable → CONFIG-LOAD, absent → undefined), noting
   * a file whose content the probe omitted.
   */
  async read(path: string): Promise<string | undefined> {
    if (!(await pathPresent(path, this.fs))) return undefined;
    try {
      return await this.fs.readFile(path);
    } catch (err) {
      const omitted = err && typeof err === 'object' && 'omitted' in err ? String(err.omitted) : undefined;
      // A FIFO or device ('special') fails a local read too: CONFIG-LOAD
      if (omitted && omitted !== 'special') {
        this.unverified.push(`${path} (omitted: ${omitted})`);
        return undefined;
      }
    }
    return readTextIfPresent(path, this.fs);
  }

  /** Appended to a passing message: '' or `; <path> (omitted: size) not verified`. */
  note(): string {
    return this.unverified.length > 0 ? `; ${this.notVerified()}` : '';
  }

  /** `<paths> not verified — content not in the snapshot (checked on local scans)`. */
  notVerified(): string {
    return `${this.unverified.join(', ')} not verified — content not in the snapshot (checked on local scans)`;
  }
}
