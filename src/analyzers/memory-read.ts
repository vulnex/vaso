import type { FSProvider } from '../core/fs-provider.js';
import { pathPresent, readTextIfPresent } from '../adapters/load-if-present.js';
import { linkedIntoSink } from '../core/config-loader.js';

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
    // A memory file that is a link into a credential store or shell history
    // (CLAUDE.md → ~/.zsh_history, a hard link to a keyring): never read,
    // as the probe never ships it (omitted: sensitive) — the same verdict
    // locally and remotely (dt25 g9-F3)
    if (this.fs.kind !== 'snapshot' && await linkedIntoSink(path, this.fs).catch(() => undefined) !== undefined) {
      this.unverified.push(`${path} (omitted: sensitive)`);
      return undefined;
    }
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

  /**
   * `<paths> not verified — content not in the snapshot (checked on local
   * scans)`; on a local scan (only links into a store are left unread)
   * `<paths> not read — a link into a credential store or history file`.
   */
  notVerified(): string {
    return this.fs.kind === 'snapshot'
      ? `${this.unverified.join(', ')} not verified — content not in the snapshot (checked on local scans)`
      : `${this.unverified.join(', ')} not read — a link into a credential store or history file`;
  }
}
