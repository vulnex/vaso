import type { FSProvider } from '../core/fs-provider.js';
import type { CheckHelpers } from '../core/check-builder.js';
import type { CheckResult, Evidence, Severity } from '../core/types.js';
import { pathPresent, readTextIfPresent } from '../adapters/load-if-present.js';
import { linkedIntoSink, sinkLinkTarget } from '../core/config-loader.js';
import { classifySensitivePath } from './sensitive-paths.js';
import { memorySecretSeverity } from './memory-secrets.js';

/** A memory file that is a link into a credential store or history file. */
export interface MemoryLink {
  path: string;
  /** Where it leads (the link target, real path or hard-linked store file). */
  target: string;
  /** What that place is (a SENSITIVE_SINKS label). */
  kind: string;
}

const SOME_STORE = 'a credential store or history file';

/**
 * Reads memory/instruction files for the memory-secret checks and remembers
 * the ones a snapshot holds without content (the probe left a 40 MB CLAUDE.md
 * out for size): a local scan reads those, so a remote "No secrets detected"
 * must say they were not verified instead of reading as clean.
 */
export class MemoryReader {
  /** `<path> (omitted: <reason>)` for each file present without content. */
  readonly unverified: string[] = [];
  /**
   * Memory files that link into a credential store or history file
   * (CLAUDE.md → ~/.zsh_history, a hard link to a keyring): never read —
   * the agent loads that content into every session, so each is a finding
   * (warning) of its own (dt25 D3).
   */
  readonly linked: MemoryLink[] = [];

  constructor(private readonly fs: FSProvider) {}

  /**
   * readTextIfPresent (unreadable → CONFIG-LOAD, absent → undefined), noting
   * a file whose content the probe omitted and a file linked into a store.
   */
  async read(path: string): Promise<string | undefined> {
    if (!(await pathPresent(path, this.fs))) return undefined;
    // Locally from the filesystem, remotely from the links and hard links the
    // probe recorded (it ships no content from behind them: omitted
    // sensitive) — the same target and verdict on both sides (dt25 g9-F3)
    const target = this.fs.kind === 'snapshot'
      ? await sinkLinkTarget(path, this.fs).catch(() => undefined)
      : await linkedIntoSink(path, this.fs).catch(() => undefined);
    if (target !== undefined && target !== path) {
      this.linked.push({ path, target, kind: classifySensitivePath(target)[0] ?? SOME_STORE });
      return undefined;
    }
    if (target !== undefined) {
      // inside a credential store itself (an agent folder set there): not read
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
   * scans)`; on a local scan (only files inside a credential store are left
   * unread) `<paths> not read — inside a credential store`.
   */
  notVerified(): string {
    return this.fs.kind === 'snapshot'
      ? `${this.unverified.join(', ')} not verified — content not in the snapshot (checked on local scans)`
      : `${this.unverified.join(', ')} not read — inside a credential store or history file`;
  }

  /** One evidence item per memory file linked into a store. */
  linkEvidence(): Evidence[] {
    return this.linked.map(l => ({ file: l.path, detail: linkSentence(l) }));
  }

  /**
   * The check's result: the secrets found (`evidence`) plus a finding for
   * each linked memory file — a warning, or critical with a recognised
   * credential among the secrets (memorySecretSeverity).
   */
  result(h: CheckHelpers, evidence: Evidence[], opts: { passed: string; failed: (n: number) => string; fixDescription: string; severity?: Severity }): CheckResult {
    const links = this.linkEvidence();
    const secrets = evidence.length;
    const linkText = this.linked.length === 1 ? linkSentence(this.linked[0])
      : `${this.linked.length} memory files link into credential stores or history files; the agent loads their content`;
    return h.fromEvidence([...evidence, ...links], {
      severity: opts.severity ?? memorySecretSeverity(evidence),
      passed: opts.passed,
      failed: () => links.length === 0 ? opts.failed(secrets) : secrets === 0 ? linkText : `${opts.failed(secrets)}; ${linkText}`,
      fixDescription: links.length === 0 ? opts.fixDescription
        : `Replace the linked memory file with a regular file (or remove the link): its target's content is loaded into every session${secrets > 0 ? `. ${opts.fixDescription}` : ''}`,
    });
  }
}

function linkSentence(l: MemoryLink): string {
  return `${l.path} links into ${l.kind}; the agent loads its content`;
}
