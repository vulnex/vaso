import type { ScanResult } from '../core/types.js';
import type { Reporter } from './reporter.js';

export class JsonReporter implements Reporter {
  readonly format = 'json';

  render(result: ScanResult): string {
    return JSON.stringify(result, null, 2);
  }
}
