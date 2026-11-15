import type { ScanResult } from '../core/types.js';
import type { Reporter } from './reporter.js';
import { toReportJson } from './serialize.js';

export class JsonReporter implements Reporter {
  readonly format = 'json';

  render(result: ScanResult): string {
    // bidi / C1 controls from scanned text become \uXXXX escapes (toReportJson)
    return toReportJson(result);
  }
}
