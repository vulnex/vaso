import type { ScanResult } from '../core/types.js';

export interface Reporter {
  readonly format: string;
  render(result: ScanResult): string;
}
