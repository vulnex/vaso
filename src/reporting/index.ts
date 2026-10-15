import type { Reporter } from './reporter.js';
import { TerminalReporter } from './terminal.js';
import { JsonReporter } from './json.js';
import { SarifReporter } from './sarif.js';
import { MarkdownReporter } from './markdown.js';
import { HtmlReporter } from './html.js';
import { CsvReporter } from './csv.js';
import { JunitReporter } from './junit.js';

const reporters: Record<string, () => Reporter> = {
  terminal: () => new TerminalReporter(),
  json: () => new JsonReporter(),
  sarif: () => new SarifReporter(),
  markdown: () => new MarkdownReporter(),
  html: () => new HtmlReporter(),
  csv: () => new CsvReporter(),
  junit: () => new JunitReporter(),
};

export function getReporter(format: string): Reporter {
  const factory = reporters[format];
  if (!factory) {
    throw new Error(`Unknown report format: "${format}". Available: ${Object.keys(reporters).join(', ')}`);
  }
  return factory();
}

/** Whether a report format is available (built-in or registered by a user plugin). */
export function isReportFormat(format: string): boolean {
  return Object.prototype.hasOwnProperty.call(reporters, format);
}

/** Every available report format, built-in and plugin-registered. */
export function reportFormats(): string[] {
  return Object.keys(reporters);
}

/**
 * Add a report format. Names already taken — the built-in formats above or
 * another plugin's — are refused, like duplicate checks and adapters: a
 * plugin silently replacing `csv` or `sarif` would change what CI ingests
 * (and drop protections such as CSV formula neutralization).
 */
export function registerReporter(format: string, factory: () => Reporter): void {
  if (!/^[a-z0-9][a-z0-9_-]*$/i.test(format)) {
    throw new Error(`Invalid report format name "${format}" (letters, digits, - and _ only)`);
  }
  if (isReportFormat(format)) {
    throw new Error(`Report format "${format}" is already registered`);
  }
  reporters[format] = factory;
}
