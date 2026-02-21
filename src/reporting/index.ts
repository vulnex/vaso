import type { Reporter } from './reporter.js';
import { TerminalReporter } from './terminal.js';
import { JsonReporter } from './json.js';
import { SarifReporter } from './sarif.js';
import { MarkdownReporter } from './markdown.js';
import { HtmlReporter } from './html.js';

const reporters: Record<string, () => Reporter> = {
  terminal: () => new TerminalReporter(),
  json: () => new JsonReporter(),
  sarif: () => new SarifReporter(),
  markdown: () => new MarkdownReporter(),
  html: () => new HtmlReporter(),
};

export function getReporter(format: string): Reporter {
  const factory = reporters[format];
  if (!factory) {
    throw new Error(`Unknown report format: "${format}". Available: ${Object.keys(reporters).join(', ')}`);
  }
  return factory();
}

export function registerReporter(format: string, factory: () => Reporter): void {
  reporters[format] = factory;
}
