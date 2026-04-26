import type { ScanResult, AgentScanResult, CheckResult } from '../core/types.js';
import type { Reporter } from './reporter.js';

function xmlEscape(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function attr(name: string, value: string | number): string {
  return `${name}="${xmlEscape(String(value))}"`;
}

function evidenceText(r: CheckResult): string {
  if (!r.evidence || r.evidence.length === 0) return r.message;
  const parts = [r.message, ''];
  for (const e of r.evidence) {
    let line = e.file;
    if (e.line !== undefined) line += `:${e.line}`;
    if (e.detail) line += ` — ${e.detail}`;
    if (e.snippet) line += `\n  ${e.snippet}`;
    parts.push(line);
  }
  return parts.join('\n');
}

function suiteCounts(agent: AgentScanResult): { tests: number; failures: number } {
  let tests = 0;
  let failures = 0;
  for (const r of agent.results) {
    tests++;
    if (!r.passed) failures++;
  }
  return { tests, failures };
}

function agentLabel(agent: AgentScanResult): string {
  return agent.installation.agentName
    ? `${agent.agent}.${agent.installation.agentName}`
    : agent.agent;
}

export class JunitReporter implements Reporter {
  readonly format = 'junit';

  render(result: ScanResult): string {
    const lines: string[] = [];
    lines.push('<?xml version="1.0" encoding="UTF-8"?>');

    let totalTests = 0;
    let totalFailures = 0;
    for (const a of result.agents) {
      const c = suiteCounts(a);
      totalTests += c.tests;
      totalFailures += c.failures;
    }

    lines.push(
      `<testsuites ${attr('name', 'vaso')} ${attr('tests', totalTests)} ${attr('failures', totalFailures)} ${attr('errors', 0)} ${attr('timestamp', result.timestamp)}>`,
    );

    for (const agent of result.agents) {
      const label = agentLabel(agent);
      const c = suiteCounts(agent);

      lines.push(
        `  <testsuite ${attr('name', label)} ${attr('tests', c.tests)} ${attr('failures', c.failures)} ${attr('errors', 0)} ${attr('timestamp', result.timestamp)}>`,
      );

      for (const r of agent.results) {
        const classname = `${label}.${r.category}`;
        const testname = `${r.id} — ${r.name}`;
        const open = `    <testcase ${attr('classname', classname)} ${attr('name', testname)}>`;
        if (r.passed) {
          lines.push(`${open}</testcase>`);
        } else {
          lines.push(open);
          lines.push(
            `      <failure ${attr('message', r.message)} ${attr('type', r.severity)}>${xmlEscape(evidenceText(r))}</failure>`,
          );
          lines.push('    </testcase>');
        }
      }

      lines.push('  </testsuite>');
    }

    lines.push('</testsuites>');
    return lines.join('\n') + '\n';
  }
}
