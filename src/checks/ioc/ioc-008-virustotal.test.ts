import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtemp, mkdir, writeFile, rm, realpath } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { ScanContext } from '../../core/types.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';
import { ioc008 } from './ioc-008-virustotal.js';

let dir: string;
let origKey: string | undefined;

beforeEach(async () => {
  dir = await realpath(await mkdtemp(join(tmpdir(), 'vaso-ioc008-')));
  for (const name of ['a', 'b', 'c']) {
    await mkdir(join(dir, name), { recursive: true });
    await writeFile(join(dir, name, 'SKILL.md'), `---\nname: ${name}\ndescription: x\n---\n${name}\n`);
  }
  origKey = process.env['VIRUSTOTAL_API_KEY'];
  process.env['VIRUSTOTAL_API_KEY'] = 'test-key';
});

afterEach(async () => {
  vi.unstubAllGlobals();
  if (origKey === undefined) delete process.env['VIRUSTOTAL_API_KEY'];
  else process.env['VIRUSTOTAL_API_KEY'] = origKey;
  await rm(dir, { recursive: true, force: true });
});

function ctx(): ScanContext {
  return {
    installation: { agent: 'openclaw', installDir: dir, configFiles: [], skillsDir: dir },
    configs: [],
    platform: 'darwin',
    fs: new LocalFSProvider(),
  };
}

function respond(statuses: number[], malicious = 0) {
  let i = 0;
  const fetch = vi.fn(async () => {
    const status = statuses[Math.min(i++, statuses.length - 1)]!;
    return new Response(JSON.stringify({ data: { attributes: { last_analysis_stats: { malicious } } } }), { status });
  });
  vi.stubGlobal('fetch', fetch);
  return fetch;
}

describe('IOC-008 VirusTotal answers', () => {
  it('a file unknown to VirusTotal (404) counts as checked', async () => {
    respond([404]);
    const r = await ioc008.run(ctx());
    expect(r.passed).toBe(true);
    expect(r.message).not.toMatch(/not checked/);
  });

  it('server errors and failed requests are reported as not checked, never clean', async () => {
    let i = 0;
    vi.stubGlobal('fetch', vi.fn(async () => {
      if (i++ === 0) throw new Error('offline');
      return new Response('', { status: 503 });
    }));
    const r = await ioc008.run(ctx());
    expect(r.passed).toBe(true);
    expect(r.message).toMatch(/3 of 3 file\(s\) not checked/);
  });

  it('stops querying at the rate limit and counts the rest as not checked', async () => {
    const fetch = respond([404, 429]);
    const r = await ioc008.run(ctx());
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(r.message).toMatch(/2 of 3 file\(s\) not checked \(rate limit reached\)/);
  });

  it('a rejected key checks nothing', async () => {
    const fetch = respond([401]);
    const r = await ioc008.run(ctx());
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(r.message).toMatch(/3 of 3 file\(s\) not checked \(API key rejected\)/);
  });

  it('still reports flagged files alongside unchecked ones', async () => {
    let i = 0;
    vi.stubGlobal('fetch', vi.fn(async () => (i++ === 0
      ? new Response(JSON.stringify({ data: { attributes: { last_analysis_stats: { malicious: 5 } } } }), { status: 200 })
      : new Response('', { status: 500 }))));
    const r = await ioc008.run(ctx());
    expect(r.passed).toBe(false);
    expect(r.evidence).toHaveLength(1);
    expect(r.message).toMatch(/1 file\(s\) flagged.*2 of 3 file\(s\) not checked/);
  });
});
