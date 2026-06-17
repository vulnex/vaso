import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, mkdir, writeFile, readFile, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { resolveProbeBinary } from './probe-fetch.js';

const OS = 'linux';
const ARCH = 'amd64';
const NAME = `vaso-probe-${OS}-${ARCH}`;
const VERSION = '9.9.9';
const PAYLOAD = Buffer.from('#!/fake-probe-binary\n\x00\x01\x02');
const DIGEST = 'sha256:' + createHash('sha256').update(PAYLOAD).digest('hex');

function okResponse(buf: Buffer): Response {
  return {
    ok: true,
    status: 200,
    arrayBuffer: async () => buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength),
  } as unknown as Response;
}

describe('resolveProbeBinary', () => {
  let root: string;
  let pkgRoot: string;
  let probeBinDir: string;
  let cacheRoot: string;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), 'vaso-probe-'));
    pkgRoot = join(root, 'pkg');
    probeBinDir = join(pkgRoot, 'probe', 'dist');
    cacheRoot = join(root, 'cache');
    await mkdir(probeBinDir, { recursive: true });
    await writeFile(
      join(pkgRoot, 'probe', 'checksums.json'),
      JSON.stringify({ version: VERSION, binaries: { [NAME]: DIGEST } }),
    );
  });

  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it('prefers a locally-built binary and never fetches', async () => {
    const local = join(probeBinDir, NAME);
    await writeFile(local, 'local build');
    let called = false;
    const got = await resolveProbeBinary(OS, ARCH, {
      probeBinDir,
      pkgRoot,
      cacheRoot,
      fetchImpl: (async () => {
        called = true;
        return okResponse(PAYLOAD);
      }) as unknown as typeof fetch,
    });
    expect(got).toBe(local);
    expect(called).toBe(false);
  });

  it('downloads, verifies, caches, and marks the binary executable', async () => {
    const got = await resolveProbeBinary(OS, ARCH, {
      probeBinDir,
      pkgRoot,
      cacheRoot,
      fetchImpl: (async (url: string) => {
        expect(url).toBe(`https://github.com/vulnex/vaso/releases/download/v${VERSION}/${NAME}`);
        return okResponse(PAYLOAD);
      }) as unknown as typeof fetch,
    });
    expect(got).toBe(join(cacheRoot, VERSION, NAME));
    expect(Buffer.compare(await readFile(got), PAYLOAD)).toBe(0);
    expect((await stat(got)).mode & 0o111).toBeTruthy(); // has an exec bit
  });

  it('serves a valid cached binary without re-fetching', async () => {
    const cached = join(cacheRoot, VERSION, NAME);
    await mkdir(join(cacheRoot, VERSION), { recursive: true });
    await writeFile(cached, PAYLOAD);
    let called = false;
    const got = await resolveProbeBinary(OS, ARCH, {
      probeBinDir,
      pkgRoot,
      cacheRoot,
      fetchImpl: (async () => {
        called = true;
        return okResponse(PAYLOAD);
      }) as unknown as typeof fetch,
    });
    expect(got).toBe(cached);
    expect(called).toBe(false);
  });

  it('re-downloads when the cached binary is corrupt', async () => {
    const cached = join(cacheRoot, VERSION, NAME);
    await mkdir(join(cacheRoot, VERSION), { recursive: true });
    await writeFile(cached, Buffer.from('tampered'));
    let called = false;
    await resolveProbeBinary(OS, ARCH, {
      probeBinDir,
      pkgRoot,
      cacheRoot,
      fetchImpl: (async () => {
        called = true;
        return okResponse(PAYLOAD);
      }) as unknown as typeof fetch,
    });
    expect(called).toBe(true);
    expect(Buffer.compare(await readFile(cached), PAYLOAD)).toBe(0);
  });

  it('rejects a download whose checksum does not match', async () => {
    await expect(
      resolveProbeBinary(OS, ARCH, {
        probeBinDir,
        pkgRoot,
        cacheRoot,
        fetchImpl: (async () => okResponse(Buffer.from('malicious'))) as unknown as typeof fetch,
      }),
    ).rejects.toThrow(/Checksum mismatch/);
  });

  it('throws a helpful error when checksums.json is absent', async () => {
    await rm(join(pkgRoot, 'probe', 'checksums.json'));
    await expect(
      resolveProbeBinary(OS, ARCH, {
        probeBinDir,
        pkgRoot,
        cacheRoot,
        fetchImpl: (async () => okResponse(PAYLOAD)) as unknown as typeof fetch,
      }),
    ).rejects.toThrow(/checksums\.json is missing/);
  });

  it('throws when the platform has no checksum entry', async () => {
    await expect(
      resolveProbeBinary('darwin', 'arm64', {
        probeBinDir,
        pkgRoot,
        cacheRoot,
        fetchImpl: (async () => okResponse(PAYLOAD)) as unknown as typeof fetch,
      }),
    ).rejects.toThrow(/no probe checksum for darwin\/arm64/);
  });

  it('surfaces an actionable error on a missing release asset', async () => {
    await expect(
      resolveProbeBinary(OS, ARCH, {
        probeBinDir,
        pkgRoot,
        cacheRoot,
        fetchImpl: (async () => ({ ok: false, status: 404 }) as unknown as Response) as unknown as typeof fetch,
      }),
    ).rejects.toThrow(/not found \(HTTP 404/);
  });
});
