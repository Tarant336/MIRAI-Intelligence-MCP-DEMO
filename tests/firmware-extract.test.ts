/**
 * Regression tests for firmware_extract CPIO handling (P0.2).
 *
 * These lock down the fix for duplicated members: the parser must consume a
 * cpio "newc" archive sequentially (header → name → 4-byte-aligned data →
 * TRAILER!!!) and must never treat a `070701` byte sequence that occurs inside
 * a member payload as the start of a new archive.
 */

import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

import { buildRegistry } from '../src/index.js';
import { parseCpioNewcArchive, parseTar } from '../src/engines/firmware-intelligence/analysis.js';
import { createLogger } from '../src/core/logger.js';
import { EvidenceCollector } from '../src/shared/evidence.js';
import { getKnowledgeBase } from '../src/shared/knowledge-base.js';
import type { ToolContext } from '../src/core/tool.js';

const registry = buildRegistry();

function makeCtx(tool: string): ToolContext {
  return {
    logger: createLogger({ test: true, tool }),
    knowledge: getKnowledgeBase(),
    evidence: new EvidenceCollector(),
  };
}

async function invoke(name: string, input: Record<string, unknown>) {
  const entry = registry.get(name);
  if (!entry) throw new Error(`Tool ${name} not registered`);
  return entry.def.handler(input, makeCtx(name));
}

interface ExtractMember {
  name: string;
  path: string;
  size: number;
  sha256: string;
}
interface ExtractData {
  mode: string;
  outputDir: string;
  members: ExtractMember[];
  streamCount: number;
}

const FIX_DIR = join('test-artifacts', '_cpio_fixtures');
const OUT_ROOT = join('test-artifacts', '_test_fw_extract');
const sha = (data: Buffer): string => `sha256:${createHash('sha256').update(data).digest('hex')}`;

/* --- cpio newc fixture builders ------------------------------------------- */

const pad4 = (n: number): number => (4 - (n % 4)) % 4;

function newcEntry(name: string, data: Buffer, ino: number): Buffer {
  const nameBytes = Buffer.concat([Buffer.from(name, 'utf8'), Buffer.from([0])]);
  const fields = [ino, 0o100644, 0, 0, 1, 0x5f000000, data.length, 0, 0, 0, 0, nameBytes.length, 0];
  const header = Buffer.concat([
    Buffer.from('070701', 'ascii'),
    Buffer.concat(fields.map((f) => Buffer.from(f.toString(16).padStart(8, '0'), 'ascii'))),
  ]);
  const head = Buffer.concat([header, nameBytes]);
  return Buffer.concat([head, Buffer.alloc(pad4(head.length)), data, Buffer.alloc(pad4(data.length))]);
}

function buildCpio(members: Array<{ name: string; data: Buffer }>, trailer = true): Buffer {
  const parts = members.map((m, i) => newcEntry(m.name, m.data, i + 1));
  if (trailer) parts.push(newcEntry('TRAILER!!!', Buffer.alloc(0), 0));
  return Buffer.concat(parts);
}

function writeFixture(name: string, buf: Buffer): string {
  mkdirSync(FIX_DIR, { recursive: true });
  const p = join(FIX_DIR, name);
  writeFileSync(p, buf);
  return p;
}

/* --- ground truth (mirrors scripts/make-fixtures.py) ----------------------- */

const GT_PASSWD = Buffer.from('root:x:0:0:root:/root:/bin/sh\n');
const GT_RCS = Buffer.from('#!/bin/sh\nmount -t proc none /proc\n');
const GT_HELLO = Buffer.from('\x7fELF' + '\x00'.repeat(60));

afterAll(() => {
  rmSync(FIX_DIR, { recursive: true, force: true });
  rmSync(OUT_ROOT, { recursive: true, force: true });
});

describe('parseCpioNewcArchive (unit)', () => {
  it('parses a 3-member archive sequentially and stops at TRAILER', () => {
    const buf = buildCpio([
      { name: 'etc/passwd', data: GT_PASSWD },
      { name: 'etc/init.d/rcS', data: GT_RCS },
      { name: 'bin/hello', data: GT_HELLO },
    ]);
    const result = parseCpioNewcArchive(buf, 0);
    expect(result.members.map((m) => m.name)).toEqual(['etc/passwd', 'etc/init.d/rcS', 'bin/hello']);
    expect(result.complete).toBe(true);
    expect(result.end).toBe(buf.length); // consumed the whole archive incl. TRAILER
  });

  it('does not parse a cpio archive embedded inside member data', () => {
    const nested = buildCpio([{ name: 'inner/file', data: Buffer.from('inner') }]);
    const outer = buildCpio([{ name: 'outer/blob', data: nested }]);
    const result = parseCpioNewcArchive(outer, 0);
    expect(result.members).toHaveLength(1);
    expect(result.members[0]!.name).toBe('outer/blob');
    expect(result.members[0]!.data.equals(nested)).toBe(true);
  });

  it('is safe on truncated input (no throw, no runaway parse)', () => {
    const first = newcEntry('a', Buffer.from('aaaa'), 1);
    const full = buildCpio([
      { name: 'a', data: Buffer.from('aaaa') },
      { name: 'b', data: Buffer.from('bbbb') },
    ]);
    // Cut into the second member's header so its record is structurally incomplete.
    const truncated = full.subarray(0, first.length + 50);
    let result!: ReturnType<typeof parseCpioNewcArchive>;
    expect(() => {
      result = parseCpioNewcArchive(truncated, 0);
    }).not.toThrow();
    expect(result.members.map((m) => m.name)).toEqual(['a']);
    expect(result.complete).toBe(false);
  });

  it('sanitises path traversal in member names', () => {
    const buf = buildCpio([{ name: '../../etc/evil', data: Buffer.from('x') }]);
    const result = parseCpioNewcArchive(buf, 0);
    expect(result.members[0]!.name).toBe('etc/evil');
  });

  it('returns no members for non-cpio input', () => {
    const result = parseCpioNewcArchive(Buffer.from('not an archive at all'), 0);
    expect(result.members).toHaveLength(0);
    expect(result.complete).toBe(false);
  });
});

describe('parseTar (unit)', () => {
  it('parses an archive whose first entries are directories (zero-size ./)', () => {
    const buf = readFileSync(join('test-artifacts', 'sample_firmware_fs.tar'));
    const members = parseTar(buf);
    expect(members.map((m) => m.name).sort()).toEqual([
      'bin/cat',
      'bin/init',
      'bin/sh',
      'etc/os-release',
      'etc/passwd',
    ]);
    expect(members.find((m) => m.name === 'etc/passwd')?.data.toString()).toBe(
      'root::0:0:root:/root:/bin/sh\n',
    );
  });
});

describe('firmware_filesystem_analyze tar regression', () => {
  it('analyses a tar whose first member is a directory instead of returning NOT_FOUND', async () => {
    const res = await invoke('firmware_filesystem_analyze', {
      path: 'test-artifacts/sample_firmware_fs.tar',
    });
    expect(res.ok).toBe(true);
    const data = res.data as { fileCount: number; sourceKind: string };
    expect(data.sourceKind).toBe('archive');
    expect(data.fileCount).toBe(5);
  });

  it('still rejects a malformed cpio archive rather than fabricating entries', async () => {
    await expect(
      invoke('firmware_filesystem_analyze', { path: 'test-artifacts/sample_firmware_fs.cpio' }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });
});

describe('firmware_extract cpio regression (P0.2)', () => {
  it('extracts valid-fs.cpio to exactly three members with matching sha256', async () => {
    const out = join(OUT_ROOT, 'valid');
    const res = await invoke('firmware_extract', {
      filePath: 'test-artifacts/valid-fs.cpio',
      outputDir: out,
    });
    expect(res.ok).toBe(true);
    const data = res.data as ExtractData;
    expect(data.mode).toBe('builtin');

    const byName = new Map(data.members.map((m) => [m.name, m]));
    expect(data.members).toHaveLength(3);
    expect(byName.get('cpio/etc/passwd')?.sha256).toBe(sha(GT_PASSWD));
    expect(byName.get('cpio/etc/init.d/rcS')?.sha256).toBe(sha(GT_RCS));
    expect(byName.get('cpio/bin/hello')?.sha256).toBe(sha(GT_HELLO));

    // No duplicated embedded-archive directories (the P0.2 bug).
    expect(data.members.some((m) => m.name.includes('cpio-embedded'))).toBe(false);
    expect(data.members.some((m) => m.name.includes('cpio-embedded'))).toBe(false);
  });

  it('does not fabricate an embedded archive from magic bytes inside a payload', async () => {
    const nested = buildCpio([{ name: 'ghost/file', data: Buffer.from('ghost') }]);
    const outer = buildCpio([
      { name: 'rootfs/data.bin', data: nested },
      { name: 'rootfs/notes.txt', data: Buffer.from('trailing') },
    ]);
    const fixture = writeFixture('payload-magic.cpio', outer);
    const out = join(OUT_ROOT, 'payload-magic');
    const res = await invoke('firmware_extract', { filePath: fixture, outputDir: out });
    const data = res.data as ExtractData;
    expect(data.members.map((m) => m.name).sort()).toEqual([
      'cpio/rootfs/data.bin',
      'cpio/rootfs/notes.txt',
    ]);
    expect(data.members.some((m) => m.name.includes('cpio-embedded'))).toBe(false);
    // The nested archive is preserved verbatim as member data.
    const dataMember = data.members.find((m) => m.name === 'cpio/rootfs/data.bin');
    expect(dataMember).toBeDefined();
    expect(readFileSync(dataMember!.path).equals(nested)).toBe(true);
  });

  it('confines path traversal members inside the output directory', async () => {
    const buf = buildCpio([{ name: '../../escape/evil.txt', data: Buffer.from('evil') }]);
    const fixture = writeFixture('traversal.cpio', buf);
    const out = join(OUT_ROOT, 'traversal');
    const res = await invoke('firmware_extract', { filePath: fixture, outputDir: out });
    const data = res.data as ExtractData;
    expect(data.members.length).toBe(1);
    expect(data.members[0]!.name).toBe('cpio/escape/evil.txt');
    expect(data.members[0]!.path.includes('escape')).toBe(true);
  });

  it('handles a truncated archive without throwing', async () => {
    const full = buildCpio([
      { name: 'a.txt', data: Buffer.from('aaaa') },
      { name: 'b.txt', data: Buffer.from('bbbb') },
    ]);
    const fixture = writeFixture('truncated.cpio', full.subarray(0, full.length - 8));
    const out = join(OUT_ROOT, 'truncated');
    const res = await invoke('firmware_extract', { filePath: fixture, outputDir: out });
    expect(res.ok).toBe(true);
    const data = res.data as ExtractData;
    expect(data.members.length).toBeGreaterThanOrEqual(1);
  });

  it('handles an archive with no TRAILER without throwing', async () => {
    const fixture = writeFixture(
      'no-trailer.cpio',
      buildCpio([{ name: 'only.txt', data: Buffer.from('only') }], false),
    );
    const out = join(OUT_ROOT, 'no-trailer');
    const res = await invoke('firmware_extract', { filePath: fixture, outputDir: out });
    expect(res.ok).toBe(true);
    const data = res.data as ExtractData;
    expect(data.members.map((m) => m.name)).toContain('cpio/only.txt');
  });
});
