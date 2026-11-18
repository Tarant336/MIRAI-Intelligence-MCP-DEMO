/**
 * Regression tests for binary_similarity exact-hash handling (P2.3).
 *
 * Exact SHA-256 identity is authoritative: two byte-identical files (or the same
 * file compared with itself) MUST score 1.0 with an `identical` verdict, and no
 * heuristic sub-score may downgrade them. This matters because the sub-scores
 * are degenerate for empty or string-less inputs — without the short-circuit an
 * exact copy of an empty file would be mis-reported as `unrelated`.
 *
 * All fixtures are generated in-process; no sample is ever executed.
 */

import { createHash } from 'node:crypto';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

import { buildRegistry } from '../src/index.js';
import { computeSimilarity } from '../src/engines/malware-intelligence/binary.js';
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

/* --- fixtures ------------------------------------------------------------- */

const FIX_DIR = join('test-artifacts', '_binary_similarity');

function writeFixture(name: string, buf: Buffer): string {
  mkdirSync(FIX_DIR, { recursive: true });
  const p = join(FIX_DIR, name);
  writeFileSync(p, buf);
  return p;
}

const realSha = (b: Buffer): string => `sha256:${createHash('sha256').update(b).digest('hex')}`;

/** `\n`-separated tokens yield one extracted string per line (extractStrings splits on non-printables). */
function tokens(prefix: string, n: number, start = 0): string[] {
  return Array.from(
    { length: n },
    (_, i) => `${prefix}_MODULE_${String(start + i).padStart(3, '0')}_SECURITY_TOKEN`,
  );
}

/**
 * A near-identical pair: a large common block followed by disjoint, equal-length
 * unique blocks. Byte identity and string overlap are both high but neither is
 * exact, so the pair must land in the `likely-related` band — never `identical`.
 */
function buildSimilarPair(): { a: Buffer; b: Buffer } {
  const shared = tokens('COMMON', 60);
  const uniqA = tokens('ALPHA', 15, 900);
  const uniqB = tokens('BRAVO', 15, 900);
  return {
    a: Buffer.from([...shared, ...uniqA].join('\n')),
    b: Buffer.from([...shared, ...uniqB].join('\n')),
  };
}

afterAll(() => {
  rmSync(FIX_DIR, { recursive: true, force: true });
});

/* --- unit tests: computeSimilarity ---------------------------------------- */

describe('computeSimilarity exact-hash identity (unit)', () => {
  it('pins self-comparison to 1.0 / identical via an exact hash match', () => {
    const buf = Buffer.from('the same bytes, compared against themselves');
    const sim = computeSimilarity(buf, buf);
    expect(sim.exactHashMatch).toBe(true);
    expect(sim.combined).toBe(1);
    expect(sim.verdict).toBe('identical');
    expect(sim.confidence).toBe('confirmed');
  });

  it('pins a byte-for-byte copy to 1.0 / identical even from a distinct Buffer', () => {
    const a = Buffer.from('a duplicated payload with identical bytes');
    const b = Buffer.from(a); // distinct instance, identical content
    expect(b).not.toBe(a);
    const sim = computeSimilarity(a, b);
    expect(sim.exactHashMatch).toBe(true);
    expect(sim.combined).toBe(1);
    expect(sim.verdict).toBe('identical');
  });

  it('treats two empty buffers as byte-identical though every sub-score is degenerate', () => {
    const sim = computeSimilarity(Buffer.alloc(0), Buffer.alloc(0));
    // Degenerate heuristics must not be allowed to downgrade an exact copy.
    expect(sim.prefixRatio).toBe(0);
    expect(sim.histogramCosine).toBe(0);
    expect(sim.stringJaccard).toBe(0);
    expect(sim.exactHashMatch).toBe(true);
    expect(sim.combined).toBe(1);
    expect(sim.verdict).toBe('identical');
  });

  it('does NOT pin an empty buffer as identical to a non-empty one', () => {
    const sim = computeSimilarity(Buffer.alloc(0), Buffer.from('not empty'));
    expect(sim.exactHashMatch).toBe(false);
    expect(sim.verdict).toBe('unrelated');
    expect(sim.combined).toBeLessThan(0.55);
  });

  it('reports wholly different content as unrelated', () => {
    const sim = computeSimilarity(Buffer.alloc(512, 0x41), Buffer.alloc(512, 0x42));
    expect(sim.exactHashMatch).toBe(false);
    expect(sim.verdict).toBe('unrelated');
    expect(sim.combined).toBeLessThan(0.55);
  });

  it('reports a near-identical edited copy as likely-related, NOT identical', () => {
    const { a, b } = buildSimilarPair();
    const sim = computeSimilarity(a, b);
    expect(sim.exactHashMatch).toBe(false);
    expect(sim.verdict).toBe('likely-related');
    expect(sim.combined).toBeGreaterThanOrEqual(0.55);
    expect(sim.combined).toBeLessThan(0.98);
  });

  it('honours caller-supplied digests instead of silently re-hashing', () => {
    const a = Buffer.from('some bytes here');
    const b = Buffer.from('totally different bytes');
    const asIdentical = computeSimilarity(a, b, { sha256A: 'same', sha256B: 'same' });
    expect(asIdentical.exactHashMatch).toBe(true);
    expect(asIdentical.combined).toBe(1);

    const asDifferent = computeSimilarity(a, a, { sha256A: 'x', sha256B: 'y' });
    expect(asDifferent.exactHashMatch).toBe(false);
  });
});

/* --- tool-level regression: binary_similarity ------------------------------ */

interface SimData {
  fileA: string;
  fileB: string;
  sha256A: string;
  sha256B: string;
  combined: number;
  verdict: string;
  confidence: string;
  exactHashMatch: boolean;
  prefixRatio: number;
  histogramCosine: number;
  stringJaccard: number;
  sectionOverlap: number | null;
}

describe('binary_similarity exact-hash handling (P2.3)', () => {
  it('reports an exact copy as byte-identical (1.0 / identical / exactHashMatch)', async () => {
    const bytes = Buffer.from('sample payload bytes for the exact-copy case');
    const pa = writeFixture('copy-a.bin', bytes);
    const pb = writeFixture('copy-b.bin', bytes);
    const res = await invoke('binary_similarity', { fileA: pa, fileB: pb });
    expect(res.ok).toBe(true);

    const data = res.data as SimData;
    expect(data.exactHashMatch).toBe(true);
    expect(data.combined).toBe(1);
    expect(data.verdict).toBe('identical');
    expect(data.sha256A).toBe(data.sha256B);
    expect(data.sha256A).toBe(realSha(bytes));

    expect(res.summary).toContain('Exact SHA-256 match**: yes');

    const claims = res.evidence as { claim: string; confidence: string }[];
    expect(
      claims.some((c) => c.claim.includes('Exact SHA-256 match') && c.confidence === 'confirmed'),
    ).toBe(true);

    const assertion = (res.assertions ?? []).find((x) => x.statement.includes('byte-identical'));
    expect(assertion?.status).toBe('verified_fact');
  });

  it('reports a file compared with itself as identical', async () => {
    const p = writeFixture('self.bin', Buffer.from('self-comparison payload'));
    const res = await invoke('binary_similarity', { fileA: p, fileB: p });
    const data = res.data as SimData;
    expect(data.exactHashMatch).toBe(true);
    expect(data.combined).toBe(1);
    expect(data.verdict).toBe('identical');
  });

  it('reports two empty files as identical (degenerate sub-scores cannot downgrade)', async () => {
    const pa = writeFixture('empty-a.bin', Buffer.alloc(0));
    const pb = writeFixture('empty-b.bin', Buffer.alloc(0));
    const res = await invoke('binary_similarity', { fileA: pa, fileB: pb });
    const data = res.data as SimData;
    expect(data.exactHashMatch).toBe(true);
    expect(data.combined).toBe(1);
    expect(data.verdict).toBe('identical');
  });

  it('reports an edited near-copy as likely-related (no false identical)', async () => {
    const { a, b } = buildSimilarPair();
    const pa = writeFixture('near-a.bin', a);
    const pb = writeFixture('near-b.bin', b);
    const res = await invoke('binary_similarity', { fileA: pa, fileB: pb });
    const data = res.data as SimData;
    expect(data.exactHashMatch).toBe(false);
    expect(data.verdict).toBe('likely-related');
    expect(res.summary).toContain('Exact SHA-256 match**: no');
  });

  it('reports unrelated content as unrelated', async () => {
    const pa = writeFixture('unrel-a.bin', Buffer.alloc(512, 0x41));
    const pb = writeFixture('unrel-b.bin', Buffer.alloc(512, 0x42));
    const res = await invoke('binary_similarity', { fileA: pa, fileB: pb });
    const data = res.data as SimData;
    expect(data.exactHashMatch).toBe(false);
    expect(data.verdict).toBe('unrelated');
  });

  it('rejects a path outside the workspace (path confinement preserved)', async () => {
    await expect(
      invoke('binary_similarity', { fileA: '../escape.bin', fileB: 'test-artifacts/sample.elf' }),
    ).rejects.toThrow();
  });

  it('rejects a missing file instead of fabricating a score', async () => {
    await expect(
      invoke('binary_similarity', {
        fileA: 'test-artifacts/sample.elf',
        fileB: 'test-artifacts/does-not-exist.bin',
      }),
    ).rejects.toThrow();
  });
});
