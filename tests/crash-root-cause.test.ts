/**
 * Regression tests for crash_root_cause_analyze (P1.1).
 *
 * The original implementation only recognised `... in FUNC ...`, so the very
 * common `FUNC at FILE:LINE` shape (GDB/glibc) produced "No function symbol
 * could be extracted". These tests lock down multi-format frame parsing and the
 * structured (symbol / address / source file / line / unresolved) output.
 */

import { describe, expect, it } from 'vitest';

import { buildRegistry } from '../src/index.js';
import { parseBacktrace, parseCrashFrame } from '../src/engines/zero-day/index.js';
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

interface Frame {
  index: number;
  raw: string;
  function?: string;
  address?: string;
  sourceFile?: string;
  sourceLine?: number;
  resolved: boolean;
  confidence: string;
}
interface AnalyzeData {
  rootCause: string;
  frames: Frame[];
  relatedFunctions: string[];
  functions: string[];
  unresolvedFrameCount: number;
  location?: { function?: string; sourceFile: string; sourceLine: number };
  matchedLines: { line: number; snippet: string }[];
  signal?: string;
  evidenceSource: string;
  confidence: string;
}

const PARSER = 'test-artifacts/vuln-fixture/parser.c';

describe('parseCrashFrame (unit, 8 backtrace shapes)', () => {
  it('1. GDB symbol-only frame: "#0  func () at file:line"', () => {
    const f = parseCrashFrame('#0  copy_payload () at parser.c:20', 0);
    expect(f.index).toBe(0);
    expect(f.function).toBe('copy_payload');
    expect(f.sourceFile).toBe('parser.c');
    expect(f.sourceLine).toBe(20);
    expect(f.resolved).toBe(true);
    expect(f.confidence).toBe('observed');
  });

  it('2. GDB frame with address: "#0  0xADDR in func () at file:line"', () => {
    const f = parseCrashFrame('#0  0x0000555555555123 in copy_payload () at parser.c:20', 0);
    expect(f.address).toBe('0x0000555555555123');
    expect(f.function).toBe('copy_payload');
    expect(f.sourceLine).toBe(20);
    expect(f.resolved).toBe(true);
  });

  it('3. Plain frame: "func at file:line"', () => {
    const f = parseCrashFrame('copy_payload at parser.c:20', 1);
    expect(f.function).toBe('copy_payload');
    expect(f.sourceFile).toBe('parser.c');
    expect(f.sourceLine).toBe(20);
    expect(f.index).toBe(1);
    expect(f.resolved).toBe(true);
  });

  it('4. Frame with arguments: "func (arg=0x1) at file:line" (arg is not a fault address)', () => {
    const f = parseCrashFrame('copy_payload (src=0x7ffe1234) at parser.c:20', 0);
    expect(f.function).toBe('copy_payload');
    expect(f.address).toBeUndefined();
    expect(f.sourceLine).toBe(20);
    expect(f.resolved).toBe(true);
  });

  it('5. AddressSanitizer frame: "#0 0xADDR in func /path/file:line:col"', () => {
    const f = parseCrashFrame('#0 0x55f0 in copy_payload /src/parser.c:20:7', 0);
    expect(f.address).toBe('0x55f0');
    expect(f.function).toBe('copy_payload');
    expect(f.sourceFile).toBe('/src/parser.c');
    expect(f.sourceLine).toBe(20);
    expect(f.resolved).toBe(true);
  });

  it('6. Unresolved symbol: "#0  0xADDR in ?? ()"', () => {
    const f = parseCrashFrame('#0  0x00007fff12345678 in ?? ()', 0);
    expect(f.resolved).toBe(false);
    expect(f.function).toBeUndefined();
    expect(f.address).toBe('0x00007fff12345678');
    expect(f.confidence).toBe('hypothesis');
  });

  it('6b. Unresolved symbol with sentinel location "at ???:0"', () => {
    const f = parseCrashFrame('#0  0x0000 in ?? () at ???:0', 0);
    expect(f.resolved).toBe(false);
    expect(f.sourceFile).toBeUndefined();
    expect(f.sourceLine).toBeUndefined();
  });

  it('7. Address-only frame: "#0  0xADDR"', () => {
    const f = parseCrashFrame('#0  0x0000555555555123', 0);
    expect(f.resolved).toBe(false);
    expect(f.address).toBe('0x0000555555555123');
    expect(f.function).toBeUndefined();
    expect(f.confidence).toBe('hypothesis');
  });

  it('8. Multiple frames are parsed in order', () => {
    const { frames, functions, unresolved, location } = parseBacktrace([
      'copy_payload at parser.c:20',
      '#1  0x0000555555555000 in handle_request () at parser.c:52',
      '#2  0x00007fff in ?? ()',
    ]);
    expect(frames).toHaveLength(3);
    expect(functions).toEqual(['copy_payload', 'handle_request']);
    expect(unresolved).toHaveLength(1);
    expect(location?.function).toBe('copy_payload');
    expect(location?.sourceFile).toBe('parser.c');
    expect(location?.sourceLine).toBe(20);
  });
});

describe('crash_root_cause_analyze (integration)', () => {
  it('resolves the "func at file:line" shape against source (the original bug)', async () => {
    const res = await invoke('crash_root_cause_analyze', {
      filePath: PARSER,
      backtrace: ['copy_payload at parser.c:20', 'handle_request at parser.c:52', 'main at parser.c:56'],
    });
    expect(res.ok).toBe(true);
    const data = res.data as AnalyzeData;
    expect(data.relatedFunctions).toContain('copy_payload');
    expect(data.relatedFunctions).toContain('handle_request');
    expect(data.location?.sourceLine).toBe(20);
    expect(data.matchedLines.some((m) => m.line === 20)).toBe(true);
    expect(data.confidence).toBe('observed');
    expect(data.unresolvedFrameCount).toBe(0);
    expect(data.rootCause).not.toMatch(/No function symbol could be extracted/);
  });

  it('flags unsymbolised frames and lowers confidence', async () => {
    const res = await invoke('crash_root_cause_analyze', {
      backtrace: ['#0  0x00007fff in ?? ()', '#1  0x0000555555 in ?? ()'],
    });
    expect(res.ok).toBe(true);
    const data = res.data as AnalyzeData;
    expect(data.relatedFunctions).toHaveLength(0);
    expect(data.unresolvedFrameCount).toBe(2);
    expect(data.confidence).toBe('hypothesis');
    expect(data.rootCause).toMatch(/no function symbol resolved/i);
    expect(res.warnings?.some((w) => /could not be symbolised/.test(w))).toBe(true);
  });

  it('reports an address-only backtrace without fabricating attribution', async () => {
    const res = await invoke('crash_root_cause_analyze', {
      backtrace: ['#0  0x0000555555555123', '#1  0x0000555555555200'],
    });
    const data = res.data as AnalyzeData;
    expect(data.functions).toHaveLength(0);
    expect(data.frames.every((f) => f.address !== undefined)).toBe(true);
    expect(data.confidence).toBe('hypothesis');
  });

  it('handles an empty backtrace gracefully', async () => {
    const res = await invoke('crash_root_cause_analyze', {});
    const data = res.data as AnalyzeData;
    expect(data.frames).toHaveLength(0);
    expect(data.rootCause).toMatch(/No function symbol could be extracted/);
  });
});
