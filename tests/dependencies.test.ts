/**
 * Regression tests for external dependency diagnostics (§6).
 *
 * Locks down the five-status contract (AVAILABLE / MISSING /
 * VERSION_UNSUPPORTED / CONFIGURATION_ERROR / NOT_REQUIRED), the pure
 * classification logic, version comparison/parsing, the probe catalogue and
 * the structured error emitted when a required dependency is unavailable.
 */

import { describe, expect, it } from 'vitest';

import { buildRegistry } from '../src/index.js';
import {
  KNOWN_DEPENDENCIES,
  classifyDependency,
  compareVersions,
  extractVersion,
  findDependency,
  probeDependencies,
  probeDependency,
  requireDependencies,
  summarizeDependencies,
} from '../src/core/dependencies.js';
import { MiraiError } from '../src/core/errors.js';
import { createLogger } from '../src/core/logger.js';
import { EvidenceCollector } from '../src/shared/evidence.js';
import { getKnowledgeBase } from '../src/shared/knowledge-base.js';
import type { ToolContext } from '../src/core/tool.js';
import type { DependencyDefinition } from '../src/core/dependencies.js';
import type { DependencyStatus } from '../src/shared/types.js';

const registry = buildRegistry();

function makeCtx(tool: string): ToolContext {
  return {
    logger: createLogger({ test: true, tool }),
    knowledge: getKnowledgeBase(),
    evidence: new EvidenceCollector(),
  };
}

async function invoke(name: string, input: Record<string, unknown> = {}) {
  const entry = registry.get(name);
  if (!entry) throw new Error(`Tool ${name} not registered`);
  return entry.def.handler(input, makeCtx(name));
}

const ALL_STATUSES: DependencyStatus[] = [
  'AVAILABLE',
  'MISSING',
  'VERSION_UNSUPPORTED',
  'CONFIGURATION_ERROR',
  'NOT_REQUIRED',
];

/* --- version helpers ------------------------------------------------------ */

describe('dependency version helpers', () => {
  it('compares dotted versions, padding missing segments with zero', () => {
    expect(compareVersions('1.2.3', '1.2.3')).toBe(0);
    expect(compareVersions('1.2', '1.2.0')).toBe(0);
    expect(compareVersions('2.0.0', '1.9.9')).toBe(1);
    expect(compareVersions('1.9', '1.10')).toBe(-1);
    expect(compareVersions('1.2.3', '1.2')).toBe(1);
  });

  it('extracts the version using the definition pattern', () => {
    expect(extractVersion('gcc (GCC) 11.4.0', /gcc[^\d]*(\d+\.\d+(?:\.\d+)?)/i)).toBe('11.4.0');
    expect(extractVersion('no digits here', /(\d+\.\d+)/)).toBeUndefined();
    expect(extractVersion('anything', undefined)).toBeUndefined();
  });
});

/* --- pure classifier: all five statuses ----------------------------------- */

describe('classifyDependency', () => {
  it('reports MISSING for a required, absent executable', () => {
    const r = classifyDependency({ found: false, required: true });
    expect(r.status).toBe('MISSING');
  });

  it('reports NOT_REQUIRED for an optional, absent executable', () => {
    const r = classifyDependency({ found: false, required: false });
    expect(r.status).toBe('NOT_REQUIRED');
  });

  it('reports AVAILABLE for a present presence-only dependency', () => {
    const r = classifyDependency({ found: true, required: true, presenceOnly: true });
    expect(r.status).toBe('AVAILABLE');
  });

  it('reports CONFIGURATION_ERROR when a present executable cannot be executed', () => {
    const r = classifyDependency({
      found: true,
      required: true,
      exec: { exitCode: null, stdout: '', stderr: '', error: 'ENOENT: not executable' },
    });
    expect(r.status).toBe('CONFIGURATION_ERROR');
  });

  it('reports CONFIGURATION_ERROR when the version probe times out', () => {
    const r = classifyDependency({
      found: true,
      required: true,
      exec: { exitCode: null, stdout: '', stderr: '', timedOut: true },
    });
    expect(r.status).toBe('CONFIGURATION_ERROR');
  });

  it('reports VERSION_UNSUPPORTED when the version is below the minimum', () => {
    const r = classifyDependency({
      found: true,
      required: true,
      versionPattern: /(\d+\.\d+\.\d+)/,
      minVersion: '6.0.0',
      exec: { exitCode: 0, stdout: 'clang version 4.0.0', stderr: '' },
    });
    expect(r.status).toBe('VERSION_UNSUPPORTED');
    expect(r.version).toBe('4.0.0');
  });

  it('reports AVAILABLE when the version meets the minimum', () => {
    const r = classifyDependency({
      found: true,
      required: true,
      versionPattern: /clang version (\d+\.\d+\.\d+)/,
      minVersion: '6.0.0',
      exec: { exitCode: 0, stdout: 'clang version 15.0.0', stderr: '' },
    });
    expect(r.status).toBe('AVAILABLE');
    expect(r.version).toBe('15.0.0');
  });

  it('reports AVAILABLE (version undetermined) when output is unparseable', () => {
    const r = classifyDependency({
      found: true,
      required: true,
      versionPattern: /(\d+\.\d+\.\d+)/,
      exec: { exitCode: 0, stdout: 'usage: tool [options]', stderr: '' },
    });
    expect(r.status).toBe('AVAILABLE');
    expect(r.version).toBeUndefined();
  });
});

/* --- catalogue coverage (§6) ---------------------------------------------- */

describe('KNOWN_DEPENDENCIES catalogue', () => {
  const required = [
    'gcc',
    'clang',
    'aflplusplus',
    'honggfuzz',
    'qemu-arm',
    'qemu-mips',
    'binwalk',
    'sevenzip',
    'objdump',
    'readelf',
    'strings',
    'nm',
    'radare2',
    'ghidra',
    'git',
  ];

  it('covers every dependency named in §6', () => {
    const ids = KNOWN_DEPENDENCIES.map((d) => d.id);
    for (const id of required) {
      expect(ids, `missing dependency definition: ${id}`).toContain(id);
    }
  });

  it('has unique ids and complete, actionable definitions', () => {
    const ids = KNOWN_DEPENDENCIES.map((d) => d.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const def of KNOWN_DEPENDENCIES) {
      expect(def.executables.length, def.id).toBeGreaterThan(0);
      expect(def.purpose.length, def.id).toBeGreaterThan(0);
      expect(def.installHint.length, def.id).toBeGreaterThan(0);
    }
  });

  it('resolves definitions by id', () => {
    expect(findDependency('gcc')?.id).toBe('gcc');
    expect(findDependency('does-not-exist')).toBeUndefined();
  });
});

/* --- probeDependency (real I/O) ------------------------------------------- */

const nodeDef: DependencyDefinition = {
  id: 'test-node',
  title: 'Node (test binary)',
  executables: ['node'],
  versionArgs: ['--version'],
  versionPattern: /v(\d+\.\d+\.\d+)/,
  purpose: 'Synthetic probe used by the test suite.',
  installHint: 'Not applicable in tests.',
};

const bogusDef: DependencyDefinition = {
  id: 'test-bogus',
  title: 'Bogus binary',
  executables: ['mirai-no-such-tool-zzz'],
  versionArgs: ['--version'],
  versionPattern: /(\d+\.\d+)/,
  purpose: 'Synthetic absent probe used by the test suite.',
  installHint: 'Not applicable in tests.',
};

describe('probeDependency', () => {
  it('detects a present executable and its version (AVAILABLE)', async () => {
    const probe = await probeDependency(nodeDef, { required: true });
    expect(probe.status).toBe('AVAILABLE');
    expect(probe.required).toBe(true);
    expect(probe.version).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it('flags a too-old version as VERSION_UNSUPPORTED', async () => {
    const probe = await probeDependency({ ...nodeDef, minVersion: '999.0.0' }, { required: true });
    expect(probe.status).toBe('VERSION_UNSUPPORTED');
    expect(probe.minVersion).toBe('999.0.0');
  });

  it('reports MISSING when a required executable is absent', async () => {
    const probe = await probeDependency(bogusDef, { required: true });
    expect(probe.status).toBe('MISSING');
    expect(probe.executable).toBeUndefined();
  });

  it('reports NOT_REQUIRED when an optional executable is absent', async () => {
    const probe = await probeDependency(bogusDef, { required: false });
    expect(probe.status).toBe('NOT_REQUIRED');
  });
});

/* --- probeDependencies / summarise ---------------------------------------- */

describe('probeDependencies', () => {
  it('returns exactly one probe per catalogue entry with a valid status', async () => {
    const probes = await probeDependencies();
    expect(probes.map((p) => p.id)).toEqual(KNOWN_DEPENDENCIES.map((d) => d.id));
    for (const probe of probes) {
      expect(ALL_STATUSES, probe.id).toContain(probe.status);
      expect(probe.installHint.length, probe.id).toBeGreaterThan(0);
    }
  });

  it('marks only the requested dependencies as required and only they can be MISSING', async () => {
    const probes = await probeDependencies({ required: ['gcc', 'clang'] });
    for (const probe of probes) {
      const shouldBeRequired = probe.id === 'gcc' || probe.id === 'clang';
      expect(probe.required, probe.id).toBe(shouldBeRequired);
      if (probe.status === 'MISSING') expect(probe.required, probe.id).toBe(true);
      if (probe.status === 'NOT_REQUIRED') expect(probe.required, probe.id).toBe(false);
    }
  });

  it('summarises totals and every dependency line', () => {
    const probes = KNOWN_DEPENDENCIES.map((def) => ({
      id: def.id,
      title: def.title,
      status: 'NOT_REQUIRED' as const,
      detail: 'absent',
      installHint: def.installHint,
      required: false,
    }));
    const summary = summarizeDependencies(probes);
    expect(summary).toMatch(/NOT_REQUIRED=/);
    for (const def of KNOWN_DEPENDENCIES) {
      expect(summary).toContain(def.id);
    }
  });
});

/* --- requireDependencies: structured failure ------------------------------ */

describe('requireDependencies', () => {
  it('throws a structured TOOL_MISSING error for an unverifiable dependency', async () => {
    await expect(requireDependencies(['mirai-not-a-dependency'])).rejects.toBeInstanceOf(MiraiError);
    try {
      await requireDependencies(['mirai-not-a-dependency']);
      throw new Error('expected requireDependencies to throw');
    } catch (err) {
      const e = err as MiraiError;
      expect(e.code).toBe('TOOL_MISSING');
      expect(e.hint.length).toBeGreaterThan(0);
      const deps = (e.details as { dependencies: Array<{ id: string }> }).dependencies;
      expect(deps.some((d) => d.id === 'mirai-not-a-dependency')).toBe(true);
    }
  });
});

/* --- tool surface --------------------------------------------------------- */

describe('dependency_diagnostics tool', () => {
  it('is registered as a safe platform tool', () => {
    const entry = registry.get('dependency_diagnostics');
    expect(entry).toBeTruthy();
    expect(entry?.def.descriptor.engine).toBe('platform');
    expect(entry?.def.descriptor.risk).toBe('safe');
    expect(entry?.def.descriptor.capabilities).toContain('run_isolated');
  });

  it('returns a valid status for every probed dependency', async () => {
    const res = await invoke('dependency_diagnostics');
    expect(res.ok).toBe(true);
    const data = res.data as { dependencies: Array<{ id: string; status: DependencyStatus }> };
    expect(data.dependencies.length).toBe(KNOWN_DEPENDENCIES.length);
    for (const probe of data.dependencies) {
      expect(ALL_STATUSES, probe.id).toContain(probe.status);
    }
    expect(res.summary).toMatch(/Dependency diagnostics/);
  });

  it('honours the required list', async () => {
    const res = await invoke('dependency_diagnostics', { required: ['gcc'] });
    const data = res.data as { dependencies: Array<{ id: string; required: boolean }> };
    const gcc = data.dependencies.find((d) => d.id === 'gcc');
    expect(gcc?.required).toBe(true);
    expect(data.dependencies.filter((d) => d.required)).toHaveLength(1);
  });
});

describe('environment_report capability reporting', () => {
  it('includes dependency diagnostics alongside the tool inventory', async () => {
    const res = await invoke('environment_report');
    expect(res.ok).toBe(true);
    const data = res.data as { dependencies?: Array<{ id: string; status: DependencyStatus }> };
    expect(Array.isArray(data.dependencies)).toBe(true);
    expect(data.dependencies?.length).toBe(KNOWN_DEPENDENCIES.length);
    for (const probe of data.dependencies ?? []) {
      expect(ALL_STATUSES, probe.id).toContain(probe.status);
    }
  });
});
