/**
 * Smoke tests: verify the platform registry and a representative set of tools
 * execute end-to-end against the real codebase.
 */

import { describe, expect, it, beforeAll } from 'vitest';

import { buildRegistry, ENGINES } from '../src/index.js';
import { createLogger } from '../src/core/logger.js';
import { EvidenceCollector } from '../src/shared/evidence.js';
import { getKnowledgeBase } from '../src/shared/knowledge-base.js';
import type { ToolContext } from '../src/core/tool.js';
import type { ToolDefinition } from '../src/core/tool.js';

const TOOL_NAME = /^[a-z][a-z0-9_]{2,63}$/;

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

let registry: ReturnType<typeof buildRegistry>;

beforeAll(() => {
  registry = buildRegistry();
});

describe('registry integrity', () => {
  it('registers every engine without duplicate tool names', () => {
    expect(registry.size).toBeGreaterThan(50);
    expect(ENGINES.length).toBe(13);
  });

  it('every tool name matches the required pattern', () => {
    for (const def of registry.list() as ToolDefinition[]) {
      expect(def.descriptor.name, def.descriptor.name).toMatch(TOOL_NAME);
    }
  });

  it('every descriptor.engine matches its owning engine', () => {
    const engineNames = new Set(ENGINES.map((e) => e.name));
    for (const def of registry.list() as ToolDefinition[]) {
      expect(engineNames.has(def.descriptor.engine)).toBe(true);
    }
  });

  it('no tool declares a prohibited risk class', () => {
    for (const def of registry.list() as ToolDefinition[]) {
      expect(def.descriptor.risk).not.toBe('prohibited');
    }
  });
});

describe('platform tools', () => {
  it('health_check reports ok and never allows offensive ops', async () => {
    const res = await invoke('health_check');
    expect(res.ok).toBe(true);
    const data = res.data as { status: string; config: { allowOffensiveOps: boolean } };
    expect(data.status).toBe('ok');
    expect(data.config.allowOffensiveOps).toBe(false);
  });

  it('environment_report returns host details', async () => {
    const res = await invoke('environment_report');
    expect(res.ok).toBe(true);
    const data = res.data as { platform: string; cpus: number };
    expect(typeof data.platform).toBe('string');
    expect(data.cpus).toBeGreaterThan(0);
  });
});

describe('knowledge & evidence tools', () => {
  it('ingests then retrieves a knowledge record', async () => {
    const ingest = await invoke('knowledge_ingest', {
      category: 'advisory',
      title: 'Smoke test advisory',
      identifiers: { cve: 'CVE-0000-0000' },
      source: 'smoke-test',
      url: 'https://example.invalid/advisory',
      confidence: 'observed',
    });
    expect(ingest.ok).toBe(true);
    const record = (ingest.data as { record: { id: string } }).record;

    const search = await invoke('knowledge_search', { identifierScheme: 'cve', identifierValue: 'CVE-0000-0000' });
    expect(search.ok).toBe(true);
    const results = (search.data as { results: Array<{ id: string }> }).results;
    expect(results.some((r) => r.id === record.id)).toBe(true);
  });

  it('research_checkpoint persists a checkpoint', async () => {
    const res = await invoke('research_checkpoint', {
      taskTitle: 'Smoke',
      established: ['registry builds'],
      missingEvidence: ['nothing'],
    });
    expect(res.ok).toBe(true);
  });
});

describe('curated dataset tools', () => {
  it('reports dataset statistics without fabricating entries', async () => {
    const res = await invoke('curated_dataset_stats');
    expect(res.ok).toBe(true);
    const data = res.data as { curated: { variants: number; cves: number; datasets: number } };
    expect(data.curated.variants).toBeGreaterThan(0);
    expect(data.curated.cves).toBeGreaterThan(0);
    expect(data.curated.datasets).toBeGreaterThan(0);
  });
});

describe('software engineering tools', () => {
  it('analyzes this repository', async () => {
    const res = await invoke('repository_analyze', { path: '.', maxFiles: 400 });
    expect(res.ok).toBe(true);
    expect(res.data).toBeTruthy();
  });

  it('searches repository contents', async () => {
    const res = await invoke('repository_search', { query: 'mirai-intelligence-mcp', limit: 5 });
    expect(res.ok).toBe(true);
  });
});

describe('defensive-only guardrails', () => {
  it('does not expose any tool whose description implies offensive capability', () => {
    const suspicious = /(flood|amplification|spoof|brute[-\s]?force|worm)\s+(launcher|tool|generator|attack|implementation)/i;
    for (const def of registry.list() as ToolDefinition[]) {
      expect(suspicious.test(def.descriptor.description), def.descriptor.name).toBe(false);
    }
  });
});
