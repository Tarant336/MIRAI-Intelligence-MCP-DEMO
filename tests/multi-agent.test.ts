/**
 * Functional tests for the Multi-Agent Research Orchestration engine.
 *
 * Covers the §15 functional test surface: role listing, task decomposition,
 * specialist briefs, findings merge and evidence reconciliation.
 */

import { describe, expect, it } from 'vitest';

import { buildRegistry } from '../src/index.js';
import { createLogger } from '../src/core/logger.js';
import { EvidenceCollector } from '../src/shared/evidence.js';
import { getKnowledgeBase } from '../src/shared/knowledge-base.js';
import type { ToolContext } from '../src/core/tool.js';

function makeCtx(tool: string): ToolContext {
  return {
    logger: createLogger({ test: true, tool }),
    knowledge: getKnowledgeBase(),
    evidence: new EvidenceCollector(),
  };
}

async function invoke(name: string, input: Record<string, unknown> = {}) {
  const registry = buildRegistry();
  const entry = registry.get(name);
  if (!entry) throw new Error(`Tool ${name} not registered`);
  return entry.def.handler(input, makeCtx(name));
}

describe('multi-agent engine tools', () => {
  it('agent_roles_list returns all specialist roles', async () => {
    const res = await invoke('agent_roles_list', {});
    expect(res.ok).toBe(true);
    const data = res.data as { count: number; roles: Array<{ id: string }> };
    expect(data.count).toBe(data.roles.length);
    expect(data.count).toBeGreaterThanOrEqual(14); // §11 requires at least 14 specialist roles
    const ids = data.roles.map((r) => r.id);
    for (const required of [
      'software-architect',
      'zero-day-discovery-specialist',
      'static-analysis-specialist',
      'fuzzing-crash-analyst',
      'vulnerability-root-cause-analyst',
      'mirai-malware-analyst',
      'malware-source-code-analyst',
      'malware-variant-analyst',
      'protocol-reverse-engineer',
      'threat-intelligence-analyst',
      'evidence-verification-auditor',
    ]) {
      expect(ids).toContain(required);
    }
  });

  it('orchestrator_plan decomposes a zero-day task into dependency-ordered phases', async () => {
    const res = await invoke('orchestrator_plan', {
      task: 'discover zero-day vulnerability candidates in router firmware and triage crashes',
    });
    expect(res.ok).toBe(true);
    const data = res.data as {
      complexity: { subtasks: number; phases: number; maxParallel: number; recommendedAgents: number };
      phases: Array<{ phase: number; parallel: boolean; subtasks: Array<{ id: string; roleId: string }> }>;
      toolCatalogue: string[];
    };
    expect(data.complexity.subtasks).toBeGreaterThanOrEqual(3);
    expect(data.complexity.phases).toBeGreaterThanOrEqual(2);
    expect(data.complexity.recommendedAgents).toBe(data.complexity.subtasks);
    expect(data.phases[0]!.phase).toBe(1);
    expect(data.toolCatalogue).toContain('zero_day');

    const allSubtasks = data.phases.flatMap((p) => p.subtasks);
    expect(allSubtasks.map((s) => s.id)).toContain('intake');
    expect(allSubtasks.map((s) => s.id)).toContain('evidence-audit');
  });

  it('orchestrator_plan avoids overspawning for a simple task', async () => {
    const res = await invoke('orchestrator_plan', { task: 'summarise this', maxAgents: 5 });
    expect(res.ok).toBe(true);
    const data = res.data as { complexity: { subtasks: number }; notes: string[] };
    expect(data.complexity.subtasks).toBeLessThanOrEqual(4); // intake + fallback + audit
    expect(data.notes.some((n) => n.toLowerCase().includes('minimal'))).toBe(true);
  });

  it('agent_brief_generate produces a structured brief for a role', async () => {
    const res = await invoke('agent_brief_generate', {
      roleId: 'zero-day-discovery-specialist',
      objective: 'discover zero-day candidates in firmware',
      context: 'router image',
    });
    expect(res.ok).toBe(true);
    const data = res.data as {
      roleId: string;
      roleTitle: string;
      objective: string;
      context: string;
      outputSchema: Record<string, string>;
      guardrails: string[];
      requiredEvidence: string[];
    };
    expect(data.roleId).toBe('zero-day-discovery-specialist');
    expect(data.roleTitle).toBe('Zero-Day Discovery Specialist');
    expect(data.objective).toBe('discover zero-day candidates in firmware');
    expect(data.context).toBe('router image');
    expect(typeof data.outputSchema).toBe('object');
    expect(data.requiredEvidence.length).toBeGreaterThan(0);
    expect(data.guardrails.length).toBeGreaterThan(0);
  });

  it('agent_brief_generate rejects an unknown role', async () => {
    try {
      await invoke('agent_brief_generate', { roleId: 'does-not-exist', objective: 'x y z' });
      expect.fail('Should have thrown');
    } catch (err) {
      expect(err instanceof Error).toBe(true);
      expect((err as Error).message).toContain('not found');
    }
  });

  it('agent_findings_merge groups findings and flags divergent confidence', async () => {
    const res = await invoke('agent_findings_merge', {
      findings: [
        {
          roleId: 'mirai-malware-analyst',
          statement: 'Mirai variant uses telnet scanning for propagation',
          confidence: 'observed',
          evidence: ['sample-hash-1'],
        },
        {
          roleId: 'mirai-malware-analyst',
          statement: 'Mirai variant uses telnet scanning for propagation',
          confidence: 'hypothesis',
        },
      ],
    });
    expect(res.ok).toBe(true);
    const data = res.data as {
      merged: {
        count: number;
        overallConfidence: string;
        divergentTopics: string[];
        groups: Array<{ topic: string; mergedConfidence: string; divergent: boolean }>;
      };
    };
    expect(data.merged.count).toBe(2);
    expect(data.merged.overallConfidence).toBe('hypothesis'); // weakest-link semantics
    expect(data.merged.divergentTopics).toContain('malware');
    expect(data.merged.groups).toHaveLength(1);
    expect(data.merged.groups[0]!.divergent).toBe(true);
    expect(res.warnings?.length).toBeGreaterThan(0);
  });

  it('agent_findings_merge detects incompatible family classifications as contradictions', async () => {
    const res = await invoke('agent_findings_merge', {
      findings: [
        { roleId: 'r-mirai', statement: 'The sample is a Mirai variant', confidence: 'confirmed' },
        { roleId: 'r-gafgyt', statement: 'The sample is a Gafgyt variant', confidence: 'confirmed' },
      ],
    });
    expect(res.ok).toBe(true);
    const data = res.data as {
      merged: {
        overallConfidence: string;
        divergentTopics: string[];
        conflictedTopics: string[];
        contradictions: Array<{ topic: string; kind: string }>;
        groups: Array<{
          topic: string;
          mergedConfidence: string;
          divergent: boolean;
          reconciliationRequired: boolean;
          requiredEvidence: string[];
        }>;
      };
    };
    expect(data.merged.conflictedTopics).toContain('malware');
    expect(data.merged.contradictions).toHaveLength(1);
    expect(data.merged.contradictions[0]!.kind).toBe('incompatible_classification');
    expect(data.merged.contradictions[0]!.topic).toBe('malware');
    // Unresolved contradiction downgrades the merged confidence.
    expect(data.merged.groups[0]!.mergedConfidence).toBe('inferred');
    expect(data.merged.overallConfidence).toBe('inferred');
    expect(data.merged.groups[0]!.reconciliationRequired).toBe(true);
    expect(data.merged.groups[0]!.requiredEvidence.length).toBeGreaterThan(0);
    expect(res.warnings?.some((w) => w.includes('Semantic contradictions'))).toBe(true);
  });

  it('agent_findings_merge treats identical findings as duplicates, not contradictions', async () => {
    const res = await invoke('agent_findings_merge', {
      findings: [
        { roleId: 'r1', statement: 'Mirai uses telnet scanning for propagation', confidence: 'observed' },
        { roleId: 'r2', statement: 'Mirai uses telnet scanning for propagation', confidence: 'observed' },
      ],
    });
    const data = res.data as {
      merged: {
        contradictions: unknown[];
        groups: Array<{ divergent: boolean; reconciliationRequired: boolean; duplicates: unknown[] }>;
      };
    };
    expect(data.merged.contradictions).toHaveLength(0);
    expect(data.merged.groups[0]!.divergent).toBe(false);
    expect(data.merged.groups[0]!.reconciliationRequired).toBe(false);
    expect(data.merged.groups[0]!.duplicates).toHaveLength(1);
  });

  it('agent_findings_merge does not flag different but compatible findings', async () => {
    const res = await invoke('agent_findings_merge', {
      findings: [
        { roleId: 'r1', statement: 'Mirai uses telnet scanning for propagation', confidence: 'observed' },
        { roleId: 'r2', statement: 'Mirai implements a DDoS flood module', confidence: 'observed' },
      ],
    });
    const data = res.data as {
      merged: { contradictions: unknown[]; conflictedTopics: string[]; groups: Array<{ divergent: boolean }> };
    };
    expect(data.merged.contradictions).toHaveLength(0);
    expect(data.merged.conflictedTopics).toHaveLength(0);
    expect(data.merged.groups[0]!.divergent).toBe(false);
  });

  it('agent_findings_merge recognises reworded restatements as agreement', async () => {
    const res = await invoke('agent_findings_merge', {
      findings: [
        { roleId: 'r1', statement: 'Mirai uses telnet scanning for propagation', confidence: 'observed' },
        { roleId: 'r2', statement: 'Propagation by telnet scanning in Mirai', confidence: 'observed' },
      ],
    });
    const data = res.data as {
      merged: { contradictions: unknown[]; groups: Array<{ duplicates: unknown[] }> };
    };
    expect(data.merged.contradictions).toHaveLength(0);
    expect(data.merged.groups[0]!.duplicates).toHaveLength(1);
  });

  it('agent_findings_merge flags opposing claims', async () => {
    const res = await invoke('agent_findings_merge', {
      findings: [
        { roleId: 'r1', statement: 'The Mirai sample contains an encryption routine', confidence: 'observed' },
        { roleId: 'r2', statement: 'The Mirai sample does not contain an encryption routine', confidence: 'observed' },
      ],
    });
    const data = res.data as { merged: { contradictions: Array<{ kind: string }> } };
    expect(data.merged.contradictions).toHaveLength(1);
    expect(data.merged.contradictions[0]!.kind).toBe('opposing_claim');
  });

  it('agent_findings_merge flags evidence disagreement on equivalent claims', async () => {
    const res = await invoke('agent_findings_merge', {
      findings: [
        {
          roleId: 'r1',
          statement: 'Mirai variant uses telnet scanning for propagation',
          confidence: 'observed',
          evidence: ['hash-a'],
        },
        {
          roleId: 'r2',
          statement: 'Mirai variant uses telnet scanning for propagation',
          confidence: 'observed',
          evidence: ['hash-b'],
        },
      ],
    });
    const data = res.data as { merged: { contradictions: Array<{ kind: string }> } };
    expect(data.merged.contradictions).toHaveLength(1);
    expect(data.merged.contradictions[0]!.kind).toBe('evidence_disagreement');
  });

  it('agent_findings_merge isolates the contradictory pair among three findings', async () => {
    const res = await invoke('agent_findings_merge', {
      findings: [
        { roleId: 'r-mirai', statement: 'The sample is a Mirai variant', confidence: 'confirmed' },
        { roleId: 'r-gafgyt', statement: 'The sample is a Gafgyt variant', confidence: 'confirmed' },
        { roleId: 'r-other', statement: 'Mirai implements telnet credential brute forcing', confidence: 'observed' },
      ],
    });
    const data = res.data as {
      merged: {
        contradictions: Array<{ kind: string }>;
        groups: Array<{ count: number; contradictions: unknown[]; duplicates: unknown[] }>;
      };
    };
    expect(data.merged.groups).toHaveLength(1);
    expect(data.merged.groups[0]!.count).toBe(3);
    expect(data.merged.contradictions).toHaveLength(1);
    expect(data.merged.groups[0]!.duplicates).toHaveLength(0);
  });

  it('evidence_reconciliation classifies conflicting and unsupported assertions', async () => {
    const res = await invoke('evidence_reconciliation', {
      topic: 'mirai-c2',
      assertions: [
        {
          statement: 'Mirai uses XOR-key table A',
          status: 'direct_observation',
          confidence: 'observed',
          supporting: ['pcap-sample-1'],
          contradicting: ['pcap-sample-2'],
        },
        {
          statement: 'Mirai uses XOR-key table B',
          status: 'hypothesis',
          confidence: 'hypothesis',
          supporting: [],
          contradicting: [],
        },
      ],
    });
    expect(res.ok).toBe(true);
    const data = res.data as {
      topic: string;
      source: string;
      reconciled: Array<{ statement: string; decidedStatus: string }>;
      conflicts: string[];
      unsupported: string[];
      assessment: string;
    };
    expect(data.topic).toBe('mirai-c2');
    expect(data.source).toBe('input');
    expect(data.reconciled).toHaveLength(2);
    expect(data.reconciled[0]!.decidedStatus).toBe('contested'); // 1 supporting vs 1 contradicting
    expect(data.reconciled[1]!.decidedStatus).toBe('unsupported'); // neither supporting nor contradicting
    expect(data.conflicts).toContain('Mirai uses XOR-key table A');
    expect(data.unsupported).toContain('Mirai uses XOR-key table B');
    expect(data.assessment).toContain('require additional evidence');
  });

  it('missing_evidence_identify reports a gap for an unrecorded topic', async () => {
    const res = await invoke('missing_evidence_identify', { topic: 'xyz-unlikely-topic-123' });
    expect(res.ok).toBe(true);
    const data = res.data as { nextActions: Array<{ priority: string; action: string }> };
    expect(data.nextActions.length).toBeGreaterThan(0);
    expect(data.nextActions.some((a) => a.priority === 'high' && a.action.includes('Ingest'))).toBe(true);
  });

  it('research_audit requires records or a resolvable topic', async () => {
    try {
      await invoke('research_audit', {});
      expect.fail('Should have thrown');
    } catch (err) {
      expect(err instanceof Error).toBe(true);
      expect((err as Error).message).toContain('recordIds');
    }
  });
});
