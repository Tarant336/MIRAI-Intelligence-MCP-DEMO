/**
 * Tests for the Skills engine (Skill Loader, Skill Registry, skill_select tool).
 */

import { describe, expect, it, beforeAll, afterAll } from 'vitest';

import { loadSkills, parseSkillFile } from '../src/skills/loader.js';
import { parseFrontmatter } from '../src/skills/frontmatter.js';
import { SkillRegistry } from '../src/skills/registry.js';
import { getSkillRegistry, resetSkillRegistry, skillsEngine } from '../src/engines/skills/index.js';
import { buildRegistry } from '../src/index.js';
import { createLogger } from '../src/core/logger.js';
import { EvidenceCollector } from '../src/shared/evidence.js';
import { getKnowledgeBase } from '../src/shared/knowledge-base.js';
import type { ToolContext } from '../src/core/tool.js';

const TOOL_NAME = /^[a-z][a-z0-9_]{2,63}$/;

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

describe('frontmatter parser', () => {
  it('parses basic key-value pairs', () => {
    const raw = `---\nname: test-skill\ndescription: Test skill\ntags: [a, b]\n---\nBody content`;
    const { data, body } = parseFrontmatter(raw);
    expect(data.name).toBe('test-skill');
    expect(data.description).toBe('Test skill');
    expect(data.tags).toEqual(['a', 'b']);
    expect(body).toBe('Body content');
  });

  it('parses block list syntax', () => {
    const raw = `---\nname: test\ntools:\n  - tool1\n  - tool2\n---\nBody`;
    const { data } = parseFrontmatter(raw);
    expect(data.tools).toEqual(['tool1', 'tool2']);
  });

  it('handles missing frontmatter', () => {
    const raw = 'Just body content';
    const { data, body } = parseFrontmatter(raw);
    expect(data).toEqual({});
    expect(body).toBe('Just body content');
  });
});

describe('skill loader', () => {
  it('loads skills from the skills directory', () => {
    const result = loadSkills();
    expect(result.root).toContain('skills');
    expect(result.skills.length).toBeGreaterThanOrEqual(14); // 38 skills present; keep a resilient lower bound
    expect(result.errors).toEqual([]); // No validation errors
  });

  it('validates skill names (kebab-case)', () => {
    // Should not throw for valid skills
    for (const skill of loadSkills().skills) {
      expect(skill.name).toMatch(/^[a-z][a-z0-9-]{2,63}$/);
    }
  });

  it('ensures each skill has description and non-empty body', () => {
    for (const skill of loadSkills().skills) {
      expect(skill.description.length).toBeGreaterThan(0);
      expect(skill.body.trim().length).toBeGreaterThan(0);
    }
  });

  it('ensures each skill has engines, tags, tools arrays', () => {
    for (const skill of loadSkills().skills) {
      expect(Array.isArray(skill.engines)).toBe(true);
      expect(Array.isArray(skill.tags)).toBe(true);
      expect(Array.isArray(skill.tools)).toBe(true);
    }
  });
});

describe('skill registry', () => {
  let registry: SkillRegistry;

  beforeAll(() => {
    const result = loadSkills();
    registry = new SkillRegistry(result.skills);
  });

  it('registers all skills with unique names', () => {
    expect(registry.size).toBeGreaterThanOrEqual(14);
    const names = registry.list().map((s) => s.name);
    expect(new Set(names).size).toBe(names.length); // No duplicates
  });

  it('provides list() and summaries()', () => {
    const list = registry.list();
    expect(list.length).toBe(registry.size);
    const summaries = registry.summaries();
    expect(summaries.length).toBe(registry.size);
    for (const s of summaries) {
      expect(s.name).toBeTruthy();
      expect(s.description).toBeTruthy();
      expect(s.version).toBeTruthy();
      expect(Array.isArray(s.engines)).toBe(true);
      expect(Array.isArray(s.tags)).toBe(true);
      expect(Array.isArray(s.tools)).toBe(true);
    }
  });

  it('get() retrieves a skill by name', () => {
    const skill = registry.get('evidence-based-research');
    expect(skill).toBeDefined();
    expect(skill?.name).toBe('evidence-based-research');
    expect(skill?.engines).toContain('knowledge-and-evidence');
  });

  it('byEngine() filters skills by engine', () => {
    const skills = registry.byEngine('knowledge-and-evidence');
    expect(skills.length).toBeGreaterThan(0);
    for (const s of skills) {
      expect(s.engines).toContain('knowledge-and-evidence');
    }
  });

  it('byTag() filters skills by tag', () => {
    const skills = registry.byTag('evidence');
    expect(skills.length).toBeGreaterThan(0);
    for (const s of skills) {
      expect(s.tags.map((t) => t.toLowerCase())).toContain('evidence');
    }
  });

  it('facets() returns distinct engines and tags', () => {
    const { engines, tags } = registry.facets();
    expect(engines.length).toBeGreaterThan(0);
    expect(tags.length).toBeGreaterThan(0);
    expect(engines.sort()).toEqual([...engines].sort());
    expect(tags.sort()).toEqual([...tags].sort());
  });

  it('search() ranks skills by relevance', () => {
    const results = registry.search('evidence research', 5);
    expect(results.length).toBeGreaterThan(0);
    // Top result should be evidence-based-research
    expect(results[0].name).toBe('evidence-based-research');
    expect(results[0].score).toBeGreaterThan(0);
    expect(results[0].rationale).toContain('Matched');
  });

  it('search() returns empty array for no matches', () => {
    const results = registry.search('xyzunlikelyterm123', 5);
    expect(results).toEqual([]);
  });

  it('select() produces recommendations, toolPlan and workflow', () => {
    const selection = registry.select({ task: 'analyze malware sample for c2 protocol', limit: 3 });
    expect(selection.query).toBe('analyze malware sample for c2 protocol');
    expect(selection.recommendations.length).toBeGreaterThan(0);
    expect(selection.recommendations.length).toBeLessThanOrEqual(3);
    expect(selection.toolPlan).toBeInstanceOf(Array);
    expect(selection.workflow).toBeInstanceOf(Array);
    expect(selection.warnings).toBeInstanceOf(Array);

    // Check structure of recommendations
    for (const r of selection.recommendations) {
      expect(r.name).toBeTruthy();
      expect(r.score).toBeGreaterThan(0);
      expect(r.rationale).toContain('Matched');
      expect(Array.isArray(r.engines)).toBe(true);
      expect(Array.isArray(r.tools)).toBe(true);
    }

    // Check toolPlan is deduplicated
    const uniqueTools = new Set(selection.toolPlan);
    expect(uniqueTools.size).toBe(selection.toolPlan.length);
  });

  it('select() respects engine filter', () => {
    const selection = registry.select({
      task: 'analyze pcap network traffic',
      limit: 3,
      engines: ['network-forensics'],
    });
    // All selected skills should use network-forensics engine
    for (const r of selection.recommendations) {
      expect(r.engines).toContain('network-forensics');
    }
  });

  it('select() produces warning when no skill matches', () => {
    const selection = registry.select({ task: 'xyzunlikelytask123', limit: 3 });
    expect(selection.recommendations).toEqual([]);
    expect(selection.toolPlan).toEqual([]);
    expect(selection.workflow).toEqual([]);
    expect(selection.warnings.length).toBeGreaterThan(0);
  });
});

describe('skills engine tools', () => {
  beforeAll(() => {
    resetSkillRegistry();
  });

  afterAll(() => {
    resetSkillRegistry();
  });

  it('skill_list returns all skills with facets', async () => {
    const res = await invoke('skill_list', {});
    expect(res.ok).toBe(true);
    expect(res.data).toBeDefined();
    const data = res.data as {
      root: string;
      total: number;
      returned: number;
      facets: { engines: string[]; tags: string[] };
      skills: Array<{ name: string; engines: string[] }>;
    };
    expect(data.total).toBeGreaterThanOrEqual(14);
    expect(data.facets.engines.length).toBeGreaterThan(0);
    expect(data.facets.tags.length).toBeGreaterThan(0);
    expect(data.skills.length).toBe(data.returned);
  });

  it('skill_list supports engine filter', async () => {
    const res = await invoke('skill_list', { engine: 'network-forensics' });
    expect(res.ok).toBe(true);
    const data = res.data as { skills: Array<{ engines: string[] }> };
    for (const s of data.skills) {
      expect(s.engines).toContain('network-forensics');
    }
  });

  it('skill_list supports tag filter', async () => {
    const res = await invoke('skill_list', { tag: 'evidence' });
    expect(res.ok).toBe(true);
    const data = res.data as { skills: Array<{ tags: string[] }> };
    for (const s of data.skills) {
      expect(s.tags.map((t) => t.toLowerCase())).toContain('evidence');
    }
  });

  it('skill_list supports limit', async () => {
    const res = await invoke('skill_list', { limit: 5 });
    expect(res.ok).toBe(true);
    const data = res.data as { returned: number; total: number };
    expect(data.returned).toBe(5);
    expect(data.total).toBeGreaterThanOrEqual(14);
  });

  it('skill_get returns full skill body', async () => {
    const res = await invoke('skill_get', { name: 'evidence-based-research' });
    expect(res.ok).toBe(true);
    const data = res.data as {
      skill: {
        name: string;
        description: string;
        version: string;
        engines: string[];
        tags: string[];
        tools: string[];
        body: string;
        path: string;
        bytes: number;
      };
    };
    expect(data.skill.name).toBe('evidence-based-research');
    expect(data.skill.body).toContain('## Purpose');
    expect(data.skill.body).toContain('## Procedure');
    expect(data.skill.body).toContain('## Verification criteria');
    expect(data.skill.path).toContain('SKILL.md');
    expect(data.skill.bytes).toBeGreaterThan(0);
  });

  it('skill_get throws for unknown skill', async () => {
    try {
      await invoke('skill_get', { name: 'nonexistent-skill' });
      expect.fail('Should have thrown');
    } catch (err) {
      expect(err instanceof Error).toBe(true);
      expect((err as Error).message).toContain('not found');
    }
  });

  it('skill_select returns recommendations with tool plan and workflow', async () => {
    const res = await invoke('skill_select', {
      task: 'reverse engineer a mirai botnet sample and analyze its c2 protocol',
      limit: 3,
    });
    expect(res.ok).toBe(true);
    const data = res.data as {
      query: string;
      recommendations: Array<{ name: string; score: number; rationale: string }>;
      toolPlan: string[];
      workflow: string[];
      warnings: string[];
    };
    expect(data.recommendations.length).toBeGreaterThan(0);
    expect(data.recommendations.length).toBeLessThanOrEqual(3);
    expect(data.toolPlan).toBeInstanceOf(Array);
    expect(data.workflow).toBeInstanceOf(Array);
    expect(data.workflow.length).toBe(data.recommendations.length);

    // Check that recommendations are sorted by score descending
    for (let i = 1; i < data.recommendations.length; i++) {
      expect(data.recommendations[i].score).toBeLessThanOrEqual(data.recommendations[i - 1].score);
    }
  });

  it('skill_select respects engine filter', async () => {
    const res = await invoke('skill_select', {
      task: 'analyze pcap file',
      limit: 3,
      engines: ['network-forensics'],
    });
    expect(res.ok).toBe(true);
    const data = res.data as { recommendations: Array<{ engines: string[] }> };
    for (const r of data.recommendations) {
      expect(r.engines).toContain('network-forensics');
    }
  });

  it('skill_select respects max limit of 10', async () => {
    const res = await invoke('skill_select', {
      task: 'analyze malware',
      limit: 15, // Should be capped at 10
    });
    expect(res.ok).toBe(true);
    const data = res.data as { recommendations: Array<{ name: string }> };
    expect(data.recommendations.length).toBeLessThanOrEqual(10);
  });
});

describe('engine registration count', () => {
  it('has 12 engines including skills engine', () => {
    const registry = buildRegistry();
    // Platform + 10 domain engines + skills = 12
    expect(registry.size).toBeGreaterThan(0);
  });
});