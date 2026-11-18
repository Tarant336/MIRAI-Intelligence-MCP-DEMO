/**
 * Skill Registry — registration, lookup, search and multi-skill selection.
 *
 * The registry owns the Skills Library invariants (unique names) and provides
 * the ranking logic that lets an agent pick and *combine* skills for a task
 * (spec: "AI tự lựa chọn, kết hợp nhiều Skills khi thực hiện nhiệm vụ phức tạp").
 */

import type {
  SkillManifest,
  SkillRecommendation,
  SkillSelection,
  SkillSummary,
} from './types.js';
import { toSkillSummary } from './types.js';

const STOPWORDS = new Set([
  'the', 'and', 'for', 'with', 'that', 'this', 'from', 'into', 'when', 'then', 'than', 'them',
  'they', 'their', 'has', 'have', 'are', 'was', 'were', 'will', 'would', 'can', 'could', 'should',
  'use', 'used', 'using', 'via', 'its', 'our', 'you', 'your', 'about', 'over', 'per', 'not', 'but',
  'all', 'any', 'how', 'why', 'what', 'which', 'who', 'where', 'task', 'work', 'need', 'want',
]);

function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .split(/[^a-z0-9+#]+/)
    .filter((token) => token.length >= 3 && !STOPWORDS.has(token));
}

function countOccurrences(haystack: string, needle: string): number {
  if (!needle) return 0;
  let count = 0;
  let index = haystack.indexOf(needle);
  while (index !== -1) {
    count += 1;
    index = haystack.indexOf(needle, index + needle.length);
  }
  return count;
}

interface ScoredSkill {
  skill: SkillManifest;
  score: number;
  matchedTerms: string[];
}

function scoreSkill(skill: SkillManifest, terms: string[]): ScoredSkill {
  const name = skill.name.toLowerCase();
  const description = skill.description.toLowerCase();
  const tags = skill.tags.map((t) => t.toLowerCase());
  const engines = skill.engines.map((e) => e.toLowerCase());
  const tools = skill.tools.map((t) => t.toLowerCase());
  const body = skill.body.toLowerCase();

  let score = 0;
  const matchedTerms: string[] = [];

  for (const term of terms) {
    let hits = 0;
    if (name.includes(term)) hits += 6;
    if (tags.some((t) => t.includes(term))) hits += 4;
    if (tools.some((t) => t.includes(term))) hits += 3;
    if (engines.some((e) => e.includes(term))) hits += 3;
    if (description.includes(term)) hits += 2;
    hits += Math.min(countOccurrences(body, term), 3);
    if (hits > 0) {
      score += hits;
      matchedTerms.push(term);
    }
  }

  return { skill, score, matchedTerms };
}

function firstSentence(text: string): string {
  const match = /^(.+?[.!?])(\s|$)/.exec(text.trim());
  return (match?.[1] ?? text).trim();
}

export class SkillRegistry {
  private readonly skills = new Map<string, SkillManifest>();

  constructor(manifests: SkillManifest[]) {
    for (const skill of manifests) {
      if (this.skills.has(skill.name)) {
        throw new Error(`Skill "${skill.name}" is already registered (duplicate name).`);
      }
      this.skills.set(skill.name, skill);
    }
  }

  get size(): number {
    return this.skills.size;
  }

  list(): SkillManifest[] {
    return [...this.skills.values()].sort((a, b) => a.name.localeCompare(b.name));
  }

  summaries(): SkillSummary[] {
    return this.list().map(toSkillSummary);
  }

  get(name: string): SkillManifest | undefined {
    return this.skills.get(name);
  }

  byEngine(engine: string): SkillManifest[] {
    return this.list().filter((s) => s.engines.includes(engine));
  }

  byTag(tag: string): SkillManifest[] {
    const target = tag.toLowerCase();
    return this.list().filter((s) => s.tags.some((t) => t.toLowerCase() === target));
  }

  /** Distinct engines and tags across the library (for discovery). */
  facets(): { engines: string[]; tags: string[] } {
    const engines = new Set<string>();
    const tags = new Set<string>();
    for (const skill of this.skills.values()) {
      skill.engines.forEach((e) => engines.add(e));
      skill.tags.forEach((t) => tags.add(t));
    }
    return { engines: [...engines].sort(), tags: [...tags].sort() };
  }

  /** Rank skills by relevance to a free-text query. */
  search(query: string, limit = 5): SkillRecommendation[] {
    const terms = tokenize(query);
    if (terms.length === 0) return [];
    return this.list()
      .map((skill) => scoreSkill(skill, terms))
      .filter((scored) => scored.score > 0)
      .sort((a, b) => b.score - a.score || a.skill.name.localeCompare(b.skill.name))
      .slice(0, limit)
      .map((scored) => ({
        name: scored.skill.name,
        score: scored.score,
        rationale: `Matched ${scored.matchedTerms.length} term(s): ${scored.matchedTerms.slice(0, 6).join(', ')}`,
        engines: scored.skill.engines,
        tools: scored.skill.tools,
      }));
  }

  /**
   * Select and combine skills for a task, producing an ordered tool plan and a
   * combined workflow. Optionally restrict to specific engines.
   */
  select(input: { task: string; limit?: number; engines?: string[] }): SkillSelection {
    const limit = Math.min(10, input.limit ?? 3);
    const terms = tokenize(input.task);
    const engineFilter = input.engines ?? [];

    const candidates = engineFilter.length
      ? this.list().filter((s) => s.engines.some((e) => engineFilter.includes(e)))
      : this.list();

    const scored = candidates
      .map((skill) => scoreSkill(skill, terms))
      .filter((s) => s.score > 0)
      .sort((a, b) => b.score - a.score || a.skill.name.localeCompare(b.skill.name))
      .slice(0, Math.max(1, limit));

    const recommendations: SkillRecommendation[] = scored.map((s) => ({
      name: s.skill.name,
      score: s.score,
      rationale: `Matched ${s.matchedTerms.length} term(s): ${s.matchedTerms.slice(0, 6).join(', ')}`,
      engines: s.skill.engines,
      tools: s.skill.tools,
    }));

    const warnings: string[] = [];
    if (recommendations.length === 0) {
      warnings.push(
        terms.length === 0
          ? 'Task description produced no usable keywords; provide a more specific task.'
          : 'No skill matched the task; fall back to direct engine tools or refine the task.',
      );
    }

    // Ordered, de-duplicated tool plan across the selected skills.
    const toolPlan: string[] = [];
    for (const s of scored) {
      for (const tool of s.skill.tools) {
        if (!toolPlan.includes(tool)) toolPlan.push(tool);
      }
    }

    const workflow = scored.map(
      (s, index) => `${index + 1}. ${s.skill.name} — ${firstSentence(s.skill.description)}`,
    );

    return { query: input.task, recommendations, toolPlan, workflow, warnings };
  }
}
