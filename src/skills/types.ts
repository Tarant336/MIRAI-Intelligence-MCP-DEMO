/**
 * Skill system types (MIRAI Skills Library).
 *
 * A skill is a reusable, documented technical capability stored as a
 * `skills/<name>/SKILL.md` file with YAML front-matter. Skills orchestrate the
 * existing engine tools; they never duplicate their functionality.
 */

/** Parsed YAML front-matter of a SKILL.md file. */
export interface SkillFrontmatter {
  name?: string;
  description?: string;
  version?: string;
  engines?: string[];
  tags?: string[];
  tools?: string[];
  license?: string;
}

/** A fully loaded, validated skill. */
export interface SkillManifest {
  name: string;
  description: string;
  version: string;
  /** Engine names this skill draws on (must reference existing engines). */
  engines: string[];
  /** Free-form discovery tags. */
  tags: string[];
  /** MCP tool names this skill instructs the agent to use. */
  tools: string[];
  license?: string;
  /** Absolute path to the SKILL.md file. */
  path: string;
  /** Markdown body (after front-matter). */
  body: string;
  /** File size in bytes. */
  bytes: number;
}

/** Compact, list-friendly projection of a skill. */
export interface SkillSummary {
  name: string;
  description: string;
  version: string;
  engines: string[];
  tags: string[];
  tools: string[];
}

/** A single ranked skill recommendation produced by `select`. */
export interface SkillRecommendation {
  name: string;
  score: number;
  rationale: string;
  engines: string[];
  tools: string[];
}

/** Result of selecting and combining skills for a task. */
export interface SkillSelection {
  query: string;
  recommendations: SkillRecommendation[];
  /** Ordered, de-duplicated union of the tools referenced by the selected skills. */
  toolPlan: string[];
  /** Human-readable combined workflow derived from the selected skills. */
  workflow: string[];
  /** Non-fatal problems (e.g. no skill matched). */
  warnings: string[];
}

export function toSkillSummary(skill: SkillManifest): SkillSummary {
  return {
    name: skill.name,
    description: skill.description,
    version: skill.version,
    engines: skill.engines,
    tags: skill.tags,
    tools: skill.tools,
  };
}
