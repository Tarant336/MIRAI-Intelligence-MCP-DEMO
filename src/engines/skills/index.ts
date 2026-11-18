/**
 * Skills engine — the MIRAI Skills Library surface.
 *
 * Exposes the auto-discovered skills (see `loader.ts`) as MCP tools so an agent
 * can list, inspect and *select/combine* skills for a complex task. Skills
 * orchestrate the existing engines; they add no new offensive capability.
 */

import { z } from 'zod';

import { errors, logger } from '../../tools/helpers.js';
import { defineTool, finish, localProvenance } from '../../tools/helpers.js';
import { loadSkills, defaultSkillsRoot } from '../../skills/loader.js';
import { SkillRegistry } from '../../skills/registry.js';
import { toSkillSummary } from '../../skills/types.js';
import type { EngineModule } from '../../core/tool.js';
import type { LoadResult } from '../../skills/loader.js';

const ENGINE = 'skills';

interface LoadedSkills {
  registry: SkillRegistry;
  errors: LoadResult['errors'];
  root: string;
}

let cached: LoadedSkills | undefined;

/** Load (once) and return the skills registry plus any load errors. */
export function getSkillRegistry(): LoadedSkills {
  if (!cached) {
    const result = loadSkills();
    cached = { registry: new SkillRegistry(result.skills), errors: result.errors, root: result.root };
    logger.info('skills.loaded', { root: result.root, skills: result.skills.length, errors: result.errors.length });
  }
  return cached;
}

/** Reset the cached registry — used by tests. */
export function resetSkillRegistry(): void {
  cached = undefined;
}

interface SkillListInput {
  engine?: string;
  tag?: string;
  limit?: number;
}

interface SkillListOutput {
  root: string;
  total: number;
  returned: number;
  facets: { engines: string[]; tags: string[] };
  skills: ReturnType<typeof toSkillSummary>[];
}

interface SkillGetOutput {
  skill: {
    name: string;
    description: string;
    version: string;
    engines: string[];
    tags: string[];
    tools: string[];
    license?: string;
    path: string;
    bytes: number;
    body: string;
  };
}

interface SkillSelectInput {
  task: string;
  limit?: number;
  engines?: string[];
}

export const skillsEngine: EngineModule = {
  name: ENGINE,
  title: 'Skills Library',
  description:
    'Reusable, versioned technical skills that orchestrate the platform engines: discovery, inspection ' +
    'and multi-skill selection for complex tasks. Each skill documents its purpose, prerequisites, ' +
    'procedure, required tools and verification criteria.',
  tools: [
    defineTool<SkillListInput, SkillListOutput>({
      name: 'skill_list',
      title: 'List skills',
      engine: ENGINE,
      description:
        'List the technical skills available in the Skills Library, optionally filtered by engine or tag. ' +
        'Returns each skill\'s name, description, associated engines, tags and the tools it uses.',
      capabilities: ['read_repo'],
      risk: 'safe',
      inputSchema: {
        engine: z.string().optional().describe('Only return skills that draw on this engine.'),
        tag: z.string().optional().describe('Only return skills carrying this tag.'),
        limit: z.number().int().min(1).max(200).optional().describe('Maximum skills to return.'),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const { registry, errors: loadErrors, root } = getSkillRegistry();
        let skills = registry.list();
        if (input.engine) {
          const engine = input.engine;
          skills = skills.filter((s: typeof skills[0]) => s.engines.includes(engine));
        }
        if (input.tag) {
          const tag = input.tag.toLowerCase();
          skills = skills.filter((s: typeof skills[0]) => s.tags.some((t: string) => t.toLowerCase() === tag));
        }
        const total = skills.length;
        const limited = typeof input.limit === 'number' ? skills.slice(0, input.limit) : skills;

        ctx.evidence.add({
          claim: `Skills Library scanned: ${total} skill(s) matched.`,
          provenance: localProvenance('skills-library', root),
          confidence: 'observed',
          data: { total, returned: limited.length },
        });

        return finish<SkillListOutput>({
          engine: ENGINE,
          tool: 'skill_list',
          startedAt: started,
          ctx,
          data: {
            root,
            total,
            returned: limited.length,
            facets: registry.facets(),
            skills: limited.map(toSkillSummary),
          },
          warnings: loadErrors.map((e) => `${e.path}: ${e.message}`),
          summary:
            `Skills Library: ${total} skill(s) matched (${registry.size} total).\n` +
            limited.map((s: typeof skills[0]) => `- ${s.name} v${s.version} [${s.engines.join(', ')}]`).join('\n'),
        });
      },
    }),

    defineTool<{ name: string }, SkillGetOutput>({
      name: 'skill_get',
      title: 'Get skill',
      engine: ENGINE,
      description:
        'Retrieve a single skill by name, including its full SKILL.md body (purpose, prerequisites, inputs/' +
        'outputs, procedure, examples, limitations and verification criteria) and the tools it uses.',
      capabilities: ['read_repo'],
      risk: 'safe',
      inputSchema: {
        name: z.string().min(1).describe('Skill name, e.g. "typescript-development".'),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const { registry } = getSkillRegistry();
        const skill = registry.get(input.name);
        if (!skill) throw errors.notFound(`Skill "${input.name}"`, { name: input.name });

        ctx.evidence.add({
          claim: `Loaded skill "${skill.name}" (v${skill.version}).`,
          provenance: localProvenance('skills-library', skill.path),
          confidence: 'observed',
          locator: { file: skill.path },
        });

        const data: SkillGetOutput = {
          skill: {
            name: skill.name,
            description: skill.description,
            version: skill.version,
            engines: skill.engines,
            tags: skill.tags,
            tools: skill.tools,
            ...(skill.license ? { license: skill.license } : {}),
            path: skill.path,
            bytes: skill.bytes,
            body: skill.body,
          },
        };

        return finish<SkillGetOutput>({
          engine: ENGINE,
          tool: 'skill_get',
          startedAt: started,
          ctx,
          data,
          summary:
            `# ${skill.name} (v${skill.version})\n` +
            `Engines: ${skill.engines.join(', ') || '—'}\n` +
            `Tools: ${skill.tools.join(', ') || '—'}\n\n${skill.body}`,
        });
      },
    }),

    defineTool<SkillSelectInput, ReturnType<SkillRegistry['select']>>({
      name: 'skill_select',
      title: 'Select and combine skills',
      engine: ENGINE,
      description:
        'Given a task description, rank the most relevant skills and combine them into an ordered tool ' +
        'plan and workflow. Use this to decide which skills (and engine tools) to apply to a complex task.',
      capabilities: ['read_repo'],
      risk: 'safe',
      inputSchema: {
        task: z.string().min(1).describe('Free-text description of the task to accomplish.'),
        limit: z.number().int().min(1).max(10).optional().describe('Maximum skills to select (default 3, max 10).'),
        engines: z
          .array(z.string())
          .optional()
          .describe('Restrict selection to skills that draw on any of these engines.'),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const { registry } = getSkillRegistry();
        const selection = registry.select({
          task: input.task,
          ...(input.limit !== undefined ? { limit: input.limit } : {}),
          ...(input.engines ? { engines: input.engines } : {}),
        });

        ctx.evidence.add({
          claim: `Selected ${selection.recommendations.length} skill(s) for the task.`,
          provenance: localProvenance('skills-library', defaultSkillsRoot()),
          confidence: 'inferred',
          data: { selected: selection.recommendations.map((r: typeof selection.recommendations[0]) => r.name) },
        });

        const body = selection.recommendations.length
          ? selection.recommendations
              .map((r: typeof selection.recommendations[0]) => `- ${r.name} (score ${r.score}): ${r.rationale}`)
              .join('\n')
          : '- (no skill matched)';

        return finish<ReturnType<SkillRegistry['select']>>({
          engine: ENGINE,
          tool: 'skill_select',
          startedAt: started,
          ctx,
          data: selection,
          warnings: selection.warnings,
          summary:
            `Task: ${input.task}\nSelected skills:\n${body}\n` +
            `Tool plan (${selection.toolPlan.length}): ${selection.toolPlan.join(' → ') || '—'}`,
        });
      },
    }),
  ],
};
