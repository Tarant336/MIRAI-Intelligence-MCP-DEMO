/**
 * Skill Loader — automatic discovery of `skills/<name>/SKILL.md` files.
 *
 * Scans a skills root directory (default: `<package root>/skills`, overridable
 * via `MIRAI_SKILLS_DIR`), parses each SKILL.md and validates its front-matter.
 * Invalid skills are reported as errors and skipped rather than crashing the
 * whole library.
 */

import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { parseFrontmatter } from './frontmatter.js';
import type { SkillManifest } from './types.js';

/** Skill directory names use kebab-case (distinct from MCP tool names). */
const SKILL_NAME_PATTERN = /^[a-z][a-z0-9-]{2,63}$/;

/** Resolve the default skills root: env override, else `<package>/skills`. */
export function defaultSkillsRoot(): string {
  const override = process.env.MIRAI_SKILLS_DIR;
  if (override) return resolve(override);
  const here = dirname(fileURLToPath(import.meta.url));
  // here = <root>/src/skills (dev) or <root>/dist/skills (built) → <root>/skills
  return resolve(here, '..', '..', 'skills');
}

function asStringList(value: string | string[] | undefined): string[] {
  if (value === undefined) return [];
  return Array.isArray(value) ? value : [value];
}

/** Parse and validate a single SKILL.md file. Throws on invalid front-matter. */
export function parseSkillFile(path: string): SkillManifest {
  const raw = readFileSync(path, 'utf8');
  const { data, body } = parseFrontmatter(raw);

  const name = typeof data.name === 'string' ? data.name.trim() : '';
  const description = typeof data.description === 'string' ? data.description.trim() : '';

  if (!name) throw new Error(`SKILL.md at ${path} is missing a "name".`);
  if (!SKILL_NAME_PATTERN.test(name)) {
    throw new Error(`Skill name "${name}" must match ${SKILL_NAME_PATTERN}.`);
  }
  if (!description) throw new Error(`Skill "${name}" is missing a "description".`);
  if (!body.trim()) throw new Error(`Skill "${name}" has an empty body.`);

  const version = typeof data.version === 'string' && data.version ? data.version : '0.0.0';

  const manifest: SkillManifest = {
    name,
    description,
    version,
    engines: asStringList(data.engines),
    tags: asStringList(data.tags),
    tools: asStringList(data.tools),
    path,
    body,
    bytes: Buffer.byteLength(raw, 'utf8'),
  };
  if (typeof data.license === 'string' && data.license) manifest.license = data.license;
  return manifest;
}

export interface LoadResult {
  skills: SkillManifest[];
  /** Files that failed validation, with the reason. */
  errors: Array<{ path: string; message: string }>;
  /** The directory that was scanned. */
  root: string;
}

/** Discover and load every skill under `root` (defaults to the package skills dir). */
export function loadSkills(root: string = defaultSkillsRoot()): LoadResult {
  const skills: SkillManifest[] = [];
  const errors: LoadResult['errors'] = [];

  if (!existsSync(root)) {
    return { skills, errors: [{ path: root, message: `Skills root "${root}" does not exist.` }], root };
  }

  for (const entry of readdirSync(root, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const skillFile = join(root, entry.name, 'SKILL.md');
    if (!existsSync(skillFile)) continue;
    try {
      if (!statSync(skillFile).isFile()) continue;
      skills.push(parseSkillFile(skillFile));
    } catch (err) {
      errors.push({ path: skillFile, message: err instanceof Error ? err.message : String(err) });
    }
  }

  skills.sort((a, b) => a.name.localeCompare(b.name));
  return { skills, errors, root };
}
