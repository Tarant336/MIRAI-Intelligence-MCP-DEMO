/**
 * Minimal, dependency-free YAML front-matter parser for SKILL.md files.
 *
 * Supports exactly the subset used by the Skills Library: `key: scalar`,
 * inline arrays (`key: [a, b]`) and block lists (`key:\n  - a\n  - b`).
 * This avoids adding a YAML dependency while keeping SKILL.md files portable.
 */

export interface ParsedFrontmatter {
  data: Record<string, string | string[]>;
  body: string;
}

function unquote(value: string): string {
  const v = value.trim();
  if (v.length >= 2) {
    const first = v[0];
    const last = v[v.length - 1];
    if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
      return v.slice(1, -1);
    }
  }
  return v;
}

export function parseFrontmatter(raw: string): ParsedFrontmatter {
  const normalised = raw.replace(/^\uFEFF/, '');
  const lines = normalised.split(/\r?\n/);
  if ((lines[0] ?? '').trim() !== '---') {
    return { data: {}, body: normalised };
  }

  let end = -1;
  for (let i = 1; i < lines.length; i += 1) {
    if ((lines[i] ?? '').trim() === '---') {
      end = i;
      break;
    }
  }
  if (end === -1) return { data: {}, body: normalised };

  const data: Record<string, string | string[]> = {};
  let currentKey: string | null = null;

  for (let i = 1; i < end; i += 1) {
    const line = lines[i] ?? '';
    if (!line.trim() || line.trim().startsWith('#')) continue;

    const listItem = /^\s*-\s+(.*)$/.exec(line);
    if (listItem && currentKey) {
      const previous = data[currentKey];
      const arr = Array.isArray(previous) ? previous : previous === undefined ? [] : [previous];
      arr.push(unquote(listItem[1] ?? ''));
      data[currentKey] = arr;
      continue;
    }

    const kv = /^([A-Za-z0-9_-]+)\s*:\s*(.*)$/.exec(line);
    if (!kv) continue;
    currentKey = kv[1] ?? null;
    if (currentKey === null) continue;

    const value = (kv[2] ?? '').trim();
    if (value === '') {
      data[currentKey] = [];
    } else if (value.startsWith('[') && value.endsWith(']')) {
      data[currentKey] = value
        .slice(1, -1)
        .split(',')
        .map((entry) => unquote(entry))
        .filter((entry) => entry.length > 0);
    } else {
      data[currentKey] = unquote(value);
    }
  }

  const body = lines
    .slice(end + 1)
    .join('\n')
    .replace(/^\n+/, '');
  return { data, body };
}
