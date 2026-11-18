/**
 * Internal helpers for the Software Engineering Intelligence engine.
 *
 * Everything here is deliberately dependency-free (no external glob or parser
 * packages) so the engine keeps working offline and with a minimal install
 * footprint. All routines are pure and bounded.
 */

import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

/** Directories that are never traversed during repository scans. */
export const IGNORE_DIRS: ReadonlySet<string> = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  'target',
  'venv',
  '__pycache__',
  '.venv',
  'vendor',
]);

/** File extension -> language / format name. */
export const LANGUAGE_BY_EXT: Record<string, string> = {
  '.ts': 'TypeScript',
  '.tsx': 'TypeScript',
  '.mts': 'TypeScript',
  '.cts': 'TypeScript',
  '.js': 'JavaScript',
  '.jsx': 'JavaScript',
  '.mjs': 'JavaScript',
  '.cjs': 'JavaScript',
  '.py': 'Python',
  '.pyi': 'Python',
  '.go': 'Go',
  '.rs': 'Rust',
  '.c': 'C',
  '.h': 'C',
  '.cc': 'C++',
  '.cpp': 'C++',
  '.cxx': 'C++',
  '.hpp': 'C++',
  '.hh': 'C++',
  '.hxx': 'C++',
  '.java': 'Java',
  '.kt': 'Kotlin',
  '.kts': 'Kotlin',
  '.cs': 'C#',
  '.rb': 'Ruby',
  '.php': 'PHP',
  '.swift': 'Swift',
  '.m': 'Objective-C',
  '.mm': 'Objective-C',
  '.sh': 'Shell',
  '.bash': 'Shell',
  '.zsh': 'Shell',
  '.ps1': 'PowerShell',
  '.sql': 'SQL',
  '.lua': 'Lua',
  '.pl': 'Perl',
  '.r': 'R',
  '.dart': 'Dart',
  '.scala': 'Scala',
  '.vue': 'Vue',
  '.svelte': 'Svelte',
  '.html': 'HTML',
  '.css': 'CSS',
  '.scss': 'SCSS',
  '.less': 'LESS',
  '.json': 'JSON',
  '.yaml': 'YAML',
  '.yml': 'YAML',
  '.toml': 'TOML',
  '.xml': 'XML',
  '.md': 'Markdown',
  '.rst': 'reStructuredText',
  '.txt': 'Text',
};

/** Extensions that count as "source code" for metrics and review. */
export const SOURCE_EXTENSIONS: ReadonlySet<string> =
  new Set([
    '.ts', '.tsx', '.mts', '.cts',
    '.js', '.jsx', '.mjs', '.cjs',
    '.py', '.pyi', '.go', '.rs',
    '.c', '.h', '.cc', '.cpp', '.cxx', '.hpp', '.hh',
    '.java', '.kt', '.kts', '.cs', '.rb', '.php', '.swift',
    '.m', '.mm', '.sh', '.bash', '.zsh', '.ps1', '.sql',
    '.lua', '.pl', '.dart', '.scala', '.vue', '.svelte',
  ]);

/** Extensions that are safe to read as UTF-8 text. */
export const TEXT_EXTENSIONS: ReadonlySet<string> =
  new Set([...SOURCE_EXTENSIONS, ...Object.keys(LANGUAGE_BY_EXT)]);

/** C-like languages where brace-based heuristics apply. */
const CODE_LANGUAGES = new Set([
  'TypeScript', 'JavaScript', 'Java', 'Kotlin', 'C#', 'C', 'C++', 'Objective-C',
  'Go', 'Rust', 'PHP', 'Swift', 'Dart', 'Scala', 'Shell',
]);

/** A file discovered by a directory walk. */
export interface WalkedFile {
  abs: string;
  /** POSIX-style path relative to the walk root. */
  rel: string;
  bytes: number;
}

/** Lower-cased extension (including the dot) of a path. */
export function extOf(path: string): string {
  const idx = path.lastIndexOf('.');
  const slash = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'));
  if (idx <= slash) return '';
  return path.slice(idx).toLowerCase();
}

/** Base name of a path (works for both separators). */
export function baseOf(path: string): string {
  const idx = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'));
  return idx === -1 ? path : path.slice(idx + 1);
}

/** Human language label derived from the file extension. */
export function languageOf(path: string): string {
  return LANGUAGE_BY_EXT[extOf(path)] ?? 'Other';
}

export function isSourcePath(path: string): boolean {
  return SOURCE_EXTENSIONS.has(extOf(path));
}

export function isTextPath(path: string): boolean {
  return TEXT_EXTENSIONS.has(extOf(path));
}

/**
 * Recursively walk a directory, skipping well-known vendor/build directories.
 * The walk is breadth-first-unbounded but capped by `maxFiles`.
 */
export function walkDirectory(
  root: string,
  options: { maxFiles?: number; maxDepth?: number } = {},
): WalkedFile[] {
  const maxFiles = options.maxFiles ?? 20000;
  const maxDepth = options.maxDepth ?? Number.POSITIVE_INFINITY;
  const out: WalkedFile[] = [];
  const stack: Array<{ dir: string; depth: number }> = [{ dir: root, depth: 0 }];

  while (stack.length > 0 && out.length < maxFiles) {
    const current = stack.pop();
    if (!current) break;
    let entries;
    try {
      entries = readdirSync(current.dir, { withFileTypes: true });
    } catch {
      continue;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));

    for (const entry of entries) {
      if (out.length >= maxFiles) break;
      const full = join(current.dir, entry.name);
      if (entry.isDirectory()) {
        if (IGNORE_DIRS.has(entry.name)) continue;
        if (current.depth + 1 > maxDepth) continue;
        stack.push({ dir: full, depth: current.depth + 1 });
      } else if (entry.isFile()) {
        let size = 0;
        try {
          size = statSync(full).size;
        } catch {
          continue;
        }
        out.push({ abs: full, rel: relative(root, full).split(sep).join('/'), bytes: size });
      }
    }
  }
  return out;
}

/** Heuristic binary detection: a NUL byte within the first 8 KiB. */
export function looksBinary(buffer: Buffer): boolean {
  const limit = Math.min(buffer.length, 8192);
  for (let i = 0; i < limit; i += 1) {
    if (buffer[i] === 0) return true;
  }
  return false;
}

/** Read a text file, refusing files above `maxBytes` or that look binary. */
export function readTextFileBounded(abs: string, maxBytes = 4 * 1024 * 1024): string | undefined {
  let size: number;
  try {
    size = statSync(abs).size;
  } catch {
    return undefined;
  }
  if (size > maxBytes) return undefined;
  try {
    const buffer = readFileSync(abs);
    if (looksBinary(buffer)) return undefined;
    return buffer.toString('utf8');
  } catch {
    return undefined;
  }
}

/** Convert a simple glob (`*`, `**`, `?`) into an anchored RegExp. */
export function globToRegExp(glob: string): RegExp {
  let out = '';
  for (let i = 0; i < glob.length; i += 1) {
    const c = glob[i] ?? '';
    if (c === '*') {
      if (glob[i + 1] === '*') {
        out += '.*';
        i += 1;
        if (glob[i + 1] === '/') i += 1;
      } else {
        out += '[^/]*';
      }
    } else if (c === '?') {
      out += '[^/]';
    } else if ('.+^${}()|[]\\'.includes(c)) {
      out += `\\${c}`;
    } else {
      out += c;
    }
  }
  return new RegExp(`^${out}$`);
}

/** Short deterministic hash used to disambiguate per-project slugs. */
export function shortHash(input: string): string {
  return createHash('sha1').update(input).digest('hex').slice(0, 8);
}

/** Normalize a project path into a stable, filesystem-safe slug. */
export function projectSlug(projectPath: string): string {
  const base = baseOf(projectPath.replace(/[\\/]+$/, '')) || 'root';
  const clean = base.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
  return `${clean || 'project'}-${shortHash(projectPath)}`;
}

/** Count TODO/FIXME markers in a text blob. */
export function countMarkers(text: string): { todo: number; fixme: number } {
  const todo = text.match(/\bTODO\b/gi)?.length ?? 0;
  const fixme = text.match(/\bFIXME\b/gi)?.length ?? 0;
  return { todo, fixme };
}

/* ------------------------------------------------------------------ */
/* Diagnostics parsing                                                */
/* ------------------------------------------------------------------ */

export interface Diagnostic {
  file?: string;
  line?: number;
  column?: number;
  severity: 'error' | 'warning' | 'note';
  message: string;
  raw: string;
}

function normalizeSeverity(value: string): 'error' | 'warning' | 'note' {
  const v = value.toLowerCase();
  if (v.startsWith('warning')) return 'warning';
  if (v.startsWith('note')) return 'note';
  return 'error';
}

/**
 * Parse compiler / test output into structured diagnostics.
 *
 * Supported shapes: gcc/clang (`file:line:col: error: msg`), TypeScript
 * (`file(line,col): error TSxxxx: msg`), rustc (`--> file:line:col` followed by
 * `error[Exxxx]: msg`) and generic `error:`/`warning:` lines.
 */
export function parseDiagnostics(output: string): Diagnostic[] {
  const results: Diagnostic[] = [];
  const lines = output.split(/\r?\n/);
  let pending: { file: string; line: number; column: number } | undefined;

  for (const raw of lines) {
    if (results.length >= 200) break;
    const trimmed = raw.trim();
    if (!trimmed) continue;

    const loc = /^\s*-->\s*(.+?):(\d+):(\d+)\s*$/.exec(raw);
    if (loc) {
      pending = { file: loc[1] ?? '', line: Number(loc[2]), column: Number(loc[3]) };
      continue;
    }

    const tsc = /^(.*?)\((\d+),(\d+)\):\s*(error|warning|fatal error)\b:?\s*(?:([A-Z]+\d+))?:?\s*(.*)$/i.exec(trimmed);
    if (tsc) {
      results.push({
        file: tsc[1],
        line: Number(tsc[2]),
        column: Number(tsc[3]),
        severity: normalizeSeverity(tsc[4] ?? 'error'),
        message: `${tsc[5] ? `${tsc[5]}: ` : ''}${tsc[6] ?? ''}`.trim(),
        raw,
      });
      pending = undefined;
      continue;
    }

    const ccCol = /^(.*?):(\d+):(\d+):\s*(fatal error|error|warning|note)\b:?\s*(.*)$/i.exec(trimmed);
    if (ccCol) {
      results.push({
        file: ccCol[1],
        line: Number(ccCol[2]),
        column: Number(ccCol[3]),
        severity: normalizeSeverity(ccCol[4] ?? 'error'),
        message: ccCol[5] ?? '',
        raw,
      });
      pending = undefined;
      continue;
    }

    const ccNoCol = /^(.*?):(\d+):\s*(fatal error|error|warning|note)\b:?\s*(.*)$/i.exec(trimmed);
    if (ccNoCol) {
      results.push({
        file: ccNoCol[1],
        line: Number(ccNoCol[2]),
        severity: normalizeSeverity(ccNoCol[3] ?? 'error'),
        message: ccNoCol[4] ?? '',
        raw,
      });
      pending = undefined;
      continue;
    }

    const generic = /^(error|warning)(?:\[[^\]]+\])?:\s*(.*)$/i.exec(trimmed);
    if (generic) {
      results.push({
        ...(pending ? { file: pending.file, line: pending.line, column: pending.column } : {}),
        severity: normalizeSeverity(generic[1] ?? 'error'),
        message: generic[2] ?? trimmed,
        raw,
      });
      pending = undefined;
    }
  }
  return results;
}

/* ------------------------------------------------------------------ */
/* Function / brace heuristics                                        */
/* ------------------------------------------------------------------ */

export interface FunctionSpan {
  name: string;
  startLine: number;
  endLine: number;
  length: number;
}

/** Compute per-line net brace delta plus the maximum nesting depth. */
export function braceMetrics(lines: string[]): { deltas: number[]; maxDepth: number } {
  const deltas: number[] = [];
  let depth = 0;
  let maxDepth = 0;
  let inBlockComment = false;

  for (const raw of lines) {
    let delta = 0;
    let i = 0;
    let inLineComment = false;
    let quote: string | undefined;

    while (i < raw.length) {
      const c = raw[i] ?? '';
      const next = raw[i + 1];
      if (inBlockComment) {
        if (c === '*' && next === '/') {
          inBlockComment = false;
          i += 2;
          continue;
        }
        i += 1;
        continue;
      }
      if (inLineComment) break;
      if (quote) {
        if (c === '\\') {
          i += 2;
          continue;
        }
        if (c === quote) quote = undefined;
        i += 1;
        continue;
      }
      if (c === '/' && next === '/') {
        inLineComment = true;
        i += 2;
        continue;
      }
      if (c === '/' && next === '*') {
        inBlockComment = true;
        i += 2;
        continue;
      }
      if (c === '"' || c === "'" || c === '`') {
        quote = c;
        i += 1;
        continue;
      }
      if (c === '{') delta += 1;
      else if (c === '}') delta -= 1;
      i += 1;
    }

    deltas.push(delta);
    depth += delta;
    if (depth > maxDepth) maxDepth = depth;
  }
  return { deltas, maxDepth };
}

function pythonFunctionSpans(lines: string[]): FunctionSpan[] {
  const spans: FunctionSpan[] = [];
  const defRe = /^(\s*)(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/;
  for (let i = 0; i < lines.length; i += 1) {
    const m = defRe.exec(lines[i] ?? '');
    if (!m) continue;
    const indent = (m[1] ?? '').length;
    let end = i;
    for (let j = i + 1; j < lines.length; j += 1) {
      const line = lines[j] ?? '';
      if (!line.trim()) {
        end = j;
        continue;
      }
      const ind = line.length - line.trimStart().length;
      if (ind <= indent) break;
      end = j;
    }
    spans.push({ name: m[2] ?? 'anonymous', startLine: i + 1, endLine: end + 1, length: end - i + 1 });
    i = end;
  }
  return spans;
}

/** Coarse function-span detection used for length and nesting heuristics. */
export function findFunctionSpans(lines: string[], language: string): FunctionSpan[] {
  if (language === 'Python') return pythonFunctionSpans(lines);
  if (!CODE_LANGUAGES.has(language)) return [];

  const { deltas } = braceMetrics(lines);
  const patterns = [
    /\b(?:function|fn|func)\s+([A-Za-z_$][\w$]*)/,
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)\s*=>|function\b)/,
    /^\s*(?:[A-Za-z_$][\w$<>,[\]\s*&]*\s+)?([A-Za-z_$][\w$]*)\s*\([^;{}]*\)\s*(?::\s*[^;{]+)?\{\s*$/,
  ];

  const spans: FunctionSpan[] = [];
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i] ?? '';
    if (!line.trim()) continue;
    if (!line.includes('{') && !/\b(function|fn|func)\b/.test(line) && !line.includes('=>')) continue;

    let name: string | undefined;
    for (const re of patterns) {
      const m = re.exec(line);
      if (m && m[1]) {
        name = m[1];
        break;
      }
    }
    if (!name) continue;

    let depth = 0;
    let started = false;
    let end = i;
    for (let j = i; j < lines.length; j += 1) {
      const d = deltas[j] ?? 0;
      depth += d;
      if (d > 0) started = true;
      end = j;
      if (started && depth <= 0) break;
    }
    spans.push({ name, startLine: i + 1, endLine: end + 1, length: end - i + 1 });
    i = end;
  }
  return spans;
}

/* ------------------------------------------------------------------ */
/* Import extraction                                                  */
/* ------------------------------------------------------------------ */

const IMPORT_PATTERNS: RegExp[] = [
  /import\s+[^'";]*?from\s*['"]([^'"]+)['"]/g,
  /import\s*['"]([^'"]+)['"]/g,
  /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
  /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
  /^\s*from\s+([A-Za-z_][\w.]*)\s+import\b/gm,
  /^\s*import\s+([A-Za-z_][\w.]*)/gm,
  /^\s*use\s+([A-Za-z_][\w:]*)/gm,
  /^\s*import\s+([A-Za-z_][\w.]*)\s*;/gm,
];

/** Extract unique import specifiers from source text. */
export function extractImportSpecifiers(text: string): string[] {
  const found = new Set<string>();
  for (const re of IMPORT_PATTERNS) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const spec = m[1];
      if (spec && spec.trim()) found.add(spec.trim());
      if (m.index === re.lastIndex) re.lastIndex += 1;
    }
  }
  return [...found];
}

/**
 * Map an import specifier to an internal top-level module when it resolves to
 * a path inside the repository; returns undefined for external packages.
 */
export function toImportModule(
  spec: string,
  fileRel: string,
  topLevel: Set<string>,
): string | undefined {
  const dir = fileRel.includes('/') ? fileRel.slice(0, fileRel.lastIndexOf('/')) : '';

  if (spec.startsWith('.') || spec.startsWith('/')) {
    const parts = (spec.startsWith('/') ? [] : dir ? dir.split('/') : []).concat(
      spec.split('/'),
    );
    const stack: string[] = [];
    for (const part of parts) {
      if (part === '' || part === '.') continue;
      if (part === '..') stack.pop();
      else stack.push(part);
    }
    const seg = stack[0];
    return seg && topLevel.has(seg) ? seg : seg ?? '(root)';
  }

  const seg = spec.split(/[.:]/)[0] ?? spec;
  return topLevel.has(seg) ? seg : undefined;
}

/* ------------------------------------------------------------------ */
/* Manifest parsing                                                   */
/* ------------------------------------------------------------------ */

export interface DependencyEntry {
  name: string;
  version: string;
  ecosystem: string;
  manifestFile: string;
  kind: string;
}

interface RawJson {
  dependencies?: Record<string, unknown>;
  devDependencies?: Record<string, unknown>;
  peerDependencies?: Record<string, unknown>;
  optionalDependencies?: Record<string, unknown>;
  scripts?: Record<string, unknown>;
}

export function parsePackageJson(text: string, manifestFile: string): DependencyEntry[] {
  const out: DependencyEntry[] = [];
  let json: RawJson;
  try {
    json = JSON.parse(text) as RawJson;
  } catch {
    return out;
  }
  const sections: Array<[keyof RawJson, string]> = [
    ['dependencies', 'dependency'],
    ['devDependencies', 'devDependency'],
    ['peerDependencies', 'peerDependency'],
    ['optionalDependencies', 'optionalDependency'],
  ];
  for (const [key, kind] of sections) {
    const obj = json[key];
    if (obj && typeof obj === 'object') {
      for (const [name, version] of Object.entries(obj)) {
        out.push({ name, version: String(version), ecosystem: 'npm', manifestFile, kind });
      }
    }
  }
  return out;
}

export function parseRequirementsTxt(text: string, manifestFile: string): DependencyEntry[] {
  const out: DependencyEntry[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith('-')) continue;
    const m = /^([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*(?:[=<>!~]=?\s*(.+))?$/.exec(line);
    if (!m || !m[1]) continue;
    out.push({
      name: m[1],
      version: (m[2] ?? '').trim(),
      ecosystem: 'pip',
      manifestFile,
      kind: 'dependency',
    });
  }
  return out;
}

export function parseCargoToml(text: string, manifestFile: string): DependencyEntry[] {
  const out: DependencyEntry[] = [];
  const sectionKind: Record<string, string> = {
    dependencies: 'dependency',
    'dev-dependencies': 'devDependency',
    'build-dependencies': 'buildDependency',
  };
  let kind: string | undefined;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    const header = /^\[([^\]]+)\]$/.exec(line);
    if (header) {
      const name = header[1] ?? '';
      kind = sectionKind[name] ?? (name.endsWith('.dependencies') ? 'dependency' : undefined);
      continue;
    }
    if (!kind || !line || line.startsWith('#')) continue;
    const simple = /^([A-Za-z0-9_.\-]+)\s*=\s*"([^"]*)"/.exec(line);
    if (simple && simple[1]) {
      out.push({ name: simple[1], version: simple[2] ?? '', ecosystem: 'cargo', manifestFile, kind });
      continue;
    }
    const table = /^([A-Za-z0-9_.\-]+)\s*=\s*\{([^}]*)\}/.exec(line);
    if (table && table[1]) {
      const ver = /version\s*=\s*"([^"]*)"/.exec(table[2] ?? '');
      out.push({ name: table[1], version: ver?.[1] ?? '', ecosystem: 'cargo', manifestFile, kind });
    }
  }
  return out;
}

export function parseGoMod(text: string, manifestFile: string): DependencyEntry[] {
  const out: DependencyEntry[] = [];
  let inBlock = false;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line.startsWith('require (')) {
      inBlock = true;
      continue;
    }
    if (inBlock && line === ')') {
      inBlock = false;
      continue;
    }
    const single = /^require\s+(\S+)\s+(\S+)/.exec(line);
    const blockItem = inBlock ? /^(\S+)\s+(\S+)/.exec(line) : null;
    const m = single ?? blockItem;
    if (!m || !m[1]) continue;
    if (m[1].startsWith('//')) continue;
    out.push({
      name: m[1],
      version: m[2] ?? '',
      ecosystem: 'go',
      manifestFile,
      kind: line.includes('// indirect') ? 'indirect' : 'dependency',
    });
  }
  return out;
}

export function parsePomXml(text: string, manifestFile: string): DependencyEntry[] {
  const out: DependencyEntry[] = [];
  const depRe = /<dependency>([\s\S]*?)<\/dependency>/g;
  let m: RegExpExecArray | null;
  const tag = (block: string, name: string): string | undefined => {
    const res = new RegExp(`<${name}>([^<]*)</${name}>`).exec(block);
    return res?.[1]?.trim();
  };
  while ((m = depRe.exec(text)) !== null) {
    const block = m[1] ?? '';
    const groupId = tag(block, 'groupId');
    const artifactId = tag(block, 'artifactId');
    if (!artifactId) continue;
    const scope = tag(block, 'scope');
    out.push({
      name: groupId ? `${groupId}:${artifactId}` : artifactId,
      version: tag(block, 'version') ?? '',
      ecosystem: 'maven',
      manifestFile,
      kind: scope === 'test' ? 'test' : 'dependency',
    });
  }
  return out;
}

export function parseGradle(text: string, manifestFile: string): DependencyEntry[] {
  const out: DependencyEntry[] = [];
  const re = /\b(implementation|api|compileOnly|runtimeOnly|testImplementation|androidTestImplementation|kapt|annotationProcessor)\s*[( ]\s*['"]([^'"]+)['"]/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const conf = m[1] ?? 'implementation';
    const spec = m[2] ?? '';
    const parts = spec.split(':');
    if (parts.length < 2) continue;
    out.push({
      name: parts.length >= 3 ? `${parts[0]}:${parts[1]}` : parts[0] ?? spec,
      version: parts[2] ?? '',
      ecosystem: 'gradle',
      manifestFile,
      kind: /test/i.test(conf) ? 'test' : 'dependency',
    });
  }
  return out;
}

export function parsePyprojectToml(text: string, manifestFile: string): DependencyEntry[] {
  const out: DependencyEntry[] = [];
  const lines = text.split(/\r?\n/);
  let mode: 'poetry' | 'poetry-dev' | 'pep621' | undefined;
  let inArray = false;

  for (const raw of lines) {
    const line = raw.trim();
    const header = /^\[([^\]]+)\]$/.exec(line);
    if (header) {
      const name = header[1] ?? '';
      if (name === 'tool.poetry.dependencies') mode = 'poetry';
      else if (name === 'tool.poetry.dev-dependencies' || name === 'tool.poetry.group.dev.dependencies') mode = 'poetry-dev';
      else if (name === 'project') mode = 'pep621';
      else if (mode === 'pep621' && name !== 'project') mode = undefined;
      inArray = false;
      continue;
    }

    if (mode === 'pep621') {
      if (!inArray && /^dependencies\s*=\s*\[/.test(line)) {
        inArray = true;
      }
      if (!inArray) continue;
      const items = line.replace(/^dependencies\s*=\s*\[/, '').replace(/\]\s*,?\s*$/, '');
      if (/\]\s*,?\s*$/.test(line)) inArray = false;
      for (const piece of items.split(',')) {
        const spec = piece.trim().replace(/^["']|["']$/g, '').trim();
        if (!spec) continue;
        const m = /^([A-Za-z0-9_.\-]+)\s*(.*)$/.exec(spec);
        if (!m || !m[1]) continue;
        out.push({ name: m[1], version: (m[2] ?? '').trim(), ecosystem: 'pip', manifestFile, kind: 'dependency' });
      }
      continue;
    }

    if (mode === 'poetry' || mode === 'poetry-dev') {
      if (!line || line.startsWith('#')) continue;
      const simple = /^([A-Za-z0-9_.\-]+)\s*=\s*"([^"]*)"/.exec(line);
      if (simple && simple[1] && simple[1] !== 'python') {
        out.push({
          name: simple[1],
          version: simple[2] ?? '',
          ecosystem: 'pip',
          manifestFile,
          kind: mode === 'poetry-dev' ? 'devDependency' : 'dependency',
        });
        continue;
      }
      const table = /^([A-Za-z0-9_.\-]+)\s*=\s*\{([^}]*)\}/.exec(line);
      if (table && table[1] && table[1] !== 'python') {
        const ver = /version\s*=\s*"([^"]*)"/.exec(table[2] ?? '');
        out.push({
          name: table[1],
          version: ver?.[1] ?? '',
          ecosystem: 'pip',
          manifestFile,
          kind: mode === 'poetry-dev' ? 'devDependency' : 'dependency',
        });
      }
    }
  }
  return out;
}

/** Severity ordering used to prioritise review findings. */
export const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};
