/**
 * Engine A — Software Engineering Intelligence.
 *
 * Pure software-engineering capability: repository understanding, dependency
 * and architecture modelling, documentation and symbol discovery, code review
 * and quality metrics, deterministic local source mutation, and sandboxed
 * build / test execution. This engine contains ZERO offensive capability.
 */

import { existsSync, mkdirSync, renameSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';

import { z } from 'zod';

import { getConfig } from '../../config/index.js';
import { collectEnvironmentReport } from '../../core/environment.js';
import type { EngineModule, ToolContext } from '../../core/tool.js';
import { runCommand, toolOnPathSync, type ExecResult } from '../../shared/exec.js';
import type { KnowledgeRecord } from '../../shared/knowledge-base.js';
import { assertArtifactSize, resolveWorkspacePath } from '../../shared/security.js';
import {
  addEvidence,
  defineTool,
  errors,
  finish,
  localProvenance,
  readTextArtifact,
  sha256,
} from '../../tools/helpers.js';
import {
  baseOf,
  braceMetrics,
  countMarkers,
  extractImportSpecifiers,
  extOf,
  findFunctionSpans,
  globToRegExp,
  isSourcePath,
  isTextPath,
  languageOf,
  parseCargoToml,
  parseDiagnostics,
  parseGoMod,
  parseGradle,
  parsePackageJson,
  parsePomXml,
  parsePyprojectToml,
  parseRequirementsTxt,
  projectSlug,
  readTextFileBounded,
  SEVERITY_RANK,
  toImportModule,
  walkDirectory,
  type DependencyEntry,
  type Diagnostic,
} from './internal.js';

const ENGINE = 'software-engineering';

/** CONTENT_SCAN_LIMIT caps per-file reads during bulk scans. */
const CONTENT_SCAN_LIMIT = 2 * 1024 * 1024;

/* ------------------------------------------------------------------ */
/* Shared helpers                                                     */
/* ------------------------------------------------------------------ */

function resolveRoot(pathInput: string | undefined): string {
  const target = pathInput && pathInput.trim() ? pathInput : '.';
  const abs = resolveWorkspacePath(target, true);
  let stat;
  try {
    stat = statSync(abs);
  } catch {
    throw errors.notFound(`Path "${target}"`);
  }
  if (!stat.isDirectory()) {
    throw errors.invalidInput(`Path "${target}" is not a directory.`, { path: abs });
  }
  return abs;
}

function resolveFile(pathInput: string): string {
  const abs = resolveWorkspacePath(pathInput, true);
  let stat;
  try {
    stat = statSync(abs);
  } catch {
    throw errors.notFound(`File "${pathInput}"`);
  }
  if (!stat.isFile()) {
    throw errors.invalidInput(`Path "${pathInput}" is not a file.`, { path: abs });
  }
  return abs;
}

/** Windows resolves `.cmd` shims only when the extension is present. */
const WIN_CMD_TOOLS = new Set([
  'npm', 'npx', 'yarn', 'pnpm', 'tsc', 'mvn', 'gradle', 'gradlew',
  'eslint', 'jest', 'vitest', 'vite', 'webpack', 'next',
]);

function platformCommand(command: string): string {
  if (process.platform !== 'win32') return command;
  if (/\.(exe|cmd|bat|ps1)$/i.test(command)) return command;
  return WIN_CMD_TOOLS.has(command) ? `${command}.cmd` : command;
}

async function exec(
  cwd: string,
  command: string,
  args: string[],
  timeoutMs?: number,
): Promise<ExecResult> {
  return runCommand(platformCommand(command), {
    args,
    cwd,
    ...(timeoutMs ? { timeoutMs } : {}),
  });
}

function listRootNames(root: string): string[] {
  try {
    return walkDirectory(root, { maxFiles: 5000, maxDepth: 1 }).map((f) => f.rel);
  } catch {
    return [];
  }
}

function packageManager(root: string): string {
  if (existsSync(join(root, 'pnpm-lock.yaml'))) return 'pnpm';
  if (existsSync(join(root, 'yarn.lock'))) return 'yarn';
  return 'npm';
}

interface DetectedCommand {
  command: string;
  args: string[];
  reason: string;
}

function detectBuildCommand(root: string): DetectedCommand | undefined {
  const names = new Set(listRootNames(root));

  if (names.has('package.json')) {
    if (existsSync(join(root, 'package.json'))) {
      const text = readTextFileBounded(join(root, 'package.json'), 1_000_000);
      if (text) {
        try {
          const json = JSON.parse(text) as { scripts?: Record<string, string> };
          if (json.scripts && typeof json.scripts.build === 'string') {
            const pm = packageManager(root);
            return { command: pm, args: ['run', 'build'], reason: `package.json scripts.build via ${pm}` };
          }
        } catch {
          /* ignore malformed manifest */
        }
      }
    }
  }
  if (names.has('Cargo.toml')) return { command: 'cargo', args: ['build'], reason: 'Cargo.toml' };
  if (names.has('go.mod')) return { command: 'go', args: ['build', './...'], reason: 'go.mod' };
  if (names.has('pom.xml')) return { command: 'mvn', args: ['-q', '-DskipTests', 'package'], reason: 'pom.xml (maven)' };
  if (names.has('build.gradle') || names.has('build.gradle.kts')) {
    const gradlew = process.platform === 'win32' ? 'gradlew.bat' : './gradlew';
    if (existsSync(join(root, process.platform === 'win32' ? 'gradlew.bat' : 'gradlew'))) {
      return { command: gradlew, args: ['build'], reason: 'gradle wrapper' };
    }
    return { command: 'gradle', args: ['build'], reason: 'build.gradle' };
  }
  if ([...names].some((n) => n.endsWith('.csproj'))) {
    return { command: 'dotnet', args: ['build'], reason: '*.csproj (dotnet)' };
  }
  if (names.has('CMakeLists.txt')) {
    if (existsSync(join(root, 'build'))) return { command: 'cmake', args: ['--build', 'build'], reason: 'CMakeLists.txt + build/' };
    if (names.has('Makefile')) return { command: 'make', args: [], reason: 'Makefile (cmake project)' };
  }
  if (names.has('Makefile') || names.has('makefile')) return { command: 'make', args: [], reason: 'Makefile' };
  return undefined;
}

function detectTestCommand(root: string): DetectedCommand | undefined {
  const names = new Set(listRootNames(root));

  if (names.has('Cargo.toml')) return { command: 'cargo', args: ['test'], reason: 'Cargo.toml' };
  if (names.has('go.mod')) return { command: 'go', args: ['test', './...'], reason: 'go.mod' };
  if (names.has('pom.xml')) return { command: 'mvn', args: ['test'], reason: 'pom.xml (maven)' };
  if (names.has('build.gradle') || names.has('build.gradle.kts')) {
    return { command: 'gradle', args: ['test'], reason: 'build.gradle' };
  }

  const pkgPath = join(root, 'package.json');
  if (existsSync(pkgPath)) {
    const text = readTextFileBounded(pkgPath, 1_000_000);
    if (text) {
      try {
        const json = JSON.parse(text) as { scripts?: Record<string, string>; devDependencies?: Record<string, string>; dependencies?: Record<string, string> };
        const deps = { ...(json.dependencies ?? {}), ...(json.devDependencies ?? {}) };
        const pm = packageManager(root);
        if (json.scripts && typeof json.scripts.test === 'string') {
          return { command: pm, args: ['run', 'test'], reason: `package.json scripts.test via ${pm}` };
        }
        if (deps.vitest) return { command: 'npx', args: ['vitest', 'run'], reason: 'vitest devDependency' };
        if (deps.jest) return { command: 'npx', args: ['jest'], reason: 'jest devDependency' };
      } catch {
        /* ignore */
      }
    }
  }

  if (names.has('requirements.txt') || names.has('pyproject.toml') || names.has('pytest.ini') || names.has('setup.py')) {
    const python = process.platform === 'win32' ? 'python' : 'python3';
    return { command: python, args: ['-m', 'pytest', '-q'], reason: 'python project' };
  }
  return undefined;
}

interface ParsedTestCounts {
  passed?: number;
  failed?: number;
  total?: number;
}

function parseTestCounts(output: string): ParsedTestCounts {
  const counts: ParsedTestCounts = {};

  const vitest = /Tests\s+(?:(\d+)\s+failed\s*\|\s*)?(\d+)\s+passed(?:\s*\((\d+)\))?/.exec(output);
  if (vitest) {
    if (vitest[1]) counts.failed = Number(vitest[1]);
    counts.passed = Number(vitest[2]);
  }
  const jestPassed = /(\d+)\s+passed/.exec(output);
  const jestFailed = /(\d+)\s+failed/.exec(output);
  if (!counts.passed && jestPassed) counts.passed = Number(jestPassed[1]);
  if (counts.failed === undefined && jestFailed) counts.failed = Number(jestFailed[1]);

  const pytest = /(\d+)\s+passed(?:.*?(\d+)\s+failed)?/.exec(output);
  if (pytest && counts.passed === undefined) {
    counts.passed = Number(pytest[1]);
    if (pytest[2]) counts.failed = Number(pytest[2]);
  }
  const pytestFailed = /(\d+)\s+failed/.exec(output);
  if (counts.failed === undefined && pytestFailed) counts.failed = Number(pytestFailed[1]);

  const cargo = /test result:.*?(\d+)\s+passed;\s*(\d+)\s+failed/.exec(output);
  if (cargo) {
    counts.passed = Number(cargo[1]);
    counts.failed = Number(cargo[2]);
  }

  const goPass = output.match(/^\s*---\s+PASS:/gm)?.length ?? 0;
  const goFail = output.match(/^\s*---\s+FAIL:/gm)?.length ?? 0;
  if (!counts.passed && goPass) counts.passed = goPass;
  if (counts.failed === undefined && goFail) counts.failed = goFail;

  if (counts.passed !== undefined || counts.failed !== undefined) {
    counts.total = (counts.passed ?? 0) + (counts.failed ?? 0);
  }
  return counts;
}

function formatExec(res: ExecResult): string {
  const out = res.stdout.trim();
  const err = res.stderr.trim();
  const parts: string[] = [];
  if (out) parts.push(out);
  if (err) parts.push(err);
  return parts.join('\n');
}

function previewRegion(content: string, anchor: number, context = 3): string {
  const before = content.slice(0, anchor);
  const startLine = before.split('\n').length;
  const lines = content.split('\n');
  const from = Math.max(0, startLine - 1 - context);
  const to = Math.min(lines.length, startLine + context);
  return lines
    .slice(from, to)
    .map((line, i) => `${String(from + i + 1).padStart(5, ' ')} | ${line}`)
    .join('\n');
}

/** Write a file atomically inside the workspace. */
function writeAtomic(target: string, content: string): void {
  mkdirSync(dirname(target), { recursive: true });
  const tmp = `${target}.mirai-tmp`;
  writeFileSync(tmp, content, 'utf8');
  renameSync(tmp, target);
}

/* ------------------------------------------------------------------ */
/* Tool 1 — engineering_toolchain_probe                               */
/* ------------------------------------------------------------------ */

const toolchainProbe = defineTool<
  Record<string, never>,
  Awaited<ReturnType<typeof collectEnvironmentReport>>
>({
  name: 'engineering_toolchain_probe',
  title: 'Engineering Toolchain Probe',
  engine: ENGINE,
  description:
    'Probe the local engineering environment: OS/CPU/memory and the availability of toolchains, ' +
    'compilers and analysis tools on PATH. Read-only.',
  capabilities: ['read_repo'],
  risk: 'safe',
  inputSchema: {},
  handler: async (_input, ctx: ToolContext) => {
    const startedAt = Date.now();
    const cfg = getConfig();
    const report = await collectEnvironmentReport();

    const toolchainNames = Object.entries(report.toolchains)
      .filter(([, v]) => Boolean(v))
      .map(([k]) => k);
    const analysisAvailable = Object.entries(report.analysisTools)
      .filter(([, v]) => v)
      .map(([k]) => k);

    addEvidence(ctx, {
      claim: `Engineering environment probed: ${report.platform}/${report.arch}, node ${report.nodeVersion}, ${report.cpus} CPUs.`,
      prov: localProvenance('environment', cfg.workspaceRoot, 'engineering toolchain probe'),
      confidence: 'observed',
      data: { toolchains: toolchainNames, analysisTools: analysisAvailable },
    });

    const summary = [
      '# Engineering Toolchain Probe',
      '',
      `- Platform: ${report.os} (${report.arch})`,
      `- Node: ${report.nodeVersion}${report.pythonVersion ? ` / ${report.pythonVersion}` : ''}`,
      `- CPUs: ${report.cpus}, Memory: ${report.totalMemoryMb} MB total / ${report.freeMemoryMb} MB free`,
      `- Workspace: \`${report.workspaceRoot}\``,
      `- Toolchains present: ${toolchainNames.join(', ') || 'none detected'}`,
      `- Analysis tools available: ${analysisAvailable.length}`,
    ].join('\n');

    return finish({
      engine: ENGINE,
      tool: 'engineering_toolchain_probe',
      summary,
      ctx,
      data: report,
      startedAt,
    });
  },
});

/* ------------------------------------------------------------------ */
/* Tool 2 — repository_analyze                                        */
/* ------------------------------------------------------------------ */

const MANIFEST_BUILD_SYSTEMS: Array<[string, string]> = [
  ['package.json', 'npm/pnpm/yarn (Node.js)'],
  ['Cargo.toml', 'cargo (Rust)'],
  ['go.mod', 'go modules'],
  ['pom.xml', 'maven (Java)'],
  ['build.gradle', 'gradle (Java/Kotlin)'],
  ['build.gradle.kts', 'gradle (Kotlin DSL)'],
  ['CMakeLists.txt', 'cmake'],
  ['Makefile', 'make'],
  ['pyproject.toml', 'python (PEP 621 / poetry)'],
  ['requirements.txt', 'python (pip)'],
  ['setup.py', 'python (setuptools)'],
];

const repositoryAnalyze = defineTool<
  { path?: string; maxFiles?: number },
  Record<string, unknown>
>({
  name: 'repository_analyze',
  title: 'Repository Analyze',
  engine: ENGINE,
  description:
    'Statically summarize a repository: languages by extension, build systems, entry points, ' +
    'file/byte totals, largest files and TODO/FIXME markers. Read-only.',
  capabilities: ['read_repo'],
  risk: 'safe',
  inputSchema: {
    path: z.string().optional().describe('Directory relative to the workspace root (default ".").'),
    maxFiles: z.number().int().min(1).max(200000).optional().describe('Maximum files to walk.'),
  },
  handler: async (input, ctx) => {
    const startedAt = Date.now();
    const root = resolveRoot(input.path);
    const files = walkDirectory(root, { maxFiles: input.maxFiles ?? 20000 });

    const languages = new Map<string, { files: number; bytes: number }>();
    let totalBytes = 0;
    for (const file of files) {
      totalBytes += file.bytes;
      const lang = languageOf(file.rel);
      const agg = languages.get(lang) ?? { files: 0, bytes: 0 };
      agg.files += 1;
      agg.bytes += file.bytes;
      languages.set(lang, agg);
    }

    const nameSet = new Set(files.map((f) => baseOf(f.rel)));
    const buildSystems = MANIFEST_BUILD_SYSTEMS.filter(([name]) => nameSet.has(name)).map(([, label]) => label);

    const entryPatterns = [
      /(^|\/)main\.[A-Za-z0-9]+$/,
      /(^|\/)index\.[A-Za-z0-9]+$/,
      /(^|\/)src\/main\.[A-Za-z0-9]+$/,
      /(^|\/)cmd\/[^/]+\/main\.go$/,
      /(^|\/)__main__\.py$/,
      /(^|\/)app\.[A-Za-z0-9]+$/,
      /(^|\/)Dockerfile$/,
      /(^|\/)docker-compose\.ya?ml$/,
    ];
    const entryPoints = files
      .filter((f) => entryPatterns.some((re) => re.test(f.rel)))
      .slice(0, 50)
      .map((f) => f.rel);

    const largestFiles = [...files]
      .sort((a, b) => b.bytes - a.bytes)
      .slice(0, 10)
      .map((f) => ({ path: f.rel, bytes: f.bytes }));

    let todo = 0;
    let fixme = 0;
    let scanned = 0;
    for (const file of files) {
      if (scanned >= 5000) break;
      if (!isSourcePath(file.rel) && !file.rel.endsWith('.md')) continue;
      const text = readTextFileBounded(file.abs, CONTENT_SCAN_LIMIT);
      if (text === undefined) continue;
      scanned += 1;
      const markers = countMarkers(text);
      todo += markers.todo;
      fixme += markers.fixme;
    }

    addEvidence(ctx, {
      claim: `Repository scanned at "${root}": ${files.length} files, ${totalBytes} bytes.`,
      prov: localProvenance('repository', root, 'repository_analyze'),
      confidence: 'observed',
      locator: { file: root },
      data: { files: files.length, bytes: totalBytes, todo, fixme },
    });

    const topLanguages = [...languages.entries()]
      .map(([language, agg]) => ({ language, ...agg }))
      .sort((a, b) => b.files - a.files);

    const summary = [
      `# Repository Analysis`,
      '',
      `Root: \`${root}\``,
      `Files: **${files.length}** · Bytes: **${totalBytes}**`,
      '',
      '## Languages',
      ...topLanguages.slice(0, 12).map((l) => `- ${l.language}: ${l.files} files (${l.bytes} bytes)`),
      '',
      `## Build systems`,
      buildSystems.length ? buildSystems.map((b) => `- ${b}`).join('\n') : '- none detected',
      '',
      `## Entry points (${entryPoints.length})`,
      entryPoints.length ? entryPoints.slice(0, 20).map((e) => `- \`${e}\``).join('\n') : '- none detected',
      '',
      `## Markers`,
      `- TODO: ${todo} · FIXME: ${fixme}`,
      '',
      `## Largest files`,
      ...largestFiles.map((f) => `- \`${f.path}\` — ${f.bytes} bytes`),
    ].join('\n');

    return finish({
      engine: ENGINE,
      tool: 'repository_analyze',
      summary,
      ctx,
      data: {
        root,
        totalFiles: files.length,
        totalBytes,
        languages: topLanguages,
        buildSystems,
        entryPoints,
        largestFiles,
        markers: { todo, fixme },
        generatedAt: new Date().toISOString(),
      },
      startedAt,
    });
  },
});

/* ------------------------------------------------------------------ */
/* Tool 3 — repository_search                                         */
/* ------------------------------------------------------------------ */

const repositorySearch = defineTool<
  {
    query: string;
    path?: string;
    regex?: boolean;
    glob?: string;
    caseSensitive?: boolean;
    limit?: number;
  },
  Record<string, unknown>
>({
  name: 'repository_search',
  title: 'Repository Search',
  engine: ENGINE,
  description:
    'Recursively search file contents across the repository and return matching file/line/column hits. Read-only.',
  capabilities: ['read_repo'],
  risk: 'safe',
  inputSchema: {
    query: z.string().min(1).describe('Literal text or regular expression to search for.'),
    path: z.string().optional().describe('Directory relative to the workspace root (default ".").'),
    regex: z.boolean().optional().describe('Treat query as a regular expression.'),
    glob: z.string().optional().describe('Glob filter on relative paths, e.g. "src/**/*.ts".'),
    caseSensitive: z.boolean().optional().describe('Case-sensitive matching (default false).'),
    limit: z.number().int().min(1).max(1000).optional().describe('Maximum matches (default 50).'),
  },
  handler: async (input, ctx) => {
    const startedAt = Date.now();
    const root = resolveRoot(input.path);
    const limit = input.limit ?? 50;
    const flags = input.caseSensitive ? 'g' : 'gi';

    let matcher: RegExp;
    try {
      matcher = input.regex ? new RegExp(input.query, flags) : new RegExp(escapeRegExp(input.query), flags);
    } catch (err) {
      throw errors.invalidInput(`Invalid regular expression: ${(err as Error).message}`, { query: input.query });
    }
    const globRe = input.glob ? globToRegExp(input.glob) : undefined;

    const files = walkDirectory(root, { maxFiles: 50000 });
    const matches: Array<{ file: string; line: number; column: number; text: string }> = [];
    const fileHits = new Map<string, number>();
    let scannedFiles = 0;

    for (const file of files) {
      if (matches.length >= limit) break;
      if (globRe && !globRe.test(file.rel)) continue;
      if (!isTextPath(file.rel)) continue;
      const text = readTextFileBounded(file.abs, CONTENT_SCAN_LIMIT);
      if (text === undefined) continue;
      scannedFiles += 1;
      fileHits.set(file.rel, 0);
      const lines = text.split('\n');
      for (let i = 0; i < lines.length && matches.length < limit; i += 1) {
        const line = lines[i] ?? '';
        matcher.lastIndex = 0;
        const m = matcher.exec(line);
        if (m) {
          matches.push({ file: file.rel, line: i + 1, column: m.index + 1, text: line.slice(0, 400) });
          fileHits.set(file.rel, (fileHits.get(file.rel) ?? 0) + 1);
        }
      }
    }

    addEvidence(ctx, {
      claim: `Content search for ${JSON.stringify(input.query)} produced ${matches.length} match(es).`,
      prov: localProvenance('repository', root, 'repository_search'),
      confidence: 'observed',
      locator: { file: root },
      data: { query: input.query, matches: matches.length },
    });

    const filesWithHits = [...fileHits.entries()].filter(([, n]) => n > 0);
    const summary = [
      `# Repository Search`,
      '',
      `Query: \`${input.query}\` ${input.regex ? '(regex)' : '(literal)'}${input.glob ? ` · glob \`${input.glob}\`` : ''}`,
      `Scanned ${scannedFiles} file(s), found **${matches.length}** match(es) in ${filesWithHits.length} file(s).`,
      '',
      ...matches.slice(0, 25).map((m) => `- \`${m.file}:${m.line}:${m.column}\` — ${m.text.trim().slice(0, 120)}`),
      matches.length > 25 ? `\n... ${matches.length - 25} more` : '',
    ].join('\n');

    return finish({
      engine: ENGINE,
      tool: 'repository_search',
      summary,
      ctx,
      data: { root, query: input.query, scannedFiles, matchCount: matches.length, matches },
      startedAt,
    });
  },
});

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/* ------------------------------------------------------------------ */
/* Tool 4 — symbol_search                                             */
/* ------------------------------------------------------------------ */

const SYMBOL_DEFINITION_PATTERNS: Record<string, RegExp[]> = {
  TypeScript: [/function\s+{S}\b/, /class\s+{S}\b/, /interface\s+{S}\b/, /type\s+{S}\b/, /enum\s+{S}\b/, /(?:const|let|var)\s+{S}\s*=/, /namespace\s+{S}\b/],
  JavaScript: [/function\s+{S}\b/, /class\s+{S}\b/, /(?:const|let|var)\s+{S}\s*=/, /export\s+(?:default\s+)?(?:class|function)\s+{S}\b/],
  Python: [/def\s+{S}\b/, /class\s+{S}\b/, /^[A-Za-z_]\w*\s*=\s*[^\n]*$/],
  Go: [/func\s+(?:\([^)]*\)\s*)?{S}\s*\(/, /type\s+{S}\s+(?:struct|interface)\b/, /var\s+{S}\b/],
  Rust: [/fn\s+{S}\b/, /struct\s+{S}\b/, /enum\s+{S}\b/, /trait\s+{S}\b/, /type\s+{S}\b/],
  C: [/\b[A-Za-z_][\w\s*]*\b{S}\s*\(/],
  'C++': [/\b[A-Za-z_][\w\s*&:<>]*\b{S}\s*\(/],
  Java: [/\b(?:class|interface|enum)\s+{S}\b/, /\b[A-Za-z_][\w<>\[\], ]*\s+{S}\s*\(/],
  'C#': [/\b(?:class|interface|struct|enum)\s+{S}\b/, /\b[A-Za-z_][\w<>\[\], ]*\s+{S}\s*\(/],
  Kotlin: [/\bfun\s+{S}\b/, /\b(?:class|interface|object)\s+{S}\b/],
  Ruby: [/\bdef\s+{S}\b/, /\b(?:class|module)\s+{S}\b/],
};

function symbolPatterns(language: string, symbol: string): RegExp[] {
  const escaped = escapeRegExp(symbol);
  const base = SYMBOL_DEFINITION_PATTERNS[language] ?? Object.values(SYMBOL_DEFINITION_PATTERNS).flat();
  return base.map((re) => new RegExp(re.source.replace(/\{S\}/g, escaped)));
}

const symbolSearch = defineTool<
  { symbol: string; path?: string; language?: string; limit?: number },
  Record<string, unknown>
>({
  name: 'symbol_search',
  title: 'Symbol Search',
  engine: ENGINE,
  description:
    'Locate symbol definitions and references across the repository using language-aware heuristics. Read-only.',
  capabilities: ['read_repo'],
  risk: 'safe',
  inputSchema: {
    symbol: z.string().min(1).describe('Symbol name to locate (function, class, type, variable).'),
    path: z.string().optional().describe('Directory relative to the workspace root (default ".").'),
    language: z.string().optional().describe('Restrict to a single language (e.g. "TypeScript").'),
    limit: z.number().int().min(1).max(1000).optional().describe('Maximum results per category (default 100).'),
  },
  handler: async (input, ctx) => {
    const startedAt = Date.now();
    const root = resolveRoot(input.path);
    const limit = input.limit ?? 100;
    const symbolRe = new RegExp(`\\b${escapeRegExp(input.symbol)}\\b`, input.symbol.match(/^[A-Za-z_]/) ? 'g' : 'g');

    const files = walkDirectory(root, { maxFiles: 50000 });
    const definitions: Array<{ file: string; line: number; text: string; kind: string }> = [];
    const references: Array<{ file: string; line: number; text: string }> = [];

    for (const file of files) {
      if (definitions.length >= limit && references.length >= limit) break;
      if (!isSourcePath(file.rel)) continue;
      const language = languageOf(file.rel);
      if (input.language && language.toLowerCase() !== input.language.toLowerCase()) continue;
      const text = readTextFileBounded(file.abs, CONTENT_SCAN_LIMIT);
      if (text === undefined) continue;

      const defPatterns = symbolPatterns(language, input.symbol);
      const lines = text.split('\n');
      for (let i = 0; i < lines.length; i += 1) {
        const line = lines[i] ?? '';
        const isDef = defPatterns.some((re) => re.test(line));
        if (isDef) {
          if (definitions.length < limit) {
            definitions.push({ file: file.rel, line: i + 1, text: line.trim().slice(0, 300), kind: classifyDefinition(line) });
          }
          continue;
        }
        symbolRe.lastIndex = 0;
        if (symbolRe.test(line) && references.length < limit) {
          references.push({ file: file.rel, line: i + 1, text: line.trim().slice(0, 300) });
        }
      }
    }

    addEvidence(ctx, {
      claim: `Symbol search for "${input.symbol}": ${definitions.length} definition(s), ${references.length} reference(s).`,
      prov: localProvenance('repository', root, 'symbol_search'),
      confidence: 'inferred',
      locator: { file: root, symbol: input.symbol },
      data: { definitions: definitions.length, references: references.length },
    });

    const summary = [
      `# Symbol Search — \`${input.symbol}\``,
      '',
      `**${definitions.length}** definition(s), **${references.length}** reference(s).`,
      '',
      '## Definitions',
      ...definitions.slice(0, 25).map((d) => `- \`${d.file}:${d.line}\` (${d.kind}) — ${d.text}`),
      definitions.length === 0 ? '- none found' : '',
      '',
      '## References',
      ...references.slice(0, 25).map((r) => `- \`${r.file}:${r.line}\` — ${r.text}`),
      references.length === 0 ? '- none found' : '',
    ].join('\n');

    return finish({
      engine: ENGINE,
      tool: 'symbol_search',
      summary,
      ctx,
      data: { root, symbol: input.symbol, definitions, references, counts: { definitions: definitions.length, references: references.length } },
      startedAt,
    });
  },
});

function classifyDefinition(line: string): string {
  if (/\b(?:class|struct|interface|trait|enum|object)\b/.test(line)) return 'type';
  if (/\b(?:function|def|fn|func)\b/.test(line)) return 'function';
  if (/(?:const|let|var)\s/.test(line)) return 'variable';
  if (/\b(?:type|typedef)\b/.test(line)) return 'type-alias';
  return 'symbol';
}

/* ------------------------------------------------------------------ */
/* Tool 5 — dependency_analyze                                        */
/* ------------------------------------------------------------------ */

const MANIFEST_HANDLERS: Record<string, (text: string, file: string) => DependencyEntry[]> = {
  'package.json': parsePackageJson,
  'requirements.txt': parseRequirementsTxt,
  'pyproject.toml': parsePyprojectToml,
  'Cargo.toml': parseCargoToml,
  'go.mod': parseGoMod,
  'pom.xml': parsePomXml,
  'build.gradle': parseGradle,
  'build.gradle.kts': parseGradle,
};

const dependencyAnalyze = defineTool<{ path?: string }, Record<string, unknown>>({
  name: 'dependency_analyze',
  title: 'Dependency Analyze',
  engine: ENGINE,
  description:
    'Parse dependency manifests (npm, pip, cargo, go, maven, gradle) and compare declared versions with ' +
    'installed versions under node_modules. Read-only.',
  capabilities: ['read_repo'],
  risk: 'safe',
  inputSchema: {
    path: z.string().optional().describe('Directory relative to the workspace root (default ".").'),
  },
  handler: async (input, ctx) => {
    const startedAt = Date.now();
    const root = resolveRoot(input.path);
    const files = walkDirectory(root, { maxFiles: 50000 });

    const dependencies: DependencyEntry[] = [];
    const manifests: string[] = [];

    for (const file of files) {
      const name = baseOf(file.rel);
      const handler = MANIFEST_HANDLERS[name];
      if (!handler) continue;
      const text = readTextFileBounded(file.abs, 4 * 1024 * 1024);
      if (text === undefined) continue;
      const parsed = handler(text, file.rel);
      if (parsed.length === 0 && name !== 'package.json') continue;
      manifests.push(file.rel);
      dependencies.push(...parsed);
    }

    const byEcosystem: Record<string, number> = {};
    for (const dep of dependencies) {
      byEcosystem[dep.ecosystem] = (byEcosystem[dep.ecosystem] ?? 0) + 1;
    }

    // Declared vs installed comparison for npm dependencies.
    const mismatches: Array<{ name: string; declared: string; installed: string }> = [];
    const unresolved: string[] = [];
    for (const dep of dependencies) {
      if (dep.ecosystem !== 'npm') continue;
      const installedPath = join(root, 'node_modules', dep.name, 'package.json');
      if (!existsSync(installedPath)) {
        unresolved.push(dep.name);
        continue;
      }
      const text = readTextFileBounded(installedPath, 1_000_000);
      if (!text) continue;
      try {
        const json = JSON.parse(text) as { version?: string };
        const installed = json.version ?? '';
        const declared = dep.version.replace(/^[\^~>=<\s]*/, '');
        if (installed && declared && !installed.startsWith(declared) && declared !== '*') {
          mismatches.push({ name: dep.name, declared: dep.version, installed });
        }
      } catch {
        /* ignore */
      }
    }

    addEvidence(ctx, {
      claim: `Parsed ${manifests.length} manifest(s) yielding ${dependencies.length} dependency declaration(s).`,
      prov: localProvenance('repository', root, 'dependency_analyze'),
      confidence: 'observed',
      locator: { file: root },
      data: { manifests, dependencies: dependencies.length },
    });

    const summary = [
      '# Dependency Analysis',
      '',
      `Manifests: ${manifests.map((m) => `\`${m}\``).join(', ') || 'none found'}`,
      `Declared dependencies: **${dependencies.length}**`,
      `By ecosystem: ${Object.entries(byEcosystem).map(([k, v]) => `${k}=${v}`).join(', ') || 'n/a'}`,
      '',
      `## Declared vs installed (npm)`,
      mismatches.length ? mismatches.map((m) => `- ${m.name}: declared \`${m.declared}\`, installed \`${m.installed}\``).join('\n') : '- no mismatches detected',
      unresolved.length ? `\nUnresolved (not installed): ${unresolved.slice(0, 20).join(', ')}${unresolved.length > 20 ? ` (+${unresolved.length - 20} more)` : ''}` : '',
    ].join('\n');

    return finish({
      engine: ENGINE,
      tool: 'dependency_analyze',
      summary,
      ctx,
      data: {
        root,
        manifests,
        dependencies,
        counts: { total: dependencies.length, byEcosystem, mismatches: mismatches.length, unresolved: unresolved.length },
        mismatches,
        unresolved,
      },
      startedAt,
    });
  },
});

/* ------------------------------------------------------------------ */
/* Tool 6 — documentation_search                                      */
/* ------------------------------------------------------------------ */

const DOC_EXTENSIONS = new Set(['.md', '.markdown', '.rst', '.txt', '.adoc']);

function isDocPath(rel: string): boolean {
  const name = baseOf(rel).toLowerCase();
  if (name.startsWith('readme') || name.startsWith('changelog') || name.startsWith('contributing')) return true;
  if (rel.split('/').includes('docs') || rel.split('/').includes('doc')) return true;
  return DOC_EXTENSIONS.has(extOf(rel));
}

const documentationSearch = defineTool<
  { query: string; path?: string; limit?: number },
  Record<string, unknown>
>({
  name: 'documentation_search',
  title: 'Documentation Search',
  engine: ENGINE,
  description:
    'Search README, docs and source comment blocks for a query and report the enclosing document heading. Read-only.',
  capabilities: ['read_repo'],
  risk: 'safe',
  inputSchema: {
    query: z.string().min(1).describe('Free-text query.'),
    path: z.string().optional().describe('Directory relative to the workspace root (default ".").'),
    limit: z.number().int().min(1).max(1000).optional().describe('Maximum results (default 50).'),
  },
  handler: async (input, ctx) => {
    const startedAt = Date.now();
    const root = resolveRoot(input.path);
    const limit = input.limit ?? 50;
    const needle = input.query.toLowerCase();

    const files = walkDirectory(root, { maxFiles: 50000 });
    const results: Array<{ file: string; line: number; heading?: string; text: string; source: 'doc' | 'comment' }> = [];
    let scanned = 0;

    for (const file of files) {
      if (results.length >= limit) break;
      const isDoc = isDocPath(file.rel);
      const isSource = isSourcePath(file.rel);
      if (!isDoc && !isSource) continue;
      const text = readTextFileBounded(file.abs, CONTENT_SCAN_LIMIT);
      if (text === undefined) continue;
      scanned += 1;

      const lines = text.split('\n');
      let heading: string | undefined;
      let inBlockComment = false;

      for (let i = 0; i < lines.length && results.length < limit; i += 1) {
        const raw = lines[i] ?? '';
        const trimmed = raw.trim();

        if (isDoc) {
          const md = /^(#{1,6})\s+(.*)$/.exec(trimmed);
          if (md) {
            heading = (md[2] ?? '').trim();
            continue;
          }
          if (/^[=\-~^]{3,}$/.test(trimmed)) continue;
        } else {
          if (trimmed.startsWith('/**')) inBlockComment = true;
          if (inBlockComment && trimmed.startsWith('*') && !trimmed.startsWith('*/')) {
            const content = trimmed.replace(/^\*\s?/, '');
            if (content.toLowerCase().includes(needle)) {
              results.push({ file: file.rel, line: i + 1, text: content.slice(0, 400), source: 'comment' });
            }
            continue;
          }
          if (trimmed.startsWith('*/')) inBlockComment = false;
        }

        if (trimmed.toLowerCase().includes(needle)) {
          const isComment = /^(?:\/\/|#|\*|--|;)/.test(trimmed);
          results.push({
            file: file.rel,
            line: i + 1,
            ...(isDoc && heading ? { heading } : {}),
            text: trimmed.slice(0, 400),
            source: isDoc ? 'doc' : isComment ? 'comment' : 'doc',
          });
        }
      }
    }

    addEvidence(ctx, {
      claim: `Documentation search for ${JSON.stringify(input.query)} across ${scanned} file(s) yielded ${results.length} hit(s).`,
      prov: localProvenance('repository', root, 'documentation_search'),
      confidence: 'observed',
      locator: { file: root },
      data: { query: input.query, results: results.length },
    });

    const summary = [
      `# Documentation Search — \`${input.query}\``,
      '',
      `Scanned ${scanned} file(s); **${results.length}** hit(s).`,
      '',
      ...results.slice(0, 30).map((r) => `- \`${r.file}:${r.line}\`${r.heading ? ` [${r.heading}]` : ''} — ${r.text}`),
    ].join('\n');

    return finish({
      engine: ENGINE,
      tool: 'documentation_search',
      summary,
      ctx,
      data: { root, query: input.query, scannedFiles: scanned, results },
      startedAt,
    });
  },
});

/* ------------------------------------------------------------------ */
/* Tool 7 — architecture_analyze                                      */
/* ------------------------------------------------------------------ */

const architectureAnalyze = defineTool<
  { path?: string; depth?: number },
  Record<string, unknown>
>({
  name: 'architecture_analyze',
  title: 'Architecture Analyze',
  engine: ENGINE,
  description:
    'Build a coarse architecture model: top-level modules with file/line counts, cross-module import edges ' +
    'and dependency cycles detected via DFS. Read-only.',
  capabilities: ['read_repo'],
  risk: 'safe',
  inputSchema: {
    path: z.string().optional().describe('Directory relative to the workspace root (default ".").'),
    depth: z.number().int().min(1).max(3).optional().describe('Path segments used to name a module (default 1).'),
  },
  handler: async (input, ctx) => {
    const startedAt = Date.now();
    const root = resolveRoot(input.path);
    const segments = input.depth ?? 1;
    const files = walkDirectory(root, { maxFiles: 50000 });

    const moduleOf = (rel: string): string => {
      const parts = rel.split('/');
      if (parts.length <= segments && !rel.includes('/')) return '(root)';
      const slice = parts.slice(0, segments).join('/');
      return slice || '(root)';
    };

    const modules = new Map<string, { files: number; lines: number }>();
    for (const file of files) {
      const mod = moduleOf(file.rel);
      const agg = modules.get(mod) ?? { files: 0, lines: 0 };
      agg.files += 1;
      modules.set(mod, agg);
    }
    const topLevel = new Set<string>([...modules.keys(), ...files.map((f) => f.rel.split('/')[0] ?? '')].filter(Boolean));

    const edgeCounts = new Map<string, number>();
    for (const file of files) {
      if (!isSourcePath(file.rel)) continue;
      const mod = moduleOf(file.rel);
      const text = readTextFileBounded(file.abs, CONTENT_SCAN_LIMIT);
      if (text === undefined) continue;
      modules.set(mod, { ...(modules.get(mod) ?? { files: 0, lines: 0 }), lines: (modules.get(mod)?.lines ?? 0) + text.split('\n').length });
      for (const spec of extractImportSpecifiers(text)) {
        const target = toImportModule(spec, file.rel, topLevel);
        if (!target || target === mod) continue;
        const key = `${mod}\u0000${target}`;
        edgeCounts.set(key, (edgeCounts.get(key) ?? 0) + 1);
      }
    }

    const edges = [...edgeCounts.entries()].map(([key, count]) => {
      const [from, to] = key.split('\u0000');
      return { from: from ?? '', to: to ?? '', count };
    });

    const adjacency = new Map<string, string[]>();
    for (const edge of edges) {
      const list = adjacency.get(edge.from) ?? [];
      list.push(edge.to);
      adjacency.set(edge.from, list);
    }

    const cycles = detectCycles(adjacency);

    addEvidence(ctx, {
      claim: `Architecture model built: ${modules.size} module(s), ${edges.length} import edge(s), ${cycles.length} cycle(s).`,
      prov: localProvenance('repository', root, 'architecture_analyze'),
      confidence: 'inferred',
      locator: { file: root },
      data: { modules: modules.size, edges: edges.length, cycles: cycles.length },
    });

    const moduleList = [...modules.entries()]
      .map(([name, agg]) => ({ name, files: agg.files, lines: agg.lines }))
      .sort((a, b) => b.files - a.files);

    const summary = [
      '# Architecture Analysis',
      '',
      `Root: \`${root}\` · modules: **${moduleList.length}** · edges: **${edges.length}** · cycles: **${cycles.length}**`,
      '',
      '## Modules',
      ...moduleList.slice(0, 30).map((m) => `- \`${m.name}\`: ${m.files} files, ~${m.lines} lines`),
      '',
      '## Import edges',
      ...edges.slice(0, 40).map((e) => `- \`${e.from}\` → \`${e.to}\` (${e.count})`),
      edges.length === 0 ? '- none detected' : '',
      '',
      '## Cycles',
      ...(cycles.length ? cycles.map((c) => `- ${c.join(' → ')} → ${c[0]}`) : ['- none detected']),
    ].join('\n');

    return finish({
      engine: ENGINE,
      tool: 'architecture_analyze',
      summary,
      ctx,
      data: { root, modules: moduleList, edges, cycles },
      startedAt,
    });
  },
});

/** DFS-based simple cycle detection on a module graph. */
function detectCycles(adjacency: Map<string, string[]>): string[][] {
  const cycles: string[][] = [];
  const seenKeys = new Set<string>();
  const state = new Map<string, number>();
  const stack: string[] = [];

  const visit = (node: string): void => {
    if (cycles.length >= 20) return;
    state.set(node, 1);
    stack.push(node);
    for (const next of adjacency.get(node) ?? []) {
      const s = state.get(next) ?? 0;
      if (s === 1) {
        const idx = stack.indexOf(next);
        if (idx !== -1) {
          const cycle = stack.slice(idx);
          const key = [...cycle].sort().join('>');
          if (!seenKeys.has(key)) {
            seenKeys.add(key);
            cycles.push(cycle);
          }
        }
      } else if (s === 0) {
        visit(next);
      }
    }
    state.set(node, 2);
    stack.pop();
  };

  for (const node of adjacency.keys()) {
    if ((state.get(node) ?? 0) === 0) visit(node);
  }
  return cycles;
}

/* ------------------------------------------------------------------ */
/* Tool 8 — source_generate                                           */
/* ------------------------------------------------------------------ */

const sourceGenerate = defineTool<
  { rootPath: string; files: Array<{ relativePath: string; content: string }>; overwrite?: boolean },
  Record<string, unknown>
>({
  name: 'source_generate',
  title: 'Source Generate',
  engine: ENGINE,
  description:
    'Write a batch of source files under the workspace. Every path is validated against the workspace boundary, ' +
    'parent directories are created, and existing files are never overwritten unless explicitly allowed.',
  capabilities: ['write_repo'],
  risk: 'local_mutation',
  inputSchema: {
    rootPath: z.string().min(1).describe('Target root directory, relative to the workspace root.'),
    files: z
      .array(z.object({ relativePath: z.string().min(1), content: z.string() }))
      .min(1)
      .describe('Files to write, each with a path relative to rootPath.'),
    overwrite: z.boolean().optional().describe('Allow overwriting existing files (default false).'),
  },
  handler: async (input, ctx) => {
    const startedAt = Date.now();
    if (input.files.length === 0) throw errors.invalidInput('At least one file is required.');
    const root = resolveWorkspacePath(input.rootPath, false);

    // Validate every target up-front so a bad path never produces partial writes.
    const targets = input.files.map((file) => {
      const abs = resolveWorkspacePath(join(root, file.relativePath), false);
      return { relativePath: file.relativePath, content: file.content, abs };
    });

    if (!input.overwrite) {
      const conflicts = targets.filter((t) => existsSync(t.abs)).map((t) => t.relativePath);
      if (conflicts.length > 0) {
        throw errors.policyBlocked(
          `Refusing to overwrite ${conflicts.length} existing file(s).`,
          'Pass "overwrite": true to replace existing files, or choose new paths.',
          { conflicts },
        );
      }
    }

    const written: Array<{ path: string; bytes: number; sha256: string }> = [];
    for (const target of targets) {
      writeAtomic(target.abs, target.content);
      const digest = await sha256(target.content);
      written.push({ path: target.relativePath, bytes: Buffer.byteLength(target.content, 'utf8'), sha256: digest });
    }

    addEvidence(ctx, {
      claim: `Generated ${written.length} source file(s) under "${input.rootPath}".`,
      prov: localProvenance('repository', root, 'source_generate'),
      confidence: 'confirmed',
      locator: { file: root },
      data: { files: written.map((w) => w.path) },
    });

    const summary = [
      '# Source Generate',
      '',
      `Wrote **${written.length}** file(s) under \`${root}\`.`,
      '',
      ...written.map((w) => `- \`${w.path}\` — ${w.bytes} bytes · ${w.sha256.slice(0, 19)}…`),
    ].join('\n');

    return finish({
      engine: ENGINE,
      tool: 'source_generate',
      summary,
      ctx,
      data: { root, count: written.length, written },
      startedAt,
    });
  },
});

/* ------------------------------------------------------------------ */
/* Tool 9 — source_modify                                             */
/* ------------------------------------------------------------------ */

const sourceModify = defineTool<
  { relativePath: string; oldString: string; newString: string; replaceAll?: boolean },
  Record<string, unknown>
>({
  name: 'source_modify',
  title: 'Source Modify',
  engine: ENGINE,
  description:
    'Perform an exact string replacement inside a workspace file, refusing ambiguous (non-unique) edits unless ' +
    'replaceAll is set. Writes atomically and reports before/after hashes.',
  capabilities: ['write_repo'],
  risk: 'local_mutation',
  inputSchema: {
    relativePath: z.string().min(1).describe('File to edit, relative to the workspace root.'),
    oldString: z.string().min(1).describe('Exact text to replace.'),
    newString: z.string().describe('Replacement text.'),
    replaceAll: z.boolean().optional().describe('Replace every occurrence (default: require uniqueness).'),
  },
  handler: async (input, ctx) => {
    const startedAt = Date.now();
    resolveFile(input.relativePath);
    const artifact = readTextArtifact(input.relativePath);
    assertArtifactSize(artifact.bytes);

    const occurrences = artifact.content.split(input.oldString).length - 1;
    if (occurrences === 0) {
      throw errors.invalidInput('oldString was not found in the target file.', { relativePath: input.relativePath });
    }
    if (occurrences > 1 && !input.replaceAll) {
      throw errors.invalidInput(
        `oldString is not unique (${occurrences} occurrences); provide more context or set replaceAll.`,
        { occurrences },
      );
    }

    const updated = input.replaceAll
      ? artifact.content.split(input.oldString).join(input.newString)
      : artifact.content.replace(input.oldString, () => input.newString);

    const beforeSha = await sha256(artifact.content);
    const afterSha = await sha256(updated);
    writeAtomic(artifact.path, updated);

    const anchor = updated.indexOf(input.newString);
    const preview = previewRegion(updated, anchor >= 0 ? anchor : 0);

    addEvidence(ctx, {
      claim: `Applied ${occurrences} replacement(s) in "${input.relativePath}".`,
      prov: localProvenance('repository', artifact.path, 'source_modify'),
      confidence: 'confirmed',
      locator: { file: artifact.path },
      data: { occurrences, beforeSha, afterSha },
    });

    const summary = [
      '# Source Modify',
      '',
      `File: \`${input.relativePath}\``,
      `Occurrences replaced: **${occurrences}**`,
      `Before: \`${beforeSha}\``,
      `After:  \`${afterSha}\``,
      '',
      '## Changed region',
      '```',
      preview,
      '```',
    ].join('\n');

    return finish({
      engine: ENGINE,
      tool: 'source_modify',
      summary,
      ctx,
      data: {
        file: input.relativePath,
        occurrences,
        replaceAll: Boolean(input.replaceAll),
        beforeSha,
        afterSha,
        bytesBefore: artifact.bytes,
        bytesAfter: Buffer.byteLength(updated, 'utf8'),
        preview,
      },
      startedAt,
    });
  },
});

/* ------------------------------------------------------------------ */
/* Tool 10 — source_review                                            */
/* ------------------------------------------------------------------ */

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

interface ReviewRule {
  id: string;
  category: string;
  severity: Severity;
  re: RegExp;
  recommendation: string;
  languages?: string[];
  skipIf?: RegExp;
}

const REVIEW_RULES: ReviewRule[] = [
  { id: 'mem_gets', category: 'memory_safety', severity: 'critical', re: /\bgets\s*\(/, recommendation: 'Never use gets(); switch to fgets/getline with an explicit buffer size.', languages: ['C', 'C++'] },
  { id: 'mem_strcpy', category: 'memory_safety', severity: 'high', re: /\bstrcpy\s*\(/, recommendation: 'Use bounded copies (strlcpy, snprintf) or safe abstractions to prevent overflow.', languages: ['C', 'C++'] },
  { id: 'mem_strcat', category: 'memory_safety', severity: 'high', re: /\bstrcat\s*\(/, recommendation: 'Use bounded concatenation (strlcat, snprintf) with explicit size limits.', languages: ['C', 'C++'] },
  { id: 'mem_sprintf', category: 'memory_safety', severity: 'high', re: /\b(?:sprintf|vsprintf)\s*\(/, recommendation: 'Replace sprintf with snprintf and pass the destination size.', languages: ['C', 'C++'] },
  { id: 'mem_memcpy', category: 'memory_safety', severity: 'medium', re: /\bmemcpy\s*\(/, recommendation: 'Validate destination capacity before memcpy; prefer sizeof(dest) constraints.', languages: ['C', 'C++'] },
  { id: 'mem_malloc', category: 'resource_management', severity: 'low', re: /\b(?:malloc|calloc|realloc)\s*\(/, recommendation: 'Ensure every allocation has a matching free on all return paths.', languages: ['C', 'C++'] },
  { id: 'inject_eval', category: 'injection', severity: 'high', re: /\beval\s*\(/, recommendation: 'Avoid eval(); use a structured parser or an allow-list of operations.' },
  { id: 'inject_os_system', category: 'injection', severity: 'high', re: /\bos\.system\s*\(|\bsubprocess\.\w+\([^)]*shell\s*=\s*True/, recommendation: 'Avoid shell=True; pass an argv array to subprocess and validate each argument.', languages: ['Python'] },
  { id: 'inject_child_process', category: 'injection', severity: 'high', re: /\bchild_process\b|\bexecSync\s*\(|\bexec\s*\(/, recommendation: 'Prefer execFile/spawn with an argv array; never interpolate untrusted input into a shell string.' },
  { id: 'inject_sql_concat', category: 'injection', severity: 'high', re: /(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^;\n]*?(?:\+|\$\{)/i, recommendation: 'Use parameterized queries instead of building SQL through string concatenation.' },
  { id: 'crypto_md5', category: 'weak_crypto', severity: 'medium', re: /\b(?:md5|createHash\(\s*['"]md5)\b/i, recommendation: 'MD5 is broken for security use; migrate to SHA-256 or a password KDF.' },
  { id: 'crypto_sha1', category: 'weak_crypto', severity: 'medium', re: /\b(?:sha1|createHash\(\s*['"]sha1)\b/i, recommendation: 'SHA-1 is deprecated for signatures; use SHA-256/384.' },
  { id: 'crypto_des', category: 'weak_crypto', severity: 'medium', re: /\b(?:DES|3DES|RC4)\b/, recommendation: 'Use AES-GCM or ChaCha20-Poly1305 instead of legacy ciphers.' },
  { id: 'crypto_weak_random', category: 'weak_crypto', severity: 'low', re: /Math\.random\s*\(|\brandom\.random\s*\(/, recommendation: 'Use a CSPRNG (crypto.randomBytes / secrets) for security-sensitive values.' },
  { id: 'secret_hardcoded', category: 'secrets', severity: 'high', re: /(?:api[_-]?key|secret|passwd|password|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?token)\s*[:=]\s*['"][^'"]{6,}['"]/i, recommendation: 'Remove hardcoded credentials; load secrets from environment variables or a secret manager.', skipIf: /(?:example|placeholder|changeme|your[_-]|xxxx|<|\$\{)/i },
  { id: 'ts_any', category: 'typing', severity: 'low', re: /(?::\s*any\b|<any>|\bas\s+any\b)/, recommendation: 'Replace any with a precise type, unknown, or a generic to retain type safety.', languages: ['TypeScript'] },
  { id: 'empty_catch', category: 'error_handling', severity: 'medium', re: /catch\s*(?:\([^)]*\))?\s*\{\s*\}/, recommendation: 'Do not swallow errors silently; log or rethrow with context.' },
  { id: 'todo_marker', category: 'maintainability', severity: 'low', re: /\b(?:TODO|FIXME)\b/, recommendation: 'Resolve or ticket the TODO/FIXME before release.' },
  { id: 'dangerous_html', category: 'injection', severity: 'medium', re: /dangerouslySetInnerHTML|\.innerHTML\s*=/, recommendation: 'Sanitize HTML (DOMPurify) or render through a safe component.', languages: ['TypeScript', 'JavaScript'] },
];

interface Finding {
  severity: Severity;
  category: string;
  rule: string;
  file: string;
  line: number;
  snippet: string;
  recommendation: string;
}

const sourceReview = defineTool<
  { relativePath?: string; path?: string; maxFindings?: number },
  Record<string, unknown>
>({
  name: 'source_review',
  title: 'Source Review',
  engine: ENGINE,
  description:
    'Static review heuristics over source files: memory-safety smells, injection sinks, weak crypto, hardcoded ' +
    'secrets, empty catch blocks, unsafe typing, TODOs and oversized functions. Read-only.',
  capabilities: ['read_repo'],
  risk: 'safe',
  inputSchema: {
    relativePath: z.string().optional().describe('Review a single file instead of a directory.'),
    path: z.string().optional().describe('Directory relative to the workspace root (default ".").'),
    maxFindings: z.number().int().min(1).max(2000).optional().describe('Maximum findings (default 200).'),
  },
  handler: async (input, ctx) => {
    const startedAt = Date.now();
    const maxFindings = input.maxFindings ?? 200;
    const files: Array<{ rel: string; abs: string }> = [];

    if (input.relativePath) {
      const abs = resolveFile(input.relativePath);
      files.push({ rel: input.relativePath, abs });
    } else {
      const root = resolveRoot(input.path);
      for (const file of walkDirectory(root, { maxFiles: 50000 })) {
        if (isSourcePath(file.rel)) files.push({ rel: file.rel, abs: file.abs });
      }
    }

    const findings: Finding[] = [];
    let scanned = 0;

    for (const file of files) {
      if (findings.length >= maxFindings) break;
      const text = readTextFileBounded(file.abs, CONTENT_SCAN_LIMIT);
      if (text === undefined) continue;
      scanned += 1;
      const language = languageOf(file.rel);
      const lines = text.split('\n');

      for (let i = 0; i < lines.length && findings.length < maxFindings; i += 1) {
        const line = lines[i] ?? '';
        if (!line.trim()) continue;
        for (const rule of REVIEW_RULES) {
          if (rule.languages && !rule.languages.includes(language)) continue;
          if (!rule.re.test(line)) continue;
          if (rule.skipIf && rule.skipIf.test(line)) continue;
          findings.push({
            severity: rule.severity,
            category: rule.category,
            rule: rule.id,
            file: file.rel,
            line: i + 1,
            snippet: line.trim().slice(0, 240),
            recommendation: rule.recommendation,
          });
        }
      }

      // Oversized function heuristic.
      for (const span of findFunctionSpans(lines, language)) {
        if (findings.length >= maxFindings) break;
        if (span.length > 80) {
          findings.push({
            severity: 'medium',
            category: 'maintainability',
            rule: 'long_function',
            file: file.rel,
            line: span.startLine,
            snippet: `${span.name}() spans ${span.length} lines (${span.startLine}-${span.endLine})`,
            recommendation: 'Split the function into smaller, single-responsibility units.',
          });
        }
      }
    }

    findings.sort((a, b) => {
      const rank = (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0);
      if (rank !== 0) return rank;
      if (a.file !== b.file) return a.file.localeCompare(b.file);
      return a.line - b.line;
    });

    const bySeverity: Record<string, number> = {};
    const byCategory: Record<string, number> = {};
    for (const f of findings) {
      bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
      byCategory[f.category] = (byCategory[f.category] ?? 0) + 1;
    }

    addEvidence(ctx, {
      claim: `Static review of ${scanned} file(s) produced ${findings.length} finding(s).`,
      prov: localProvenance('repository', input.relativePath ?? resolveRoot(input.path), 'source_review'),
      confidence: 'inferred',
      data: { scanned, findings: findings.length, bySeverity },
    });

    const summary = [
      '# Source Review',
      '',
      `Scanned ${scanned} file(s); **${findings.length}** finding(s).`,
      `Severity: ${Object.entries(bySeverity).map(([k, v]) => `${k}=${v}`).join(', ') || 'none'}`,
      `Categories: ${Object.entries(byCategory).map(([k, v]) => `${k}=${v}`).join(', ') || 'none'}`,
      '',
      ...findings.slice(0, 40).map((f) => `- **[${f.severity}]** \`${f.file}:${f.line}\` (${f.category}) — ${f.snippet}`),
      findings.length > 40 ? `\n... ${findings.length - 40} more finding(s)` : '',
    ].join('\n');

    return finish({
      engine: ENGINE,
      tool: 'source_review',
      summary,
      ctx,
      data: { scannedFiles: scanned, findingCount: findings.length, bySeverity, byCategory, findings },
      startedAt,
    });
  },
});

/* ------------------------------------------------------------------ */
/* Tool 11 — source_refactor                                          */
/* ------------------------------------------------------------------ */

const sourceRefactor = defineTool<
  { relativePath: string; operations: Array<{ find: string; replace: string }> },
  Record<string, unknown>
>({
  name: 'source_refactor',
  title: 'Source Refactor',
  engine: ENGINE,
  description:
    'Apply a batch of exact string replacements atomically: every find string is validated for existence and ' +
    'uniqueness before any write happens. Nothing is written when any operation fails validation.',
  capabilities: ['write_repo'],
  risk: 'local_mutation',
  inputSchema: {
    relativePath: z.string().min(1).describe('File to refactor, relative to the workspace root.'),
    operations: z
      .array(z.object({ find: z.string().min(1), replace: z.string() }))
      .min(1)
      .describe('Ordered list of exact find/replace operations.'),
  },
  handler: async (input, ctx) => {
    const startedAt = Date.now();
    if (input.operations.length === 0) throw errors.invalidInput('At least one operation is required.');
    resolveFile(input.relativePath);
    const artifact = readTextArtifact(input.relativePath);

    // Phase 1 — validate all operations against the original content.
    const problems: string[] = [];
    input.operations.forEach((op, index) => {
      const count = artifact.content.split(op.find).length - 1;
      if (count === 0) problems.push(`operation #${index}: find string not found`);
      else if (count > 1) problems.push(`operation #${index}: find string is not unique (${count} occurrences)`);
    });
    if (problems.length > 0) {
      throw errors.invalidInput('Refactor aborted; no changes were written.', { problems });
    }

    // Phase 2 — apply in memory, then write once.
    let updated = artifact.content;
    const applied: Array<{ index: number; find: string; replace: string; at: number }> = [];
    input.operations.forEach((op, index) => {
      const at = updated.indexOf(op.find);
      updated = updated.replace(op.find, () => op.replace);
      applied.push({ index, find: op.find, replace: op.replace, at });
    });

    const beforeSha = await sha256(artifact.content);
    const afterSha = await sha256(updated);
    writeAtomic(artifact.path, updated);

    addEvidence(ctx, {
      claim: `Applied ${applied.length} refactor operation(s) atomically to "${input.relativePath}".`,
      prov: localProvenance('repository', artifact.path, 'source_refactor'),
      confidence: 'confirmed',
      locator: { file: artifact.path },
      data: { operations: applied.length, beforeSha, afterSha },
    });

    const summary = [
      '# Source Refactor',
      '',
      `File: \`${input.relativePath}\``,
      `Operations applied: **${applied.length}**`,
      `Before: \`${beforeSha}\` → After: \`${afterSha}\``,
      '',
      ...applied.map((a) => `- #${a.index}: \`${a.find.slice(0, 40)}\` → \`${a.replace.slice(0, 40)}\``),
    ].join('\n');

    return finish({
      engine: ENGINE,
      tool: 'source_refactor',
      summary,
      ctx,
      data: {
        file: input.relativePath,
        applied,
        beforeSha,
        afterSha,
        bytesBefore: artifact.bytes,
        bytesAfter: Buffer.byteLength(updated, 'utf8'),
      },
      startedAt,
    });
  },
});

/* ------------------------------------------------------------------ */
/* Tool 12 — build_project                                            */
/* ------------------------------------------------------------------ */

interface BuildData {
  root: string;
  command: string;
  args: string[];
  exitCode: number | null;
  timedOut: boolean;
  durationMs: number;
  diagnostics: Diagnostic[];
  stdout: string;
  stderr: string;
}

const buildProject = defineTool<
  { path?: string; command?: string; args?: string[]; timeoutMs?: number },
  BuildData
>({
  name: 'build_project',
  title: 'Build Project',
  engine: ENGINE,
  description:
    'Build a project inside the sandbox. When no command is supplied, the build system is auto-detected ' +
    '(npm run build, cargo build, go build, cmake/make, maven, gradle, dotnet). Returns parsed diagnostics.',
  capabilities: ['run_build'],
  risk: 'isolated_exec',
  inputSchema: {
    path: z.string().optional().describe('Project directory relative to the workspace root (default ".").'),
    command: z.string().optional().describe('Explicit build command (overrides auto-detection).'),
    args: z.array(z.string()).optional().describe('Arguments for the explicit command.'),
    timeoutMs: z.number().int().min(1000).optional().describe('Timeout in milliseconds.'),
  },
  handler: async (input, ctx) => {
    const startedAt = Date.now();
    const root = resolveRoot(input.path);

    let command = input.command?.trim();
    let args = input.args ?? [];
    let reason: string;
    if (!command) {
      const detected = detectBuildCommand(root);
      if (!detected) {
        throw errors.toolMissing(
          'build system',
          ['npm', 'cargo', 'go', 'cmake/make', 'mvn', 'gradle', 'dotnet'],
        );
      }
      command = detected.command;
      args = detected.args;
      reason = detected.reason;
    } else {
      reason = 'explicit command';
    }

    const warnings: string[] = [];
    if (!toolOnPathSync(command.split(/[\\/]/).pop() ?? command)) {
      warnings.push(`Executable "${command}" was not found on PATH; the build may fail to spawn.`);
    }

    const result = await exec(root, command, args, input.timeoutMs);
    const combined = `${result.stdout}\n${result.stderr}`;
    const diagnostics = parseDiagnostics(combined);
    if (result.timedOut) warnings.push(`Build exceeded the timeout and was terminated.`);

    addEvidence(ctx, {
      claim: `Build executed (${reason}): ${command} ${args.join(' ')} exited with ${result.exitCode}.`,
      prov: localProvenance('build', root, 'build_project'),
      confidence: 'observed',
      locator: { file: root },
      data: { exitCode: result.exitCode, diagnostics: diagnostics.length },
    });

    const errorCount = diagnostics.filter((d) => d.severity === 'error').length;
    const warningCount = diagnostics.filter((d) => d.severity === 'warning').length;
    const summary = [
      '# Build Project',
      '',
      `Command: \`${command} ${args.join(' ')}\` (${reason})`,
      `Exit code: **${result.exitCode}**${result.timedOut ? ' (timed out)' : ''} in ${result.durationMs}ms`,
      `Diagnostics: ${errorCount} error(s), ${warningCount} warning(s)`,
      '',
      ...diagnostics.slice(0, 25).map((d) => `- ${d.severity.toUpperCase()}${d.file ? ` \`${d.file}${d.line ? `:${d.line}${d.column ? `:${d.column}` : ''}` : ''}\`` : ''} — ${d.message}`),
    ].join('\n');

    return finish({
      engine: ENGINE,
      tool: 'build_project',
      summary,
      ctx,
      warnings,
      data: {
        root,
        command,
        args,
        exitCode: result.exitCode,
        timedOut: result.timedOut,
        durationMs: result.durationMs,
        diagnostics,
        stdout: result.stdout.slice(0, 100_000),
        stderr: result.stderr.slice(0, 100_000),
      },
      startedAt,
    });
  },
});

/* ------------------------------------------------------------------ */
/* Tool 13 — run_tests                                                */
/* ------------------------------------------------------------------ */

const runTests = defineTool<
  { path?: string; command?: string; args?: string[]; timeoutMs?: number },
  Record<string, unknown>
>({
  name: 'run_tests',
  title: 'Run Tests',
  engine: ENGINE,
  description:
    'Run the test suite inside the sandbox. The runner is auto-detected (vitest, jest, pytest, cargo test, ' +
    'go test, maven test, gradle test) and pass/fail counts are parsed from the output.',
  capabilities: ['run_tests'],
  risk: 'isolated_exec',
  inputSchema: {
    path: z.string().optional().describe('Project directory relative to the workspace root (default ".").'),
    command: z.string().optional().describe('Explicit test command (overrides auto-detection).'),
    args: z.array(z.string()).optional().describe('Arguments for the explicit command.'),
    timeoutMs: z.number().int().min(1000).optional().describe('Timeout in milliseconds.'),
  },
  handler: async (input, ctx) => {
    const startedAt = Date.now();
    const root = resolveRoot(input.path);

    let command = input.command?.trim();
    let args = input.args ?? [];
    let reason: string;
    if (!command) {
      const detected = detectTestCommand(root);
      if (!detected) {
        throw errors.toolMissing('test runner', ['vitest', 'jest', 'pytest', 'cargo', 'go', 'mvn', 'gradle']);
      }
      command = detected.command;
      args = detected.args;
      reason = detected.reason;
    } else {
      reason = 'explicit command';
    }

    const result = await exec(root, command, args, input.timeoutMs);
    const combined = `${result.stdout}\n${result.stderr}`;
    const counts = parseTestCounts(combined);

    const warnings: string[] = [];
    if (result.timedOut) warnings.push('Test run exceeded the timeout and was terminated.');
    if (result.exitCode !== 0) warnings.push('Tests reported a non-zero exit code.');

    addEvidence(ctx, {
      claim: `Test run (${reason}): exit ${result.exitCode}, passed=${counts.passed ?? 'unknown'}, failed=${counts.failed ?? 'unknown'}.`,
      prov: localProvenance('test', root, 'run_tests'),
      confidence: 'observed',
      locator: { file: root },
      data: counts,
    });

    const summary = [
      '# Run Tests',
      '',
      `Command: \`${command} ${args.join(' ')}\` (${reason})`,
      `Exit code: **${result.exitCode}**${result.timedOut ? ' (timed out)' : ''} in ${result.durationMs}ms`,
      `Results: passed=${counts.passed ?? 'n/a'}, failed=${counts.failed ?? 'n/a'}, total=${counts.total ?? 'n/a'}`,
    ].join('\n');

    return finish({
      engine: ENGINE,
      tool: 'run_tests',
      summary,
      ctx,
      warnings,
      data: {
        root,
        command,
        args,
        exitCode: result.exitCode,
        timedOut: result.timedOut,
        durationMs: result.durationMs,
        ...counts,
        stdout: result.stdout.slice(0, 100_000),
        stderr: result.stderr.slice(0, 100_000),
      },
      startedAt,
    });
  },
});

/* ------------------------------------------------------------------ */
/* Tool 14 — debug_project                                            */
/* ------------------------------------------------------------------ */

const debugProject = defineTool<
  { path?: string; buildCommand?: string; runCommand?: string; args?: string[]; timeoutMs?: number },
  Record<string, unknown>
>({
  name: 'debug_project',
  title: 'Debug Project',
  engine: ENGINE,
  description:
    'Two-phase diagnostics: build the project, and if the build succeeds run the program. ' +
    'Returns both phases plus a heuristic likely-root-cause derived from the first error line.',
  capabilities: ['run_build'],
  risk: 'isolated_exec',
  inputSchema: {
    path: z.string().optional().describe('Project directory relative to the workspace root (default ".").'),
    buildCommand: z.string().optional().describe('Explicit build command (defaults to auto-detection).'),
    runCommand: z.string().optional().describe('Command used to run the program after a successful build.'),
    args: z.array(z.string()).optional().describe('Arguments passed to the run command.'),
    timeoutMs: z.number().int().min(1000).optional().describe('Timeout in milliseconds per phase.'),
  },
  handler: async (input, ctx) => {
    const startedAt = Date.now();
    const root = resolveRoot(input.path);
    const warnings: string[] = [];

    let buildCommand = input.buildCommand?.trim();
    let buildArgs: string[] = [];
    if (!buildCommand) {
      const detected = detectBuildCommand(root);
      if (!detected) throw errors.toolMissing('build system', ['npm', 'cargo', 'go', 'cmake/make', 'mvn', 'gradle', 'dotnet']);
      buildCommand = detected.command;
      buildArgs = detected.args;
    }

    const buildResult = await exec(root, buildCommand, buildArgs, input.timeoutMs);
    const buildDiagnostics = parseDiagnostics(`${buildResult.stdout}\n${buildResult.stderr}`);
    const build = {
      command: buildCommand,
      args: buildArgs,
      exitCode: buildResult.exitCode,
      timedOut: buildResult.timedOut,
      durationMs: buildResult.durationMs,
      diagnostics: buildDiagnostics,
      stdout: buildResult.stdout.slice(0, 60_000),
      stderr: buildResult.stderr.slice(0, 60_000),
    };

    let run: Record<string, unknown> | undefined;
    if (buildResult.exitCode === 0 && input.runCommand) {
      const runResult = await exec(root, input.runCommand, input.args ?? [], input.timeoutMs);
      run = {
        command: input.runCommand,
        args: input.args ?? [],
        exitCode: runResult.exitCode,
        timedOut: runResult.timedOut,
        durationMs: runResult.durationMs,
        stdout: runResult.stdout.slice(0, 60_000),
        stderr: runResult.stderr.slice(0, 60_000),
      };
    } else if (buildResult.exitCode !== 0) {
      warnings.push('Build failed; the run phase was skipped.');
    } else {
      warnings.push('No runCommand provided; only the build phase was executed.');
    }

    const firstError = buildDiagnostics.find((d) => d.severity === 'error');
    let likelyRootCause: string;
    if (firstError) {
      likelyRootCause = `Build error${firstError.file ? ` in ${firstError.file}${firstError.line ? `:${firstError.line}` : ''}` : ''}: ${firstError.message}`;
    } else if (buildResult.exitCode !== 0) {
      const firstLine = formatExec(buildResult).split('\n').find((l) => l.trim());
      likelyRootCause = firstLine
        ? `Build exited with ${buildResult.exitCode}; first output line: ${firstLine.trim()}`
        : `Build exited with ${buildResult.exitCode} with no diagnostic output.`;
    } else if (run && run.exitCode !== 0) {
      likelyRootCause = `Program ran but exited with ${run.exitCode}.`;
    } else {
      likelyRootCause = 'No build or runtime failure detected.';
    }

    addEvidence(ctx, {
      claim: `Debug phase complete: build exit ${buildResult.exitCode}${run ? `, run exit ${run.exitCode as number}` : ''}.`,
      prov: localProvenance('build', root, 'debug_project'),
      confidence: 'observed',
      locator: { file: root },
      data: { buildExit: buildResult.exitCode, likelyRootCause },
    });

    const summary = [
      '# Debug Project',
      '',
      `Build: \`${buildCommand} ${buildArgs.join(' ')}\` → exit **${buildResult.exitCode}** in ${buildResult.durationMs}ms`,
      ...buildDiagnostics.slice(0, 10).map((d) => `- ${d.severity.toUpperCase()}${d.file ? ` \`${d.file}:${d.line ?? 0}\`` : ''} — ${d.message}`),
      run ? `\nRun: \`${String(run.command)}\` → exit **${String(run.exitCode)}**` : '\nRun: (skipped)',
      '',
      `**Likely root cause:** ${likelyRootCause}`,
    ].join('\n');

    return finish({
      engine: ENGINE,
      tool: 'debug_project',
      summary,
      ctx,
      warnings,
      data: { root, build, ...(run ? { run } : {}), likelyRootCause },
      startedAt,
    });
  },
});

/* ------------------------------------------------------------------ */
/* Tool 15 — regression_test                                          */
/* ------------------------------------------------------------------ */

const regressionTest = defineTool<
  { path?: string; testCommand?: string; baselineCommand?: string; timeoutMs?: number },
  Record<string, unknown>
>({
  name: 'regression_test',
  title: 'Regression Test',
  engine: ENGINE,
  description:
    'Run a test command, report a strict PASS/FAIL verdict with parsed counts, and optionally compare against ' +
    'a baseline command. Success is never claimed unless the exit code is exactly 0.',
  capabilities: ['run_tests'],
  risk: 'isolated_exec',
  inputSchema: {
    path: z.string().optional().describe('Project directory relative to the workspace root (default ".").'),
    testCommand: z.string().optional().describe('Test command (defaults to auto-detection).'),
    baselineCommand: z.string().optional().describe('Optional baseline command for comparison.'),
    timeoutMs: z.number().int().min(1000).optional().describe('Timeout in milliseconds per run.'),
  },
  handler: async (input, ctx) => {
    const startedAt = Date.now();
    const root = resolveRoot(input.path);

    let command = input.testCommand?.trim();
    let args: string[] = [];
    if (!command) {
      const detected = detectTestCommand(root);
      if (!detected) throw errors.toolMissing('test runner', ['vitest', 'jest', 'pytest', 'cargo', 'go', 'mvn', 'gradle']);
      command = detected.command;
      args = detected.args;
    }

    const result = await exec(root, command, args, input.timeoutMs);
    const counts = parseTestCounts(`${result.stdout}\n${result.stderr}`);
    const status: 'PASS' | 'FAIL' = result.exitCode === 0 ? 'PASS' : 'FAIL';

    const warnings: string[] = [];
    if (result.exitCode !== 0) {
      warnings.push(`Test command exited with ${result.exitCode}; reporting FAIL — success is only claimed on exit code 0.`);
    }
    if (result.timedOut) warnings.push('Test command timed out.');

    let baseline: Record<string, unknown> | undefined;
    if (input.baselineCommand) {
      const baseResult = await exec(root, input.baselineCommand, [], input.timeoutMs);
      const baseCounts = parseTestCounts(`${baseResult.stdout}\n${baseResult.stderr}`);
      baseline = {
        command: input.baselineCommand,
        exitCode: baseResult.exitCode,
        durationMs: baseResult.durationMs,
        ...baseCounts,
      };
    }

    addEvidence(ctx, {
      claim: `Regression test verdict ${status} (exit ${result.exitCode}).`,
      prov: localProvenance('test', root, 'regression_test'),
      confidence: 'observed',
      locator: { file: root },
      data: { status, exitCode: result.exitCode, ...counts },
    });

    const summary = [
      `# Regression Test — **${status}**`,
      '',
      `Command: \`${command} ${args.join(' ')}\``,
      `Exit code: **${result.exitCode}**${result.timedOut ? ' (timed out)' : ''} in ${result.durationMs}ms`,
      `Counts: passed=${counts.passed ?? 'n/a'}, failed=${counts.failed ?? 'n/a'}, total=${counts.total ?? 'n/a'}`,
      baseline
        ? `\nBaseline: exit ${String(baseline.exitCode)} · passed=${String(baseline.passed ?? 'n/a')}, failed=${String(baseline.failed ?? 'n/a')}`
        : '',
    ].join('\n');

    return finish({
      engine: ENGINE,
      tool: 'regression_test',
      summary,
      ctx,
      warnings,
      data: {
        root,
        status,
        command,
        args,
        exitCode: result.exitCode,
        timedOut: result.timedOut,
        durationMs: result.durationMs,
        ...counts,
        ...(baseline ? { baseline } : {}),
        stdout: result.stdout.slice(0, 60_000),
        stderr: result.stderr.slice(0, 60_000),
      },
      startedAt,
    });
  },
});

/* ------------------------------------------------------------------ */
/* Tool 16 — code_quality_report                                      */
/* ------------------------------------------------------------------ */

const codeQualityReport = defineTool<
  { path?: string; maxFiles?: number },
  Record<string, unknown>
>({
  name: 'code_quality_report',
  title: 'Code Quality Report',
  engine: ENGINE,
  description:
    'Aggregate quality metrics: lines of code per language, comment ratio, average and longest function lengths, ' +
    'duplicate-line ratio, TODO/FIXME density and maximum nesting depth, synthesized into a score. Read-only.',
  capabilities: ['read_repo'],
  risk: 'safe',
  inputSchema: {
    path: z.string().optional().describe('Directory relative to the workspace root (default ".").'),
    maxFiles: z.number().int().min(1).max(20000).optional().describe('Maximum files to analyze (default 2000).'),
  },
  handler: async (input, ctx) => {
    const startedAt = Date.now();
    const root = resolveRoot(input.path);
    const files = walkDirectory(root, { maxFiles: input.maxFiles ?? 2000 });

    const byLanguage = new Map<string, { files: number; code: number; comments: number; blank: number }>();
    const lineCounts = new Map<string, number>();
    const functionLengths: number[] = [];
    let maxNesting = 0;
    let todo = 0;
    let fixme = 0;
    let totalCode = 0;
    let totalComments = 0;
    let totalNonEmpty = 0;
    let analyzed = 0;

    for (const file of files) {
      if (!isSourcePath(file.rel)) continue;
      const text = readTextFileBounded(file.abs, CONTENT_SCAN_LIMIT);
      if (text === undefined) continue;
      analyzed += 1;
      const language = languageOf(file.rel);
      const lines = text.split('\n');
      const agg = byLanguage.get(language) ?? { files: 0, code: 0, comments: 0, blank: 0 };
      agg.files += 1;

      for (const raw of lines) {
        const trimmed = raw.trim();
        if (!trimmed) {
          agg.blank += 1;
          continue;
        }
        totalNonEmpty += 1;
        lineCounts.set(trimmed, (lineCounts.get(trimmed) ?? 0) + 1);
        if (/^(?:\/\/|#|\*|\/\*|--|;)/.test(trimmed)) {
          agg.comments += 1;
          totalComments += 1;
        } else {
          agg.code += 1;
          totalCode += 1;
        }
      }

      const markers = countMarkers(text);
      todo += markers.todo;
      fixme += markers.fixme;

      const metrics = braceMetrics(lines);
      maxNesting = Math.max(maxNesting, metrics.maxDepth);

      for (const span of findFunctionSpans(lines, language)) {
        if (span.length > 1) functionLengths.push(span.length);
      }

      byLanguage.set(language, agg);
    }

    let duplicateLines = 0;
    for (const count of lineCounts.values()) {
      if (count > 1) duplicateLines += count - 1;
    }
    const duplicateRatio = totalNonEmpty > 0 ? duplicateLines / totalNonEmpty : 0;
    const commentRatio = totalCode + totalComments > 0 ? totalComments / (totalCode + totalComments) : 0;
    const avgFunctionLength = functionLengths.length
      ? functionLengths.reduce((a, b) => a + b, 0) / functionLengths.length
      : 0;
    const longFunctions = functionLengths.filter((l) => l > 80).length;

    let score = 100;
    score -= Math.min(40, duplicateRatio * 100);
    if (commentRatio < 0.05) score -= 10;
    else if (commentRatio < 0.1) score -= 5;
    if (avgFunctionLength > 60) score -= 10;
    score -= Math.min(20, longFunctions * 3);
    score -= Math.min(10, (todo + fixme) * 0.5);
    score = Math.max(0, Math.round(score));
    const grade = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : 'F';

    addEvidence(ctx, {
      claim: `Code quality report over ${analyzed} file(s): score ${score} (${grade}).`,
      prov: localProvenance('repository', root, 'code_quality_report'),
      confidence: 'inferred',
      locator: { file: root },
      data: { score, grade, analyzed, duplicateRatio, commentRatio },
    });

    const languages = [...byLanguage.entries()]
      .map(([language, agg]) => ({ language, ...agg }))
      .sort((a, b) => b.code - a.code);

    const summary = [
      '# Code Quality Report',
      '',
      `**Score: ${score}/100 (grade ${grade})** over ${analyzed} source file(s).`,
      '',
      '## Metrics',
      `- Total code lines: ${totalCode}`,
      `- Comment ratio: ${(commentRatio * 100).toFixed(1)}%`,
      `- Duplicate-line ratio: ${(duplicateRatio * 100).toFixed(1)}%`,
      `- Functions analysed: ${functionLengths.length}, average length: ${avgFunctionLength.toFixed(1)} lines`,
      `- Long functions (>80 lines): ${longFunctions}`,
      `- Max nesting depth: ${maxNesting}`,
      `- TODO/FIXME: ${todo}/${fixme}`,
      '',
      '## Languages',
      ...languages.slice(0, 15).map((l) => `- ${l.language}: ${l.files} files · ${l.code} code · ${l.comments} comments · ${l.blank} blank`),
    ].join('\n');

    return finish({
      engine: ENGINE,
      tool: 'code_quality_report',
      summary,
      ctx,
      data: {
        root,
        score,
        grade,
        analyzedFiles: analyzed,
        totalCodeLines: totalCode,
        totalCommentLines: totalComments,
        commentRatio,
        duplicateRatio,
        avgFunctionLength,
        longFunctions,
        maxNestingDepth: maxNesting,
        markers: { todo, fixme },
        languages,
      },
      startedAt,
    });
  },
});

/* ------------------------------------------------------------------ */
/* Tool 17 — project_memory                                           */
/* ------------------------------------------------------------------ */

const projectMemory = defineTool<
  { projectPath: string; action: 'get' | 'set'; key?: string; value?: unknown; note?: string },
  Record<string, unknown>
>({
  name: 'project_memory',
  title: 'Project Memory',
  engine: ENGINE,
  description:
    'Persist and retrieve per-project engineering memory (architecture decisions, key files/symbols, build ' +
    'commands, dependency versions, past errors/fixes, test results, open issues). Memory is keyed by a slug ' +
    'derived from projectPath so unrelated repositories are never mixed.',
  capabilities: ['write_repo', 'write_knowledge'],
  risk: 'local_mutation',
  inputSchema: {
    projectPath: z.string().min(1).describe('Project root path (relative to the workspace root).'),
    action: z.enum(['get', 'set']).describe('"set" upserts a memory entry; "get" retrieves memory entries.'),
    key: z.string().optional().describe('Memory key (required for "set"; optional filter for "get").'),
    value: z.unknown().optional().describe('Arbitrary JSON value to remember (for "set").'),
    note: z.string().optional().describe('Optional free-form note.'),
  },
  handler: async (input, ctx) => {
    const startedAt = Date.now();
    const resolved = resolveWorkspacePath(input.projectPath, false);
    const slug = projectSlug(resolved);
    const baseTags = ['project-memory', slug];

    if (input.action === 'set') {
      if (!input.key) throw errors.invalidInput('A "key" is required when action is "set".');
      const now = new Date().toISOString();
      const id = `project-memory:${slug}:${input.key}`;
      const existing = ctx.knowledge.getRecord(id);

      const record: KnowledgeRecord = {
        id,
        category: 'research_paper',
        title: `Project memory — ${input.key}`,
        identifiers: {
          'project-memory-slug': slug,
          'project-memory-key': input.key,
          'project-memory-payload': JSON.stringify(input.value ?? null),
          'project-memory-path': resolved,
        },
        product: basename(resolved),
        affectedVersions: [],
        fixedVersions: [],
        klass: 'project-memory',
        ...(input.note ? { rootCause: input.note } : {}),
        preconditions: [],
        publicExploitState: 'unknown',
        relatedMalwareFamilies: [],
        relatedMiraiVariants: [],
        relatedRecordIds: [],
        verification: 'statically_reviewed',
        confidence: 'confirmed',
        provenance: [localProvenance('project-memory', resolved, input.note)],
        evidence: [],
        tags: [...baseTags, `key:${input.key}`],
        createdAt: existing?.createdAt ?? now,
        updatedAt: now,
      };
      const stored = ctx.knowledge.upsertRecord(record);
      ctx.knowledge.flush();

      addEvidence(ctx, {
        claim: `Stored project memory "${input.key}" for ${slug}.`,
        prov: localProvenance('project-memory', resolved, 'project_memory.set'),
        confidence: 'confirmed',
        locator: { file: resolved },
      });

      return finish({
        engine: ENGINE,
        tool: 'project_memory',
        summary: `# Project Memory\n\nStored key \`${input.key}\` for project \`${slug}\` (record \`${stored.id}\`).`,
        ctx,
        data: { action: 'set', projectSlug: slug, key: input.key, recordId: stored.id, updatedAt: stored.updatedAt },
        startedAt,
      });
    }

    // action === 'get'
    const tags = input.key ? [...baseTags, `key:${input.key}`] : baseTags;
    const records = ctx.knowledge.searchRecords({ categories: ['research_paper'], tags, limit: 200 });

    const entries = records.map((record) => {
      let value: unknown = null;
      const payload = record.identifiers['project-memory-payload'];
      if (payload !== undefined) {
        try {
          value = JSON.parse(payload);
        } catch {
          value = payload;
        }
      }
      return {
        key: record.identifiers['project-memory-key'] ?? record.id,
        value,
        note: record.rootCause,
        updatedAt: record.updatedAt,
      };
    });

    addEvidence(ctx, {
      claim: `Retrieved ${entries.length} project memory entr(y/ies) for ${slug}.`,
      prov: localProvenance('project-memory', resolved, 'project_memory.get'),
      confidence: 'confirmed',
      locator: { file: resolved },
      data: { count: entries.length },
    });

    const summary = [
      '# Project Memory',
      '',
      `Project: \`${slug}\``,
      `Entries: **${entries.length}**${input.key ? ` (key \`${input.key}\`)` : ''}`,
      '',
      ...entries.slice(0, 50).map((e) => `- \`${e.key}\` — ${JSON.stringify(e.value).slice(0, 200)}${e.note ? ` · ${e.note}` : ''}`),
      entries.length === 0 ? '- no memory recorded for this project yet' : '',
    ].join('\n');

    return finish({
      engine: ENGINE,
      tool: 'project_memory',
      summary,
      ctx,
      data: { action: 'get', projectSlug: slug, count: entries.length, entries },
      startedAt,
    });
  },
});

/* ------------------------------------------------------------------ */
/* Engine export                                                      */
/* ------------------------------------------------------------------ */

export const softwareEngineeringEngine: EngineModule = {
  name: 'software-engineering',
  title: 'Software Engineering Intelligence',
  description:
    'Technical software engineering intelligence: repository and architecture analysis, dependency and ' +
    'documentation discovery, symbol search, static code review, code quality metrics, deterministic local ' +
    'source generation/modification/refactoring, and sandboxed build/test debugging. Contains no offensive capability.',
  tools: [
    toolchainProbe,
    repositoryAnalyze,
    repositorySearch,
    symbolSearch,
    dependencyAnalyze,
    documentationSearch,
    architectureAnalyze,
    sourceGenerate,
    sourceModify,
    sourceReview,
    sourceRefactor,
    buildProject,
    runTests,
    debugProject,
    regressionTest,
    codeQualityReport,
    projectMemory,
  ],
};
