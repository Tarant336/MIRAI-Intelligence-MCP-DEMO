/**
 * Zero-Day Research Engine (§4 of the MIRAI upgrade specification).
 *
 * This is a defensive, analysis-only research pipeline. It discovers candidate
 * vulnerabilities, formulates falsifiable hypotheses, performs static/binary
 * research, plans fuzzing, triages crashes, reconstructs root causes and
 * tracks the lifecycle of findings. It NEVER executes a target, NEVER ships an
 * operational capability, and never asserts an unverified hypothesis as a
 * confirmed vulnerability.
 *
 * All heuristics here are explicit string/pattern-based analyses plus a minimal,
 * intra-file taint heuristic. They are labelled as heuristics and are never
 * represented as compiler-grade data-flow or symbolic execution (§4.3 of the
 * specification).
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { extname, join, relative } from 'node:path';

import { z } from 'zod';

import { getConfig } from '../../config/index.js';
import { errors } from '../../core/errors.js';
import type { EngineModule } from '../../core/tool.js';
import { getKnowledgeBase } from '../../shared/knowledge-base.js';
import { assertArtifactSize, resolveWorkspacePath } from '../../shared/security.js';
import type { ConfidenceLevel } from '../../shared/types.js';
import {
  addEvidence,
  curatedProvenance,
  defineTool,
  finish,
  localProvenance,
  readBinaryArtifact,
  readTextArtifact,
  zodCommon,
} from '../../tools/helpers.js';
import { analyzeBuffer, extractStrings } from '../malware-intelligence/binary.js';

const ENGINE = 'zero-day-research';

/* ------------------------------------------------------------------ */
/* Shared types & constants                                            */
/* ------------------------------------------------------------------ */

type Severity = 'critical' | 'high' | 'medium' | 'low';

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 100,
  high: 70,
  medium: 40,
  low: 10,
};

const CONFIDENCE_WEIGHT: Record<ConfidenceLevel, number> = {
  confirmed: 100,
  observed: 75,
  inferred: 50,
  hypothesis: 25,
  unknown: 10,
};

const LIFECYCLE_STATES = [
  'candidate',
  'under_analysis',
  'reproducible',
  'verified',
  'duplicate',
  'false_positive',
  'reported',
  'patched',
  'publicly_disclosed',
] as const;

type LifecycleState = (typeof LIFECYCLE_STATES)[number];

const LIFECYCLE_ENUM = z.enum(LIFECYCLE_STATES);

const VULN_CLASSES = [
  'buffer-overflow',
  'stack-overflow',
  'heap-corruption',
  'use-after-free',
  'integer-overflow',
  'out-of-bounds-read',
  'out-of-bounds-write',
  'format-string',
  'race-condition',
  'logic-flaw',
  'authentication-bypass',
  'authorization-bypass',
  'command-injection',
  'sql-injection',
  'path-traversal',
  'deserialization',
  'memory-safety',
  'parser-vulnerability',
  'protocol-vulnerability',
  'hardcoded-secret',
  'weak-crypto',
  'null-dereference',
  'privilege-boundary',
] as const;

type VulnerabilityClass = (typeof VULN_CLASSES)[number];

interface StaticPattern {
  id: string;
  klass: string;
  severity: Severity;
  description: string;
  /** Must NOT carry the /g flag (shared regex objects are reused). */
  regex: RegExp;
}

const STATIC_PATTERNS: StaticPattern[] = [
  {
    id: 'command-injection',
    klass: 'command-injection',
    severity: 'high',
    description: 'Shell/command execution sink fed by a non-literal argument.',
    regex: /system\s*\(|popen\s*\(|\bexec\s*\(|os\.system|subprocess\.(?:call|Popen|run)|child_process\.(?:exec|spawn|execFile)|Runtime\.getRuntime\(\)\.exec|shell\s*=\s*True|eval\s*\(/,
  },
  {
    id: 'sql-injection',
    klass: 'sql-injection',
    severity: 'high',
    description: 'SQL execution sink likely assembled by string concatenation.',
    regex: /executeQuery\s*\(|rawQuery\s*\(|cursor\.execute\s*\(|db\.query\s*\(|prepareStatement\s*\(\s*['"].*\+|\.execute\s*\(\s*['"].*\+/i,
  },
  {
    id: 'format-string',
    klass: 'format-string',
    severity: 'high',
    description: 'printf-family call whose format argument is a variable.',
    regex: /\b(?:sprintf|snprintf|fprintf|printf|vsprintf|vprintf)\s*\(\s*[a-zA-Z_]/,
  },
  {
    id: 'memory-unsafe-copy',
    klass: 'buffer-overflow',
    severity: 'high',
    description: 'Unbounded C string/memory copy that may overflow a destination.',
    regex: /\b(strcpy|strcat|gets|sprintf|strncpy|memcpy|strncat|scanf)\s*\(/,
  },
  {
    id: 'integer-overflow-allocation',
    klass: 'integer-overflow',
    severity: 'medium',
    description: 'Allocation size computed from a multiplication (possible wrap).',
    regex: /malloc\s*\(\s*[a-zA-Z_]\w*\s*\*|calloc\s*\(\s*[^,]+,\s*sizeof/,
  },
  {
    id: 'use-after-free-marker',
    klass: 'use-after-free',
    severity: 'medium',
    description: 'Memory release site; requires flow analysis to confirm use-after-free.',
    regex: /\bfree\s*\(\s*[a-zA-Z_]|\bdelete\s+[a-zA-Z_]\w*/,
  },
  {
    id: 'path-traversal',
    klass: 'path-traversal',
    severity: 'high',
    description: 'User-influenced path used in a file-open primitive.',
    regex: /(?:\.\.\/|\.\.\\)|readFileSync\s*\(\s*[a-zA-Z_]|fopen\s*\(\s*[a-zA-Z_]|open\s*\(\s*[a-zA-Z_].*['"][a-zA-Z_]/,
  },
  {
    id: 'deserialization',
    klass: 'deserialization',
    severity: 'high',
    description: 'Unsafe object deserialization primitive.',
    regex: /pickle\.loads|unserialize\s*\(|yaml\.load\s*\(|ObjectInputStream|readObject\s*\(/,
  },
  {
    id: 'weak-crypto',
    klass: 'weak-crypto',
    severity: 'low',
    description: 'Use of a known-weak cryptographic primitive.',
    regex: /\b(md5|sha1|rc4|arc4|des_ecb)\b|hashlib\.md5|MessageDigest\.getInstance\(["'](MD5|SHA-?1)/i,
  },
  {
    id: 'hardcoded-secret',
    klass: 'hardcoded-secret',
    severity: 'high',
    description: 'Hard-coded credential/token literal.',
    regex: /(?:password|passwd|secret|api[_-]?key|apikey|token|private[_-]?key)\s*[:=]\s*['"][^'"]{4,}['"]/i,
  },
  {
    id: 'race-condition',
    klass: 'race-condition',
    severity: 'medium',
    description: 'Explicit time-of-check/time-of-use or race condition marker.',
    regex: /\bTOCTOU\b|time[- ]of[- ]check|race\s+condition/i,
  },
];

const DEFAULT_SOURCE_EXTS = [
  '.c', '.h', '.cpp', '.cc', '.cxx', '.hpp',
  '.js', '.mjs', '.cjs', '.ts', '.tsx',
  '.py', '.go', '.rs', '.java', '.php', '.sh',
];

const LANG_EXTS: Record<string, string[]> = {
  c: ['.c', '.h'],
  'c++': ['.cpp', '.cc', '.cxx', '.hpp', '.hh'],
  javascript: ['.js', '.mjs', '.cjs'],
  typescript: ['.ts', '.tsx'],
  python: ['.py'],
  go: ['.go'],
  rust: ['.rs'],
  java: ['.java'],
  php: ['.php'],
  shell: ['.sh', '.bash'],
};

export interface Finding {
  sourceLocation: string;
  line: number;
  klass: string;
  severity: Severity;
  patternId: string;
  snippet: string;
  confidence: ConfidenceLevel;
  /** CWE identifier for the detected class (e.g. "CWE-121"). */
  cwe?: string;
  /** Taint origin that reaches this sink, when a minimal data-flow path was found. */
  source?: string;
  /** The dangerous call/operation that constitutes the sink. */
  sink?: string;
  /** Human-readable justification for the finding. */
  reasoning?: string;
  /** Explicit limits of this heuristic detection (why it may be wrong). */
  limitations?: string[];
  /** Concrete reasons this match may be a false positive. */
  falsePositiveConsiderations: string[];
  /** Next step an analyst should take to confirm or dismiss the finding. */
  recommendedVerification: string;
}

interface CrashClassification {
  signal: string;
  faultClass: string;
  exploitability: 'dos' | 'potential-memory-corruption' | 'assertion' | 'undefined';
  confidence: ConfidenceLevel;
  notes: string[];
}

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

function slug(input: string): string {
  const s = input
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64);
  return s || 'untitled';
}

function fnv1a(input: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < input.length; i += 1) {
    h ^= input.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16);
}

function makeId(prefix: string, ...parts: string[]): string {
  return `${prefix}:${slug(parts.join('-'))}`;
}

function nowIso(): string {
  return new Date().toISOString();
}

function tagValue(tags: string[], prefix: string): string | undefined {
  return tags.find((t) => t.startsWith(prefix))?.slice(prefix.length);
}

function severityFromTags(tags: string[], fallback: Severity = 'medium'): Severity {
  const v = tagValue(tags, 'sev:');
  return v === 'critical' || v === 'high' || v === 'medium' || v === 'low' ? v : fallback;
}

function languageFor(path: string): string {
  const ext = extname(path).toLowerCase();
  for (const [lang, exts] of Object.entries(LANG_EXTS)) {
    if (exts.includes(ext)) return lang;
  }
  return 'unknown';
}

function abortIfNeeded(signal?: AbortSignal): void {
  if (signal?.aborted) throw errors.timeout('zero-day analysis', 0);
}

function walkDir(dirAbs: string, exts: string[], maxFiles: number): string[] {
  const out: string[] = [];
  const stack = [dirAbs];
  while (stack.length > 0 && out.length < maxFiles) {
    const cur = stack.pop();
    if (!cur) continue;
    let entries;
    try {
      entries = readdirSync(cur, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (out.length >= maxFiles) break;
      const full = join(cur, entry.name);
      if (entry.isDirectory()) {
        if (!/node_modules|\.git|dist|build|target|__pycache__|\.venv|vendor/i.test(entry.name)) {
          stack.push(full);
        }
      } else if (entry.isFile() && exts.includes(extname(entry.name).toLowerCase())) {
        out.push(full);
      }
    }
  }
  return out;
}

/** Read a bounded text slice, skipping files that exceed the per-file budget. */
function readFileCapped(absPath: string, maxBytes: number): { content: string; truncated: boolean } | null {
  let size = 0;
  try {
    size = statSync(absPath).size;
  } catch {
    return null;
  }
  if (size > maxBytes) {
    const buf = readFileSync(absPath).subarray(0, maxBytes);
    return { content: buf.toString('utf8'), truncated: true };
  }
  return { content: readFileSync(absPath, 'utf8'), truncated: false };
}

/* ------------------------------------------------------------------ */
/* Source scanning: comments, sink modelling and minimal data-flow     */
/* ------------------------------------------------------------------ */

interface CallSite {
  callee: string;
  args: string[];
}

/** Pattern ids handled by the dedicated detectors below (skipped by the generic loop). */
const SPECIAL_PATTERN_IDS = new Set(['format-string', 'memory-unsafe-copy']);

const COMMAND_SINKS = new Set([
  'system', 'popen',
  'execl', 'execlp', 'execle', 'execv', 'execvp', 'execvpe', 'execve',
]);

/** For each printf-family function, the index of its format-string argument. */
const FORMAT_FN_FORMAT_ARG: Record<string, number> = {
  printf: 0, vprintf: 0,
  fprintf: 1, vfprintf: 1,
  sprintf: 1, vsprintf: 1,
  snprintf: 2, vsnprintf: 2,
  syslog: 1,
};

/** Memory/string copy sinks: dest is always arg 0; `size` is the length arg if bounded-capable. */
const COPY_SINKS: Record<string, { cwe: string; src: number | null; size: number | null }> = {
  strcpy: { cwe: 'CWE-121', src: 1, size: null },
  strcat: { cwe: 'CWE-121', src: 1, size: null },
  gets: { cwe: 'CWE-120', src: null, size: null },
  sprintf: { cwe: 'CWE-120', src: 1, size: null },
  scanf: { cwe: 'CWE-120', src: null, size: null },
  memcpy: { cwe: 'CWE-787', src: 1, size: 2 },
  memmove: { cwe: 'CWE-787', src: 1, size: 2 },
  strncpy: { cwe: 'CWE-787', src: 1, size: 2 },
  strncat: { cwe: 'CWE-787', src: 1, size: 2 },
};

/** Functions that write attacker-controlled data into a destination argument. */
const COPY_WRITERS = new Set([
  'sprintf', 'snprintf', 'vsprintf', 'vsnprintf',
  'strcpy', 'strcat', 'strncpy', 'strncat', 'memcpy', 'memmove',
]);

/** Input sources: which argument receives attacker-controlled bytes (arg -1 ⇒ return value). */
const INPUT_PRODUCERS: Record<string, { arg: number; label: string }> = {
  recv: { arg: 1, label: 'recv()' },
  recvfrom: { arg: 1, label: 'recvfrom()' },
  recvmsg: { arg: 2, label: 'recvmsg()' },
  read: { arg: 1, label: 'read()' },
  pread: { arg: 1, label: 'pread()' },
  fread: { arg: 0, label: 'fread()' },
  fgets: { arg: 0, label: 'fgets()' },
  gets: { arg: 0, label: 'gets()' },
  scanf: { arg: 1, label: 'scanf()' },
  sscanf: { arg: 1, label: 'sscanf()' },
  fscanf: { arg: 2, label: 'fscanf()' },
  getenv: { arg: -1, label: 'getenv()' },
};

/**
 * Blank out `//` and block comments while preserving line count and the contents
 * of string / char literals, so line numbers remain accurate and patterns inside
 * comments never match. Preprocessor lines are preserved; the scanner skips them.
 */
export function stripCommentsPreserveLines(content: string): string[] {
  const lines = content.split(/\r?\n/);
  let inBlock = false;
  return lines.map((raw) => {
    let out = '';
    let i = 0;
    let quote: string | null = null;
    while (i < raw.length) {
      const ch = raw[i]!;
      const next = raw[i + 1];
      if (inBlock) {
        if (ch === '*' && next === '/') { inBlock = false; out += '  '; i += 2; continue; }
        out += ' ';
        i += 1;
        continue;
      }
      if (quote) {
        out += ch;
        if (ch === '\\') { out += next ?? ''; i += 2; continue; }
        if (ch === quote) quote = null;
        i += 1;
        continue;
      }
      if (ch === '"' || ch === "'") { quote = ch; out += ch; i += 1; continue; }
      if (ch === '/' && next === '*') { inBlock = true; out += '  '; i += 2; continue; }
      if (ch === '/' && next === '/') break;
      out += ch;
      i += 1;
    }
    return out;
  });
}

/** Split a call argument list on top-level commas (ignores commas inside (), [], "" and ''). */
function splitArgs(inside: string): string[] {
  const args: string[] = [];
  let depth = 0;
  let quote: string | null = null;
  let cur = '';
  for (let i = 0; i < inside.length; i += 1) {
    const ch = inside[i]!;
    if (quote) {
      cur += ch;
      if (ch === '\\') { cur += inside[i + 1] ?? ''; i += 1; continue; }
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") { quote = ch; cur += ch; continue; }
    if (ch === '(' || ch === '[' || ch === '{') { depth += 1; cur += ch; continue; }
    if (ch === ')' || ch === ']' || ch === '}') { depth -= 1; cur += ch; continue; }
    if (ch === ',' && depth === 0) { args.push(cur.trim()); cur = ''; continue; }
    cur += ch;
  }
  if (cur.trim() !== '' || args.length > 0) args.push(cur.trim());
  return args;
}

function matchCloseParen(line: string, open: number): number {
  let depth = 0;
  let quote: string | null = null;
  for (let i = open; i < line.length; i += 1) {
    const ch = line[i]!;
    if (quote) {
      if (ch === '\\') { i += 1; continue; }
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") { quote = ch; continue; }
    if (ch === '(') depth += 1;
    else if (ch === ')') { depth -= 1; if (depth === 0) return i; }
  }
  return -1;
}

/** Enumerate every call expression on a line (including nested calls). */
function scanCalls(line: string): CallSite[] {
  const calls: CallSite[] = [];
  const re = /\b([A-Za-z_]\w*)\s*\(/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(line)) !== null) {
    const callee = m[1]!;
    const open = m.index + m[0].length - 1;
    const close = matchCloseParen(line, open);
    const inside = close >= 0 ? line.slice(open + 1, close) : line.slice(open + 1);
    calls.push({ callee, args: splitArgs(inside) });
    re.lastIndex = open + 1;
  }
  return calls;
}

function identifiersIn(expr: string): string[] {
  return expr.match(/[A-Za-z_]\w*/g) ?? [];
}

/** First identifier of an argument (skips a leading cast such as "(char *)buf"). */
function firstIdentifier(expr: string): string | undefined {
  const m = (expr ?? '').match(/^\s*(?:\([^()]*\)\s*)?([A-Za-z_]\w*)/);
  return m ? m[1]! : undefined;
}

/** True when a copy size argument is provably bounded (a literal or `sizeof(dest)`). */
function isBoundedSize(sizeArg: string, dest: string | undefined): boolean {
  const s = (sizeArg ?? '').replace(/\s+/g, '');
  if (/^\d+$/.test(s)) return true;
  if (dest && s === `sizeof(${dest})`) return true;
  return false;
}

/** True when the enclosing function guards the size variable against `sizeof(dest)` before use. */
function hasBoundsGuard(
  codeLines: string[],
  start: number,
  upto: number,
  sizeVar: string | undefined,
  dest: string | undefined,
): boolean {
  if (!sizeVar || !dest) return false;
  const sizeofDest = new RegExp(`sizeof\\s*\\(\\s*${dest}\\s*\\)`);
  for (let j = Math.max(0, start); j < upto; j += 1) {
    const l = codeLines[j] ?? '';
    if (!/\bif\b|=/.test(l)) continue;
    if (!identifiersIn(l).includes(sizeVar)) continue;
    if (sizeofDest.test(l)) return true;
  }
  return false;
}

interface DataflowModel {
  fnAtLine: string[];
  fnStart: Map<string, number>;
  fnParams: Map<string, string[]>;
  /** function -> param index -> taint label */
  paramTaint: Map<string, Map<number, string>>;
  /** function -> local variable -> taint label */
  localTaint: Map<string, Map<string, string>>;
}

type TaintMap = Map<string | number, string>;

function putTaint(map: TaintMap, key: string | number, label: string): boolean {
  const existing = map.get(key);
  if (existing === undefined) { map.set(key, label); return true; }
  if (!existing.split('/').includes(label)) { map.set(key, `${existing}/${label}`); return true; }
  return false;
}

const FN_DEF = /^\s*(?:[A-Za-z_]\w*[\s*]+)+\s*([A-Za-z_]\w*)\s*\(([^;{)]*)\)\s*\{?\s*$/;

/**
 * Minimal, intra-file taint heuristic: identifies variables written by known
 * input primitives (recv/read/fgets/argv/getenv/...) and propagates the taint
 * through copies and user-function parameters via a small fixpoint. It is NOT a
 * compiler-grade data-flow analysis and is always reported as a heuristic.
 */
function analyzeDataflow(codeLines: string[]): DataflowModel {
  const fnAtLine: string[] = new Array(codeLines.length).fill('<global>');
  const fnStart = new Map<string, number>();
  const fnParams = new Map<string, string[]>();
  let cur = '<global>';
  for (let i = 0; i < codeLines.length; i += 1) {
    const line = codeLines[i]!;
    const def = line.match(FN_DEF);
    if (def) {
      cur = def[1]!;
      if (!fnStart.has(cur)) fnStart.set(cur, i);
      const names = splitArgs(def[2] ?? '')
        .map((p) => p.match(/([A-Za-z_]\w*)\s*$/)?.[1] ?? '')
        .filter((n) => n !== '');
      fnParams.set(cur, names);
      fnAtLine[i] = cur;
      continue;
    }
    fnAtLine[i] = cur;
    if (/^\}\s*$/.test(line)) cur = '<global>';
  }

  const paramTaint = new Map<string, Map<number, string>>();
  const localTaint = new Map<string, Map<string, string>>();
  const getParam = (fn: string): TaintMap => {
    let m = paramTaint.get(fn);
    if (!m) { m = new Map(); paramTaint.set(fn, m); }
    return m;
  };
  const getLocal = (fn: string): TaintMap => {
    let m = localTaint.get(fn);
    if (!m) { m = new Map(); localTaint.set(fn, m); }
    return m;
  };
  const taintedLabels = (fn: string): Map<string, string> => {
    const out = new Map<string, string>();
    const names = fnParams.get(fn) ?? [];
    const params = paramTaint.get(fn);
    if (params) for (const [idx, label] of params) { const nm = names[idx]; if (nm) out.set(nm, label); }
    const locals = localTaint.get(fn);
    if (locals) for (const [v, label] of locals) out.set(v, label);
    return out;
  };
  const labelFor = (expr: string, fn: string): string | undefined => {
    const ids = identifiersIn(expr);
    if (ids.includes('argv')) return 'argv';
    if (/getenv\s*\(/.test(expr)) return 'getenv()';
    const tm = taintedLabels(fn);
    for (const id of ids) { const l = tm.get(id); if (l) return l; }
    return undefined;
  };

  for (let iter = 0; iter < 8; iter += 1) {
    let changed = false;
    for (let i = 0; i < codeLines.length; i += 1) {
      const line = codeLines[i]!;
      if (!line.trim() || line.trim().startsWith('#')) continue;
      const fn = fnAtLine[i]!;
      for (const c of scanCalls(line)) {
        const prod = INPUT_PRODUCERS[c.callee];
        if (prod && prod.arg >= 0) {
          const dest = firstIdentifier(c.args[prod.arg] ?? '');
          if (dest && putTaint(getLocal(fn), dest, prod.label)) changed = true;
        } else if (prod && prod.arg === -1) {
          const lhs = line.match(/^\s*(?:[A-Za-z_][\w\s*]*?\s+)?([A-Za-z_]\w*)\s*=/);
          if (lhs && putTaint(getLocal(fn), lhs[1]!, prod.label)) changed = true;
        }
        if (COPY_WRITERS.has(c.callee)) {
          const dest = firstIdentifier(c.args[0] ?? '');
          if (dest) {
            for (let k = 1; k < c.args.length; k += 1) {
              const l = labelFor(c.args[k] ?? '', fn);
              if (l && putTaint(getLocal(fn), dest, l)) changed = true;
            }
          }
        }
        if (fnParams.has(c.callee)) {
          for (let k = 0; k < c.args.length; k += 1) {
            const l = labelFor(c.args[k] ?? '', fn);
            if (l && putTaint(getParam(c.callee), k, l)) changed = true;
          }
        }
      }
    }
    if (!changed) break;
  }

  return { fnAtLine, fnStart, fnParams, paramTaint, localTaint };
}

/** Resolve the taint label (if any) reaching an expression inside a function. */
function taintOf(expr: string, fn: string, df: DataflowModel): string | undefined {
  const ids = identifiersIn(expr);
  if (ids.includes('argv')) return 'argv';
  if (/getenv\s*\(/.test(expr)) return 'getenv()';
  const tm = new Map<string, string>();
  const names = df.fnParams.get(fn) ?? [];
  const params = df.paramTaint.get(fn);
  if (params) for (const [idx, label] of params) { const nm = names[idx]; if (nm) tm.set(nm, label); }
  const locals = df.localTaint.get(fn);
  if (locals) for (const [v, label] of locals) tm.set(v, label);
  for (const id of ids) { const l = tm.get(id); if (l) return l; }
  return undefined;
}

const TAINT_LIMITATIONS = [
  'Intra-file heuristic data-flow only; calls through pointers/macros and inter-file flows are not tracked.',
  'A tainted path is a candidate, not a proof: sanitisation/validation may exist off-line.',
];
const PATTERN_LIMITATIONS = [
  'Heuristic signature scan, not a compiler-grade static analyser; manual confirmation required.',
];

function makeFinding(args: {
  sourceLocation: string;
  line: number;
  klass: string;
  severity: Severity;
  patternId: string;
  snippet: string;
  cwe?: string;
  source?: string;
  sink?: string;
  reasoning: string;
  limitations: string[];
  falsePositiveConsiderations?: string[];
  recommendedVerification?: string;
}): Finding {
  const sink = args.sink ?? args.patternId;
  return {
    sourceLocation: `${args.sourceLocation}:${args.line}`,
    line: args.line,
    klass: args.klass,
    severity: args.severity,
    patternId: args.patternId,
    snippet: args.snippet,
    confidence: args.source ? 'inferred' : 'hypothesis',
    ...(args.cwe ? { cwe: args.cwe } : {}),
    ...(args.source ? { source: args.source } : {}),
    ...(args.sink ? { sink: args.sink } : {}),
    reasoning: args.reasoning,
    limitations: args.limitations,
    falsePositiveConsiderations:
      args.falsePositiveConsiderations ?? [
        args.source
          ? `The proven taint path ("${args.source}" → "${sink}") is intra-file only; an inter-procedural sanitiser may exist.`
          : 'No intra-file taint path was proven; the argument may be a constant or a validated value.',
        'The sink may be unreachable on the real code path (dead code or compile-time guard).',
      ],
    recommendedVerification:
      args.recommendedVerification ??
      `Trace "${sink}" back to an untrusted input and confirm with a focused test or an ASan/UBSan build at ${args.sourceLocation}:${args.line}.`,
  };
}

/** printf-family call whose format argument is a variable ⇒ CWE-134. */
function detectFormatString(
  line: string,
  fn: string,
  df: DataflowModel,
  sourceLocation: string,
  i: number,
): Finding | null {
  for (const c of scanCalls(line)) {
    const fmtIdx = FORMAT_FN_FORMAT_ARG[c.callee];
    if (fmtIdx === undefined) continue;
    const fmtArg = c.args[fmtIdx];
    if (fmtArg === undefined) continue;
    if (/^\s*"/.test(fmtArg)) continue; // literal format string ⇒ safe
    const source = taintOf(fmtArg, fn, df);
    return makeFinding({
      sourceLocation, line: i + 1,
      klass: 'format-string', severity: 'high', patternId: 'format-string',
      cwe: 'CWE-134',
      source,
      sink: `${c.callee}(${fmtArg})`,
      snippet: line.trim().slice(0, 200),
      reasoning:
        `${c.callee}() receives a non-literal format string ("${fmtArg.trim()}"). If that value is ` +
        'attacker-influenced, format specifiers can be abused to leak memory or write to it (CWE-134).',
      limitations: source
        ? [...TAINT_LIMITATIONS]
        : [...PATTERN_LIMITATIONS, 'The format argument is a variable but its provenance was not resolved within this file.'],
    });
  }
  return null;
}

/** Unbounded copy sink whose size is not provably bounded ⇒ CWE-121/CWE-120/CWE-787. */
function detectMemoryCopy(
  line: string,
  fn: string,
  df: DataflowModel,
  codeLines: string[],
  sourceLocation: string,
  i: number,
): Finding | null {
  for (const c of scanCalls(line)) {
    const spec = COPY_SINKS[c.callee];
    if (!spec) continue;
    const dest = firstIdentifier(c.args[0] ?? '');
    if (spec.size !== null) {
      const sizeArg = c.args[spec.size] ?? '';
      if (isBoundedSize(sizeArg, dest)) continue;
      const sizeVar = identifiersIn(sizeArg).pop();
      const start = df.fnStart.get(fn) ?? Math.max(0, i - 40);
      if (hasBoundsGuard(codeLines, start, i, sizeVar, dest)) continue;
    }
    const srcArg = spec.src !== null ? (c.args[spec.src] ?? '') : '';
    const source = srcArg ? taintOf(srcArg, fn, df) : undefined;
    const bounded = spec.size !== null;
    const reasoning = bounded
      ? `${c.callee}() copies a caller-controlled length ("${(c.args[spec.size!] ?? '').trim()}") into ` +
        `"${dest ?? '?'}" with no provable bound, so the length can exceed the destination and overwrite memory (${spec.cwe}).`
      : `${c.callee}() copies without checking the destination size of "${dest ?? '?'}"; an ` +
        `over-long source overflows the buffer (${spec.cwe}).`;
    return makeFinding({
      sourceLocation, line: i + 1,
      klass: 'buffer-overflow', severity: 'high', patternId: 'memory-unsafe-copy',
      cwe: spec.cwe,
      source,
      sink: `${c.callee}(${c.args.join(', ')})`,
      snippet: line.trim().slice(0, 200),
      reasoning,
      limitations: source
        ? [...TAINT_LIMITATIONS]
        : [...PATTERN_LIMITATIONS, 'Destination buffer capacity and source length were not evaluated.'],
    });
  }
  return null;
}

/** Shell/command execution sink fed by a variable argument ⇒ CWE-78. */
function detectCommandInjection(
  line: string,
  fn: string,
  df: DataflowModel,
  sourceLocation: string,
  i: number,
): Finding | null {
  for (const c of scanCalls(line)) {
    if (!COMMAND_SINKS.has(c.callee)) continue;
    const arg = c.args[0] ?? '';
    if (/^\s*"/.test(arg)) continue; // literal command ⇒ no injection
    const source = taintOf(arg, fn, df);
    return makeFinding({
      sourceLocation, line: i + 1,
      klass: 'command-injection', severity: 'high', patternId: 'command-injection',
      cwe: 'CWE-78',
      source,
      sink: `${c.callee}(${arg})`,
      snippet: line.trim().slice(0, 200),
      reasoning:
        `${c.callee}() executes a shell command built from a non-literal argument ("${arg.trim()}"). ` +
        'If that value is attacker-influenced, shell metacharacters allow arbitrary command execution (CWE-78).',
      limitations: source
        ? [...TAINT_LIMITATIONS]
        : [...PATTERN_LIMITATIONS, 'The command argument is a variable but its provenance was not resolved within this file.'],
    });
  }
  return null;
}

/** Fallback: the remaining signature rules (SQLi, path traversal, secrets, crypto, ...). */
function detectGenericPattern(
  line: string,
  trimmed: string,
  sourceLocation: string,
  i: number,
): Finding | null {
  for (const pattern of STATIC_PATTERNS) {
    if (SPECIAL_PATTERN_IDS.has(pattern.id)) continue;
    if (!pattern.regex.test(line)) continue;
    return makeFinding({
      sourceLocation, line: i + 1,
      klass: pattern.klass, severity: pattern.severity, patternId: pattern.id,
      snippet: trimmed.slice(0, 200),
      reasoning: `${pattern.description} (matched rule "${pattern.id}").`,
      limitations: [...PATTERN_LIMITATIONS],
    });
  }
  return null;
}

export function scanSource(content: string, sourceLocation: string, maxFindings = 200): Finding[] {
  const codeLines = stripCommentsPreserveLines(content);
  const df = analyzeDataflow(codeLines);
  const findings: Finding[] = [];
  for (let i = 0; i < codeLines.length && findings.length < maxFindings; i += 1) {
    const line = codeLines[i] ?? '';
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const fn = df.fnAtLine[i] ?? '<global>';
    const finding =
      detectFormatString(line, fn, df, sourceLocation, i) ??
      detectMemoryCopy(line, fn, df, codeLines, sourceLocation, i) ??
      detectCommandInjection(line, fn, df, sourceLocation, i) ??
      detectGenericPattern(line, trimmed, sourceLocation, i);
    if (finding) findings.push(finding);
  }
  return findings;
}

function rankFindings(findings: Finding[]): Finding[] {
  return findings.sort((a, b) => SEVERITY_WEIGHT[b.severity] - SEVERITY_WEIGHT[a.severity]);
}

function classifyCrash(input: {
  signal?: string;
  faultAddress?: string;
  backtrace: string[];
}): CrashClassification {
  const signal = input.signal ?? 'UNKNOWN';
  const backtrace = input.backtrace.map((b) => b.toLowerCase()).join(' ');
  const notes: string[] = [];
  let faultClass = 'unknown-fault';
  let exploitability: CrashClassification['exploitability'] = 'undefined';
  let confidence: ConfidenceLevel = 'hypothesis';

  if (/sigsegv|segmentation/i.test(signal)) {
    faultClass = 'memory-access-violation';
    exploitability = 'potential-memory-corruption';
    confidence = 'observed';
  } else if (/sigabrt|abort/i.test(signal)) {
    faultClass = 'assertion-abort';
    exploitability = 'assertion';
    confidence = 'observed';
  } else if (/sigbus/i.test(signal)) {
    faultClass = 'bus-error';
    exploitability = 'potential-memory-corruption';
  } else if (/sigill/i.test(signal)) {
    faultClass = 'illegal-instruction';
    exploitability = 'undefined';
  } else if (/sigfpe/i.test(signal)) {
    faultClass = 'arithmetic-error';
    exploitability = 'assertion';
  }

  if (/free\s*\(|malloc|heap|delete\s/.test(backtrace)) {
    notes.push('Backtrace touches heap allocation/deallocation; possible heap corruption or use-after-free.');
    exploitability = 'potential-memory-corruption';
  }
  if (/(recursion|__stack_chk_fail|stack overflow)/i.test(backtrace)) {
    notes.push('Backtrace suggests stack exhaustion; likely stack overflow.');
    faultClass = 'stack-overflow';
    exploitability = 'potential-memory-corruption';
  }
  if (/\b(null|0x0+)\b/.test(input.faultAddress ?? '') || /null pointer|segfault at 0\b/i.test(backtrace)) {
    notes.push('Fault address is null/zero; likely null-pointer dereference (usually DoS, not control-flow hijack).');
    exploitability = 'dos';
    confidence = 'inferred';
  }

  notes.push('Crash classification is heuristic; a crash is NOT automatically a security vulnerability (§4.5).');
  return { signal, faultClass, exploitability, confidence, notes };
}

/** A single symbolised (or unsymbolised) stack frame extracted from a backtrace. */
export interface ParsedCrashFrame {
  index: number;
  raw: string;
  function?: string;
  address?: string;
  sourceFile?: string;
  sourceLine?: number;
  /** True when a real function symbol (not `??` / an address) was recovered. */
  resolved: boolean;
  confidence: ConfidenceLevel;
}

/**
 * Parse one backtrace line into a structured frame.
 *
 * Recognises the shapes emitted by GDB, glibc's backtrace_symbols and
 * AddressSanitizer, e.g.:
 *   `#0  func () at file.c:42`
 *   `#0  0x5555555123 in func () at file.c:42`
 *   `func at file.c:42`
 *   `func (arg=0x1) at file.c:42`
 *   `#0 0x55f0 in func /src/file.c:42:7`   (ASan)
 *   `#0  0x7fff in ?? ()`                  (unresolved symbol)
 *   `#0  0x0000555555555123`               (address only)
 */
export function parseCrashFrame(raw: string, positionalIndex: number): ParsedCrashFrame {
  const line = raw.trim();
  const frame: ParsedCrashFrame = { index: positionalIndex, raw: line, resolved: false, confidence: 'unknown' };
  if (!line) return frame;

  // Frame index: a leading `#N` or `N ` token.
  const idxMatch = line.match(/^#?\s*(\d+)\b/);
  if (idxMatch) frame.index = Number.parseInt(idxMatch[1]!, 10);

  // Frame address only counts when it sits right after the frame index, so an
  // argument such as `(arg=0x1)` is not mistaken for the faulting address.
  const addrMatch =
    line.match(/^#?\s*\d+\s+(0x[0-9a-fA-F]+\b)/) ?? line.match(/^(0x[0-9a-fA-F]+)$/);
  if (addrMatch) frame.address = addrMatch[1];

  // Source location: GDB `at FILE:LINE[:COL]`, or ASan `in FUNC FILE:LINE:COL`.
  const loc =
    line.match(/\bat\s+([^\s:()]+):(\d+)(?::\d+)?/) ??
    line.match(/\bin\s+\S+\s+([^\s:]+\.[A-Za-z0-9_]+):(\d+)(?::\d+)?/);
  if (loc) {
    const file = loc[1]!;
    const lineNo = Number.parseInt(loc[2]!, 10);
    if (file !== '??' && file !== '???' && lineNo > 0) {
      frame.sourceFile = file;
      frame.sourceLine = lineNo;
    }
  }

  // Function symbol: strip the frame index + optional address, then read the
  // token after `in`, or the leading token before `(` / `at`.
  let rest = line.replace(/^#?\s*\d+\b\s*/, '');
  rest = rest.replace(/^\s*0x[0-9a-fA-F]+\b\s*/, '');
  const symbol =
    rest.match(/^in\s+([^\s(]+)/)?.[1] ?? rest.match(/^([^\s(]+)\s*(?:\(|\bat\b)/)?.[1];
  if (symbol && symbol !== '??' && symbol !== '???' && !/^0x/i.test(symbol)) {
    frame.function = symbol;
    frame.resolved = true;
  }

  if (frame.resolved && frame.sourceFile) frame.confidence = 'observed';
  else if (frame.resolved) frame.confidence = 'inferred';
  else if (frame.address) frame.confidence = 'hypothesis';
  return frame;
}

/** Parse a whole backtrace into frames, collecting the resolved symbols/locations. */
export function parseBacktrace(backtrace: string[]): {
  frames: ParsedCrashFrame[];
  functions: string[];
  unresolved: ParsedCrashFrame[];
  location?: { function?: string; sourceFile: string; sourceLine: number };
} {
  const frames = backtrace.map((raw, i) => parseCrashFrame(raw, i));
  const functions = frames.filter((f) => f.function).map((f) => f.function!);
  const unresolved = frames.filter((f) => !f.resolved);
  const top = frames.find((f) => f.function && f.sourceFile);
  return {
    frames,
    functions,
    unresolved,
    ...(top ? { location: { function: top.function, sourceFile: top.sourceFile!, sourceLine: top.sourceLine! } } : {}),
  };
}

/* ------------------------------------------------------------------ */
/* Binary / firmware heuristics                                        */
/* ------------------------------------------------------------------ */

const BINARY_DANGEROUS: { id: string; klass: string; severity: Severity; regex: RegExp }[] = [
  { id: 'command-exec', klass: 'command-injection', severity: 'high', regex: /\b(system|popen|execv|execl|execvp|execve)\b/ },
  { id: 'memory-unsafe', klass: 'memory-safety', severity: 'high', regex: /\b(strcpy|strcat|sprintf|gets|memcpy|strncpy|scanf)\b/ },
  { id: 'shell', klass: 'command-injection', severity: 'medium', regex: /\/bin\/sh|sh\s+-c|\bbusybox\b/ },
  { id: 'weak-crypto', klass: 'weak-crypto', severity: 'low', regex: /\b(md5|sha-?1|des|rc4|arc4)\b/i },
];

function detectFirmwareMagic(buf: Buffer): { name: string; kind: string } | null {
  if (buf.length >= 4 && buf[0] === 0x27 && buf[1] === 0x05 && buf[2] === 0x19 && buf[3] === 0x56) {
    return { name: 'uImage', kind: 'linux-kernel-image' };
  }
  if (buf.length >= 4 && buf.toString('latin1', 0, 4) === 'hsqs') return { name: 'squashfs', kind: 'filesystem' };
  if (buf.length >= 4 && buf.toString('latin1', 0, 4) === 'qshs') return { name: 'squashfs-be', kind: 'filesystem' };
  if (buf.length >= 4 && buf[0] === 0x45 && buf[1] === 0x3d && buf[2] === 0xcd && buf[3] === 0x28) {
    return { name: 'cramfs', kind: 'filesystem' };
  }
  if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) return { name: 'gzip', kind: 'compressed' };
  if (buf.length >= 6 && buf[0] === 0xfd && buf[1] === 0x37 && buf[2] === 0x7a && buf[3] === 0x58 && buf[4] === 0x5a && buf[5] === 0x00) {
    return { name: 'xz', kind: 'compressed' };
  }
  if (buf.length >= 2 && buf[0] === 0x50 && buf[1] === 0x4b) return { name: 'zip', kind: 'archive' };
  if (buf.length >= 6 && buf.toString('latin1', 0, 6) === '070701') return { name: 'cpio', kind: 'archive' };
  return null;
}

const KNOWN_COMPONENTS: { name: string; regex: RegExp }[] = [
  { name: 'busybox', regex: /\bbusybox\b/i },
  { name: 'OpenSSL', regex: /openssl/i },
  { name: 'dropbear', regex: /\bdropbear\b/i },
  { name: 'MiniUPnP/UPnP', regex: /miniupnpd|upnp/i },
  { name: 'lighttpd', regex: /lighttpd/i },
  { name: 'mini_httpd', regex: /mini[_-]?httpd/i },
  { name: 'telnetd', regex: /\btelnetd\b/i },
  { name: 'dnsmasq', regex: /dnsmasq/i },
];

/* ------------------------------------------------------------------ */
/* Fuzzing harness skeleton generator (analysis-only, never runs)      */
/* ------------------------------------------------------------------ */

function generateHarness(language: string, framework: string, targetName: string, inputModel: string): string {
  const t = slug(targetName);
  const model = inputModel || 'raw bytes';
  if (language === 'c' || language === 'cpp') {
    if (framework === 'libfuzzer') {
      return `// Research harness skeleton (libFuzzer) — REVIEW BEFORE COMPILING in isolated env.\n// Target: ${targetName}\n// Input model: ${model}\n#include <stddef.h>\n#include <stdint.h>\n\nint LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n  // TODO: call the parser/entry point under test with (data, size).\n  // return ${t}(data, size);\n  (void)data; (void)size;\n  return 0;\n}`;
    }
    return `// Research harness skeleton (AFL++) — REVIEW BEFORE COMPILING in isolated env.\n// Target: ${targetName}\n// Input model: ${model}\n#include <stdio.h>\n#include <stdint.h>\n\nint main(void) {\n  unsigned char buf[4096];\n  size_t n = fread(buf, 1, sizeof(buf), stdin);\n  // TODO: call the parser/entry point under test with (buf, n).\n  (void)n;\n  return 0;\n}`;
  }
  if (language === 'python') {
    return `# Research harness skeleton (Atheris/libFuzzer for Python) — REVIEW BEFORE RUNNING in isolated env.\n# Target: ${targetName}\n# Input model: ${model}\nimport sys\n\ndef fuzz(data: bytes) -> None:\n    # TODO: call the parser/entry point under test with data.\n    pass\n\nif __name__ == "__main__":\n    import atheris\n    atheris.Setup(sys.argv, fuzz)\n    atheris.Fuzz()\n`;
  }
  if (language === 'go') {
    return `// Research harness skeleton (Go native fuzzing) — REVIEW BEFORE BUILDING in isolated env.\n// Target: ${targetName}\n// Input model: ${model}\npackage fuzz\n\nfunc Fuzz${slug(targetName).replace(/-/g, '')}(f *testing.F) {\n\tf.Add([]byte("seed"))\n\tf.Fuzz(func(t *testing.T, data []byte) {\n\t\t// TODO: call the parser/entry point under test with data.\n\t\t_ = data\n\t})\n}\n`;
  }
  return `// Research harness skeleton (${framework}) — REVIEW BEFORE BUILDING in isolated env.\n// Target: ${targetName}\n// Input model: ${model}\n// TODO: wire the target entry point to consume one fuzz input and report crashes.\n`;
}

/* ------------------------------------------------------------------ */
/* Engine                                                              */
/* ------------------------------------------------------------------ */

export const zeroDayEngine: EngineModule = {
  name: ENGINE,
  title: 'Zero-Day Research',
  description:
    'Defensive, analysis-only pipeline for vulnerability discovery, hypothesis formation, static/binary ' +
    'research, fuzzing planning, crash triage, root-cause analysis, verification, lifecycle tracking and ' +
    'research reporting. Heuristics are explicit and never reported as data-flow/symbolic analysis.',
  tools: [
    defineTool({
      name: 'zero_day_discovery_analyze',
      title: 'Discover candidate vulnerabilities',
      engine: ENGINE,
      description:
        'Scan a workspace source tree for vulnerability-class patterns (memory safety, injection, weak crypto, ' +
        'secrets, path traversal, deserialization, race conditions). Returns ranked candidate findings. ' +
        'Pattern hits are hypotheses, not confirmed vulnerabilities.',
      capabilities: ['read_repo'],
      risk: 'safe',
      inputSchema: {
        directoryPath: z.string().min(1).default('.').describe('Directory to scan, relative to the workspace root.'),
        language: z.string().optional().describe('Restrict to a language key (c, c++, javascript, python, go, rust, java, php, shell).'),
        limit: zodCommon.limit,
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const args = input as { directoryPath?: string; language?: string; limit?: number };
        const dirAbs = resolveWorkspacePath(args.directoryPath ?? '.', true);
        const exts = args.language ? (LANG_EXTS[args.language] ?? DEFAULT_SOURCE_EXTS) : DEFAULT_SOURCE_EXTS;
        const cfg = getConfig();
        const files = walkDir(dirAbs, exts, 500);
        const findings: Finding[] = [];
        let scanned = 0;
        const warnings: string[] = [];
        for (const file of files) {
          abortIfNeeded(ctx.signal);
          const rel = relative(cfg.workspaceRoot, file);
          const content = readFileCapped(file, 1024 * 1024);
          if (!content) continue;
          scanned += 1;
          if (content.truncated) warnings.push(`Truncated large file during scan: ${rel}`);
          findings.push(...scanSource(content.content, rel));
        }
        const ranked = rankFindings(findings).slice(0, args.limit ?? 50);
        addEvidence(ctx, {
          claim: `Scanned ${scanned} source file(s) and produced ${findings.length} candidate finding(s).`,
          prov: localProvenance(ENGINE, dirAbs, 'static pattern scan'),
          confidence: 'observed',
        });
        return finish({
          engine: ENGINE,
          tool: 'zero_day_discovery_analyze',
          startedAt: started,
          ctx,
          warnings,
          data: { scannedFiles: scanned, totalFindings: findings.length, findings: ranked },
          summary: `Scanned ${scanned} file(s); ${findings.length} candidate finding(s), top ${ranked.length} returned.`,
        });
      },
    }),

    defineTool({
      name: 'vulnerability_hypothesis_generate',
      title: 'Formulate a vulnerability hypothesis',
      engine: ENGINE,
      description:
        'Create a structured, falsifiable vulnerability hypothesis and persist it as a knowledge record and graph ' +
        'node. A hypothesis is explicitly unverified and is never auto-promoted to a confirmed vulnerability.',
      capabilities: ['write_knowledge'],
      risk: 'local_mutation',
      inputSchema: {
        component: z.string().min(1).describe('Affected component, e.g. "http parser" or "telnetd".'),
        attackSurface: z.string().optional().describe('Trust/input boundary under study.'),
        vulnerabilityClass: z.string().min(1).describe('Candidate vulnerability class.'),
        preconditions: z.array(z.string()).optional().describe('Conditions required to reach the suspected flaw.'),
        sourceLocation: z.string().optional().describe('File/function/line hint, e.g. "src/parser.c:42".'),
        severity: z.enum(['critical', 'high', 'medium', 'low']).optional(),
        impact: z.string().optional().describe('Worst-case impact if the hypothesis were true.'),
        notes: z.array(z.string()).optional().describe('Technical observations supporting the hypothesis.'),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const args = input as {
          component: string;
          attackSurface?: string;
          vulnerabilityClass: string;
          preconditions?: string[];
          sourceLocation?: string;
          severity?: Severity;
          impact?: string;
          notes?: string[];
        };
        const severity = args.severity ?? 'medium';
        const surface = args.attackSurface ?? args.component;
        const id = makeId('vuln-hyp', args.component, args.vulnerabilityClass, surface);
        const title = `Hypothesis: ${args.vulnerabilityClass} in ${args.component}`;
        const explanation = [args.impact, ...(args.notes ?? [])].filter(Boolean).join(' ');
        const prov = curatedProvenance(ENGINE, 'vulnerability hypothesis');
        const kb = getKnowledgeBase();
        const now = nowIso();

        const tags = [
          'zero-day',
          `sev:${severity}`,
          'state:candidate',
          ...(args.sourceLocation ? [`loc:${args.sourceLocation}`] : []),
        ];

        kb.upsertRecord({
          id,
          category: 'vulnerability_hypothesis',
          title,
          identifiers: {},
          affectedVersions: [],
          fixedVersions: [],
          klass: args.vulnerabilityClass,
          rootCause: explanation || undefined,
          attackSurface: surface,
          preconditions: args.preconditions ?? [],
          publicExploitState: 'unknown',
          relatedMalwareFamilies: [],
          relatedMiraiVariants: [],
          relatedRecordIds: [],
          verification: 'unverified',
          confidence: 'hypothesis',
          provenance: [prov],
          evidence: [],
          tags,
          createdAt: now,
          updatedAt: now,
        });

        kb.upsertNode({
          id,
          kind: 'vulnerability_hypothesis',
          label: title,
          properties: {
            vulnerabilityClass: args.vulnerabilityClass,
            severity,
            sourceLocation: args.sourceLocation,
            lifecycleState: 'candidate',
            lifecycleHistory: [{ state: 'candidate', at: now, note: 'created' }],
          },
          provenance: [prov],
          confidence: 'hypothesis',
        });
        kb.flush();

        const hypothesis = {
          id,
          title,
          component: args.component,
          attackSurface: surface,
          vulnerabilityClass: args.vulnerabilityClass,
          severity,
          preconditions: args.preconditions ?? [],
          sourceLocation: args.sourceLocation,
          impact: args.impact,
          confidence: 'hypothesis' as ConfidenceLevel,
          verificationStatus: 'unverified',
          falsifiability:
            `This hypothesis is falsified if, after static review and (optionally) isolated lab testing, ` +
            `${args.component} does not reach the suspected ${args.vulnerabilityClass} primitive for attacker-controlled input.`,
        };

        addEvidence(ctx, {
          claim: `Recorded unverified vulnerability hypothesis "${title}".`,
          prov,
          confidence: 'hypothesis',
          locator: args.sourceLocation ? { file: args.sourceLocation.split(':')[0] } : undefined,
        });

        return finish({
          engine: ENGINE,
          tool: 'vulnerability_hypothesis_generate',
          startedAt: started,
          ctx,
          data: { hypothesis },
          summary: `Recorded hypothesis ${id} (${args.vulnerabilityClass}, severity ${severity}, status unverified).`,
        });
      },
    }),

    defineTool({
      name: 'vulnerability_hypothesis_rank',
      title: 'Rank vulnerability hypotheses',
      engine: ENGINE,
      description:
        'Rank stored vulnerability hypotheses by a heuristic score combining severity, confidence, precondition ' +
        'detail and presence of a technical explanation.',
      capabilities: ['write_knowledge'],
      risk: 'safe',
      inputSchema: {
        severity: z.enum(['critical', 'high', 'medium', 'low']).optional().describe('Only rank hypotheses of this severity.'),
        limit: zodCommon.limit,
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const args = input as { severity?: Severity; limit?: number };
        const records = getKnowledgeBase().searchRecords({ categories: ['vulnerability_hypothesis'], limit: 500 });
        const scored = records
          .filter((r) => !args.severity || severityFromTags(r.tags) === args.severity)
          .map((r) => {
            const severity = severityFromTags(r.tags);
            const score =
              SEVERITY_WEIGHT[severity] +
              CONFIDENCE_WEIGHT[r.confidence] +
              r.preconditions.length * 5 +
              (r.rootCause ? 10 : 0);
            return {
              id: r.id,
              title: r.title,
              klass: r.klass,
              severity,
              confidence: r.confidence,
              verification: r.verification,
              score,
            };
          })
          .sort((a, b) => b.score - a.score)
          .slice(0, args.limit ?? 50);

        addEvidence(ctx, {
          claim: `Ranked ${scored.length} vulnerability hypothesis/hypotheses.`,
          prov: curatedProvenance(ENGINE, 'hypothesis ranking'),
          confidence: 'observed',
        });

        return finish({
          engine: ENGINE,
          tool: 'vulnerability_hypothesis_rank',
          startedAt: started,
          ctx,
          data: { ranked: scored },
          summary: `Ranked ${scored.length} hypothesis/hypotheses by heuristic score.`,
        });
      },
    }),

    defineTool({
      name: 'source_vulnerability_analyze',
      title: 'Analyze source for a hypothesis',
      engine: ENGINE,
      description:
        'Static, pattern-based analysis of a single source file. Optionally narrows to the vulnerability class of a ' +
        'previously recorded hypothesis. Findings are heuristic and clearly labelled.',
      capabilities: ['read_repo'],
      risk: 'safe',
      inputSchema: {
        filePath: zodCommon.filePath,
        hypothesisId: z.string().optional().describe('Optional hypothesis id to focus the analysis on its vulnerability class.'),
        maxBytes: zodCommon.maxBytes,
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const args = input as { filePath: string; hypothesisId?: string; maxBytes?: number };
        const text = readTextArtifact(args.filePath, args.maxBytes);
        const cfg = getConfig();
        const rel = relative(cfg.workspaceRoot, text.path);
        let klass: string | undefined;
        if (args.hypothesisId) {
          const rec = getKnowledgeBase().getRecord(args.hypothesisId);
          klass = rec?.klass;
        }
        const all = scanSource(text.content, rel);
        const findings = klass ? all.filter((f) => f.klass === klass) : all;

        addEvidence(ctx, {
          claim: `Statically analyzed ${rel}; found ${findings.length} pattern match(es).`,
          prov: localProvenance(ENGINE, text.path, 'source static analysis'),
          confidence: 'observed',
        });

        return finish({
          engine: ENGINE,
          tool: 'source_vulnerability_analyze',
          startedAt: started,
          ctx,
          data: {
            filePath: rel,
            language: languageFor(text.path),
            hypothesisClass: klass,
            truncated: text.truncated,
            findings,
          },
          summary: `Analyzed ${rel} (${findings.length} heuristic finding(s)${klass ? ` for class ${klass}` : ''}).`,
        });
      },
    }),

    defineTool({
      name: 'binary_vulnerability_analyze',
      title: 'Analyze a binary for vulnerability markers',
      engine: ENGINE,
      description:
        'Read-only binary triage: detect container format/architecture and scan extracted strings for dangerous ' +
        'libc sinks, shell primitives and weak crypto. Never executes the sample.',
      capabilities: ['read_binary'],
      risk: 'safe',
      inputSchema: {
        filePath: zodCommon.filePath,
        maxBytes: zodCommon.maxBytes,
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const args = input as { filePath: string; maxBytes?: number };
        const bin = readBinaryArtifact(args.filePath, args.maxBytes);
        const analysis = analyzeBuffer(bin.buffer);
        const strings = extractStrings(bin.buffer, 4, 8000);
        const findings: { id: string; klass: string; severity: Severity; value: string; offset: number }[] = [];
        const seen = new Set<string>();
        for (const s of strings) {
          for (const p of BINARY_DANGEROUS) {
            const m = p.regex.exec(s.value);
            if (!m) continue;
            const key = `${p.id}:${m[0]}`;
            if (seen.has(key)) continue;
            seen.add(key);
            findings.push({ id: p.id, klass: p.klass, severity: p.severity, value: m[0].slice(0, 120), offset: s.offset });
            break;
          }
        }

        addEvidence(ctx, {
          claim: `Analyzed binary (${analysis.format}/${analysis.arch}); ${findings.length} string marker(s).`,
          prov: localProvenance(ENGINE, bin.path, 'binary string analysis'),
          confidence: 'observed',
        });

        return finish({
          engine: ENGINE,
          tool: 'binary_vulnerability_analyze',
          startedAt: started,
          ctx,
          data: {
            filePath: bin.path,
            binary: {
              format: analysis.format,
              arch: analysis.arch,
              bits: analysis.bits,
              endianness: analysis.endianness,
              entry: analysis.entry,
              stripped: analysis.stripped,
              packerHints: analysis.packerHints,
              sizeBytes: analysis.sizeBytes,
            },
            findings,
            truncated: bin.truncated,
          },
          summary: `Analyzed ${analysis.format}/${analysis.arch} binary; ${findings.length} heuristic string marker(s).`,
        });
      },
    }),

    defineTool({
      name: 'firmware_vulnerability_analyze',
      title: 'Analyze firmware for vulnerable components',
      engine: ENGINE,
      description:
        'Read-only firmware triage: detect image magic (uImage, squashfs, gzip, cpio, ...) and flag known-vulnerable ' +
        'embedded component names found in extracted strings. Does NOT perform full filesystem extraction.',
      capabilities: ['read_binary', 'read_firmware'],
      risk: 'safe',
      inputSchema: {
        filePath: zodCommon.filePath,
        maxBytes: zodCommon.maxBytes,
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const args = input as { filePath: string; maxBytes?: number };
        const bin = readBinaryArtifact(args.filePath, args.maxBytes);
        const magic = detectFirmwareMagic(bin.buffer);
        const strings = extractStrings(bin.buffer, 4, 8000);
        const components: { name: string; evidence: string }[] = [];
        for (const component of KNOWN_COMPONENTS) {
          const hit = strings.find((s) => component.regex.test(s.value));
          if (hit) components.push({ name: component.name, evidence: hit.value.slice(0, 80) });
        }

        addEvidence(ctx, {
          claim: `Triaged firmware (${magic?.name ?? 'unknown-magic'}); ${components.length} known component hint(s).`,
          prov: localProvenance(ENGINE, bin.path, 'firmware string triage'),
          confidence: 'observed',
        });

        return finish({
          engine: ENGINE,
          tool: 'firmware_vulnerability_analyze',
          startedAt: started,
          ctx,
          warnings: ['Firmware analysis is heuristic (magic + strings only); full extraction is not performed.'],
          data: {
            filePath: bin.path,
            imageType: magic,
            sizeBytes: bin.bytes,
            truncated: bin.truncated,
            componentHints: components,
          },
          summary: `Triaged firmware image (${magic?.name ?? 'unknown'}) with ${components.length} known component hint(s).`,
        });
      },
    }),

    defineTool({
      name: 'static_analysis_run',
      title: 'Run a static ruleset over a tree',
      engine: ENGINE,
      description:
        'Run the built-in defensive static ruleset over a source tree and return a rule-level summary plus findings. ' +
        'This is pattern/heuristic analysis, not a Clang/CodeQL/Semgrep invocation.',
      capabilities: ['read_repo'],
      risk: 'safe',
      inputSchema: {
        directoryPath: z.string().min(1).default('.').describe('Directory to scan, relative to the workspace root.'),
        language: z.string().optional(),
        rules: z.array(z.string()).optional().describe('Restrict to pattern ids, e.g. ["command-injection"].'),
        limit: zodCommon.limit,
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const args = input as { directoryPath?: string; language?: string; rules?: string[]; limit?: number };
        const dirAbs = resolveWorkspacePath(args.directoryPath ?? '.', true);
        const exts = args.language ? (LANG_EXTS[args.language] ?? DEFAULT_SOURCE_EXTS) : DEFAULT_SOURCE_EXTS;
        const cfg = getConfig();
        const files = walkDir(dirAbs, exts, 500);
        const findings: Finding[] = [];
        const ruleCounts: Record<string, number> = {};
        for (const file of files) {
          abortIfNeeded(ctx.signal);
          const rel = relative(cfg.workspaceRoot, file);
          const content = readFileCapped(file, 1024 * 1024);
          if (!content) continue;
          for (const f of scanSource(content.content, rel)) {
            if (args.rules && !args.rules.includes(f.patternId)) continue;
            ruleCounts[f.patternId] = (ruleCounts[f.patternId] ?? 0) + 1;
            findings.push(f);
          }
        }
        const ranked = rankFindings(findings).slice(0, args.limit ?? 50);

        addEvidence(ctx, {
          claim: `Ran static ruleset; ${findings.length} total match(es) across ${Object.keys(ruleCounts).length} rule(s).`,
          prov: localProvenance(ENGINE, dirAbs, 'static ruleset'),
          confidence: 'observed',
        });

        return finish({
          engine: ENGINE,
          tool: 'static_analysis_run',
          startedAt: started,
          ctx,
          data: { ruleCounts, totalFindings: findings.length, findings: ranked },
          summary: `Static ruleset produced ${findings.length} match(es); ${ranked.length} returned.`,
        });
      },
    }),

    defineTool({
      name: 'fuzz_target_identify',
      title: 'Identify candidate fuzz targets',
      engine: ENGINE,
      description:
        'Locate input-boundary functions in a source tree (recv/read/scanf/parse/decode/json.load/...). Returns ' +
        'candidate fuzz targets with file/line and reason. Identification only; nothing is fuzzed here.',
      capabilities: ['read_repo'],
      risk: 'safe',
      inputSchema: {
        directoryPath: z.string().min(1).default('.').describe('Directory to scan.'),
        limit: zodCommon.limit,
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const args = input as { directoryPath?: string; limit?: number };
        const dirAbs = resolveWorkspacePath(args.directoryPath ?? '.', true);
        const cfg = getConfig();
        const files = walkDir(dirAbs, DEFAULT_SOURCE_EXTS, 500);
        const boundaryRegex = /\b(recv|recvfrom|read|fread|fgets|scanf|gets|input\s*\(|readLine|readline|json\.load|parse\s*\(|decode\s*\(|unpack\s*\()/;
        const targets: { sourceLocation: string; line: number; reason: string; snippet: string }[] = [];
        for (const file of files) {
          abortIfNeeded(ctx.signal);
          const rel = relative(cfg.workspaceRoot, file);
          const content = readFileCapped(file, 1024 * 1024);
          if (!content) continue;
          const lines = content.content.split(/\r?\n/);
          for (let i = 0; i < lines.length && targets.length < (args.limit ?? 50); i += 1) {
            const line = lines[i] ?? '';
            if (boundaryRegex.test(line)) {
              targets.push({
                sourceLocation: `${rel}:${i + 1}`,
                line: i + 1,
                reason: 'Input boundary / parser sink candidate',
                snippet: line.trim().slice(0, 160),
              });
            }
          }
        }

        addEvidence(ctx, {
          claim: `Identified ${targets.length} candidate fuzz target(s).`,
          prov: localProvenance(ENGINE, dirAbs, 'fuzz target identification'),
          confidence: 'observed',
        });

        return finish({
          engine: ENGINE,
          tool: 'fuzz_target_identify',
          startedAt: started,
          ctx,
          data: { targets },
          summary: `Identified ${targets.length} candidate fuzz target(s).`,
        });
      },
    }),

    defineTool({
      name: 'fuzz_harness_generate',
      title: 'Generate a fuzzing harness skeleton',
      engine: ENGINE,
      description:
        'Generate a defensive fuzzing harness skeleton (libFuzzer/AFL++/Go/Python) for a chosen target. ' +
        'This is a template to review and compile inside an isolated environment; it is NOT built or run here.',
      capabilities: ['read_repo'],
      risk: 'safe',
      inputSchema: {
        targetName: z.string().min(1).describe('Name of the target entry point / parser.'),
        language: z.enum(['c', 'cpp', 'python', 'go', 'rust']).describe('Implementation language of the target.'),
        framework: z.enum(['libfuzzer', 'aflpp', 'honggfuzz']).describe('Fuzzing framework to target.'),
        inputModel: z.string().optional().describe('Description of the input the target consumes.'),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const args = input as { targetName: string; language: string; framework: string; inputModel?: string };
        const harness = generateHarness(args.language, args.framework, args.targetName, args.inputModel ?? 'raw bytes');

        addEvidence(ctx, {
          claim: `Generated a ${args.framework} harness skeleton for "${args.targetName}".`,
          prov: curatedProvenance(ENGINE, 'fuzz harness skeleton'),
          confidence: 'observed',
        });

        return finish({
          engine: ENGINE,
          tool: 'fuzz_harness_generate',
          startedAt: started,
          ctx,
          warnings: ['Harness is a skeleton only; compile/run it exclusively in an isolated, resource-limited environment (§4.4).'],
          data: { targetName: args.targetName, language: args.language, framework: args.framework, harness },
          summary: `Generated ${args.framework} harness skeleton for "${args.targetName}".`,
        });
      },
    }),

    defineTool({
      name: 'fuzzing_crash_analyze',
      title: 'Analyze and classify a crash',
      engine: ENGINE,
      description:
        'Normalize and classify crash metadata (signal, fault address, backtrace) into a fault class and an ' +
        'exploitability assessment. Explicitly distinguishes crash vs bug vs vulnerability. Optionally persists ' +
        'a crash-triage record for lifecycle tracking.',
      capabilities: ['write_knowledge'],
      risk: 'local_mutation',
      inputSchema: {
        signal: z.string().optional().describe('Crash signal, e.g. "SIGSEGV".'),
        faultAddress: z.string().optional().describe('Faulting address, e.g. "0x0".'),
        backtrace: z.array(z.string()).optional().describe('Backtrace / stack frames.'),
        crashReportPath: z.string().optional().describe('Path to a crash report text file (alternative to inline fields).'),
        metadata: z.string().optional().describe('Free-form context (target, seed input, sanitizer output).'),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const args = input as {
          signal?: string;
          faultAddress?: string;
          backtrace?: string[];
          crashReportPath?: string;
          metadata?: string;
        };
        let signal = args.signal;
        let faultAddress = args.faultAddress;
        let backtrace = args.backtrace ?? [];
        if (args.crashReportPath) {
          const report = readTextArtifact(args.crashReportPath, 256 * 1024);
          const text = report.content;
          const sigMatch = text.match(/(?:signal|Signal)\s*[:#]\s*(\w+)/);
          if (sigMatch) signal = sigMatch[1];
          const faMatch = text.match(/fault(?:ing)?\s*address\s*[:=]\s*(0x[0-9a-f]+|\d+)/i);
          if (faMatch) faultAddress = faMatch[1];
          const frames = text.match(/#\d+\s+[^\n]+/g);
          if (frames) backtrace = frames.slice(0, 40);
        }

        const classification = classifyCrash({ signal, faultAddress, backtrace });
        const fingerprint = fnv1a(`${signal}|${faultAddress ?? ''}|${backtrace.join('|')}`);
        const id = makeId('crash', signal ?? 'unknown', fingerprint);
        const kb = getKnowledgeBase();
        const now = nowIso();
        const prov = curatedProvenance(ENGINE, 'crash triage');

        kb.upsertRecord({
          id,
          category: 'crash_triage',
          title: `Crash: ${classification.faultClass} (${signal ?? 'UNKNOWN'})`,
          identifiers: { fingerprint },
          affectedVersions: [],
          fixedVersions: [],
          klass: classification.faultClass,
          rootCause: classification.notes.join(' '),
          attackSurface: args.metadata,
          preconditions: [],
          publicExploitState: 'unknown',
          relatedMalwareFamilies: [],
          relatedMiraiVariants: [],
          relatedRecordIds: [],
          verification: 'unverified',
          confidence: classification.confidence,
          provenance: [prov],
          evidence: [],
          tags: ['zero-day', 'crash', `sev:${classification.exploitability === 'dos' ? 'low' : 'high'}`, 'state:candidate'],
          createdAt: now,
          updatedAt: now,
        });
        kb.upsertNode({
          id,
          kind: 'crash',
          label: `Crash ${fingerprint}`,
          properties: { signal, faultAddress, exploitability: classification.exploitability, lifecycleState: 'candidate' },
          provenance: [prov],
          confidence: classification.confidence,
        });
        kb.flush();

        addEvidence(ctx, {
          claim: `Classified crash as ${classification.faultClass} (${classification.exploitability}).`,
          prov,
          confidence: classification.confidence,
        });

        return finish({
          engine: ENGINE,
          tool: 'fuzzing_crash_analyze',
          startedAt: started,
          ctx,
          data: { id, fingerprint, ...classification, backtrace: backtrace.slice(0, 40) },
          summary: `Classified crash as ${classification.faultClass}; exploitability: ${classification.exploitability}.`,
        });
      },
    }),

    defineTool({
      name: 'crash_root_cause_analyze',
      title: 'Reconstruct crash root cause',
      engine: ENGINE,
      description:
        'Map a crash backtrace onto a source file to locate the likely faulting function/line and propose a root ' +
        'cause hypothesis. Parses GDB, glibc and AddressSanitizer frame shapes (symbol, address, source file/line) ' +
        'and reports which frames could not be symbolised.',
      capabilities: ['read_repo', 'write_knowledge'],
      risk: 'safe',
      inputSchema: {
        filePath: z.string().optional().describe('Source file likely implicated by the crash.'),
        crashId: z.string().optional().describe('Crash record id to load context from.'),
        backtrace: z.array(z.string()).optional().describe('Inline backtrace frames.'),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const args = input as { filePath?: string; crashId?: string; backtrace?: string[] };
        const backtrace = args.backtrace ?? [];
        let signal: string | undefined;
        let evidenceSource = 'inline backtrace';
        if (args.crashId) {
          const rec = getKnowledgeBase().getRecord(args.crashId);
          if (!rec) throw errors.notFound(`Crash record ${args.crashId}`);
          signal = rec.klass;
          evidenceSource = `knowledge-base crash record ${args.crashId}`;
        }

        const parsed = parseBacktrace(backtrace);
        const relatedFunctions = [...new Set(parsed.functions)];

        let matchedLines: { line: number; snippet: string }[] = [];
        if (args.filePath) {
          const text = readTextArtifact(args.filePath, 1024 * 1024);
          const lines = text.content.split(/\r?\n/);
          // The frame's own source line is the strongest signal; add it first.
          const frameLine = parsed.location?.sourceLine;
          if (frameLine && frameLine >= 1 && frameLine <= lines.length) {
            matchedLines.push({ line: frameLine, snippet: (lines[frameLine - 1] ?? '').trim().slice(0, 160) });
          }
          const names = new Set(relatedFunctions.map((f) => f.toLowerCase()));
          for (let i = 0; i < lines.length && matchedLines.length < 20; i += 1) {
            const line = (lines[i] ?? '').toLowerCase();
            for (const name of names) {
              if (line.includes(name)) {
                const lineNo = i + 1;
                if (!matchedLines.some((m) => m.line === lineNo)) {
                  matchedLines.push({ line: lineNo, snippet: (lines[i] ?? '').trim().slice(0, 160) });
                }
                break;
              }
            }
          }
        }

        const confidence: ConfidenceLevel = parsed.location
          ? 'observed'
          : relatedFunctions.length
            ? 'inferred'
            : 'hypothesis';
        const unparsed = parsed.frames.length - parsed.functions.length;
        const rootCause = relatedFunctions.length
          ? `Parsed ${parsed.frames.length} frame(s); crash likely originates in or near: ${relatedFunctions
              .slice(0, 5)
              .join(', ')}.${parsed.location ? ` Top frame resolves to ${parsed.location.sourceFile}:${parsed.location.sourceLine}.` : ''} ${
              signal ?? 'fault class unknown'
            }.${unparsed ? ` ${unparsed} frame(s) could not be symbolised.` : ''}`
          : parsed.frames.some((f) => f.address)
            ? `Parsed ${parsed.frames.length} frame(s), but no function symbol resolved (unsymbolised/address-only backtrace); cannot attribute to a source function.`
            : 'No function symbol could be extracted from the backtrace.';

        addEvidence(ctx, {
          claim: `Parsed ${parsed.frames.length} backtrace frame(s); mapped to ${matchedLines.length} source match(es); ${parsed.functions.length} symbol(s) resolved.`,
          prov: args.filePath ? localProvenance(ENGINE, args.filePath, 'crash root cause') : curatedProvenance(ENGINE, 'crash root cause'),
          confidence,
        });

        return finish({
          engine: ENGINE,
          tool: 'crash_root_cause_analyze',
          startedAt: started,
          ctx,
          ...(parsed.unresolved.length
            ? { warnings: [`${parsed.unresolved.length} frame(s) could not be symbolised; attribution confidence is limited.`] }
            : {}),
          data: {
            rootCause,
            frames: parsed.frames,
            relatedFunctions,
            functions: parsed.functions,
            unresolvedFrames: parsed.unresolved,
            unresolvedFrameCount: parsed.unresolved.length,
            location: parsed.location,
            matchedLines,
            signal,
            evidenceSource,
            confidence,
          },
          summary: `Proposed root cause: ${rootCause}`,
        });
      },
    }),

    defineTool({
      name: 'vulnerability_verify',
      title: 'Verify a vulnerability finding',
      engine: ENGINE,
      description:
        'Update the verification state of a finding/hypothesis using a defensive workflow. Static review does not ' +
        'require lab execution; lab validation is recorded as non-destructive only. Never produces weaponized claims.',
      capabilities: ['write_knowledge'],
      risk: 'local_mutation',
      inputSchema: {
        findingId: z.string().min(1).describe('Hypothesis/crash/finding record id.'),
        verdict: z.enum(['static_review', 'lab_validated', 'false_positive']).describe('Verification verdict.'),
        confidence: z.enum(['unknown', 'hypothesis', 'inferred', 'observed', 'confirmed']).optional(),
        reproSteps: z.array(z.string()).optional().describe('Non-destructive reproduction steps taken.'),
        evidenceNotes: z.array(z.string()).optional().describe('Additional evidence gathered.'),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const args = input as {
          findingId: string;
          verdict: 'static_review' | 'lab_validated' | 'false_positive';
          confidence?: ConfidenceLevel;
          reproSteps?: string[];
          evidenceNotes?: string[];
        };
        const kb = getKnowledgeBase();
        const rec = kb.getRecord(args.findingId);
        if (!rec) throw errors.notFound(`Finding ${args.findingId}`);

        const verification = args.verdict === 'false_positive'
          ? 'disputed'
          : args.verdict === 'lab_validated'
            ? 'lab_validated_non_destructive'
            : 'statically_reviewed';
        const confidence = args.confidence ?? (args.verdict === 'false_positive' ? 'observed' : 'inferred');
        const newState: LifecycleState = args.verdict === 'false_positive' ? 'false_positive' : 'verified';

        const nextTags = rec.tags.filter((t) => !t.startsWith('state:'));
        nextTags.push(`state:${newState}`);
        rec.verification = verification;
        rec.confidence = confidence;
        rec.tags = nextTags;
        rec.updatedAt = nowIso();
        if (args.reproSteps?.length) rec.preconditions = [...new Set([...rec.preconditions, ...args.reproSteps])];
        kb.upsertRecord(rec);

        const node = kb.getNode(args.findingId);
        const now = nowIso();
        if (node) {
          const history = Array.isArray(node.properties.lifecycleHistory) ? node.properties.lifecycleHistory : [];
          kb.upsertNode({
            ...node,
            properties: {
              ...node.properties,
              verificationState: verification,
              lifecycleState: newState,
              lifecycleHistory: [...(history as unknown[]), { state: newState, at: now, note: args.evidenceNotes?.join('; ') ?? 'verified' }],
            },
          });
        }
        kb.flush();

        addEvidence(ctx, {
          claim: `Updated finding ${args.findingId} to verification state "${verification}".`,
          prov: curatedProvenance(ENGINE, 'verification workflow'),
          confidence,
        });

        return finish({
          engine: ENGINE,
          tool: 'vulnerability_verify',
          startedAt: started,
          ctx,
          data: { findingId: args.findingId, verification, confidence, lifecycleState: newState },
          summary: `Finding ${args.findingId} now "${verification}" (confidence ${confidence}).`,
        });
      },
    }),

    defineTool({
      name: 'patch_root_cause_analyze',
      title: 'Analyze a patch for root cause',
      engine: ENGINE,
      description:
        'Compare a vulnerable source file against a patched version and infer the root cause from the dangerous ' +
        'constructs that changed. Also emits a fix-effectiveness assessment. Line-based, heuristic.',
      capabilities: ['read_repo'],
      risk: 'safe',
      inputSchema: {
        vulnerableFilePath: zodCommon.filePath,
        patchedFilePath: zodCommon.filePath,
        maxBytes: zodCommon.maxBytes,
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const args = input as { vulnerableFilePath: string; patchedFilePath: string; maxBytes?: number };
        const vuln = readTextArtifact(args.vulnerableFilePath, args.maxBytes);
        const patch = readTextArtifact(args.patchedFilePath, args.maxBytes);

        const vulnLines = new Set(vuln.content.split(/\r?\n/).map((l) => l.trim()).filter(Boolean));
        const patchLines = new Set(patch.content.split(/\r?\n/).map((l) => l.trim()).filter(Boolean));
        const removed: string[] = [];
        const added: string[] = [];
        for (const l of vulnLines) if (!patchLines.has(l)) removed.push(l);
        for (const l of patchLines) if (!vulnLines.has(l)) added.push(l);

        const changedDangerous: { klass: string; removedLine: string; addedLine: string }[] = [];
        for (const pattern of STATIC_PATTERNS) {
          const removedHits = removed.filter((l) => pattern.regex.test(l));
          const addedHits = added.filter((l) => pattern.regex.test(l));
          if (removedHits.length || addedHits.length) {
            changedDangerous.push({
              klass: pattern.klass,
              removedLine: removedHits[0] ?? '',
              addedLine: addedHits[0] ?? '',
            });
          }
        }

        const rootCause = changedDangerous.length
          ? `Patch modifies dangerous constructs: ${changedDangerous.map((c) => c.klass).join(', ')}.`
          : 'No dangerous-construct change detected by the built-in ruleset; root cause requires manual diff review.';
        const fixAssessment = removed.length === 0
          ? 'Vulnerable and patched files appear identical (no line-level difference detected).'
          : `Patch changes ${removed.length} removed / ${added.length} added line(s). ${changedDangerous.length ? 'Dangerous construct(s) were altered.' : 'Fix effectiveness is inconclusive from line diff alone.'}`;

        addEvidence(ctx, {
          claim: `Compared ${vuln.path} vs ${patch.path}: ${removed.length} removed / ${added.length} added line(s).`,
          prov: localProvenance(ENGINE, vuln.path, 'patch diff'),
          confidence: 'observed',
        });

        return finish({
          engine: ENGINE,
          tool: 'patch_root_cause_analyze',
          startedAt: started,
          ctx,
          warnings: ['Line-based diff only; it does not run a real 3-way diff or semantic analysis.'],
          data: {
            vulnerableFilePath: vuln.path,
            patchedFilePath: patch.path,
            removedLines: removed.slice(0, 100),
            addedLines: added.slice(0, 100),
            changedDangerous,
            rootCause,
            fixAssessment,
          },
          summary: rootCause,
        });
      },
    }),

    defineTool({
      name: 'vulnerability_variant_hunt',
      title: 'Hunt for vulnerability variants',
      engine: ENGINE,
      description:
        'Search a source tree for literal (or optional regex) occurrences of a pattern to find candidate variants of ' +
        'a known vulnerability. Returns matching file/line locations.',
      capabilities: ['read_repo'],
      risk: 'safe',
      inputSchema: {
        pattern: z.string().min(1).describe('Literal string or regex to hunt for.'),
        directoryPath: z.string().min(1).default('.').describe('Directory to search.'),
        patternType: z.enum(['literal', 'regex']).optional().describe('Match mode. Defaults to literal.'),
        limit: zodCommon.limit,
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const args = input as { pattern: string; directoryPath?: string; patternType?: 'literal' | 'regex'; limit?: number };
        const dirAbs = resolveWorkspacePath(args.directoryPath ?? '.', true);
        const cfg = getConfig();
        const files = walkDir(dirAbs, DEFAULT_SOURCE_EXTS, 500);
        let needle: RegExp;
        if (args.patternType === 'regex') {
          try {
            needle = new RegExp(args.pattern, 'i');
          } catch {
            throw errors.invalidInput('Invalid regex pattern.', { pattern: args.pattern });
          }
        } else {
          needle = new RegExp(args.pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
        }

        const matches: { sourceLocation: string; line: number; snippet: string }[] = [];
        for (const file of files) {
          abortIfNeeded(ctx.signal);
          const rel = relative(cfg.workspaceRoot, file);
          const content = readFileCapped(file, 1024 * 1024);
          if (!content) continue;
          const lines = content.content.split(/\r?\n/);
          for (let i = 0; i < lines.length && matches.length < (args.limit ?? 50); i += 1) {
            const line = lines[i] ?? '';
            if (needle.test(line)) {
              matches.push({ sourceLocation: `${rel}:${i + 1}`, line: i + 1, snippet: line.trim().slice(0, 160) });
            }
          }
        }

        addEvidence(ctx, {
          claim: `Found ${matches.length} variant match(es) for pattern "${args.pattern}".`,
          prov: localProvenance(ENGINE, dirAbs, 'variant hunt'),
          confidence: 'observed',
        });

        return finish({
          engine: ENGINE,
          tool: 'vulnerability_variant_hunt',
          startedAt: started,
          ctx,
          data: { pattern: args.pattern, matches },
          summary: `Found ${matches.length} variant match(es) for "${args.pattern}".`,
        });
      },
    }),

    defineTool({
      name: 'zero_day_lifecycle_update',
      title: 'Update a finding lifecycle state',
      engine: ENGINE,
      description:
        'Transition a finding/hypothesis/crash through the research lifecycle (candidate → ... → publicly_disclosed). ' +
        'Appends history and stores affected versions. Never auto-discloses to third parties.',
      capabilities: ['write_knowledge'],
      risk: 'local_mutation',
      inputSchema: {
        findingId: z.string().min(1),
        state: LIFECYCLE_ENUM.describe('New lifecycle state.'),
        note: z.string().optional().describe('Reason/context for the transition.'),
        affectedVersions: z.array(z.string()).optional(),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const args = input as { findingId: string; state: LifecycleState; note?: string; affectedVersions?: string[] };
        const kb = getKnowledgeBase();
        const rec = kb.getRecord(args.findingId);
        if (!rec) throw errors.notFound(`Finding ${args.findingId}`);

        const nextTags = rec.tags.filter((t) => !t.startsWith('state:'));
        nextTags.push(`state:${args.state}`);
        rec.tags = nextTags;
        if (args.affectedVersions?.length) rec.affectedVersions = [...new Set([...rec.affectedVersions, ...args.affectedVersions])];
        rec.updatedAt = nowIso();
        kb.upsertRecord(rec);

        const node = kb.getNode(args.findingId);
        const now = nowIso();
        if (node) {
          const history = Array.isArray(node.properties.lifecycleHistory) ? node.properties.lifecycleHistory : [];
          kb.upsertNode({
            ...node,
            properties: {
              ...node.properties,
              lifecycleState: args.state,
              lifecycleHistory: [...(history as unknown[]), { state: args.state, at: now, note: args.note ?? '' }],
            },
          });
        }
        kb.flush();

        addEvidence(ctx, {
          claim: `Transitioned finding ${args.findingId} to lifecycle state "${args.state}".`,
          prov: curatedProvenance(ENGINE, 'lifecycle management'),
          confidence: 'observed',
        });

        return finish({
          engine: ENGINE,
          tool: 'zero_day_lifecycle_update',
          startedAt: started,
          ctx,
          data: { findingId: args.findingId, state: args.state, note: args.note },
          summary: `Finding ${args.findingId} is now "${args.state}".`,
        });
      },
    }),

    defineTool({
      name: 'zero_day_research_report',
      title: 'Generate a research report',
      engine: ENGINE,
      description:
        'Assemble a structured defensive research report (JSON + Markdown) for a finding/hypothesis/crash, including ' +
        'category, root cause, source location, reproduction conditions, evidence, confidence, impact and remediation.',
      capabilities: ['write_knowledge'],
      risk: 'safe',
      inputSchema: {
        findingId: z.string().min(1),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const args = input as { findingId: string };
        const kb = getKnowledgeBase();
        const rec = kb.getRecord(args.findingId);
        if (!rec) throw errors.notFound(`Finding ${args.findingId}`);
        const node = kb.getNode(args.findingId);

        const report = {
          id: rec.id,
          category: rec.category,
          title: rec.title,
          vulnerabilityClass: rec.klass,
          affectedComponent: rec.attackSurface ?? rec.product ?? 'unknown',
          affectedVersions: rec.affectedVersions,
          technicalRootCause: rec.rootCause ?? 'not yet determined',
          sourceLocation: node?.properties.sourceLocation ?? undefined,
          reproductionConditions: rec.preconditions,
          verificationStatus: rec.verification,
          confidence: rec.confidence,
          impactAssessment: node?.properties.severity ?? severityFromTags(rec.tags),
          remediation: 'Apply the corresponding defensive fix, add a regression test, and re-verify.',
          relatedIdentifiers: rec.identifiers,
          tags: rec.tags,
          createdAt: rec.createdAt,
          updatedAt: rec.updatedAt,
        };

        const md = [
          `# Research Report: ${report.title}`,
          '',
          `- **Finding ID:** \`${report.id}\``,
          `- **Category:** ${report.category}`,
          `- **Vulnerability class:** ${report.vulnerabilityClass ?? 'n/a'}`,
          `- **Affected component:** ${report.affectedComponent}`,
          `- **Affected versions:** ${report.affectedVersions.join(', ') || 'unknown'}`,
          `- **Verification:** ${report.verificationStatus}`,
          `- **Confidence:** ${report.confidence}`,
          '',
          '## Root cause',
          '',
          report.technicalRootCause,
          '',
          '## Reproduction conditions',
          '',
          report.reproductionConditions.map((p) => `- ${p}`).join('\n') || '- none recorded',
          '',
          '## Impact assessment',
          '',
          String(report.impactAssessment),
          '',
          '## Recommended remediation',
          '',
          report.remediation,
          '',
        ].join('\n');

        addEvidence(ctx, {
          claim: `Generated research report for ${rec.id}.`,
          prov: curatedProvenance(ENGINE, 'research report'),
          confidence: 'observed',
        });

        return finish({
          engine: ENGINE,
          tool: 'zero_day_research_report',
          startedAt: started,
          ctx,
          data: { report, markdown: md },
          summary: `Generated research report for ${rec.id}.`,
        });
      },
    }),
  ],
};
