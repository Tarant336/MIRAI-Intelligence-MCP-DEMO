/**
 * External dependency diagnostics (§6).
 *
 * The platform must never assume an external tool is installed. This module
 * probes the analysis dependencies it can leverage (compilers, fuzzers,
 * emulators, disassemblers, archive/utility tooling) and reports a precise
 * status for each one, so that:
 *
 *   1. detection verifies both the executable and its version where possible;
 *   2. the status distinguishes AVAILABLE / MISSING / VERSION_UNSUPPORTED /
 *      CONFIGURATION_ERROR / NOT_REQUIRED;
 *   3. tools that depend on a missing dependency can fail with a structured,
 *      actionable error instead of pretending to succeed.
 *
 * Probing is strictly read-only: this module NEVER downloads or installs
 * anything, and it never executes a target artifact.
 */

import { getConfig } from '../config/index.js';
import { errors } from './errors.js';
import { runCommand, toolOnPathSync } from '../shared/exec.js';
import type { DependencyProbe, DependencyStatus } from '../shared/types.js';

/** Definition of a probed external dependency. */
export interface DependencyDefinition {
  /** Stable id used by callers, e.g. "gcc", "qemu-arm". */
  id: string;
  title: string;
  /** Candidate executable names, most preferred first. */
  executables: readonly string[];
  /**
   * argv for the version probe. `null` means presence-only: the tool is a
   * script/directory install whose version flag is not reliable, so existence
   * is verified without executing it.
   */
  versionArgs: readonly string[] | null;
  /** Capture group 1 is the version string. Only used when versionArgs is set. */
  versionPattern?: RegExp;
  /** Optional minimum acceptable version. */
  minVersion?: string;
  purpose: string;
  installHint: string;
}

/**
 * The dependency catalogue (§6): GCC, Clang, AFL++, Honggfuzz, QEMU ARM/MIPS,
 * Binwalk, 7-Zip, objdump, readelf, strings, nm, Radare2, Ghidra and Git.
 */
export const KNOWN_DEPENDENCIES: readonly DependencyDefinition[] = [
  {
    id: 'gcc',
    title: 'GCC (GNU Compiler Collection)',
    executables: ['gcc', 'cc'],
    versionArgs: ['--version'],
    versionPattern: /gcc[^\d]*(\d+\.\d+(?:\.\d+)?)/i,
    minVersion: '5.0.0',
    purpose: 'Compile harnesses, instrumentation and analysis helpers.',
    installHint: 'Install the GCC toolchain (e.g. build-essential / gcc) and ensure it is on PATH.',
  },
  {
    id: 'clang',
    title: 'Clang / LLVM',
    executables: ['clang'],
    versionArgs: ['--version'],
    versionPattern: /clang version (\d+\.\d+(?:\.\d+)?)/i,
    minVersion: '6.0.0',
    purpose: 'Sanitizer (-fsanitize=fuzzer,address) builds and static analysis.',
    installHint: 'Install Clang/LLVM 6+ (e.g. apt install clang) and ensure it is on PATH.',
  },
  {
    id: 'aflplusplus',
    title: 'AFL++',
    executables: ['afl-fuzz'],
    // AFL++'s afl-fuzz does not offer a portable version flag; verify presence
    // only rather than risk a misleading CONFIGURATION_ERROR.
    versionArgs: null,
    purpose: 'Coverage-guided fuzzing of local authorized targets.',
    installHint: 'Build/install AFL++ (afl-fuzz) from https://github.com/AFLplusplus/AFLplusplus and add it to PATH.',
  },
  {
    id: 'honggfuzz',
    title: 'Honggfuzz',
    executables: ['honggfuzz'],
    versionArgs: ['--version'],
    versionPattern: /honggfuzz[\s\S]*?(\d+\.\d+(?:\.\d+)?)/i,
    purpose: 'Feedback-driven fuzzing of local authorized targets.',
    installHint: 'Install Honggfuzz (e.g. apt install honggfuzz) and ensure it is on PATH.',
  },
  {
    id: 'qemu-arm',
    title: 'QEMU system emulator (ARM)',
    executables: ['qemu-system-arm'],
    versionArgs: ['--version'],
    versionPattern: /QEMU emulator version (\d+\.\d+(?:\.\d+)?)/i,
    purpose: 'Emulate ARM firmware images for offline analysis.',
    installHint: 'Install QEMU ARM system emulation (e.g. apt install qemu-system-arm) and add it to PATH.',
  },
  {
    id: 'qemu-mips',
    title: 'QEMU system emulator (MIPS/MIPSel)',
    executables: ['qemu-system-mipsel', 'qemu-system-mips'],
    versionArgs: ['--version'],
    versionPattern: /QEMU emulator version (\d+\.\d+(?:\.\d+)?)/i,
    purpose: 'Emulate MIPS/MIPSel (router/IoT) firmware images for offline analysis.',
    installHint: 'Install QEMU MIPS system emulation (e.g. apt install qemu-system-mips) and add it to PATH.',
  },
  {
    id: 'binwalk',
    title: 'Binwalk',
    executables: ['binwalk'],
    versionArgs: ['--version'],
    versionPattern: /binwalk[\s\S]*?v?(\d+\.\d+(?:\.\d+)?)/i,
    purpose: 'Firmware signature scanning and nested archive extraction.',
    installHint: 'Install Binwalk (e.g. apt install binwalk or pip install binwalk) and add it to PATH.',
  },
  {
    id: 'sevenzip',
    title: '7-Zip',
    executables: ['7z', '7za', '7zr'],
    versionArgs: ['i'],
    versionPattern: /7-?Zip[^\d]*(\d+\.\d+(?:\.\d+)?)/i,
    purpose: 'Extract vendor firmware archives (7z/zip/gzip and friends).',
    installHint: 'Install 7-Zip (p7zip-full / 7zip) and ensure 7z is on PATH.',
  },
  {
    id: 'objdump',
    title: 'objdump',
    executables: ['objdump', 'llvm-objdump'],
    versionArgs: ['--version'],
    versionPattern: /(\d+\.\d+(?:\.\d+)?)/,
    purpose: 'Disassemble and inspect ELF/binaries offline.',
    installHint: 'Install binutils (objdump) or llvm and ensure it is on PATH.',
  },
  {
    id: 'readelf',
    title: 'readelf',
    executables: ['readelf', 'llvm-readelf'],
    versionArgs: ['--version'],
    versionPattern: /(\d+\.\d+(?:\.\d+)?)/,
    purpose: 'Inspect ELF headers, sections and symbols offline.',
    installHint: 'Install binutils (readelf) or llvm and ensure it is on PATH.',
  },
  {
    id: 'strings',
    title: 'strings',
    executables: ['strings', 'llvm-strings'],
    versionArgs: ['--version'],
    versionPattern: /(\d+\.\d+(?:\.\d+)?)/,
    purpose: 'Extract printable strings from binaries and firmware blobs.',
    installHint: 'Install binutils (strings) or llvm and ensure it is on PATH.',
  },
  {
    id: 'nm',
    title: 'nm',
    executables: ['nm', 'llvm-nm'],
    versionArgs: ['--version'],
    versionPattern: /(\d+\.\d+(?:\.\d+)?)/,
    purpose: 'List symbols from object files and binaries offline.',
    installHint: 'Install binutils (nm) or llvm and ensure it is on PATH.',
  },
  {
    id: 'radare2',
    title: 'Radare2',
    executables: ['radare2', 'r2', 'rabin2'],
    versionArgs: ['-v'],
    versionPattern: /radare2[\s\S]*?(\d+\.\d+(?:\.\d+)?)/i,
    purpose: 'Interactive/scriptable reverse engineering of binaries.',
    installHint: 'Install Radare2 (or rizin) and ensure r2/radare2 is on PATH.',
  },
  {
    id: 'ghidra',
    title: 'Ghidra',
    // Ghidra ships as a directory with a launcher script whose version flag is
    // not portable; verify presence only.
    executables: ['analyzeHeadless', 'ghidraRun'],
    versionArgs: null,
    purpose: 'Headless decompilation and large-scale binary analysis.',
    installHint: 'Install Ghidra and add its support/ directory (analyzeHeadless) to PATH.',
  },
  {
    id: 'git',
    title: 'Git',
    executables: ['git'],
    versionArgs: ['--version'],
    versionPattern: /git version (\d+\.\d+(?:\.\d+)?)/i,
    purpose: 'Repository provenance, patch and diff analysis.',
    installHint: 'Install Git and ensure it is on PATH.',
  },
] as const;

/** Look up a dependency definition by id. */
export function findDependency(id: string): DependencyDefinition | undefined {
  return KNOWN_DEPENDENCIES.find((d) => d.id === id);
}

/** Extract the version from probe output using a definition's pattern. */
export function extractVersion(text: string, pattern?: RegExp): string | undefined {
  if (!pattern) return undefined;
  const match = pattern.exec(text);
  return match?.[1];
}

/**
 * Compare two dotted version strings. Returns -1, 0 or 1. Missing trailing
 * segments are treated as zero (so "1.2" === "1.2.0").
 */
export function compareVersions(a: string, b: string): number {
  const pa = a.split('.').map((p) => Number.parseInt(p, 10) || 0);
  const pb = b.split('.').map((p) => Number.parseInt(p, 10) || 0);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i += 1) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x < y) return -1;
    if (x > y) return 1;
  }
  return 0;
}

/** Result of the pure classification step (no I/O). */
export interface DependencyClassification {
  status: DependencyStatus;
  version?: string;
  detail: string;
}

export interface ClassifyInput {
  found: boolean;
  required: boolean;
  versionPattern?: RegExp;
  minVersion?: string;
  /** Presence-only dependency: skip version verification. */
  presenceOnly?: boolean;
  exec?: {
    exitCode: number | null;
    stdout: string;
    stderr: string;
    /** Set when the process could not be spawned/executed at all. */
    error?: string;
    timedOut?: boolean;
  };
}

/**
 * Pure status classifier. Separated from I/O so the status logic can be tested
 * exhaustively without depending on which tools happen to be installed.
 */
export function classifyDependency(input: ClassifyInput): DependencyClassification {
  const { found, required, versionPattern, minVersion, presenceOnly, exec } = input;

  if (!found) {
    return required
      ? { status: 'MISSING', detail: 'Executable not found on PATH (required).' }
      : { status: 'NOT_REQUIRED', detail: 'Executable not found on PATH (not required).' };
  }

  if (presenceOnly) {
    return { status: 'AVAILABLE', detail: 'Executable found on PATH (version not verified).' };
  }

  if (!exec || exec.error) {
    return {
      status: 'CONFIGURATION_ERROR',
      detail: `Executable found on PATH but could not be executed${exec?.error ? `: ${exec.error}` : '.'}`,
    };
  }

  if (exec.timedOut) {
    return {
      status: 'CONFIGURATION_ERROR',
      detail: 'Executable found but the version probe timed out.',
    };
  }

  const version = extractVersion(`${exec.stdout}\n${exec.stderr}`, versionPattern);

  if (version && minVersion && compareVersions(version, minVersion) < 0) {
    return {
      status: 'VERSION_UNSUPPORTED',
      version,
      detail: `Version ${version} is below the required minimum ${minVersion}.`,
    };
  }

  if (!version) {
    return {
      status: 'AVAILABLE',
      detail: `Executable found and ran (exit ${exec.exitCode}); version could not be determined.`,
    };
  }

  return { status: 'AVAILABLE', version, detail: `Executable found, version ${version}.` };
}

const DEFAULT_VERSION_TIMEOUT_MS = 3000;

export interface ProbeOptions {
  /** Whether the caller requires this dependency (defaults to false). */
  required?: boolean;
  /** Timeout for the version probe, in milliseconds. */
  timeoutMs?: number;
}

/** Probe a single dependency definition. Read-only; never installs anything. */
export async function probeDependency(
  def: DependencyDefinition,
  options: ProbeOptions = {},
): Promise<DependencyProbe> {
  const required = options.required ?? false;
  const timeoutMs = options.timeoutMs ?? DEFAULT_VERSION_TIMEOUT_MS;

  const executable = def.executables.find((name) => toolOnPathSync(name));
  const found = Boolean(executable);

  // Version probing requires isolated execution; when it is disabled we fall
  // back to presence-only detection rather than misreport a policy as a fault.
  const presenceOnly = def.versionArgs === null || !getConfig().allowIsolatedExec;

  let exec: ClassifyInput['exec'];
  if (found && !presenceOnly) {
    try {
      const res = await runCommand(executable as string, {
        args: [...(def.versionArgs as readonly string[])],
        timeoutMs,
      });
      exec = {
        exitCode: res.exitCode,
        stdout: res.stdout,
        stderr: res.stderr,
        timedOut: res.timedOut,
      };
    } catch (err) {
      exec = { exitCode: null, stdout: '', stderr: '', error: (err as Error).message };
    }
  }

  const classified = classifyDependency({
    found,
    required,
    versionPattern: def.versionPattern,
    minVersion: def.minVersion,
    presenceOnly,
    exec,
  });

  return {
    id: def.id,
    title: def.title,
    status: classified.status,
    ...(executable ? { executable } : {}),
    ...(classified.version ? { version: classified.version } : {}),
    ...(def.minVersion ? { minVersion: def.minVersion } : {}),
    ...(exec ? { exitCode: exec.exitCode } : {}),
    detail: classified.detail,
    installHint: def.installHint,
    required,
  };
}

export interface ProbeAllOptions {
  /** Dependency ids the caller requires; all others are optional. */
  required?: readonly string[];
  timeoutMs?: number;
}

/** Probe every known dependency in parallel. */
export async function probeDependencies(options: ProbeAllOptions = {}): Promise<DependencyProbe[]> {
  const requiredIds = new Set(options.required ?? []);
  return Promise.all(
    KNOWN_DEPENDENCIES.map((def) =>
      probeDependency(def, { required: requiredIds.has(def.id), timeoutMs: options.timeoutMs }),
    ),
  );
}

/** Render a compact human-readable summary of probe results. */
export function summarizeDependencies(probes: readonly DependencyProbe[]): string {
  const counts = new Map<DependencyStatus, number>();
  for (const p of probes) counts.set(p.status, (counts.get(p.status) ?? 0) + 1);
  const order: DependencyStatus[] = [
    'AVAILABLE',
    'MISSING',
    'VERSION_UNSUPPORTED',
    'CONFIGURATION_ERROR',
    'NOT_REQUIRED',
  ];
  const tally = order
    .filter((s) => counts.has(s))
    .map((s) => `${s}=${counts.get(s)}`)
    .join(', ');

  const lines = probes.map((p) => {
    const ver = p.version ? ` ${p.version}` : '';
    return `- ${p.id}: ${p.status}${ver}${p.required ? ' (required)' : ''} — ${p.detail}`;
  });

  return [`Dependency diagnostics (${tally}):`, ...lines].join('\n');
}

/**
 * Ensure the given dependencies are AVAILABLE. Throws a structured
 * `TOOL_MISSING` error listing every blocking dependency when any is not.
 */
export async function requireDependencies(
  ids: readonly string[],
  options: { timeoutMs?: number } = {},
): Promise<DependencyProbe[]> {
  const probes = await probeDependencies({ required: ids, timeoutMs: options.timeoutMs });
  const wanted = new Set(ids);
  const known = probes.filter((p) => wanted.has(p.id));

  // An id with no definition cannot be verified, so it blocks as MISSING.
  const unknown: DependencyProbe[] = ids
    .filter((id) => !findDependency(id))
    .map((id) => ({
      id,
      title: id,
      status: 'MISSING',
      detail: `Unknown dependency id "${id}" — no probe definition exists.`,
      installHint: `Provide a valid dependency id (see dependency_diagnostics).`,
      required: true,
    }));

  const blocking = [...known.filter((p) => p.status !== 'AVAILABLE'), ...unknown];
  if (blocking.length > 0) {
    throw errors.dependencyMissing(blocking);
  }
  return known;
}
