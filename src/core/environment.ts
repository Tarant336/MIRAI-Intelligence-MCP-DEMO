/**
 * Phase 1 — Environment discovery (§14).
 *
 * Produces the environment report used to decide which analysis backends are
 * available and to record the constraints the platform is operating under.
 */

import { arch, cpus, freemem, platform, release, totalmem } from 'node:os';

import { getConfig } from '../config/index.js';
import { logger } from './logger.js';
import { runCommand, toolOnPathSync } from '../shared/exec.js';
import { probeDependencies } from './dependencies.js';
import type { EnvironmentReport } from '../shared/types.js';

const log = logger.child({ component: 'environment' });

/** Analysis tools the platform knows how to leverage when present. */
export const KNOWN_ANALYSIS_TOOLS = [
  'ghidra',
  'analyzeHeadless',
  'radare2',
  'r2',
  'rabin2',
  'binwalk',
  'qemu-system-arm',
  'qemu-system-mipsel',
  'objdump',
  'readelf',
  'nm',
  'strings',
  'file',
  'checksec',
  'yara',
  'tshark',
  'zeek',
  'suricata',
  'nmap',
  'tcpdump',
  'git',
  'python',
  'python3',
  'pip',
  'pip3',
  'cargo',
  'rustc',
  'go',
  'gcc',
  'g++',
  'clang',
  'clang++',
  'cmake',
  'make',
  'ninja',
  'javac',
  'mvn',
  'gradle',
  'dotnet',
  'node',
  'npm',
  'pnpm',
  'yarn',
  'tsc',
  'eslint',
  'docker',
] as const;

/** Collect a full environment report. */
export async function collectEnvironmentReport(): Promise<EnvironmentReport> {
  const cfg = getConfig();

  let pythonVersion: string | undefined;
  try {
    const probe = platform() === 'win32' ? 'python' : 'python3';
    const res = await runCommand(probe, { args: ['--version'], timeoutMs: 5000 });
    pythonVersion = (res.stdout || res.stderr).trim() || undefined;
  } catch {
    pythonVersion = undefined;
  }

  const toolchains: Record<string, string | undefined> = {};
  for (const tool of ['node', 'npm', 'tsc', 'git', 'python', 'python3', 'gcc', 'clang', 'cargo', 'go', 'javac']) {
    toolchains[tool] = toolOnPathSync(tool) ? 'present' : undefined;
  }

  const analysisTools: Record<string, boolean> = {};
  for (const tool of KNOWN_ANALYSIS_TOOLS) {
    analysisTools[tool] = toolOnPathSync(tool);
  }

  // §6 — precise dependency diagnostics (executable + version where possible).
  const dependencies = await probeDependencies();

  const report: EnvironmentReport = {
    os: `${platform()} ${release()}`,
    platform: platform(),
    arch: arch(),
    nodeVersion: process.version,
    ...(pythonVersion ? { pythonVersion } : {}),
    cpus: cpus().length,
    totalMemoryMb: Math.round(totalmem() / (1024 * 1024)),
    freeMemoryMb: Math.round(freemem() / (1024 * 1024)),
    cwd: process.cwd(),
    workspaceRoot: cfg.workspaceRoot,
    toolchains,
    analysisTools,
    dependencies,
    networkRestricted: !cfg.allowPublicFetch,
    generatedAt: new Date().toISOString(),
  };

  log.info('environment.report', {
    platform: report.platform,
    arch: report.arch,
    cpus: report.cpus,
    toolsAvailable: Object.values(analysisTools).filter(Boolean).length,
    dependenciesAvailable: dependencies.filter((d) => d.status === 'AVAILABLE').length,
  });

  return report;
}
