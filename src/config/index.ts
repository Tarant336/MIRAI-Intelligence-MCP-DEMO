/**
 * Platform configuration.
 *
 * Configuration is resolved from, in order of precedence:
 *   1. Environment variables (MIRAI_*).
 *   2. A JSON config file passed via MIRAI_CONFIG.
 *   3. Built-in defaults.
 */

import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';

export interface PlatformConfig {
  /** Root directory that tools are allowed to read/write. */
  workspaceRoot: string;
  /** Directory used for the persistent knowledge store. */
  dataDir: string;
  /** Log level for structured logging. */
  logLevel: 'debug' | 'info' | 'warn' | 'error';
  /** Whether the network layer is allowed to reach public endpoints. */
  allowPublicFetch: boolean;
  /** Whether isolated execution (build/test/emulation) is enabled at all. */
  allowIsolatedExec: boolean;
  /** Hard timeout (ms) for any single isolated command. */
  execTimeoutMs: number;
  /** Hard cap on bytes captured from a spawned process. */
  execMaxOutputBytes: number;
  /** Maximum file size (bytes) a single analysis operation may load. */
  maxArtifactBytes: number;
  /** Whether destructive/attack-capable behaviour is permitted (always false by policy). */
  allowOffensiveOps: boolean;
  /** Explicit authorization token required for any active/lab testing. */
  labAuthorizationToken?: string;
  /** Transport: stdio (default) or http. */
  transport: 'stdio' | 'http';
  /** HTTP port when transport === 'http'. */
  httpPort: number;
}

const DEFAULT_DATA_DIR = join(homedir(), '.mirai-mcp');

function envBool(name: string, fallback: boolean): boolean {
  const raw = process.env[name];
  if (raw === undefined) return fallback;
  return ['1', 'true', 'yes', 'on'].includes(raw.toLowerCase());
}

function envInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined) return fallback;
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

const SAFE_DEFAULTS: PlatformConfig = {
  workspaceRoot: process.cwd(),
  dataDir: DEFAULT_DATA_DIR,
  logLevel: 'info',
  allowPublicFetch: true,
  allowIsolatedExec: true,
  execTimeoutMs: 120_000,
  execMaxOutputBytes: 4 * 1024 * 1024,
  maxArtifactBytes: 256 * 1024 * 1024,
  allowOffensiveOps: false,
  transport: 'stdio',
  httpPort: 8757,
};

function loadConfigFile(): Partial<PlatformConfig> {
  const explicit = process.env.MIRAI_CONFIG;
  const candidate = explicit ? resolve(explicit) : join(process.cwd(), 'mirai.config.json');
  if (!existsSync(candidate)) return {};
  try {
    return JSON.parse(readFileSync(candidate, 'utf8')) as Partial<PlatformConfig>;
  } catch {
    return {};
  }
}

let cached: PlatformConfig | undefined;

/** Resolve the effective configuration (cached after first call). */
export function getConfig(): PlatformConfig {
  if (cached) return cached;

  const fileConfig = loadConfigFile();
  const workspaceRoot = resolve(
    process.env.MIRAI_WORKSPACE ?? fileConfig.workspaceRoot ?? SAFE_DEFAULTS.workspaceRoot,
  );

  cached = {
    ...SAFE_DEFAULTS,
    ...fileConfig,
    workspaceRoot,
    dataDir: resolve(process.env.MIRAI_DATA_DIR ?? fileConfig.dataDir ?? SAFE_DEFAULTS.dataDir),
    logLevel:
      (process.env.MIRAI_LOG_LEVEL as PlatformConfig['logLevel']) ??
      fileConfig.logLevel ??
      SAFE_DEFAULTS.logLevel,
    allowPublicFetch: envBool(
      'MIRAI_ALLOW_PUBLIC_FETCH',
      fileConfig.allowPublicFetch ?? SAFE_DEFAULTS.allowPublicFetch,
    ),
    allowIsolatedExec: envBool(
      'MIRAI_ALLOW_ISOLATED_EXEC',
      fileConfig.allowIsolatedExec ?? SAFE_DEFAULTS.allowIsolatedExec,
    ),
    execTimeoutMs: envInt('MIRAI_EXEC_TIMEOUT_MS', fileConfig.execTimeoutMs ?? SAFE_DEFAULTS.execTimeoutMs),
    execMaxOutputBytes: envInt(
      'MIRAI_EXEC_MAX_OUTPUT_BYTES',
      fileConfig.execMaxOutputBytes ?? SAFE_DEFAULTS.execMaxOutputBytes,
    ),
    maxArtifactBytes: envInt(
      'MIRAI_MAX_ARTIFACT_BYTES',
      fileConfig.maxArtifactBytes ?? SAFE_DEFAULTS.maxArtifactBytes,
    ),
    // Offensive operations can never be enabled through configuration.
    allowOffensiveOps: false,
    labAuthorizationToken: process.env.MIRAI_LAB_TOKEN ?? fileConfig.labAuthorizationToken,
    transport: (process.env.MIRAI_TRANSPORT as PlatformConfig['transport']) ?? fileConfig.transport ?? 'stdio',
    httpPort: envInt('MIRAI_HTTP_PORT', fileConfig.httpPort ?? SAFE_DEFAULTS.httpPort),
  };

  return cached;
}

/** Reset the cache — used by tests. */
export function resetConfig(): void {
  cached = undefined;
}
