/**
 * Isolated process execution and tool discovery.
 *
 * SECURITY: commands are executed WITHOUT a shell (argv form only), with a
 * hard timeout, a hard output cap, and a working directory constrained to the
 * authorized workspace. This prevents shell injection and runaway processes.
 */

import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { platform } from 'node:os';

import { getConfig } from '../config/index.js';
import { errors, MiraiError } from '../core/errors.js';
import { logger } from '../core/logger.js';
import { resolveWorkspacePath } from './security.js';

export interface ExecOptions {
  args?: string[];
  cwd?: string;
  timeoutMs?: number;
  maxOutputBytes?: number;
  env?: Record<string, string>;
}

export interface ExecResult {
  command: string;
  args: string[];
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  truncated: boolean;
  timedOut: boolean;
  durationMs: number;
}

const log = logger.child({ component: 'sandbox' });

/** Run a command in the isolated sandbox and capture bounded output. */
export async function runCommand(command: string, options: ExecOptions = {}): Promise<ExecResult> {
  const cfg = getConfig();
  if (!cfg.allowIsolatedExec) {
    throw errors.policyBlocked(
      'Isolated execution is disabled.',
      'Set MIRAI_ALLOW_ISOLATED_EXEC=true to permit sandboxed commands.',
    );
  }

  const args = options.args ?? [];
  const cwd = options.cwd ? resolveWorkspacePath(options.cwd, true) : cfg.workspaceRoot;
  const timeoutMs = options.timeoutMs ?? cfg.execTimeoutMs;
  const maxBytes = options.maxOutputBytes ?? cfg.execMaxOutputBytes;

  const started = Date.now();
  log.debug('exec.start', { command, args, cwd, timeoutMs });

  return new Promise<ExecResult>((resolve, reject) => {
    let child;
    try {
      child = spawn(command, args, {
        cwd,
        shell: false,
        windowsHide: true,
        env: { ...process.env, ...(options.env ?? {}) },
      });
    } catch (err) {
      reject(
        new MiraiError(
          'TOOL_MISSING',
          `Failed to spawn "${command}": ${(err as Error).message}`,
          `Verify "${command}" is installed and on PATH.`,
          { command },
        ),
      );
      return;
    }

    let stdout = '';
    let stderr = '';
    let truncated = false;
    let timedOut = false;
    let bytes = 0;

    const append = (prev: string, chunk: Buffer): string => {
      if (bytes >= maxBytes) {
        truncated = true;
        return prev;
      }
      bytes += chunk.length;
      const next = prev + chunk.toString('utf8');
      if (bytes >= maxBytes) {
        truncated = true;
        return next.slice(0, maxBytes);
      }
      return next;
    };

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, timeoutMs);

    child.stdout?.on('data', (chunk: Buffer) => {
      stdout = append(stdout, chunk);
    });
    child.stderr?.on('data', (chunk: Buffer) => {
      stderr = append(stderr, chunk);
    });

    child.on('error', (err) => {
      clearTimeout(timer);
      reject(
        new MiraiError(
          'TOOL_MISSING',
          `Failed to execute "${command}": ${err.message}`,
          `Verify "${command}" is installed and executable.`,
          { command },
        ),
      );
    });

    child.on('close', (exitCode, signal) => {
      clearTimeout(timer);
      const result: ExecResult = {
        command,
        args,
        exitCode,
        signal,
        stdout,
        stderr,
        truncated,
        timedOut,
        durationMs: Date.now() - started,
      };
      log.debug('exec.done', { command, exitCode, durationMs: result.durationMs, timedOut });
      resolve(result);
    });
  });
}

/** Check whether an executable is available on PATH. */
export async function hasTool(name: string): Promise<boolean> {
  const probe = platform() === 'win32' ? 'where' : 'which';
  try {
    const res = await runCommand(probe, { args: [name], timeoutMs: 5000 });
    return res.exitCode === 0;
  } catch {
    return false;
  }
}

/** Discover a set of tools, returning a name -> available map. */
export async function discoverTools(names: string[]): Promise<Record<string, boolean>> {
  const entries = await Promise.all(
    names.map(async (name) => [name, await hasTool(name)] as const),
  );
  return Object.fromEntries(entries);
}

/** Synchronous, best-effort PATH probe used in the environment report. */
export function toolOnPathSync(name: string): boolean {
  const pathValue = process.env.PATH ?? '';
  const sepChar = platform() === 'win32' ? ';' : ':';
  const exts = platform() === 'win32' ? (process.env.PATHEXT ?? '.EXE').split(';') : [''];
  for (const dir of pathValue.split(sepChar)) {
    if (!dir) continue;
    for (const ext of exts) {
      try {
        if (existsSync(`${dir}/${name}${ext}`)) return true;
      } catch {
        /* ignore */
      }
    }
  }
  return false;
}
