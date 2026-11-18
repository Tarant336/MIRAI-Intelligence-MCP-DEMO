/**
 * Error taxonomy with actionable messages.
 *
 * Every error carries a stable `code`, an actionable `hint` and optional
 * structured `details`, so that MCP clients can programmatically react.
 */

import type { DependencyProbe } from '../shared/types.js';

export type MiraiErrorCode =
  | 'INVALID_INPUT'
  | 'NOT_FOUND'
  | 'PERMISSION_DENIED'
  | 'POLICY_BLOCKED'
  | 'PATH_OUTSIDE_WORKSPACE'
  | 'TIMEOUT'
  | 'TOOL_MISSING'
  | 'EXTERNAL_FETCH_DISABLED'
  | 'UPSTREAM_FAILURE'
  | 'ARTIFACT_TOO_LARGE'
  | 'UNSUPPORTED_FORMAT'
  | 'INTERNAL';

export class MiraiError extends Error {
  readonly code: MiraiErrorCode;
  readonly hint: string;
  readonly details?: Record<string, unknown>;

  constructor(code: MiraiErrorCode, message: string, hint: string, details?: Record<string, unknown>) {
    super(message);
    this.name = 'MiraiError';
    this.code = code;
    this.hint = hint;
    this.details = details;
  }

  toJSON(): Record<string, unknown> {
    return {
      code: this.code,
      message: this.message,
      hint: this.hint,
      ...(this.details ? { details: this.details } : {}),
    };
  }
}

export const errors = {
  invalidInput: (message: string, details?: Record<string, unknown>) =>
    new MiraiError(
      'INVALID_INPUT',
      message,
      'Check the tool input schema and provide the required fields with valid values.',
      details,
    ),

  notFound: (what: string, details?: Record<string, unknown>) =>
    new MiraiError(
      'NOT_FOUND',
      `${what} was not found.`,
      'Verify the identifier/path exists; use the corresponding search or listing tool first.',
      details,
    ),

  policyBlocked: (reason: string, hint: string, details?: Record<string, unknown>) =>
    new MiraiError('POLICY_BLOCKED', reason, hint, details),

  pathOutsideWorkspace: (path: string, workspaceRoot: string) =>
    new MiraiError(
      'PATH_OUTSIDE_WORKSPACE',
      `Path "${path}" resolves outside the authorized workspace.`,
      `Only paths under "${workspaceRoot}" may be accessed. Set MIRAI_WORKSPACE to widen the boundary.`,
      { path, workspaceRoot },
    ),

  toolMissing: (tool: string, alternatives: string[]) =>
    new MiraiError(
      'TOOL_MISSING',
      `Required external tool "${tool}" is not installed.`,
      alternatives.length
        ? `Install one of: ${alternatives.join(', ')} — or use the built-in fallback if available.`
        : `Install "${tool}" and ensure it is on PATH.`,
      { tool, alternatives },
    ),

  /**
   * A tool depends on external dependencies that are missing or unusable (§6).
   * Carries the full probe results so callers can act on each one.
   */
  dependencyMissing: (dependencies: DependencyProbe[]) =>
    new MiraiError(
      'TOOL_MISSING',
      `Required dependency unavailable: ${dependencies.map((d) => `${d.id} (${d.status})`).join(', ')}.`,
      dependencies.map((d) => `[${d.id}] ${d.installHint}`).join(' ') ||
        'Install the missing dependency and ensure it is on PATH.',
      { dependencies },
    ),

  fetchDisabled: (url: string) =>
    new MiraiError(
      'EXTERNAL_FETCH_DISABLED',
      `Public network fetch is disabled; cannot retrieve ${url}.`,
      'Set MIRAI_ALLOW_PUBLIC_FETCH=true to enable read-only public fetches.',
      { url },
    ),

  timeout: (what: string, ms: number) =>
    new MiraiError(
      'TIMEOUT',
      `${what} exceeded the ${ms}ms budget.`,
      'Reduce the scope of the request or raise MIRAI_EXEC_TIMEOUT_MS.',
      { ms },
    ),

  artifactTooLarge: (bytes: number, limit: number) =>
    new MiraiError(
      'ARTIFACT_TOO_LARGE',
      `Artifact is ${bytes} bytes which exceeds the ${limit} byte limit.`,
      'Increase MIRAI_MAX_ARTIFACT_BYTES or process a smaller slice / extracted section.',
      { bytes, limit },
    ),

  internal: (message: string, details?: Record<string, unknown>) =>
    new MiraiError('INTERNAL', message, 'This is an internal error; check logs for the stack trace.', details),
};

/** Normalize any thrown value into a MiraiError. */
export function toMiraiError(err: unknown): MiraiError {
  if (err instanceof MiraiError) return err;
  if (err instanceof Error) {
    return new MiraiError('INTERNAL', err.message, 'Unexpected failure; see server logs.', {
      stack: err.stack,
    });
  }
  return new MiraiError('INTERNAL', String(err), 'Unexpected non-Error value was thrown.');
}
