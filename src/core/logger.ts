/**
 * Structured logging.
 *
 * All logs are emitted as single-line JSON to stderr so that they never
 * corrupt the stdio MCP transport on stdout.
 */

import { getConfig } from '../config/index.js';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LEVEL_ORDER: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40 };

export interface LogFields {
  [key: string]: unknown;
}

function currentLevel(): LogLevel {
  return getConfig().logLevel;
}

function emit(level: LogLevel, message: string, fields?: LogFields): void {
  if (LEVEL_ORDER[level] < LEVEL_ORDER[currentLevel()]) return;
  const record = {
    ts: new Date().toISOString(),
    level,
    msg: message,
    ...(fields ?? {}),
  };
  process.stderr.write(`${JSON.stringify(record)}\n`);
}

export interface Logger {
  debug(message: string, fields?: LogFields): void;
  info(message: string, fields?: LogFields): void;
  warn(message: string, fields?: LogFields): void;
  error(message: string, fields?: LogFields): void;
  child(bindings: LogFields): Logger;
}

/** Create a scoped logger. */
export function createLogger(bindings: LogFields = {}): Logger {
  const withBindings = (fields?: LogFields): LogFields => ({ ...bindings, ...(fields ?? {}) });
  return {
    debug: (m, f) => emit('debug', m, withBindings(f)),
    info: (m, f) => emit('info', m, withBindings(f)),
    warn: (m, f) => emit('warn', m, withBindings(f)),
    error: (m, f) => emit('error', m, withBindings(f)),
    child: (extra) => createLogger({ ...bindings, ...extra }),
  };
}

export const logger = createLogger({ component: 'mirai-mcp' });
