// End-to-end stdio check for the MCP server.
//
// Spawns the server and performs a real JSON-RPC MCP handshake over
// stdin/stdout. The check is *event driven*: it waits for the response that
// matches each request id instead of sleeping for a fixed amount of time and
// assuming the server is ready. This makes cold starts (e.g. on a slow 2 vCPU
// machine) reliable while still failing fast on real protocol problems.
//
// Design notes (§4 P1.3 of the specification):
//   * `initialize` is sent first and the matching response id is awaited.
//   * Only after `initialize` succeeds are `tools/list`, `prompts/list` and
//     `resources/list` requested (also awaited by id).
//   * Response ids, JSON-RPC errors, process exit and stderr are all checked.
//   * A configurable global timeout guarantees the check can never hang.
//   * If the server dies, its stderr and exit reason are reported.
//   * The child process and its streams are always cleaned up.
//
// The core routine is exported so regression tests can drive it against fake
// servers; the CLI part only runs when the file is executed directly.

import { spawn } from 'node:child_process';
import { pathToFileURL } from 'node:url';

/** Counts expected from the current registry (113 tools / 6 prompts / 2 resources). */
export const DEFAULT_EXPECTED = { tools: 113, prompts: 6, resources: 2 };

/** Default global timeout, in milliseconds, guarding against an unresponsive server. */
export const DEFAULT_GLOBAL_TIMEOUT_MS = 60000;

/** Environment variable that overrides the global timeout. */
export const TIMEOUT_ENV = 'MIRAI_STDIO_CHECK_TIMEOUT';

function truncate(text, max) {
  return text.length <= max ? text : `${text.slice(0, max)}…`;
}

/** Resolve the global timeout from CLI value (preferred) or environment. */
export function resolveTimeout(cliValue, env = process.env) {
  if (typeof cliValue === 'number' && Number.isFinite(cliValue) && cliValue > 0) return cliValue;
  const raw = env?.[TIMEOUT_ENV];
  if (raw !== undefined && raw !== '') {
    const parsed = Number(raw);
    if (Number.isFinite(parsed) && parsed > 0) return parsed;
  }
  return DEFAULT_GLOBAL_TIMEOUT_MS;
}

function makeError(kind, message) {
  const err = new Error(message);
  err.kind = kind;
  return err;
}

/**
 * Run the stdio handshake check and resolve with a structured result.
 *
 * @param {object} [options]
 * @param {string} [options.command] executable to spawn (default: node).
 * @param {string[]} [options.args] arguments (default: ['dist/index.js']).
 * @param {string} [options.cwd] working directory for the child.
 * @param {Record<string,string>} [options.env] environment for the child.
 * @param {number} [options.globalTimeoutMs] hard timeout for the whole check.
 * @param {number} [options.expectedTools] expected number of tools.
 * @param {number} [options.expectedPrompts] expected number of prompts.
 * @param {number} [options.expectedResources] expected number of resources.
 * @returns {Promise<{
 *   ok: boolean, serverName: string|null, serverVersion: string|null,
 *   toolCount: number, promptCount: number, resourceCount: number,
 *   toolNames: string[], promptNames: string[], resourceUris: string[],
 *   stderr: string, exitReason: string|null, exitCode: number|null,
 *   exitSignal: string|null, error: string|null, errors: string[]
 * }>}
 */
export function runStdioCheck(options = {}) {
  return new Promise((resolve) => {
    const command = options.command ?? process.execPath;
    const args = options.args ?? ['dist/index.js'];
    const cwd = options.cwd ?? process.cwd();
    const env = options.env ?? process.env;
    const globalTimeoutMs = resolveTimeout(options.globalTimeoutMs, env);
    const expectedTools = options.expectedTools ?? DEFAULT_EXPECTED.tools;
    const expectedPrompts = options.expectedPrompts ?? DEFAULT_EXPECTED.prompts;
    const expectedResources = options.expectedResources ?? DEFAULT_EXPECTED.resources;

    const result = {
      ok: false,
      serverName: null,
      serverVersion: null,
      toolCount: 0,
      promptCount: 0,
      resourceCount: 0,
      toolNames: [],
      promptNames: [],
      resourceUris: [],
      stderr: '',
      exitReason: null,
      exitCode: null,
      exitSignal: null,
      error: null,
      errors: [],
    };

    let finished = false;
    let exitObserved = false;
    let timedOut = false;
    let stdoutBuffer = '';
    let stderrBuffer = '';
    let nextId = 1;
    const pending = new Map();
    let globalTimer = null;

    let child;
    try {
      child = spawn(command, args, { cwd, env, stdio: ['pipe', 'pipe', 'pipe'] });
    } catch (err) {
      result.errors.push(`failed to spawn ${command}: ${err?.message ?? String(err)}`);
      result.error = result.errors[0];
      result.exitReason = 'spawn-error';
      resolve(result);
      return;
    }

    const recordError = (message) => {
      if (!result.errors.includes(message)) result.errors.push(message);
      if (!result.error) result.error = message;
    };

    const rejectAll = (err) => {
      for (const entry of pending.values()) {
        try {
          entry.reject(err);
        } catch {
          /* ignore */
        }
      }
      pending.clear();
    };

    const cleanup = () => {
      if (globalTimer) {
        clearTimeout(globalTimer);
        globalTimer = null;
      }
      child.stdout?.removeAllListeners();
      child.stderr?.removeAllListeners();
      child.stdin?.removeAllListeners();
      child.removeAllListeners();
      try {
        child.stdin?.destroy();
      } catch {
        /* ignore */
      }
      try {
        if (!child.killed) child.kill('SIGTERM');
      } catch {
        /* ignore */
      }
      const killer = setTimeout(() => {
        try {
          child.kill('SIGKILL');
        } catch {
          /* ignore */
        }
      }, 1000);
      killer.unref?.();
    };

    const finish = (reason) => {
      if (finished) return;
      finished = true;
      result.exitReason = reason;
      result.stderr = stderrBuffer;
      if (timedOut) recordError(`global timeout after ${globalTimeoutMs}ms`);
      result.ok = reason === 'completed' && result.errors.length === 0;
      cleanup();
      resolve(result);
    };

    const dispatch = (msg) => {
      if (msg === null || typeof msg !== 'object' || Array.isArray(msg)) return;
      const hasId = msg.id !== undefined && msg.id !== null;
      const isResponse = hasId && ('result' in msg || 'error' in msg);
      if (!isResponse) {
        // Server-initiated notification or request: not part of this check.
        return;
      }
      const entry = pending.get(msg.id);
      if (!entry) {
        if (pending.size > 0) {
          const expected = [...pending.keys()].join(',');
          rejectAll(
            makeError('protocol', `response id mismatch: received ${JSON.stringify(msg.id)}, expected ${expected}`),
          );
        } else {
          recordError(`unexpected response id ${JSON.stringify(msg.id)} with no outstanding request`);
        }
        return;
      }
      pending.delete(msg.id);
      if (msg.error) {
        entry.reject(
          makeError(
            'rpc',
            `JSON-RPC error for ${entry.method} (id ${msg.id}): ${msg.error.code} ${msg.error.message}`,
          ),
        );
        return;
      }
      entry.resolve(msg.result);
    };

    const onStdout = (chunk) => {
      stdoutBuffer += chunk.toString('utf8');
      let idx;
      while ((idx = stdoutBuffer.indexOf('\n')) !== -1) {
        const line = stdoutBuffer.slice(0, idx).trim();
        stdoutBuffer = stdoutBuffer.slice(idx + 1);
        if (!line) continue;
        let msg;
        try {
          msg = JSON.parse(line);
        } catch {
          recordError(`non-JSON on stdout: ${truncate(line, 200)}`);
          rejectAll(makeError('protocol', 'invalid JSON-RPC on stdout'));
          finish('protocol-error');
          return;
        }
        dispatch(msg);
      }
    };

    child.stdout.on('data', onStdout);
    child.stderr.on('data', (chunk) => {
      stderrBuffer += chunk.toString('utf8');
    });
    child.on('error', (err) => {
      recordError(`failed to start server: ${err?.message ?? String(err)}`);
      finish('spawn-error');
    });
    child.on('exit', (code, signal) => {
      exitObserved = true;
      result.exitCode = typeof code === 'number' ? code : null;
      result.exitSignal = signal ?? null;
      if (pending.size > 0) {
        // The awaiting flow records the message and picks the finish reason.
        rejectAll(makeError('exited', `server exited before responding (code=${code}, signal=${signal})`));
      } else if (!finished) {
        recordError(`server exited unexpectedly (code=${code}, signal=${signal})`);
        finish('exited');
      }
    });

    globalTimer = setTimeout(() => {
      timedOut = true;
      rejectAll(makeError('timeout', `global timeout after ${globalTimeoutMs}ms`));
      finish('timeout');
    }, globalTimeoutMs);
    globalTimer.unref?.();

    const send = (msg) => {
      if (exitObserved || finished || !child.stdin?.writable) {
        throw makeError('exited', 'cannot send: server stdin is not writable');
      }
      child.stdin.write(`${JSON.stringify(msg)}\n`);
    };

    const request = (method, params) =>
      new Promise((resolveP, rejectP) => {
        const id = nextId++;
        pending.set(id, { method, resolve: resolveP, reject: rejectP });
        try {
          send({ jsonrpc: '2.0', id, method, params });
        } catch (err) {
          pending.delete(id);
          rejectP(err);
        }
      });

    const notify = (method, params) => {
      send({ jsonrpc: '2.0', method, ...(params ? { params } : {}) });
    };

    (async () => {
      try {
        const init = await request('initialize', {
          protocolVersion: '2024-11-05',
          capabilities: {},
          clientInfo: { name: 'stdio-check', version: '1.0.0' },
        });
        result.serverName = init?.serverInfo?.name ?? null;
        result.serverVersion = init?.serverInfo?.version ?? null;
        notify('notifications/initialized');

        const tools = await request('tools/list', {});
        const toolList = Array.isArray(tools?.tools) ? tools.tools : [];
        result.toolNames = toolList.map((t) => t?.name).filter((n) => typeof n === 'string');
        result.toolCount = toolList.length;

        const prompts = await request('prompts/list', {});
        const promptList = Array.isArray(prompts?.prompts) ? prompts.prompts : [];
        result.promptNames = promptList.map((p) => p?.name).filter((n) => typeof n === 'string');
        result.promptCount = promptList.length;

        const resources = await request('resources/list', {});
        const resourceList = Array.isArray(resources?.resources) ? resources.resources : [];
        result.resourceUris = resourceList.map((r) => r?.uri).filter((u) => typeof u === 'string');
        result.resourceCount = resourceList.length;

        if (result.toolCount !== expectedTools) {
          recordError(`expected ${expectedTools} tools, got ${result.toolCount}`);
        }
        if (result.promptCount !== expectedPrompts) {
          recordError(`expected ${expectedPrompts} prompts, got ${result.promptCount}`);
        }
        if (result.resourceCount !== expectedResources) {
          recordError(`expected ${expectedResources} resources, got ${result.resourceCount}`);
        }

        finish('completed');
      } catch (err) {
        const kind = err?.kind;
        const reason = timedOut
          ? 'timeout'
          : kind === 'timeout'
            ? 'timeout'
            : kind === 'rpc'
              ? 'rpc-error'
              : kind === 'exited'
                ? 'exited'
                : 'protocol-error';
        recordError(err?.message ?? String(err));
        finish(reason);
      }
    })();
  });
}

const USAGE = `Usage: node scripts/stdio-check.mjs [--timeout <ms>] [--help]

Spawns the built MCP server (dist/index.js) and performs a real JSON-RPC
handshake over stdio, waiting for each response by request id.

Options:
  -t, --timeout <ms>   Global timeout in milliseconds (default: ${DEFAULT_GLOBAL_TIMEOUT_MS}).
  -h, --help           Show this help.

Environment:
  ${TIMEOUT_ENV}   Overrides the global timeout when --timeout is absent.
`;

function parseArgs(argv) {
  const opts = { timeoutMs: undefined, help: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      opts.help = true;
    } else if (arg === '--timeout' || arg === '-t') {
      opts.timeoutMs = Number(argv[i + 1]);
      i += 1;
    } else if (arg.startsWith('--timeout=')) {
      opts.timeoutMs = Number(arg.slice('--timeout='.length));
    }
  }
  return opts;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    process.stdout.write(USAGE);
    return;
  }
  const timeoutMs = resolveTimeout(opts.timeoutMs, process.env);
  const result = await runStdioCheck({ globalTimeoutMs: timeoutMs });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);

  if (!result.ok) {
    process.stderr.write(`stdio-check failed: ${result.exitReason}${result.error ? ` — ${result.error}` : ''}\n`);
    if (result.stderr) process.stderr.write(`--- server stderr ---\n${result.stderr}\n`);
  }
  process.exit(result.ok ? 0 : 1);
}

const isMain = (() => {
  try {
    return !!process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
  } catch {
    return false;
  }
})();

if (isMain) {
  main().catch((err) => {
    process.stderr.write(`stdio-check crashed: ${err?.stack ?? String(err)}\n`);
    process.exit(1);
  });
}