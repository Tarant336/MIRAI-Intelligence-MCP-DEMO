/**
 * Regression tests for scripts/stdio-check.mjs (§4 P1.3).
 *
 * The check must wait for the protocol response that matches each request id
 * rather than sleeping for a fixed duration, must surface JSON-RPC errors,
 * exit reasons and stderr, must honour a configurable global timeout and must
 * always clean up the child process.
 *
 * Most scenarios are driven against tiny fake servers spawned with `node -e`
 * so they are deterministic and fast. A final test runs the real server and
 * asserts the current registry surface (113 tools / 6 prompts / 2 resources).
 */

import { describe, expect, it } from 'vitest';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

interface StdioCheckResult {
  ok: boolean;
  serverName: string | null;
  serverVersion: string | null;
  toolCount: number;
  promptCount: number;
  resourceCount: number;
  toolNames: string[];
  promptNames: string[];
  resourceUris: string[];
  stderr: string;
  exitReason: string | null;
  exitCode: number | null;
  exitSignal: string | null;
  error: string | null;
  errors: string[];
}

interface StdioCheckOptions {
  command?: string;
  args?: string[];
  cwd?: string;
  env?: Record<string, string>;
  globalTimeoutMs?: number;
  expectedTools?: number;
  expectedPrompts?: number;
  expectedResources?: number;
}

interface StdioCheckModule {
  runStdioCheck: (options?: StdioCheckOptions) => Promise<StdioCheckResult>;
  resolveTimeout: (cliValue?: number, env?: Record<string, string>) => number;
  DEFAULT_EXPECTED: { tools: number; prompts: number; resources: number };
  DEFAULT_GLOBAL_TIMEOUT_MS: number;
  TIMEOUT_ENV: string;
}

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..');
const distEntry = path.join(root, 'dist', 'index.js');
const tsxCli = path.join(root, 'node_modules', 'tsx', 'dist', 'cli.mjs');

const mod = (await import('../scripts/stdio-check.mjs')) as unknown as StdioCheckModule;

/**
 * Build the source of a fake MCP server for `node -e`.
 * Modes: normal | slow | init-error | silent | early-exit | invalid-json | id-mismatch.
 */
function fakeServerSource(mode: string): string {
  return `
'use strict';
const MODE = ${JSON.stringify(mode)};
const NL = String.fromCharCode(10);
let buf = '';
function send(o) { process.stdout.write(JSON.stringify(o) + NL); }
function reply(id, result) { send({ jsonrpc: '2.0', id: id, result: result }); }
if (MODE === 'early-exit') {
  process.stderr.write('fake-server: boot failure' + NL);
  setTimeout(function () { process.exit(3); }, 50);
} else {
  process.stdin.on('data', function (d) {
    buf += d.toString('utf8');
    let i;
    while ((i = buf.indexOf(NL)) !== -1) {
      const line = buf.slice(0, i).trim();
      buf = buf.slice(i + 1);
      if (!line) continue;
      let msg;
      try { msg = JSON.parse(line); } catch (e) { continue; }
      handle(msg);
    }
  });
}
function handle(msg) {
  if (msg.method === 'initialize') {
    if (MODE === 'silent') return;
    if (MODE === 'invalid-json') { process.stdout.write('not-json-on-stdout' + NL); return; }
    if (MODE === 'id-mismatch') { reply(msg.id + 100, { serverInfo: { name: 'fake-server', version: '9.9.9' } }); return; }
    if (MODE === 'init-error') { send({ jsonrpc: '2.0', id: msg.id, error: { code: -32603, message: 'boom' } }); return; }
    const respond = function () {
      reply(msg.id, { protocolVersion: '2024-11-05', capabilities: {}, serverInfo: { name: 'fake-server', version: '9.9.9' } });
      send({ jsonrpc: '2.0', method: 'notifications/message', params: { level: 'info', data: 'ready' } });
    };
    if (MODE === 'slow') setTimeout(respond, 2000); else respond();
    return;
  }
  if (msg.id === undefined || msg.id === null) return;
  if (msg.method === 'tools/list') { reply(msg.id, { tools: [{ name: 'alpha' }, { name: 'beta' }] }); return; }
  if (msg.method === 'prompts/list') { reply(msg.id, { prompts: [{ name: 'p1' }, { name: 'p2' }, { name: 'p3' }] }); return; }
  if (msg.method === 'resources/list') { reply(msg.id, { resources: [{ uri: 'fake://only' }] }); return; }
}
`;
}

function runFake(mode: string, extra: StdioCheckOptions = {}): Promise<StdioCheckResult> {
  return mod.runStdioCheck({
    command: process.execPath,
    args: ['-e', fakeServerSource(mode)],
    cwd: root,
    globalTimeoutMs: 10000,
    expectedTools: 2,
    expectedPrompts: 3,
    expectedResources: 1,
    ...extra,
  });
}

/** Prefer the built server; fall back to running the TypeScript entry via tsx. */
function realServerTarget(): { command: string; args: string[] } {
  if (existsSync(distEntry)) return { command: process.execPath, args: [distEntry] };
  return { command: process.execPath, args: [tsxCli, path.join(root, 'src', 'index.ts')] };
}

describe('resolveTimeout', () => {
  it('prefers an explicit CLI value', () => {
    expect(mod.resolveTimeout(1234, {})).toBe(1234);
  });

  it('reads the environment variable when no CLI value is given', () => {
    expect(mod.resolveTimeout(undefined, { [mod.TIMEOUT_ENV]: '4321' })).toBe(4321);
  });

  it('falls back to the default for invalid values', () => {
    expect(mod.resolveTimeout(Number.NaN, { [mod.TIMEOUT_ENV]: 'not-a-number' })).toBe(mod.DEFAULT_GLOBAL_TIMEOUT_MS);
  });
});

describe('runStdioCheck — normal startup', () => {
  it('waits for initialize by id, then lists tools/prompts/resources', async () => {
    const result = await runFake('normal');
    expect(result.errors).toEqual([]);
    expect(result.ok).toBe(true);
    expect(result.exitReason).toBe('completed');
    expect(result.serverName).toBe('fake-server');
    expect(result.serverVersion).toBe('9.9.9');
    expect(result.toolCount).toBe(2);
    expect(result.promptCount).toBe(3);
    expect(result.resourceCount).toBe(1);
    expect(result.toolNames).toEqual(['alpha', 'beta']);
    expect(result.promptNames).toEqual(['p1', 'p2', 'p3']);
    expect(result.resourceUris).toEqual(['fake://only']);
  });
});

describe('runStdioCheck — slow cold startup', () => {
  it('keeps waiting past the old fixed 400/800/1600ms schedule', async () => {
    const started = Date.now();
    const result = await runFake('slow', { globalTimeoutMs: 15000 });
    const elapsed = Date.now() - started;
    expect(result.ok).toBe(true);
    expect(result.exitReason).toBe('completed');
    expect(result.toolCount).toBe(2);
    expect(elapsed).toBeGreaterThanOrEqual(1900);
  });
});

describe('runStdioCheck — failure modes', () => {
  it('reports a JSON-RPC error returned for initialize', async () => {
    const result = await runFake('init-error', { globalTimeoutMs: 5000 });
    expect(result.ok).toBe(false);
    expect(result.exitReason).toBe('rpc-error');
    expect(result.error).toMatch(/JSON-RPC error/);
    expect(result.errors.join(' ')).toMatch(/boom/);
  });

  it('times out and cleans up when the server never responds', async () => {
    const result = await runFake('silent', { globalTimeoutMs: 1200 });
    expect(result.ok).toBe(false);
    expect(result.exitReason).toBe('timeout');
    expect(result.errors.join(' ')).toMatch(/global timeout/);
  });

  it('reports stderr and the exit reason when the server exits early', async () => {
    const result = await runFake('early-exit', { globalTimeoutMs: 5000 });
    expect(result.ok).toBe(false);
    expect(result.exitReason).toBe('exited');
    expect(result.exitCode).toBe(3);
    expect(result.stderr).toMatch(/fake-server: boot failure/);
  });

  it('flags non-JSON output on stdout as a protocol error', async () => {
    const result = await runFake('invalid-json', { globalTimeoutMs: 5000 });
    expect(result.ok).toBe(false);
    expect(result.exitReason).toBe('protocol-error');
    expect(result.error).toMatch(/non-JSON on stdout/);
  });

  it('detects a response whose id does not match the request', async () => {
    const result = await runFake('id-mismatch', { globalTimeoutMs: 5000 });
    expect(result.ok).toBe(false);
    expect(result.exitReason).toBe('protocol-error');
    expect(result.errors.join(' ')).toMatch(/id mismatch/);
  });
});

describe('runStdioCheck — real server', () => {
  it(
    'reports the current registry surface (113 tools / 6 prompts / 2 resources)',
    async () => {
      const { command, args } = realServerTarget();
      const result = await mod.runStdioCheck({ command, args, cwd: root, globalTimeoutMs: 90000 });
      expect(result.errors).toEqual([]);
      expect(result.ok).toBe(true);
      expect(result.exitReason).toBe('completed');
      expect(result.serverName).toBe('mirai-intelligence-research-mcp');
      expect(result.toolCount).toBe(113);
      expect(result.promptCount).toBe(6);
      expect(result.resourceCount).toBe(2);
    },
    120000,
  );
});
