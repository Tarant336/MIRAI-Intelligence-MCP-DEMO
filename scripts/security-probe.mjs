/**
 * Read-only security-control probe (deep validation §12).
 * Spawns the real server, issues a small set of adversarial-but-benign requests,
 * and records whether each control holds. Never fabricates tokens or credentials.
 *
 * Usage: node scripts/security-probe.mjs
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';

const TOOL_TIMEOUT = 45000;
const STARTUP = 4000;

class Client {
  constructor() {
    this.child = null;
    this.buf = '';
    this.pending = new Map();
    this.id = 1;
  }
  start() {
    return new Promise((resolve, reject) => {
      this.child = spawn(process.execPath, ['dist/index.js'], { cwd: process.cwd(), stdio: ['pipe', 'pipe', 'pipe'] });
      this.child.stdout.on('data', (d) => this._onData(d));
      this.child.stderr.on('data', () => {});
      this.child.on('error', reject);
      setTimeout(resolve, STARTUP);
    });
  }
  _onData(d) {
    this.buf += d.toString('utf8');
    let idx;
    while ((idx = this.buf.indexOf('\n')) !== -1) {
      const line = this.buf.slice(0, idx).trim();
      this.buf = this.buf.slice(idx + 1);
      if (!line) continue;
      let msg;
      try {
        msg = JSON.parse(line);
      } catch {
        continue;
      }
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        resolve(msg);
      }
    }
  }
  request(method, params) {
    const id = this.id++;
    this.child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      setTimeout(() => {
        if (this.pending.has(id)) {
          this.pending.delete(id);
          reject(new Error(`timeout ${method}`));
        }
      }, TOOL_TIMEOUT);
    });
  }
  async init() {
    await this.request('initialize', {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: { name: 'security-probe', version: '1.0.0' },
    });
    this.child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`);
  }
  callTool(name, args) {
    return this.request('tools/call', { name, arguments: args });
  }
}

const text = (r) => (r?.result?.content ?? []).map((x) => x.text || '').join(' ') || JSON.stringify(r?.result ?? r);

const checks = [
  {
    id: 'sec-01',
    control: 'Path confinement — repository_search path traversal',
    tool: 'repository_search',
    args: { query: 'root', path: '../../../../Windows' },
  },
  {
    id: 'sec-02',
    control: 'Path confinement — absolute path outside workspace',
    tool: 'malware_sample_analyze',
    args: { filePath: 'C:\\Windows\\win.ini' },
  },
  {
    id: 'sec-03',
    control: 'Path confinement — source_generate rootPath escape',
    tool: 'source_generate',
    args: { rootPath: '../_sec_escape_out', files: [{ relativePath: 'x.txt', content: 'x' }] },
  },
  {
    id: 'sec-04',
    control: 'No shell interpolation — run_tests explicit command with metacharacters',
    tool: 'run_tests',
    args: { path: '.', command: 'echo hi; calc.exe', args: [] },
  },
  {
    id: 'sec-05',
    control: 'Lab authorization gate — defense_test_plan without token is plan-only',
    tool: 'defense_test_plan',
    args: { systemDescription: 'local HTTP parser under test', scope: ['buffer overflow'] },
  },
  {
    id: 'sec-06',
    control: 'Path confinement — fuzzing_crash_analyze crashReportPath outside workspace',
    tool: 'fuzzing_crash_analyze',
    args: { crashReportPath: 'C:\\Windows\\win.ini' },
  },
  {
    id: 'sec-07',
    control: 'Write guard — knowledge_update on unknown record does not silently create',
    tool: 'knowledge_update',
    args: { recordId: 'does-not-exist-xyz', patch: { title: 'x' } },
  },
  {
    id: 'sec-08',
    control: 'Knowledge ingest requires provenance source (schema boundary)',
    tool: 'knowledge_ingest',
    args: { category: 'advisory', title: 'probe' },
  },
];

const c = new Client();
await c.start();
await c.init();

const results = [];
for (const chk of checks) {
  let resp;
  let err;
  try {
    resp = await c.callTool(chk.tool, chk.args);
  } catch (e) {
    err = String(e.message || e);
  }
  const isError = resp?.result?.isError === true;
  const body = err ? `HARNESS_ERROR: ${err}` : text(resp);
  results.push({
    id: chk.id,
    control: chk.control,
    tool: chk.tool,
    args: chk.args,
    isError,
    body: body.slice(0, 1200),
    structured: resp?.result?.structuredContent ?? null,
  });
  console.log(`\n## ${chk.id} ${chk.control}\n  tool=${chk.tool} isError=${isError}\n  ${body.slice(0, 700).replace(/\n/g, ' ')}`);
}

fs.writeFileSync('scripts/_security-probe.json', JSON.stringify(results, null, 2));
c.child.kill();
process.exit(0);