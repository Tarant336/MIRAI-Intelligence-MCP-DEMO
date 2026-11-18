/**
 * MIRAI deep-validation batch 2 (read-only).
 * Ground-truth driven checks for §4 (zero-day), §5 (fuzzing), §6 (firmware, valid archives),
 * §7 (exploit intel), §8 (multi-agent conflict detection).
 *
 * Usage: node scripts/deep-validate-2.mjs
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';

const TOOL_TIMEOUT = 180000;
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
      clientInfo: { name: 'deep-validate-2', version: '1.0.0' },
    });
    this.child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`);
  }
  callTool(name, args) {
    return this.request('tools/call', { name, arguments: args });
  }
}

const V = 'test-artifacts/vuln-fixture';

const calls = [
  // §4 zero-day vs designed vulnerable fixture (ground truth in parser.c header)
  { id: 'zd-11', tool: 'source_vulnerability_analyze', args: { filePath: `${V}/parser.c` } },
  { id: 'zd-12', tool: 'static_analysis_run', args: { directoryPath: V } },
  { id: 'zd-13', tool: 'zero_day_discovery_analyze', args: { directoryPath: V, language: 'c' } },
  { id: 'zd-14', tool: 'vulnerability_variant_hunt', args: { pattern: 'strcpy\\(', patternType: 'regex', directoryPath: V } },
  { id: 'zd-15', tool: 'patch_diff_analyze', args: { beforePath: `${V}/parser.c`, afterPath: `${V}/parser_patched.c` } },
  { id: 'zd-16', tool: 'patch_root_cause_analyze', args: { vulnerableFilePath: `${V}/parser.c`, patchedFilePath: `${V}/parser_patched.c` } },

  // §5 fuzzing states
  { id: 'fz-11', tool: 'fuzz_target_identify', args: { directoryPath: V } },
  {
    id: 'fz-12',
    tool: 'fuzz_harness_generate',
    args: { targetName: 'handle_request', language: 'c', framework: 'libfuzzer', inputModel: 'TCP frame bytes' },
  },
  {
    id: 'fz-13',
    tool: 'crash_root_cause_analyze',
    args: {
      filePath: `${V}/parser.c`,
      backtrace: [
        'copy_payload at parser.c:20',
        'handle_request at parser.c:46',
        'main at parser.c:56',
      ],
    },
  },

  // §6 firmware on WELL-FORMED archives (ground truth: 3 members)
  { id: 'fw-11', tool: 'firmware_extract', args: { filePath: 'test-artifacts/valid-fs.cpio', outputDir: 'test-artifacts/_extract_cpio' } },
  { id: 'fw-12', tool: 'firmware_extract', args: { filePath: 'test-artifacts/valid-fs.tar', outputDir: 'test-artifacts/_extract_tar' } },
  { id: 'fw-13', tool: 'firmware_vulnerability_analyze', args: { filePath: 'test-artifacts/sample_firmware.bin' } },

  // §7 exploit intelligence
  { id: 'ex-11', tool: 'cve_search', args: { cveId: 'CVE-2021-44228', offline: true } },
  { id: 'ex-12', tool: 'exploit_metadata_analyze', args: { path: 'test-artifacts/known-vulns.jsonl' } },

  // §8 multi-agent conflict detection
  { id: 'ma-11', tool: 'research_audit', args: { topic: 'mirai' } },
  {
    id: 'ma-12',
    tool: 'agent_findings_merge',
    args: {
      findings: [
        { roleId: 'malware-analyst', statement: 'The sample is Mirai family.', evidence: ['C2 table strings'], confidence: 'confirmed' },
        { roleId: 'firmware-analyst', statement: 'The sample is Mirai family.', evidence: ['weak string overlap'], confidence: 'hypothesis' },
      ],
    },
  },
  {
    id: 'ma-13',
    tool: 'evidence_reconciliation',
    args: {
      topic: 'sample family attribution',
      assertions: [
        { statement: 'The sample is Mirai.', confidence: 'confirmed', supporting: ['C2 table strings'], contradicting: ['attack module mismatch'] },
        { statement: 'The sample is Gafgyt.', confidence: 'hypothesis', supporting: [], contradicting: ['C2 table present'] },
      ],
    },
  },
];

const c = new Client();
await c.start();
await c.init();

const out = [];
for (const call of calls) {
  const t0 = Date.now();
  let resp;
  let err;
  try {
    resp = await c.callTool(call.tool, call.args);
  } catch (e) {
    err = String(e.message || e);
  }
  const elapsed = Date.now() - t0;
  const body = err
    ? `HARNESS_ERROR: ${err}`
    : (resp?.result?.content ?? []).map((x) => x.text || '').join(' ');
  out.push({ ...call, elapsedMs: elapsed, isError: resp?.result?.isError === true, body, structured: resp?.result?.structuredContent ?? null });
  console.log(`\n######## ${call.id} ${call.tool} (${elapsed}ms) isError=${resp?.result?.isError === true}`);
  console.log(body.slice(0, 1800));
  const sc = resp?.result?.structuredContent;
  if (sc?.data) console.log('STRUCT:', JSON.stringify(sc.data).slice(0, 1800));
}

fs.writeFileSync('scripts/_deep-out-2.json', JSON.stringify({ calls: out }, null, 2));
c.child.kill();
process.exit(0);