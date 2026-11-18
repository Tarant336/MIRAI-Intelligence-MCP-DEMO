/**
 * MIRAI Deep Functional Validation harness (read-only, evidence collection).
 *
 * Spawns the built server over stdio, performs a real MCP handshake, and invokes
 * a curated set of tools against the *real* test-artifacts/ fixtures whose ground
 * truth is known. Dumps full raw outputs to scripts/_deep-out.json for inspection.
 *
 * This harness NEVER modifies production code, never fabricates credentials, and
 * never executes malware. It only observes what the tools actually do.
 *
 * Usage:
 *   node scripts/deep-validate.mjs schemas   # dump all tool input schemas
 *   node scripts/deep-validate.mjs run       # run curated validation calls
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const MODE = process.argv[2] || 'run';
const TOOL_TIMEOUT = 60000;
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
      this.child = spawn(process.execPath, ['dist/index.js'], {
        cwd: process.cwd(),
        stdio: ['pipe', 'pipe', 'pipe'],
      });
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
      try { msg = JSON.parse(line); } catch { continue; }
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
    const r = await this.request('initialize', {
      protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'deep-validate', version: '1.0.0' },
    });
    this.child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`);
    return r;
  }
  callTool(name, args) {
    return this.request('tools/call', { name, arguments: args });
  }
}

const c = new Client();
await c.start();
const init = await c.init();

if (MODE === 'schemas') {
  const list = await c.request('tools/list', {});
  const out = {};
  for (const t of list.result.tools) out[t.name] = t.inputSchema;
  fs.writeFileSync('scripts/_tool-schemas.json', JSON.stringify(out, null, 2));
  console.log(`wrote ${Object.keys(out).length} schemas`);
  c.child.kill();
  process.exit(0);
}

// ---- curated validation calls (§3-§8) --------------------------------
const A = 'test-artifacts';
const calls = [
  // §3 Mirai botnet intelligence (real ELF / telemetry / pcap fixtures)
  { id: 'mirai-01', tool: 'malware_sample_analyze', args: { filePath: `${A}/sample.elf` } },
  { id: 'mirai-02', tool: 'binary_similarity', args: { fileA: `${A}/sample.elf`, fileB: `${A}/sample.elf` } },
  { id: 'mirai-03', tool: 'honeypot_telemetry_analyze', args: { telemetryPath: `${A}/telemetry.log`, format: 'log' } },
  { id: 'mirai-04', tool: 'mirai_variant_analyze', args: { reference: 'mirai', filePath: `${A}/sample.elf` } },
  { id: 'mirai-05', tool: 'c2_protocol_analyze', args: { pcapPath: `${A}/sample.pcap` } },
  { id: 'mirai-06', tool: 'malware_behavior_report', args: { filePath: `${A}/sample.elf` } },
  { id: 'mirai-07', tool: 'botnet_lifecycle_stage_search', args: { stage: 'scanner' } },
  { id: 'mirai-08', tool: 'malware_family_compare', args: { samplesOrRefs: [{ name: 'a', filePath: `${A}/sample.elf`, family: 'mirai' }] } },
  { id: 'mirai-09', tool: 'malware_source_analyze', args: { path: `${A}/sample-repo` } },

  // §4 zero-day research
  { id: 'zd-01', tool: 'static_analysis_run', args: { directoryPath: `${A}/sample-repo` } },
  { id: 'zd-02', tool: 'zero_day_discovery_analyze', args: { directoryPath: `${A}/sample-repo` } },
  { id: 'zd-03', tool: 'vulnerability_hypothesis_generate', args: { component: 'http parser', vulnerabilityClass: 'buffer-overflow' } },
  { id: 'zd-04', tool: 'source_vulnerability_analyze', args: { filePath: `${A}/sample-repo/src/index.ts` } },
  { id: 'zd-05', tool: 'patch_root_cause_analyze', args: { vulnerableFilePath: `${A}/sample-repo/src/index.ts`, patchedFilePath: `${A}/sample-repo/src/index.ts` } },
  { id: 'zd-06', tool: 'vulnerability_variant_hunt', args: { pattern: 'outputPath', directoryPath: `${A}/sample-repo`, patternType: 'literal' } },
  { id: 'zd-07', tool: 'safe_validation_generate', args: { outputPath: `${A}/_safe_validation_test.py`, vulnClass: 'command-injection', targetDescription: 'local http parser under test' } },
  { id: 'zd-08', tool: 'binary_vulnerability_analyze', args: { filePath: `${A}/sample.elf` } },

  // §5 fuzzing & crash analysis
  { id: 'fuzz-01', tool: 'fuzz_target_identify', args: { directoryPath: `${A}/sample-repo` } },
  { id: 'fuzz-02', tool: 'fuzz_harness_generate', args: { targetName: 'parse_input', language: 'c', framework: 'libfuzzer' } },
  { id: 'fuzz-03', tool: 'fuzzing_crash_analyze', args: { signal: 'SIGSEGV', faultAddress: '0x7f', backtrace: ['vulnerable_function at vulnerable.c:42', 'parse_input at parser.c:128', 'main at main.c:15'] } },
  { id: 'fuzz-04', tool: 'fuzzing_crash_analyze', args: { crashReportPath: `${A}/crash.log` } },
  { id: 'fuzz-05', tool: 'crash_root_cause_analyze', args: { filePath: `${A}/sample-repo/src/index.ts`, backtrace: ['vulnerable_function at vulnerable.c:42'] } },

  // §6 binary & firmware intelligence
  { id: 'fw-01', tool: 'elf_analyze', args: { filePath: `${A}/sample.elf` } },
  { id: 'fw-02', tool: 'firmware_analyze', args: { filePath: `${A}/sample_firmware.bin` } },
  { id: 'fw-03', tool: 'firmware_extract', args: { filePath: `${A}/sample_firmware_fs.cpio`, outputDir: `${A}/_extract_out` } },
  { id: 'fw-04', tool: 'firmware_filesystem_analyze', args: { path: `${A}/sample_firmware_fs.tar` } },
  { id: 'fw-05', tool: 'firmware_component_scan', args: { path: `${A}/sample_firmware.bin` } },
  { id: 'fw-06', tool: 'emulation_plan', args: { filePath: `${A}/sample_firmware.bin`, arch: 'arm', goal: 'observe default services' } },
  { id: 'fw-07', tool: 'firmware_patch_diff', args: { beforePath: `${A}/sample_firmware.bin`, afterPath: `${A}/sample_firmware_v2.bin` } },
  { id: 'fw-08', tool: 'firmware_integrity_check', args: { filePath: `${A}/sample_firmware.bin` } },
  // Malformed cpio must be rejected, never turned into fabricated entries.
  { id: 'fw-09', tool: 'firmware_filesystem_analyze', args: { path: `${A}/sample_firmware_fs.cpio` } },

  // §6b network forensics (real pcap fixture)
  { id: 'net-01', tool: 'pcap_flow_analyze', args: { pcapPath: `${A}/sample.pcap` } },
  { id: 'net-02', tool: 'ioc_extract', args: { pcapPath: `${A}/sample.pcap` } },

  // §7 exploit intelligence
  { id: 'exp-01', tool: 'cwe_search', args: { keyword: 'buffer overflow' } },
  { id: 'exp-02', tool: 'advisory_search', args: { query: 'log4j' } },
  { id: 'exp-03', tool: 'exploit_reference_search', args: { query: 'log4j' } },
  { id: 'exp-04', tool: 'patch_diff_analyze', args: { beforePath: `${A}/sample-repo/src/index.ts`, afterPath: `${A}/sample-repo/src/index.ts` } },
  { id: 'exp-05', tool: 'vulnerability_root_cause', args: { sourcePath: `${A}/sample-repo/src/index.ts`, cveId: 'CVE-2021-44228' } },
  { id: 'exp-06', tool: 'curated_dataset_stats', args: {} },
  { id: 'exp-07', tool: 'curated_dataset_ingest', args: { kind: 'mirai_variants', dryRun: true } },
  { id: 'exp-08', tool: 'curated_dataset_search', args: { query: 'mirai' } },

  // §8 multi-agent (deliberately contradictory findings)
  { id: 'ma-01', tool: 'agent_roles_list', args: {} },
  { id: 'ma-02', tool: 'orchestrator_plan', args: { task: 'Analyze a suspicious ELF sample for Mirai botnet indicators and produce a threat report' } },
  {
    id: 'ma-03', tool: 'agent_findings_merge', args: {
      findings: [
        { roleId: 'malware-analyst', statement: 'The sample is Mirai family.', evidence: ['C2 table strings'], confidence: 'confirmed' },
        { roleId: 'firmware-analyst', statement: 'The sample is Gafgyt, not Mirai.', evidence: ['different attack module strings'], confidence: 'confirmed' },
      ],
    },
  },
  {
    id: 'ma-04', tool: 'evidence_reconciliation', args: {
      topic: 'sample family attribution',
      assertions: [
        { statement: 'The sample is Mirai.', status: 'verified_fact', confidence: 'confirmed', supporting: ['C2 table strings'], contradicting: ['attack module mismatch'] },
        { statement: 'The sample is Gafgyt.', status: 'verified_fact', confidence: 'confirmed', supporting: ['gafgyt module names'], contradicting: ['C2 table present'] },
      ],
    },
  },
  { id: 'ma-05', tool: 'missing_evidence_identify', args: { topic: 'sample family attribution', established: ['binary is ELF x86-64'] } },
  { id: 'ma-06', tool: 'research_audit', args: { topic: 'mirai' } },

  // §9 skills
  { id: 'sk-01', tool: 'skill_list', args: {} },
  { id: 'sk-02', tool: 'skill_get', args: { name: 'mirai-botnet-lineage-analysis' } },
  { id: 'sk-03', tool: 'skill_select', args: { task: 'analyze a Mirai malware sample and compare variants' } },
];

const results = { init: init.result?.serverInfo, calls: [] };
for (const spec of calls) {
  const t0 = Date.now();
  try {
    const r = await c.callTool(spec.tool, spec.args);
    results.calls.push({ id: spec.id, tool: spec.tool, args: spec.args, ms: Date.now() - t0, response: r });
  } catch (e) {
    results.calls.push({ id: spec.id, tool: spec.tool, args: spec.args, ms: Date.now() - t0, error: String(e) });
  }
}

fs.writeFileSync('scripts/_deep-out.json', JSON.stringify(results, null, 2));
console.log(`ran ${results.calls.length} calls -> scripts/_deep-out.json`);
c.child.kill();
process.exit(0);
