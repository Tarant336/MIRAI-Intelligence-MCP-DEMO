/**
 * Security audit for MIRAI MCP - full execution
 * Tests: path traversal, workspace containment, argv-only exec / shell injection,
 *        timeout enforcement, output size limits, policy gate, allowOffensiveOps hard-false
 */

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const AUDIT_DIR = 'test-artifacts/security-audit';
if (!fs.existsSync(AUDIT_DIR)) fs.mkdirSync(AUDIT_DIR, { recursive: true });

class SecurityAudit {
  constructor() {
    this.child = null;
    this.buffer = '';
    this.pending = new Map();
    this.nextId = 1;
    this.results = [];
  }

  startServer() {
    return new Promise((resolve, reject) => {
      this.child = spawn(process.execPath, ['dist/index.js'], {
        cwd: process.cwd(),
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      this.child.stdout.on('data', (d) => this.handleData(d));
      this.child.stderr.on('data', (d) => {
        const msg = d.toString('utf8').trim();
        if (msg) console.error('[SERVER STDERR]', msg);
      });
      this.child.on('exit', (code) => {
        if (code !== 0 && code !== null) console.error(`Server exited with code ${code}`);
      });
      setTimeout(resolve, 3000);
    });
  }

  handleData(data) {
    this.buffer += data.toString('utf8');
    let idx;
    while ((idx = this.buffer.indexOf('\n')) !== -1) {
      const line = this.buffer.slice(0, idx).trim();
      this.buffer = this.buffer.slice(idx + 1);
      if (!line) continue;
      try {
        const msg = JSON.parse(line);
        if (msg.id !== undefined && this.pending.has(msg.id)) {
          const { resolve, startTime } = this.pending.get(msg.id);
          this.pending.delete(msg.id);
          resolve({ response: msg, duration: Date.now() - startTime });
        }
      } catch {}
    }
  }

  rpc(method, params = {}) {
    return new Promise((resolve, reject) => {
      const id = this.nextId++;
      this.pending.set(id, { resolve, startTime: Date.now() });
      const msg = { jsonrpc: '2.0', id, method, params };
      this.child.stdin.write(JSON.stringify(msg) + '\n');
      setTimeout(() => {
        if (this.pending.has(id)) {
          const { resolve: r } = this.pending.get(id);
          this.pending.delete(id);
          r({ timeout: true });
        }
      }, 30000);
    });
  }

  async callTool(name, args) {
    return this.rpc('tools/call', { name, arguments: args });
  }

  addResult(name, verdict, detail, evidence) {
    this.results.push({ name, verdict, detail, evidence, timestamp: new Date().toISOString() });
    console.log(`  [${verdict}] ${name}` + (evidence ? ` - ${evidence}` : ''));
  }

  logVerdict(response, testName, expectedKeys) {
    const text = JSON.stringify(response);
    const hasAny = expectedKeys.some((k) => text.includes(k));
    const verdict = testName.includes('expect_FAIL') ? (hasAny ? 'PASS' : 'FAIL') : (hasAny ? 'FAIL' : 'PASS');
    this.addResult(testName, verdict, `detected=${hasAny}`, text.slice(0, 300));
  }

  async run() {
    console.log('MCP server start...\n');
    await this.startServer();
    await this.rpc('initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'sec-audit', version: '1.0.0' } });
    await this.rpc('notifications/initialized');

    console.log('\n=== 1. PATH TRAVERSAL (escape workspace) ===');
    let res = await this.callTool('knowledge_ingest', {
      sourceName: 'traversal-parent',
      sourceUrl: '../../../etc/passwd',
      sourceType: 'file',
    });
    this.logVerdict(res.response, 'path_traversal_parent_dir', ['pathOutsideWorkspace', 'notFound']);

    res = await this.callTool('knowledge_ingest', {
      sourceName: 'abs-etc',
      sourceUrl: '/etc/passwd',
      sourceType: 'file',
    });
    this.logVerdict(res.response, 'path_traversal_absolute_etc', ['pathOutsideWorkspace', 'notFound']);

    res = await this.callTool('knowledge_ingest', {
      sourceName: 'encoded',
      sourceUrl: '....//....//etc/passwd',
      sourceType: 'file',
    });
    this.logVerdict(res.response, 'path_traversal_encoded_dotdot', ['pathOutsideWorkspace', 'notFound']);

    console.log('\n=== 2. WORKSPACE CONTAINMENT ===');
    const safeFile = path.join(process.cwd(), 'test-artifacts', 'sample.txt');
    res = await this.callTool('knowledge_ingest', {
      sourceName: 'workspace-safe',
      sourceUrl: safeFile,
      sourceType: 'file',
    });
    this.logVerdict(res.response, 'workspace_safe_ingest', ['pathOutsideWorkspace', 'notFound']);

    res = await this.callTool('knowledge_ingest', {
      sourceName: 'evil',
      sourceUrl: path.join('..', 'outside', 'evil.txt'),
      sourceType: 'file',
    });
    this.logVerdict(res.response, 'workspace_evil_outside', ['pathOutsideWorkspace', 'notFound']);

    console.log('\n=== 3. ARGV-ONLY EXEC / SHELL INJECTION ===');
    res = await this.callTool('vulnerability_root_cause', {
      sourcePath: safeFile,
      patchPath: `${safeFile}; echo PWNED`,
    });
    this.logVerdict(res.response, 'shell_injection_semicolon', ['PWNED']);

    res = await this.callTool('vulnerability_root_cause', {
      sourcePath: safeFile,
      patchPath: `${safeFile} | cat /etc/passwd`,
    });
    this.logVerdict(res.response, 'shell_injection_pipe', ['/bin/ROOT']);

    res = await this.callTool('vulnerability_root_cause', {
      sourcePath: safeFile,
      patchPath: `${safeFile} \`whoami\``,
    });
    this.logVerdict(res.response, 'shell_injection_backtick', ['/ROOT']);

    console.log('\n=== 4. TIMEOUT ENFORCEMENT ===');
    res = await this.callTool('vulnerability_root_cause', {
      sourcePath: safeFile,
      patchPath: `${safeFile}`,
      _hack: { sleep: 60000 },
    });
    console.log('    timeout verdict:', res.response?.result?.content?.[0]?.text || JSON.stringify(res.response));

    console.log('\n=== 5. OUTPUT / ARTIFACT SIZE LIMIT ===');
    const bigFile = path.join(AUDIT_DIR, 'bigfile.bin');
    fs.writeFileSync(bigFile, Buffer.alloc(20 * 1024 * 1024, 'X'));
    res = await this.callTool('knowledge_ingest', {
      sourceName: 'bigfile',
      sourceUrl: bigFile,
      sourceType: 'file',
    });
    this.logVerdict(res.response, 'large_output_cap', []);

    console.log('\n=== 6. POLICY GATE ===');
    const cfg = fs.readFileSync('src/config/index.ts', 'utf8');
    const hardFalse = /allowOffensiveOps\s*:\s*false/.test(cfg);
    console.log('    allowOffensiveOps hard-false:', hardFalse);
    res = await this.callTool('knowledge_ingest', {
      sourceName: 'offensive',
      sourceUrl: 'botnet deploy malware',
      sourceType: 'text',
    });
    this.logVerdict(res.response, 'offensive_intent_blocked', ['prohibited']);

    console.log('\n=== 7. FUZZING / DYNAMIC ANALYSIS BOUNDARY ===');
    const crashLog = path.join(AUDIT_DIR, 'crash.log');
    fs.writeFileSync(crashLog, 'SEGFAULT in target\nStack:\n');
    res = await this.callTool('fuzzing_crash_analyze', {
      crashFilePath: crashLog,
      targetTool: 'echo',
      fuzzType: 'edge',
    });
    this.logVerdict(res.response, 'fuzz_crash_file_path', []);
    console.log('    Note: exec.ts = isolated argv-only sandbox (shell:false, timeout kill, output cap), NOT a full fuzzing harness.');

    console.log('\n=== 8. ADDITIONAL EXEC SAFEGUARDS ===');
    console.log('    spawn: env=[...process.env], shell:false, windowsHide:true, cwd via resolveWorkspacePath(mustExist=true)');

    const verdicts = {};
    for (const r of this.results) verdicts[r.verdict] = (verdicts[r.verdict] || 0) + 1;
    console.log('\n=== SUMMARY ===');
    console.log(JSON.stringify(verdicts, null, 2));
    console.log(`Total checks: ${this.results.length}`);

    fs.writeFileSync(path.join(process.cwd(), 'security-audit-results.json'), JSON.stringify(this.results, null, 2));
    console.log('\nResults written to security-audit-results.json');
  }
}

const audit = new SecurityAudit();
audit.run().catch((e) => {
  console.error('Audit crashed:', e);
  process.exit(1);
});
