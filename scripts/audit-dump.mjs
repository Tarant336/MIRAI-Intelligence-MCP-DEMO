// Dump full MCP handshake + tools/prompts/resources to a JSON file for analysis.
import { spawn } from 'node:child_process';
import { writeFileSync } from 'node:fs';

const child = spawn(process.execPath, ['dist/index.js'], {
  cwd: process.cwd(),
  stdio: ['pipe', 'pipe', 'pipe'],
});

let buffer = '';
const responses = [];
child.stdout.on('data', (d) => {
  buffer += d.toString('utf8');
  let idx;
  while ((idx = buffer.indexOf('\n')) !== -1) {
    const line = buffer.slice(0, idx).trim();
    buffer = buffer.slice(idx + 1);
    if (line) {
      try {
        responses.push(JSON.parse(line));
      } catch {
        console.error('NON-JSON STDOUT:', line);
      }
    }
  }
});
let stderr = '';
child.stderr.on('data', (d) => { stderr += d.toString('utf8'); });

const send = (msg) => child.stdin.write(`${JSON.stringify(msg)}\n`);

send({
  jsonrpc: '2.0', id: 1, method: 'initialize',
  params: {
    protocolVersion: '2024-11-05',
    capabilities: {},
    clientInfo: { name: 'audit-dump', version: '1.0.0' },
  },
});

setTimeout(() => send({ jsonrpc: '2.0', method: 'notifications/initialized' }), 300);
setTimeout(() => send({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }), 500);
setTimeout(() => send({ jsonrpc: '2.0', id: 3, method: 'prompts/list', params: {} }), 700);
setTimeout(() => send({ jsonrpc: '2.0', id: 4, method: 'resources/list', params: {} }), 900);
setTimeout(() => send({ jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'health_check', arguments: {} } }), 1200);
setTimeout(() => send({ jsonrpc: '2.0', id: 6, method: 'tools/call', params: { name: 'environment_report', arguments: {} } }), 1600);

setTimeout(() => {
  const out = {
    init: responses.find((r) => r.id === 1),
    tools: responses.find((r) => r.id === 2),
    prompts: responses.find((r) => r.id === 3),
    resources: responses.find((r) => r.id === 4),
    health_check: responses.find((r) => r.id === 5),
    environment_report: responses.find((r) => r.id === 6),
    stderr,
  };
  writeFileSync('data/audit-dump.json', JSON.stringify(out, null, 2), 'utf8');
  console.log('wrote data/audit-dump.json');
  child.kill();
  process.exit(0);
}, 4000);
