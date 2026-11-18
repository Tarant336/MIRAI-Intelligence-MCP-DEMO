import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';

const child = spawn(process.execPath, ['dist/index.js'], { stdio: ['pipe', 'pipe', 'pipe'] });
const rl = createInterface({ input: child.stdout });

let buf = '';
send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'x', version: '1' } } });

function send(obj) {
  child.stdin.write(JSON.stringify(obj) + '\n');
}

rl.on('line', (line) => {
  buf += line;
  let msg;
  try { msg = JSON.parse(line); } catch { return; }
  if (msg.id === 1) {
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
    send({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
  } else if (msg.id === 2) {
    const t = msg.result.tools.find((x) => x.name === 'patch_root_cause_analyze');
    console.log(JSON.stringify(t.inputSchema, null, 1));
    child.kill();
    process.exit(0);
  }
});