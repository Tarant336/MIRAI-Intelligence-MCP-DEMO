import { spawn } from 'node:child_process';
import fs from 'node:fs';

const child = spawn(process.execPath, ['dist/index.js'], { stdio: ['pipe', 'pipe', 'pipe'] });
let buf = '';
const pending = new Map();
let nextId = 1;

child.stdout.on('data', (d) => {
  buf += d.toString('utf8');
  let idx;
  while ((idx = buf.indexOf('\n')) !== -1) {
    const line = buf.slice(0, idx).trim();
    buf = buf.slice(idx + 1);
    if (!line) continue;
    const msg = JSON.parse(line);
    if (msg.id !== undefined && pending.has(msg.id)) {
      const { resolve } = pending.get(msg.id);
      pending.delete(msg.id);
      resolve(msg);
    }
  }
});
child.stderr.on('data', (d) => process.stderr.write(d));

try {
  const init = new Promise((resolve) => {
    const id = nextId++;
    pending.set(id, { resolve });
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'dump', version: '1.0' } } }) + '\n');
    setTimeout(resolve, 2000);
  });
  await init;
  await new Promise((r) => setTimeout(r, 200));
  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: nextId++, method: 'notifications/initialized', params: {} }) + '\n');

  const list = new Promise((resolve) => {
    const id = nextId++;
    pending.set(id, { resolve });
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/list', params: {} }) + '\n');
    setTimeout(() => resolve({ timeout: true }), 10000);
  });
  const msg = await list;
  const tools = msg.result?.tools?.map((t) => t.name) || [];
  console.log('Total tools:', tools.length);
  fs.writeFileSync('data/tool-list.txt', tools.join('\n'));
  console.log('Wrote', tools.length, 'tool names to data/tool-list.txt');
} catch (e) {
  console.error(e);
} finally {
  child.kill();
}
