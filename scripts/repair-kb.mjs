import fs from 'node:fs';
import path from 'node:path';

const p = 'C:\\Users\\sida\\.mirai-mcp\\knowledge\\knowledge.json';
const backup = `${p}.corrupt.bak`;

const raw = fs.readFileSync(p, 'utf8');
const data = JSON.parse(raw);

function dedupe(list) {
  if (!Array.isArray(list)) return list;
  const seen = new Set();
  const out = [];
  for (const e of list) {
    const k = JSON.stringify(e);
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(e);
  }
  return out;
}

let before = 0;
let after = 0;
for (const node of Object.values(data.nodes ?? {})) {
  const prev = node.provenance;
  if (!Array.isArray(prev)) continue;
  before += prev.length;
  node.provenance = dedupe(prev);
  after += node.provenance.length;
}
for (const rec of Object.values(data.records ?? {})) {
  const prev = rec.provenance;
  if (!Array.isArray(prev)) continue;
  before += prev.length;
  rec.provenance = dedupe(prev);
  after += rec.provenance.length;
}

const out = JSON.stringify(data);
const tmp = `${p}.tmp`;
fs.renameSync(p, backup);
fs.writeFileSync(tmp, out);
fs.renameSync(tmp, p);

console.log('provenance entries:', before, '->', after);
console.log('new size', fs.statSync(p).size, 'backup', fs.statSync(backup).size);