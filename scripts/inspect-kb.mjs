import fs from 'node:fs';

const p = 'C:\\Users\\sida\\.mirai-mcp\\knowledge\\knowledge.json';
const raw = fs.readFileSync(p, 'utf8');
const data = JSON.parse(raw);
const node = data.nodes['vuln-hyp:test-test-test'];
const prov = node.provenance;
console.log('typeof provenance', typeof prov, Array.isArray(prov), 'len', Array.isArray(prov) ? prov.length : 'n/a');
if (Array.isArray(prov)) {
  const sizes = prov.map((x, i) => ({ i, size: JSON.stringify(x).length, keys: Object.keys(x ?? {}) }));
  console.log('first', JSON.stringify(prov[0]).slice(0, 300));
  console.log('last ', JSON.stringify(prov[prov.length - 1]).slice(0, 300));
  const big = sizes.filter(s => s.size > 1000);
  console.log('entries >1KB:', big.length, big.slice(0, 5));
  const uniq = new Map();
  for (const x of prov) {
    const k = JSON.stringify(x).slice(0, 200);
    uniq.set(k, (uniq.get(k) ?? 0) + 1);
  }
  const top = [...uniq.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3);
  console.log('top duplicate patterns:', top.map(([k, c]) => ({ count: c, sample: k.slice(0, 150) })));
}