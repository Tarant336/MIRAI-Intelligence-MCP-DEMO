// Read-only validation of the skills library against the live registry.
// Usage: node scripts/validate-skills.mjs
import { loadSkills } from '../dist/skills/loader.js';
import { buildRegistry, ENGINES } from '../dist/index.js';

const registry = buildRegistry();
const toolNames = new Set(registry.list().map((t) => t.descriptor.name));
const engineIds = new Set(ENGINES.map((e) => e.name));

const load = loadSkills();
const out = {
  root: load.root,
  count: load.skills.length,
  errors: load.errors,
  engineIds: [...engineIds],
  toolCount: toolNames.size,
  skills: [],
};

const seen = new Map();
for (const s of load.skills) {
  if (seen.has(s.name)) out.errors.push({ path: s.path, message: `duplicate name ${s.name}` });
  seen.set(s.name, s.path);

  const unknownEngines = s.engines.filter((e) => !engineIds.has(e));
  const unknownTools = s.tools.filter((t) => !toolNames.has(t));
  const backticks = [...s.body.matchAll(/`([a-z][a-z0-9_]{2,63})`/g)].map((m) => m[1]);
  // Only treat identifiers that look like tool names (contain underscore) as tool claims.
  const btCandidates = [...new Set(backticks)].filter((x) => x.includes('_'));
  const btUnknown = btCandidates.filter((x) => !toolNames.has(x));

  const sections = ['Purpose', 'Procedure', 'Verification criteria'].filter(
    (h) => !new RegExp(`^##\\s+${h}`, 'mi').test(s.body),
  );

  out.skills.push({
    name: s.name,
    path: s.path,
    version: s.version,
    engines: s.engines,
    tools: s.tools.length,
    unknownEngines,
    unknownTools,
    btUnknown,
    missingSections: sections,
    bytes: s.bytes,
  });
}

console.log(JSON.stringify(out, null, 2));

const bad = out.skills.filter(
  (s) => s.unknownEngines.length || s.unknownTools.length || s.btUnknown.length || s.missingSections.length,
);
console.error(
  `\nSUMMARY: ${out.count} skills, ${out.errors.length} load errors, ${bad.length} skills with reference issues`,
);
for (const s of bad) {
  console.error(
    ` - ${s.name}: engines?[${s.unknownEngines}] tools?[${s.unknownTools}] bodyTools?[${s.btUnknown}] missing[${s.missingSections}]`,
  );
}

// `--strict` turns the report into a quality gate: any load error or dangling
// engine/tool reference fails the run. Used by CI (§9).
if (process.argv.includes('--strict') && (out.errors.length > 0 || bad.length > 0)) {
  console.error('\nSTRICT: skill validation failed.');
  process.exit(1);
}