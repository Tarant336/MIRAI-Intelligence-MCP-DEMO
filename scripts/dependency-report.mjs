/**
 * External dependency preflight (§6 / §9).
 *
 * Reports the status of every external analysis dependency the platform can
 * leverage, so CI records exactly which integrations are AVAILABLE and which
 * are BLOCKED because a tool is not installed. This is read-only: it never
 * installs or downloads anything, and it never fails the build — the tests
 * that do not need an external dependency must still run.
 *
 * Usage: node scripts/dependency-report.mjs
 * Writes: scripts/_dependency-report.json (full probe results)
 */
import fs from 'node:fs';

import { probeDependencies, summarizeDependencies } from '../dist/core/dependencies.js';

const probes = await probeDependencies();
const summary = summarizeDependencies(probes);
console.log(summary);

const blocked = probes.filter((p) => p.status !== 'AVAILABLE' && p.status !== 'NOT_REQUIRED');
console.log(
  blocked.length
    ? `\nBLOCKED (dependency required but unavailable): ${blocked.map((p) => `${p.id}[${p.status}]`).join(', ')}`
    : '\nNo blocking dependencies.',
);

fs.writeFileSync('scripts/_dependency-report.json', JSON.stringify({ probes }, null, 2));

const stepSummary = process.env.GITHUB_STEP_SUMMARY;
if (stepSummary) {
  const rows = probes
    .map((p) => `| ${p.id} | ${p.status} | ${p.version ?? '—'} | ${p.executable ?? '—'} |`)
    .join('\n');
  fs.appendFileSync(
    stepSummary,
    `\n### Dependency diagnostics (§6)\n\n| dependency | status | version | executable |\n|---|---|---|---|\n${rows}\n`,
  );
}

process.exit(0);
