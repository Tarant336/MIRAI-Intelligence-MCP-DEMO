/**
 * Regression tests for the curated CVE/advisory dataset and knowledge-store
 * isolation (§P2.2).
 *
 * Covers:
 *   - schema + cross-field consistency validation of every curated record,
 *   - the detection of silently "drifted" rows (the Log4j mislabelled as a
 *     siemens product bug) — reported, never auto-repaired,
 *   - in-progress checkpoint notes are excluded from research results,
 *   - the test run writes to an isolated data directory, not the user's store.
 */

import { beforeAll, describe, expect, it } from 'vitest';

import { buildRegistry } from '../src/index.js';
import { createLogger } from '../src/core/logger.js';
import { EvidenceCollector } from '../src/shared/evidence.js';
import { getConfig } from '../src/config/index.js';
import { getKnowledgeBase } from '../src/shared/knowledge-base.js';
import {
  IOT_CVES,
  IOT_DATASETS,
  MIRAI_VARIANTS,
  cveConsistencyIssues,
  iotCveRefSchema,
  validateCuratedDatasets,
  type IotCveRef,
} from '../src/shared/curated-datasets.js';
import type { ToolContext } from '../src/core/tool.js';

function makeCtx(tool: string): ToolContext {
  return {
    logger: createLogger({ test: true, tool }),
    knowledge: getKnowledgeBase(),
    evidence: new EvidenceCollector(),
  };
}

let registry: ReturnType<typeof buildRegistry>;

beforeAll(() => {
  registry = buildRegistry();
});

async function invoke(name: string, input: Record<string, unknown> = {}) {
  const entry = registry.get(name);
  if (!entry) throw new Error(`Tool ${name} not registered`);
  return entry.def.handler(input, makeCtx(name));
}

describe('curated dataset schema validation', () => {
  it('every curated record satisfies its schema and is mutually consistent', () => {
    const result = validateCuratedDatasets();
    // Surface the offending rows if this ever regresses.
    expect(result.issues, JSON.stringify(result.issues, null, 2)).toEqual([]);
    expect(result.ok).toBe(true);
    expect(result.counts).toEqual({
      variants: MIRAI_VARIANTS.length,
      cves: IOT_CVES.length,
      datasets: IOT_DATASETS.length,
    });
  });

  it('CVE identifiers are unique and well formed, with primary provenance', () => {
    const seen = new Set<string>();
    for (const ref of IOT_CVES) {
      expect(ref.cve, ref.cve).toMatch(/^CVE-\d{4}-\d{4,}$/);
      expect(seen.has(ref.cve), `duplicate ${ref.cve}`).toBe(false);
      seen.add(ref.cve);
      expect(ref.sources.length, `${ref.cve} must cite at least one source`).toBeGreaterThan(0);
      expect(ref.sources.some((s) => /^https:\/\//.test(s.url)), ref.cve).toBe(true);
    }
  });

  it('rejects a malformed record at the schema layer', () => {
    const malformed = { ...IOT_CVES[0], cve: 'CVE-17-17215', sources: [] };
    expect(iotCveRefSchema.safeParse(malformed).success).toBe(false);
  });

  it('accepts every curated CVE row against the schema', () => {
    for (const ref of IOT_CVES) {
      const parsed = iotCveRefSchema.safeParse(ref);
      expect(parsed.success, `${ref.cve}: ${JSON.stringify(parsed)}`).toBe(true);
    }
  });
});

describe('CVE cross-field consistency', () => {
  it('passes for the reviewed curated rows', () => {
    IOT_CVES.forEach((ref, index) => {
      expect(cveConsistencyIssues(ref, index), ref.cve).toEqual([]);
    });
  });

  it('flags a Log4j row whose vendor/product/CWE drift from the narrative', () => {
    // Mirrors the mislabelled record: Log4j content but a Siemens/6bk1602
    // attribution and a raw CWE id in the class field. Must be REPORTED, not
    // silently repaired.
    const drifted: IotCveRef = {
      cve: 'CVE-2021-44228',
      vendor: 'siemens',
      product: '6bk1602 firmware',
      classText: 'CWE-20',
      description:
        'Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not ' +
        'protect against attacker-controlled LDAP and other JNDI related endpoints, allowing remote ' +
        'code execution.',
      sources: [
        { title: 'NVD — CVE-2021-44228', url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228' },
      ],
      confidence: 'observed',
    };

    const issues = cveConsistencyIssues(drifted);
    const fields = issues.map((i) => i.field);
    expect(fields).toContain('classText');
    expect(fields).toContain('description');
    expect(issues.some((i) => /not a documented vulnerability class/.test(i.message))).toBe(true);
    expect(issues.some((i) => /contains an identifier/.test(i.message))).toBe(true);
    expect(issues.some((i) => /names neither vendor/.test(i.message))).toBe(true);
  });

  it('does not flag the correctly attributed Apache Log4j record', () => {
    const correct: IotCveRef = {
      cve: 'CVE-2021-44228',
      vendor: 'Apache',
      product: 'Log4j2',
      classText: 'remote-code-execution',
      description: 'Apache Log4j2 allows remote code execution via JNDI lookups in log messages.',
      sources: [
        { title: 'NVD — CVE-2021-44228', url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228' },
      ],
      confidence: 'confirmed',
    };
    expect(cveConsistencyIssues(correct)).toEqual([]);
  });
});

describe('curated_dataset_stats reports dataset health', () => {
  it('surfaces the validation result of the curated module', async () => {
    const res = await invoke('curated_dataset_stats');
    expect(res.ok).toBe(true);
    const data = res.data as { validation: { ok: boolean; issues: unknown[] } };
    expect(data.validation.ok).toBe(true);
    expect(data.validation.issues).toEqual([]);
  });
});

describe('checkpoint notes are excluded from research results', () => {
  it('a research checkpoint never appears in lifecycle stage search output', async () => {
    const marker = 'lifecycleprobe';
    const created = await invoke('research_checkpoint', {
      taskTitle: marker,
      established: ['probe'],
      missingEvidence: ['none'],
    });
    expect(created.ok).toBe(true);

    // Sanity: the raw store *does* contain the checkpoint, so the exclusion in
    // the research tool is what keeps it out — not a missing match.
    const raw = getKnowledgeBase().searchRecords({ text: marker });
    expect(raw.some((r) => r.title.includes(marker))).toBe(true);

    const res = await invoke('botnet_lifecycle_stage_search', { text: marker });
    expect(res.ok).toBe(true);
    const records = (res.data as { records: Array<{ title: string; tags?: string[] }> }).records;
    expect(records.some((r) => r.title.includes(marker))).toBe(false);
    expect(records.some((r) => (r.tags ?? []).includes('checkpoint'))).toBe(false);
  });
});

describe('test isolation', () => {
  it('persists knowledge to an isolated test directory, not the user store', () => {
    const configured = getConfig().dataDir;
    expect(process.env.MIRAI_DATA_DIR).toBeTruthy();
    expect(configured).toBe(process.env.MIRAI_DATA_DIR);
  });
});
