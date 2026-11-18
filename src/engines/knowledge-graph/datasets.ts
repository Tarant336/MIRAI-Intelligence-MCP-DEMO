/**
 * Curated datasets engine (§12).
 *
 * Exposes the hand-reviewed reference module in `src/shared/curated-datasets.ts`
 * as MCP tools: free-text search over the curated entries, ingestion of those
 * entries into the shared knowledge base and evidence graph, and summary
 * statistics. This engine lives in the knowledge-graph directory but is its own,
 * separately registered engine.
 *
 * Defensive posture only: it imports factual intelligence about Mirai-lineage
 * malware, frequently exploited IoT CVEs and public research datasets so that
 * detection, attribution and mitigation work can cite real sources.
 */

import { z } from 'zod';

import { errors } from '../../core/errors.js';
import { defineTool, finish } from '../../tools/helpers.js';
import { provenance } from '../../shared/evidence.js';
import {
  getKnowledgeBase,
  type GraphEdge,
  type GraphNode,
  type KnowledgeCategory,
  type KnowledgeRecord,
} from '../../shared/knowledge-base.js';
import {
  IOT_CVES,
  IOT_DATASETS,
  MIRAI_VARIANTS,
  datasetStats,
  validateCuratedDatasets,
  type IotCveRef,
  type IotMalwareDatasetRef,
  type MiraiVariantRef,
} from '../../shared/curated-datasets.js';
import type { ConfidenceLevel, Provenance } from '../../shared/types.js';
import type { EngineModule } from '../../core/tool.js';

const ENGINE = 'datasets';

/* -------------------------------------------------------------------------- */
/* Relationship knowledge (used when building graph edges).                    */
/* -------------------------------------------------------------------------- */

/**
 * Malware families documented as exploiting a given CVE. Family names match the
 * entries in MIRAI_VARIANTS exactly so they resolve to the same graph nodes.
 */
const CVE_EXPLOITED_BY: Record<string, string[]> = {
  'CVE-2017-17215': ['Satori'],
  'CVE-2018-10561': ['Satori'],
  'CVE-2018-10562': ['Satori'],
  'CVE-2014-8361': ['Mirai', 'Satori'],
  'CVE-2016-10372': ['Mirai'],
  'CVE-2016-6277': ['Mirai'],
  'CVE-2016-20017': ['Satori'],
  'CVE-2020-9054': ['Mukashi'],
};

/** Families documented as derived from the leaked Mirai codebase. */
const FAMILY_DERIVED_FROM_MIRAI = ['Satori', 'Okiru', 'Masuta', 'Wicked', 'Reaper (IoTroop)', 'Mukashi'];

/** Related IoT botnet families that reuse Mirai techniques but are not forks. */
const FAMILY_SIMILAR_TO_MIRAI = ['Mozi', 'Gafgyt (Bashlite)'];

/* -------------------------------------------------------------------------- */
/* Helpers                                                                     */
/* -------------------------------------------------------------------------- */

/** Deterministic, URL-safe slug used to build stable identifiers. */
function slugify(input: string): string {
  return input
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

function variantRecordId(name: string): string {
  return `curated:mirai-variant:${slugify(name)}`;
}
function cveRecordId(cve: string): string {
  return `curated:cve:${cve}`;
}
function datasetRecordId(name: string): string {
  return `curated:dataset:${slugify(name)}`;
}
function variantNodeId(name: string): string {
  return variantRecordId(name);
}

function asConfidence(value: 'confirmed' | 'observed' | 'inferred'): ConfidenceLevel {
  return value;
}

function provenanceFrom(source: { title: string; url: string }, license?: string): Provenance {
  return provenance({
    source: 'curated-dataset',
    url: source.url,
    note: source.title,
    ...(license ? { license } : {}),
  });
}

/* -------------------------------------------------------------------------- */
/* Record / node / edge builders                                               */
/* -------------------------------------------------------------------------- */

function buildVariantRecord(variant: MiraiVariantRef, now: string): KnowledgeRecord {
  return {
    id: variantRecordId(variant.name),
    category: 'mirai_variant',
    title: variant.name,
    identifiers: { mirai_variant: slugify(variant.name) },
    affectedVersions: [],
    fixedVersions: [],
    klass: 'iot-botnet-family',
    rootCause: variant.summary,
    preconditions: [],
    publicExploitState: 'weaponized_in_wild',
    relatedMalwareFamilies: [],
    relatedMiraiVariants: [variant.name],
    relatedRecordIds: [],
    verification: 'unverified',
    confidence: asConfidence(variant.confidence),
    provenance: variant.sources.map((s) => provenanceFrom(s)),
    evidence: [],
    tags: ['curated', 'mirai-variant', slugify(variant.name)],
    createdAt: now,
    updatedAt: now,
  };
}

function buildCveRecord(ref: IotCveRef, now: string): KnowledgeRecord {
  return {
    id: cveRecordId(ref.cve),
    category: 'advisory',
    title: `${ref.cve} — ${ref.vendor} ${ref.product}`,
    identifiers: { cve: ref.cve },
    vendor: ref.vendor,
    product: ref.product,
    affectedVersions: [],
    fixedVersions: [],
    klass: ref.classText,
    rootCause: ref.description,
    preconditions: [],
    publicExploitState: 'weaponized_in_wild',
    relatedMalwareFamilies: CVE_EXPLOITED_BY[ref.cve] ?? [],
    relatedMiraiVariants: CVE_EXPLOITED_BY[ref.cve] ?? [],
    relatedRecordIds: [],
    verification: 'unverified',
    confidence: asConfidence(ref.confidence),
    provenance: ref.sources.map((s) => provenanceFrom(s)),
    evidence: [],
    tags: ['curated', 'advisory', 'iot-cve', ref.cve.toLowerCase()],
    createdAt: now,
    updatedAt: now,
  };
}

function buildDatasetRecord(dataset: IotMalwareDatasetRef, now: string): KnowledgeRecord {
  return {
    id: datasetRecordId(dataset.name),
    category: 'dataset',
    title: dataset.name,
    identifiers: { dataset: slugify(dataset.name) },
    affectedVersions: [],
    fixedVersions: [],
    klass: 'research-dataset',
    rootCause: dataset.description,
    preconditions: [],
    publicExploitState: 'unknown',
    relatedMalwareFamilies: dataset.malwareFamilies,
    relatedMiraiVariants: [],
    relatedRecordIds: [],
    verification: 'unverified',
    confidence: 'confirmed',
    license: dataset.licence,
    provenance: [provenanceFrom({ title: dataset.name, url: dataset.url }, dataset.licence)],
    evidence: [],
    tags: ['curated', 'dataset', slugify(dataset.name), ...dataset.malwareFamilies.map((f) => slugify(f))],
    createdAt: now,
    updatedAt: now,
  };
}

function buildVariantNode(variant: MiraiVariantRef): GraphNode {
  return {
    id: variantNodeId(variant.name),
    kind: 'mirai_variant',
    label: variant.name,
    properties: {
      aliases: variant.aliases,
      firstSeen: variant.firstSeen,
      summary: variant.summary,
      notableTraits: variant.notableTraits,
      sources: variant.sources.map((s) => s.url),
      category: 'curated:mirai_variant',
    },
    provenance: variant.sources.map((s) => provenanceFrom(s)),
    confidence: asConfidence(variant.confidence),
  };
}

function buildCveNode(ref: IotCveRef): GraphNode {
  return {
    id: cveRecordId(ref.cve),
    kind: 'cve',
    label: ref.cve,
    properties: {
      vendor: ref.vendor,
      product: ref.product,
      class: ref.classText,
      description: ref.description,
      sources: ref.sources.map((s) => s.url),
      category: 'curated:advisory',
    },
    provenance: ref.sources.map((s) => provenanceFrom(s)),
    confidence: asConfidence(ref.confidence),
  };
}

function buildDatasetNode(dataset: IotMalwareDatasetRef): GraphNode {
  return {
    id: datasetRecordId(dataset.name),
    kind: 'documentation',
    label: dataset.name,
    properties: {
      url: dataset.url,
      licence: dataset.licence,
      format: dataset.format,
      malwareFamilies: dataset.malwareFamilies,
      archScope: dataset.archScope,
      limitations: dataset.knownLimitations,
      bias: dataset.potentialBias,
      reproducibility: dataset.reproducibility,
      category: 'curated:dataset',
    },
    provenance: [provenanceFrom({ title: dataset.name, url: dataset.url }, dataset.licence)],
    confidence: 'confirmed',
  };
}

function edgeId(from: string, relation: string, to: string): string {
  return `curated:edge:${from}->${relation}->${to}`;
}

/* -------------------------------------------------------------------------- */
/* Search index                                                                */
/* -------------------------------------------------------------------------- */

interface SearchEntry {
  kind: 'mirai_variants' | 'iot_cves' | 'datasets';
  id: string;
  title: string;
  text: string;
  sources: Array<{ title: string; url: string }>;
  confidence: 'confirmed' | 'observed' | 'inferred';
  summary: string;
}

function buildSearchIndex(): SearchEntry[] {
  const entries: SearchEntry[] = [];

  for (const v of MIRAI_VARIANTS) {
    entries.push({
      kind: 'mirai_variants',
      id: variantRecordId(v.name),
      title: v.name,
      text: [v.name, ...v.aliases, v.firstSeen, v.summary, ...v.notableTraits].join(' '),
      sources: v.sources,
      confidence: v.confidence,
      summary: v.summary,
    });
  }

  for (const c of IOT_CVES) {
    entries.push({
      kind: 'iot_cves',
      id: cveRecordId(c.cve),
      title: `${c.cve} — ${c.vendor} ${c.product}`,
      text: [c.cve, c.vendor, c.product, c.classText, c.description].join(' '),
      sources: c.sources,
      confidence: c.confidence,
      summary: c.description,
    });
  }

  for (const d of IOT_DATASETS) {
    entries.push({
      kind: 'datasets',
      id: datasetRecordId(d.name),
      title: d.name,
      text: [d.name, d.description, d.format, ...d.malwareFamilies, ...d.archScope].join(' '),
      sources: [{ title: d.name, url: d.url }],
      confidence: 'confirmed',
      summary: d.description,
    });
  }

  return entries;
}

/* -------------------------------------------------------------------------- */
/* Engine                                                                      */
/* -------------------------------------------------------------------------- */

const KIND_ENUM = z.enum(['mirai_variants', 'iot_cves', 'datasets']);

export const datasetsEngine: EngineModule = {
  name: ENGINE,
  title: 'Curated Datasets',
  description:
    'Hand-reviewed reference intelligence: Mirai-lineage families, frequently exploited IoT/embedded ' +
    'CVEs and public research datasets. Supports free-text search, ingestion into the shared knowledge ' +
    'base and evidence graph, and coverage statistics. Every entry carries source URLs and a declared ' +
    'confidence; no facts are fabricated.',
  tools: [
    defineTool({
      name: 'curated_dataset_search',
      title: 'Search the curated datasets',
      engine: ENGINE,
      description:
        'Free-text search across the curated Mirai variant, IoT CVE and public dataset references. ' +
        'Returns matching entries with their sources and declared confidence. Filter by kind to search ' +
        'only one collection.',
      capabilities: [],
      risk: 'safe',
      inputSchema: {
        kind: KIND_ENUM.optional().describe('Restrict the search to one curated collection.'),
        query: z
          .string()
          .min(1)
          .optional()
          .describe('Free-text query matched against names, aliases, CVE identifiers and descriptions.'),
        limit: z.number().int().min(1).max(100).optional().describe('Maximum number of results (default 25).'),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const i = input as { kind?: SearchEntry['kind']; query?: string; limit?: number };
        const limit = i.limit ?? 25;

        let entries = buildSearchIndex();
        if (i.kind) entries = entries.filter((e) => e.kind === i.kind);

        if (i.query) {
          const tokens = i.query.toLowerCase().split(/\s+/).filter(Boolean);
          const scored = entries
            .map((e) => {
              const haystack = e.text.toLowerCase();
              const score = tokens.reduce((acc, t) => acc + (haystack.includes(t) ? 1 : 0), 0);
              return { entry: e, score };
            })
            .filter((x) => x.score > 0)
            .sort((a, b) => (b.score - a.score) || a.entry.title.localeCompare(b.entry.title));
          entries = scored.map((x) => x.entry);
        }

        const results = entries.slice(0, limit).map((e) => ({
          kind: e.kind,
          id: e.id,
          title: e.title,
          summary: e.summary,
          sources: e.sources,
          confidence: e.confidence,
        }));

        ctx.evidence.add({
          claim: `Curated dataset search returned ${results.length} entr(ies).`,
          provenance: provenance({ source: 'curated-dataset', note: 'search index' }),
          confidence: 'confirmed',
          data: { kind: i.kind ?? 'all', query: i.query ?? null, count: results.length },
        });

        return finish({
          engine: ENGINE,
          tool: 'curated_dataset_search',
          startedAt: started,
          ctx,
          data: { count: results.length, results },
          summary:
            `Found ${results.length} curated entr(ies)` +
            (i.query ? ` matching "${i.query}"` : '') +
            (i.kind ? ` in ${i.kind}` : '') +
            '.',
        });
      },
    }),

    defineTool({
      name: 'curated_dataset_ingest',
      title: 'Ingest curated datasets into the knowledge base',
      engine: ENGINE,
      description:
        'Load curated entries into the shared knowledge base with the correct categories (mirai_variant ' +
        'for families, advisory for CVEs, dataset for datasets), full per-source provenance, licenses ' +
        'where known and the entry\'s declared confidence. Entries are deduplicated by deterministic ' +
        'identifier, and graph nodes plus edges (CVE exploited_by family, family derived_from/similar_to ' +
        'Mirai) are created with provenance and confidence. Use dryRun to preview counts.',
      capabilities: ['write_knowledge'],
      risk: 'local_mutation',
      inputSchema: {
        kind: z
          .enum(['mirai_variants', 'iot_cves', 'datasets', 'all'])
          .describe('Which curated collection(s) to ingest.'),
        dryRun: z.boolean().optional().describe('When true, report counts without writing anything.'),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const i = input as { kind: 'mirai_variants' | 'iot_cves' | 'datasets' | 'all'; dryRun?: boolean };
        const now = new Date().toISOString();
        const includeVariants = i.kind === 'all' || i.kind === 'mirai_variants';
        const includeCves = i.kind === 'all' || i.kind === 'iot_cves';
        const includeDatasets = i.kind === 'all' || i.kind === 'datasets';

        const records: KnowledgeRecord[] = [];
        const nodes = new Map<string, GraphNode>();
        const edges: GraphEdge[] = [];

        const variants = includeVariants ? MIRAI_VARIANTS : [];
        const cves = includeCves ? IOT_CVES : [];
        const datasets = includeDatasets ? IOT_DATASETS : [];

        for (const v of variants) {
          records.push(buildVariantRecord(v, now));
          nodes.set(variantNodeId(v.name), buildVariantNode(v));
        }
        for (const c of cves) {
          records.push(buildCveRecord(c, now));
          nodes.set(cveRecordId(c.cve), buildCveNode(c));
        }
        for (const d of datasets) {
          records.push(buildDatasetRecord(d, now));
          nodes.set(datasetRecordId(d.name), buildDatasetNode(d));
        }

        // Ensure referenced family endpoints exist as nodes so edges resolve.
        const variantByName = new Map(MIRAI_VARIANTS.map((v) => [v.name, v]));
        const ensureVariantNode = (name: string): GraphNode | undefined => {
          const existing = nodes.get(variantNodeId(name));
          if (existing) return existing;
          const ref = variantByName.get(name);
          if (!ref) return undefined;
          const node = buildVariantNode(ref);
          nodes.set(node.id, node);
          return node;
        };

        // CVE -> exploited_by -> malware family.
        for (const c of cves) {
          const families = CVE_EXPLOITED_BY[c.cve] ?? [];
          for (const family of families) {
            const familyNode = ensureVariantNode(family);
            if (!familyNode) continue;
            edges.push({
              id: edgeId(cveRecordId(c.cve), 'exploited_by', familyNode.id),
              from: cveRecordId(c.cve),
              to: familyNode.id,
              relation: 'exploited_by',
              provenance: c.sources.map((s) => provenanceFrom(s)),
              confidence: 'confirmed',
              note: `${c.cve} used by ${family}`,
            });
          }
        }

        // Family -> derived_from / similar_to -> Mirai.
        const miraiNode = ensureVariantNode('Mirai');
        if (miraiNode) {
          for (const name of FAMILY_DERIVED_FROM_MIRAI) {
            const node = ensureVariantNode(name);
            if (!node) continue;
            edges.push({
              id: edgeId(node.id, 'derived_from', miraiNode.id),
              from: node.id,
              to: miraiNode.id,
              relation: 'derived_from',
              provenance: node.provenance,
              confidence: name === 'Reaper (IoTroop)' ? 'inferred' : 'observed',
              note: `${name} derived from the leaked Mirai codebase`,
            });
          }
          for (const name of FAMILY_SIMILAR_TO_MIRAI) {
            const node = ensureVariantNode(name);
            if (!node) continue;
            edges.push({
              id: edgeId(node.id, 'similar_to', miraiNode.id),
              from: node.id,
              to: miraiNode.id,
              relation: 'similar_to',
              provenance: node.provenance,
              confidence: 'observed',
              note: `${name} is a related IoT botnet family that reuses Mirai techniques`,
            });
          }
        }

        const plan = {
          kind: i.kind,
          records: records.length,
          nodes: nodes.size,
          edges: edges.length,
          byCategory: {
            mirai_variant: records.filter((r) => r.category === 'mirai_variant').length,
            advisory: records.filter((r) => r.category === 'advisory').length,
            dataset: records.filter((r) => r.category === 'dataset').length,
          } satisfies Record<string, number>,
        };

        if (i.dryRun) {
          return finish({
            engine: ENGINE,
            tool: 'curated_dataset_ingest',
            startedAt: started,
            ctx,
            data: { dryRun: true, created: 0, updated: 0, ...plan },
            summary:
              `Dry run (kind=${i.kind}): would ingest ${plan.records} record(s), ${plan.nodes} node(s) ` +
              `and ${plan.edges} edge(s).`,
          });
        }

        const kb = getKnowledgeBase();
        let created = 0;
        let updated = 0;
        for (const record of records) {
          const existed = Boolean(kb.getRecord(record.id));
          kb.upsertRecord(record);
          if (existed) updated += 1;
          else created += 1;
          ctx.evidence.add({
            claim: `Ingested curated ${record.category} record "${record.title}".`,
            provenance: record.provenance[0] ?? provenance({ source: 'curated-dataset' }),
            confidence: record.confidence,
            data: { recordId: record.id, category: record.category },
          });
        }
        for (const node of nodes.values()) kb.upsertNode(node);
        for (const edge of edges) kb.upsertEdge(edge);
        kb.flush();

        ctx.evidence.assert({
          statement:
            `Curated dataset ingestion (kind=${i.kind}) wrote ${created} new and updated ${updated} ` +
            `knowledge record(s), ${nodes.size} graph node(s) and ${edges.length} edge(s).`,
          status: 'direct_observation',
          confidence: 'confirmed',
          producedBy: 'curated_dataset_ingest',
        });

        return finish({
          engine: ENGINE,
          tool: 'curated_dataset_ingest',
          startedAt: started,
          ctx,
          data: { dryRun: false, created, updated, ...plan },
          summary:
            `Ingested curated datasets (kind=${i.kind}): ${created} created, ${updated} updated, ` +
            `${nodes.size} node(s), ${edges.length} edge(s).`,
        });
      },
    }),

    defineTool({
      name: 'curated_dataset_stats',
      title: 'Curated dataset coverage statistics',
      engine: ENGINE,
      description:
        'Return the size of the curated dataset module (variants, CVEs, datasets) alongside how many ' +
        'of those entries are currently ingested in the shared knowledge base and graph.',
      capabilities: [],
      risk: 'safe',
      inputSchema: {},
      handler: async (_input, ctx) => {
        const started = Date.now();
        const kb = getKnowledgeBase();
        const curated = kb.searchRecords({ tags: ['curated'], limit: 1000 });
        const stats = datasetStats();
        // Report (never auto-repair) any schema or cross-field inconsistency in
        // the curated module so drift surfaces in results instead of silently
        // propagating (§P2.2).
        const validation = validateCuratedDatasets();
        const ingested = {
          variants: curated.filter((r) => r.category === 'mirai_variant').length,
          cves: curated.filter((r) => r.category === 'advisory').length,
          datasets: curated.filter((r) => r.category === 'dataset').length,
        };
        const kbStats = kb.stats();
        const data = {
          curated: stats,
          ingested,
          coverage: {
            variants: stats.variants ? Number((ingested.variants / stats.variants).toFixed(3)) : 0,
            cves: stats.cves ? Number((ingested.cves / stats.cves).toFixed(3)) : 0,
            datasets: stats.datasets ? Number((ingested.datasets / stats.datasets).toFixed(3)) : 0,
          },
          knowledgeBase: {
            records: kbStats.records,
            nodes: kbStats.nodes,
            edges: kbStats.edges,
          },
          validation: { ok: validation.ok, issues: validation.issues },
        };
        return finish({
          engine: ENGINE,
          tool: 'curated_dataset_stats',
          startedAt: started,
          ctx,
          data,
          summary:
            `Curated: ${stats.variants} variants, ${stats.cves} CVEs, ${stats.datasets} datasets. ` +
            `Ingested: ${ingested.variants}/${stats.variants} variants, ${ingested.cves}/${stats.cves} ` +
            `CVEs, ${ingested.datasets}/${stats.datasets} datasets. ` +
            `Consistency: ${validation.ok ? 'ok' : `${validation.issues.length} issue(s)`}.`,
        });
      },
    }),
  ],
};
