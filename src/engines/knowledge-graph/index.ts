/**
 * Knowledge & Evidence engine (§11 "Tri thức và Bằng chứng", §7).
 *
 * Provides the shared knowledge base and evidence graph operations that all
 * other engines write into and read from.
 */

import { randomUUID } from 'node:crypto';

import { z } from 'zod';

import { errors } from '../../core/errors.js';
import { logger } from '../../core/logger.js';
import { defineTool, finish, zodCommon } from '../../tools/helpers.js';
import { provenance } from '../../shared/evidence.js';
import { getKnowledgeBase, type KnowledgeCategory, type KnowledgeRecord, type GraphNodeKind, type GraphRelation } from '../../shared/knowledge-base.js';
import { requirePolicy } from '../../shared/security.js';
import type { EngineModule } from '../../core/tool.js';

const ENGINE = 'knowledge-and-evidence';

const CATEGORY_ENUM = z.enum([
  'advisory',
  'detection_template',
  'fingerprint_template',
  'exploit_poc',
  'exploit_module',
  'malware_sample_ref',
  'yara_rule',
  'sigma_rule',
  'network_detection_rule',
  'remediation_guidance',
  'patch_reference',
  'research_paper',
  'attack_method',
  'defense_technology',
  'dataset',
  'firmware_component',
  'malware_family',
  'mirai_variant',
  'c2_protocol_spec',
  'vulnerability_hypothesis',
  'zero_day_finding',
  'crash_triage',
  'fuzz_target',
]);

const NODE_KIND_ENUM = z.enum([
  'repository',
  'source_file',
  'function',
  'dependency',
  'documentation',
  'cve',
  'cwe',
  'vendor',
  'product',
  'firmware_version',
  'malware_family',
  'mirai_variant',
  'binary_sample',
  'attack_method',
  'pcap_evidence',
  'c2_indicator',
  'detection_rule',
  'patch',
  'defense_technology',
  'research_paper',
  'knowledge_record',
  'vulnerability_hypothesis',
  'zero_day_finding',
  'crash',
]);

const RELATION_ENUM = z.enum([
  'affects',
  'has_vulnerability',
  'runs_on',
  'exploited_by',
  'detected_by',
  'mitigated_by',
  'fixed_in',
  'derived_from',
  'similar_to',
  'communicates_with',
  'documented_in',
  'references',
  'implements',
]);

export const knowledgeEngine: EngineModule = {
  name: ENGINE,
  title: 'Knowledge & Evidence',
  description:
    'Shared, versioned knowledge base and evidence graph. Separates detection templates, PoCs, ' +
    'advisories and malware references into distinct categories and preserves provenance.',
  tools: [
    defineTool({
      name: 'knowledge_search',
      title: 'Search the knowledge base',
      engine: ENGINE,
      description:
        'Search stored knowledge records by free text, category, identifier (e.g. CVE) or tags. ' +
        'Categories are strictly separated, so a detection template is never returned as an exploit.',
      capabilities: ['write_knowledge'],
      risk: 'safe',
      inputSchema: {
        text: z.string().optional().describe('Free-text query matched against title, vendor, product, root cause and identifiers.'),
        categories: z.array(CATEGORY_ENUM).optional().describe('Restrict results to these knowledge categories.'),
        identifierScheme: z.string().optional().describe('Identifier scheme, e.g. "cve", "cwe", "ghsa".'),
        identifierValue: z.string().optional().describe('Identifier value to match exactly, e.g. "CVE-2016-10372".'),
        tags: z.array(z.string()).optional().describe('All of these tags must be present.'),
        limit: zodCommon.limit,
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const query = input as {
          text?: string;
          categories?: KnowledgeCategory[];
          identifierScheme?: string;
          identifierValue?: string;
          tags?: string[];
          limit?: number;
        };
        const results = getKnowledgeBase().searchRecords(query);
        return finish({
          engine: ENGINE,
          tool: 'knowledge_search',
          startedAt: started,
          ctx,
          data: { count: results.length, results },
          summary: `Found ${results.length} knowledge record(s) matching the query.`,
        });
      },
    }),

    defineTool({
      name: 'knowledge_ingest',
      title: 'Ingest a knowledge record',
      engine: ENGINE,
      description:
        'Insert or update a single knowledge record with mandatory provenance. Each record is filed ' +
        'under exactly one category so that advisories, detection templates, PoCs and malware ' +
        'references never get conflated. Provide source URL/version/license when known.',
      capabilities: ['write_knowledge'],
      risk: 'local_mutation',
      inputSchema: {
        category: CATEGORY_ENUM.describe('Knowledge category for this record.'),
        title: z.string().min(1).describe('Human-readable title.'),
        identifiers: z.record(z.string()).optional().describe('Identifier map, e.g. { cve: "CVE-...", cwe: "CWE-..." }.'),
        vendor: z.string().optional(),
        product: z.string().optional(),
        affectedVersions: z.array(z.string()).optional(),
        fixedVersions: z.array(z.string()).optional(),
        klass: z.string().optional().describe('Vulnerability/artifact class, e.g. buffer-overflow.'),
        rootCause: z.string().optional(),
        attackSurface: z.string().optional(),
        preconditions: z.array(z.string()).optional(),
        publicExploitState: z.enum(['unknown', 'none', 'poc_public', 'weaponized_in_wild']).optional(),
        relatedMalwareFamilies: z.array(z.string()).optional(),
        relatedMiraiVariants: z.array(z.string()).optional(),
        relatedRecordIds: z.array(z.string()).optional(),
        verification: z.enum(['unverified', 'statically_reviewed', 'lab_validated_non_destructive', 'disputed']).optional(),
        confidence: z.enum(['confirmed', 'observed', 'inferred', 'hypothesis', 'unknown']).optional(),
        source: z.string().min(1).describe('Provenance source identifier, e.g. "nvd", "github-advisory", "vendor-advisory".'),
        url: z.string().optional().describe('Canonical URL of the source material.'),
        version: z.string().optional(),
        license: z.string().optional(),
        commit: z.string().optional(),
        publishedAt: z.string().optional(),
        tags: z.array(z.string()).optional(),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const i = input as Record<string, any>;
        const now = new Date().toISOString();
        const record: KnowledgeRecord = {
          id: randomUUID(),
          category: i.category as KnowledgeCategory,
          title: i.title,
          identifiers: i.identifiers ?? {},
          vendor: i.vendor,
          product: i.product,
          affectedVersions: i.affectedVersions ?? [],
          fixedVersions: i.fixedVersions ?? [],
          klass: i.klass,
          rootCause: i.rootCause,
          attackSurface: i.attackSurface,
          preconditions: i.preconditions ?? [],
          publicExploitState: i.publicExploitState ?? 'unknown',
          relatedMalwareFamilies: i.relatedMalwareFamilies ?? [],
          relatedMiraiVariants: i.relatedMiraiVariants ?? [],
          relatedRecordIds: i.relatedRecordIds ?? [],
          verification: i.verification ?? 'unverified',
          confidence: i.confidence ?? 'observed',
          license: i.license,
          provenance: [
            provenance({
              source: i.source,
              url: i.url,
              version: i.version,
              license: i.license,
              commit: i.commit,
              publishedAt: i.publishedAt,
            }),
          ],
          evidence: [],
          tags: i.tags ?? [],
          createdAt: now,
          updatedAt: now,
        };
        const stored = getKnowledgeBase().upsertRecord(record);
        getKnowledgeBase().flush();
        ctx.evidence.add({
          claim: `Knowledge record "${stored.title}" ingested under category "${stored.category}".`,
          provenance: record.provenance[0]!,
          confidence: record.confidence,
        });
        return finish({
          engine: ENGINE,
          tool: 'knowledge_ingest',
          startedAt: started,
          ctx,
          data: { record: stored },
          summary: `Ingested knowledge record ${stored.id} (${stored.category}): ${stored.title}.`,
        });
      },
    }),

    defineTool({
      name: 'evidence_graph_query',
      title: 'Query the evidence graph',
      engine: ENGINE,
      description:
        'Traverse the cross-engine knowledge graph from a starting node. Returns connected nodes and ' +
        'edges with provenance and confidence. Example chain: CVE → vulnerable component → firmware ' +
        'version → affected devices → malware family → detection rule → mitigation → fixed version.',
      capabilities: ['write_knowledge'],
      risk: 'safe',
      inputSchema: {
        nodeId: z.string().optional().describe('Exact node id to start from.'),
        kind: NODE_KIND_ENUM.optional().describe('Node kind to look up when nodeId is not supplied.'),
        label: z.string().optional().describe('Node label to look up when nodeId is not supplied.'),
        depth: z.number().int().min(1).max(4).optional().describe('Traversal depth in hops (default 2).'),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const i = input as { nodeId?: string; kind?: GraphNodeKind; label?: string; depth?: number };
        const kb = getKnowledgeBase();
        let startId = i.nodeId;
        if (!startId) {
          if (!i.kind || !i.label) {
            throw errors.invalidInput('Provide either nodeId, or both kind and label.');
          }
          const node = kb.findNode(i.kind, i.label);
          if (!node) throw errors.notFound(`Node ${i.kind}:"${i.label}"`);
          startId = node.id;
        }
        const subgraph = kb.traverse(startId, i.depth ?? 2);
        return finish({
          engine: ENGINE,
          tool: 'evidence_graph_query',
          startedAt: started,
          ctx,
          data: subgraph,
          summary: `Traversed graph from ${startId}: ${subgraph.nodes.length} nodes, ${subgraph.edges.length} edges.`,
        });
      },
    }),

    defineTool({
      name: 'source_provenance_check',
      title: 'Check source provenance',
      engine: ENGINE,
      description:
        'Audit provenance of a knowledge record: list every source, retrieval timestamp, version and ' +
        'license, and flag records with missing provenance or unverified status. Use to enforce ' +
        'evidence-based reporting before publishing conclusions.',
      capabilities: ['write_knowledge'],
      risk: 'safe',
      inputSchema: {
        recordId: z.string().min(1).describe('Knowledge record id to audit.'),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const { recordId } = input as { recordId: string };
        const record = getKnowledgeBase().getRecord(recordId);
        if (!record) throw errors.notFound(`Knowledge record "${recordId}"`);
        const issues: string[] = [];
        if (record.provenance.length === 0) issues.push('No provenance recorded.');
        if (!record.license) issues.push('No license recorded.');
        if (record.verification === 'unverified') issues.push('Verification state is "unverified".');
        if (record.confidence === 'hypothesis' || record.confidence === 'unknown') {
          issues.push(`Confidence is "${record.confidence}" — must not be reported as a confirmed finding.`);
        }
        const data = {
          recordId,
          provenance: record.provenance,
          verification: record.verification,
          confidence: record.confidence,
          issues,
        };
        return finish({
          engine: ENGINE,
          tool: 'source_provenance_check',
          startedAt: started,
          ctx,
          data,
          summary:
            `Provenance audit for ${recordId}: ${record.provenance.length} source(s). ` +
            (issues.length ? `Issues: ${issues.join(' ')}` : 'No issues found.'),
        });
      },
    }),

    defineTool({
      name: 'research_report_generate',
      title: 'Generate a research report',
      engine: ENGINE,
      description:
        'Assemble a structured, evidence-only research report from stored knowledge records and graph ' +
        'traversal. The report separates verified facts, direct observations, interpretations and ' +
        'hypotheses, and lists contradicting evidence.',
      capabilities: ['write_knowledge'],
      risk: 'safe',
      inputSchema: {
        title: z.string().min(1).describe('Report title.'),
        recordIds: z.array(z.string()).optional().describe('Knowledge records to include.'),
        categories: z.array(CATEGORY_ENUM).optional().describe('Include all records in these categories.'),
        graphStartNodeId: z.string().optional().describe('Optional graph node to expand into a relationship section.'),
        depth: z.number().int().min(1).max(4).optional(),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const i = input as {
          title: string;
          recordIds?: string[];
          categories?: KnowledgeCategory[];
          graphStartNodeId?: string;
          depth?: number;
        };
        const kb = getKnowledgeBase();
        const records: KnowledgeRecord[] = [];
        for (const id of i.recordIds ?? []) {
          const r = kb.getRecord(id);
          if (r) records.push(r);
        }
        if (i.categories?.length) {
          records.push(...kb.searchRecords({ categories: i.categories, limit: 200 }));
        }

        const byStatus = {
          verified: records.filter((r) => r.confidence === 'confirmed' || r.confidence === 'observed'),
          interpretation: records.filter((r) => r.confidence === 'inferred'),
          hypothesis: records.filter((r) => r.confidence === 'hypothesis' || r.confidence === 'unknown'),
        };

        const lines: string[] = [
          `# ${i.title}`,
          '',
          `Generated: ${new Date().toISOString()}`,
          `Records: ${records.length}`,
          '',
          '## Verified facts & direct observations',
          ...byStatus.verified.map((r) => `- **${r.title}** [${r.category}] (${r.confidence}) — ${r.provenance[0]?.source ?? 'n/a'}`),
          '',
          '## Researcher interpretation',
          ...byStatus.interpretation.map((r) => `- **${r.title}** — ${r.rootCause ?? 'interpretation recorded'}`),
          '',
          '## Hypotheses & unverified claims',
          ...byStatus.hypothesis.map((r) => `- **${r.title}** (${r.confidence}) — requires corroboration`),
        ];

        let graph: unknown;
        if (i.graphStartNodeId) {
          graph = kb.traverse(i.graphStartNodeId, i.depth ?? 2);
          lines.push('', '## Relationship graph', `- Nodes: ${(graph as any).nodes.length}, edges: ${(graph as any).edges.length}`);
        }

        const markdown = lines.join('\n');
        return finish({
          engine: ENGINE,
          tool: 'research_report_generate',
          startedAt: started,
          ctx,
          data: { markdown, recordCount: records.length, graph },
          summary: markdown,
        });
      },
    }),

    defineTool({
      name: 'knowledge_update',
      title: 'Update a knowledge record',
      engine: ENGINE,
      description:
        'Patch fields of an existing knowledge record (e.g. set verification state after lab review, ' +
        'add related records, correct versions). Provenance is appended, never overwritten.',
      capabilities: ['write_knowledge'],
      risk: 'local_mutation',
      inputSchema: {
        recordId: z.string().min(1),
        patch: z.record(z.unknown()).describe('Partial fields to merge into the record.'),
        provenanceSource: z.string().optional().describe('Optional provenance source for this update.'),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const i = input as { recordId: string; patch: Record<string, unknown>; provenanceSource?: string };
        const kb = getKnowledgeBase();
        const existing = kb.getRecord(i.recordId);
        if (!existing) throw errors.notFound(`Knowledge record "${i.recordId}"`);
        const updated: KnowledgeRecord = {
          ...existing,
          ...(i.patch as Partial<KnowledgeRecord>),
          id: existing.id,
          createdAt: existing.createdAt,
          updatedAt: new Date().toISOString(),
          provenance: i.provenanceSource
            ? [...existing.provenance, provenance({ source: i.provenanceSource, note: 'record update' })]
            : existing.provenance,
        };
        kb.upsertRecord(updated);
        kb.flush();
        return finish({
          engine: ENGINE,
          tool: 'knowledge_update',
          startedAt: started,
          ctx,
          data: { record: updated },
          summary: `Updated knowledge record ${updated.id}.`,
        });
      },
    }),

    defineTool({
      name: 'research_checkpoint',
      title: 'Research checkpoint',
      engine: ENGINE,
      description:
        'Persist an evidence checkpoint for a long-running research task: record what has been ' +
        'established, what remains missing and the open questions. Use between phases so progress is ' +
        'durable and resumable.',
      capabilities: ['write_knowledge'],
      risk: 'local_mutation',
      inputSchema: {
        taskTitle: z.string().min(1),
        established: z.array(z.string()).describe('Findings established so far.'),
        missingEvidence: z.array(z.string()).describe('Evidence still required.'),
        openQuestions: z.array(z.string()).optional(),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const i = input as {
          taskTitle: string;
          established: string[];
          missingEvidence: string[];
          openQuestions?: string[];
        };
        const kb = getKnowledgeBase();
        const now = new Date().toISOString();
        const record: KnowledgeRecord = {
          id: randomUUID(),
          category: 'research_paper',
          title: `Checkpoint: ${i.taskTitle}`,
          identifiers: {},
          affectedVersions: [],
          fixedVersions: [],
          preconditions: [],
          publicExploitState: 'unknown',
          relatedMalwareFamilies: [],
          relatedMiraiVariants: [],
          relatedRecordIds: [],
          verification: 'unverified',
          confidence: 'observed',
          provenance: [provenance({ source: 'research-checkpoint', note: 'in-progress checkpoint' })],
          evidence: [],
          tags: ['checkpoint'],
          createdAt: now,
          updatedAt: now,
        };
        kb.upsertRecord(record);
        kb.flush();
        ctx.evidence.add({
          claim: `Checkpoint recorded for "${i.taskTitle}".`,
          provenance: record.provenance[0]!,
          confidence: 'observed',
          data: { established: i.established, missingEvidence: i.missingEvidence },
        });
        const missing = i.missingEvidence.length ? i.missingEvidence.join('; ') : 'none recorded';
        return finish({
          engine: ENGINE,
          tool: 'research_checkpoint',
          startedAt: started,
          ctx,
          data: { recordId: record.id, ...i },
          summary:
            `Checkpoint stored (${record.id}). Established: ${i.established.length} item(s). ` +
            `Missing evidence: ${missing}.`,
        });
      },
    }),
  ],
};

export const knowledgeDeps = { requirePolicy, logger };
