/**
 * Persistent knowledge base and evidence graph (§7, §C2–C4).
 *
 * Storage is a versioned JSON store on disk. All writes are atomic (write to a
 * temporary file then rename) so that a crash cannot corrupt the knowledge
 * base. Knowledge categories are kept strictly separated (§C2): a detection
 * template is never merged into an exploit record store.
 */

import { mkdirSync, readFileSync, renameSync, writeFileSync, existsSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';

import { getConfig } from '../config/index.js';
import { logger } from '../core/logger.js';
import type { ConfidenceLevel, EvidenceRef, Provenance } from './types.js';

const log = logger.child({ component: 'knowledge-base' });

/**
 * Knowledge categories. These MUST NOT be conflated (§C2).
 */
export type KnowledgeCategory =
  | 'advisory'
  | 'detection_template'
  | 'fingerprint_template'
  | 'exploit_poc'
  | 'exploit_module'
  | 'malware_sample_ref'
  | 'yara_rule'
  | 'sigma_rule'
  | 'network_detection_rule'
  | 'remediation_guidance'
  | 'patch_reference'
  | 'research_paper'
  | 'attack_method'
  | 'defense_technology'
  | 'dataset'
  | 'firmware_component'
  | 'malware_family'
  | 'mirai_variant'
  | 'c2_protocol_spec'
  | 'vulnerability_hypothesis'
  | 'zero_day_finding'
  | 'crash_triage'
  | 'fuzz_target';

/** Verification state — a published PoC is NOT automatically verified (§C2). */
export type VerificationState =
  | 'unverified'
  | 'statically_reviewed'
  | 'lab_validated_non_destructive'
  | 'disputed';

/** A single knowledge record (§C3). */
export interface KnowledgeRecord {
  id: string;
  category: KnowledgeCategory;
  title: string;
  /** Optional identifiers keyed by scheme, e.g. { cve: 'CVE-2016-10372', cwe: 'CWE-798' }. */
  identifiers: Record<string, string>;
  vendor?: string;
  product?: string;
  affectedVersions: string[];
  fixedVersions: string[];
  /** Vulnerability / artifact class, e.g. "default-credentials", "buffer-overflow". */
  klass?: string;
  rootCause?: string;
  attackSurface?: string;
  preconditions: string[];
  /** Whether public exploitation evidence exists (recorded, not asserted). */
  publicExploitState: 'unknown' | 'none' | 'poc_public' | 'weaponized_in_wild';
  /** Related malware families — only recorded when evidence exists (§C2). */
  relatedMalwareFamilies: string[];
  relatedMiraiVariants: string[];
  /** Other knowledge records this one references (detection templates, PoCs, patches). */
  relatedRecordIds: string[];
  verification: VerificationState;
  confidence: ConfidenceLevel;
  license?: string;
  provenance: Provenance[];
  evidence: EvidenceRef[];
  tags: string[];
  createdAt: string;
  updatedAt: string;
}

/** Graph node kinds (§7). */
export type GraphNodeKind =
  | 'repository'
  | 'source_file'
  | 'function'
  | 'dependency'
  | 'documentation'
  | 'cve'
  | 'cwe'
  | 'vendor'
  | 'product'
  | 'firmware_version'
  | 'malware_family'
  | 'mirai_variant'
  | 'binary_sample'
  | 'attack_method'
  | 'pcap_evidence'
  | 'c2_indicator'
  | 'detection_rule'
  | 'patch'
  | 'defense_technology'
  | 'research_paper'
  | 'knowledge_record'
  | 'vulnerability_hypothesis'
  | 'zero_day_finding'
  | 'crash';

export type GraphRelation =
  | 'affects'
  | 'has_vulnerability'
  | 'runs_on'
  | 'exploited_by'
  | 'detected_by'
  | 'mitigated_by'
  | 'fixed_in'
  | 'derived_from'
  | 'similar_to'
  | 'communicates_with'
  | 'documented_in'
  | 'references'
  | 'implements';

export interface GraphNode {
  id: string;
  kind: GraphNodeKind;
  label: string;
  properties: Record<string, unknown>;
  provenance: Provenance[];
  confidence: ConfidenceLevel;
}

export interface GraphEdge {
  id: string;
  from: string;
  to: string;
  relation: GraphRelation;
  provenance: Provenance[];
  confidence: ConfidenceLevel;
  note?: string;
}

interface KnowledgeFile {
  version: number;
  records: Record<string, KnowledgeRecord>;
  nodes: Record<string, GraphNode>;
  edges: Record<string, GraphEdge>;
}

const EMPTY: KnowledgeFile = { version: 1, records: {}, nodes: {}, edges: {} };

export class KnowledgeBase {
  private readonly filePath: string;
  private data: KnowledgeFile;
  private dirty = false;

  constructor(filePath?: string) {
    const cfg = getConfig();
    this.filePath = filePath ?? join(cfg.dataDir, 'knowledge', 'knowledge.json');
    this.data = this.load();
  }

  private load(): KnowledgeFile {
    try {
      if (existsSync(this.filePath)) {
        const parsed = JSON.parse(readFileSync(this.filePath, 'utf8')) as KnowledgeFile;
        return {
          version: parsed.version ?? 1,
          records: parsed.records ?? {},
          nodes: parsed.nodes ?? {},
          edges: parsed.edges ?? {},
        };
      }
    } catch (err) {
      log.warn('knowledge.load.failed', { error: (err as Error).message, filePath: this.filePath });
    }
    return structuredClone(EMPTY);
  }

  /** Persist atomically. */
  flush(): void {
    if (!this.dirty) return;
    mkdirSync(dirname(this.filePath), { recursive: true });
    const tmp = `${this.filePath}.tmp`;
    writeFileSync(tmp, JSON.stringify(this.data, null, 2), 'utf8');
    renameSync(tmp, this.filePath);
    this.dirty = false;
    log.info('knowledge.flush', { filePath: this.filePath, records: Object.keys(this.data.records).length });
  }

  stats(): { records: number; nodes: number; edges: number; filePath: string; sizeBytes: number } {
    let sizeBytes = 0;
    try {
      sizeBytes = existsSync(this.filePath) ? statSync(this.filePath).size : 0;
    } catch {
      /* ignore */
    }
    return {
      records: Object.keys(this.data.records).length,
      nodes: Object.keys(this.data.nodes).length,
      edges: Object.keys(this.data.edges).length,
      filePath: this.filePath,
      sizeBytes,
    };
  }

  // ---- Records -----------------------------------------------------------

  upsertRecord(record: KnowledgeRecord): KnowledgeRecord {
    const existing = this.data.records[record.id];
    const now = new Date().toISOString();
    this.data.records[record.id] = existing
      ? { ...existing, ...record, createdAt: existing.createdAt, updatedAt: now }
      : record;
    this.dirty = true;
    return this.data.records[record.id]!;
  }

  getRecord(id: string): KnowledgeRecord | undefined {
    return this.data.records[id];
  }

  /** Search records by free text, category and identifier. */
  searchRecords(query: {
    text?: string;
    categories?: KnowledgeCategory[];
    identifierScheme?: string;
    identifierValue?: string;
    tags?: string[];
    /** Records carrying any of these tags are skipped entirely. */
    excludeTags?: string[];
    limit?: number;
  }): KnowledgeRecord[] {
    const limit = query.limit ?? 50;
    const text = query.text?.toLowerCase();
    const results: KnowledgeRecord[] = [];
    for (const record of Object.values(this.data.records)) {
      if (query.categories && !query.categories.includes(record.category)) continue;
      if (query.excludeTags && query.excludeTags.some((t) => record.tags.includes(t))) continue;
      if (query.identifierScheme && query.identifierValue) {
        const value = record.identifiers[query.identifierScheme];
        if (!value || value.toLowerCase() !== query.identifierValue.toLowerCase()) continue;
      }
      if (query.tags && !query.tags.every((t) => record.tags.includes(t))) continue;
      if (text) {
        const haystack = [
          record.title,
          record.klass,
          record.rootCause,
          record.vendor,
          record.product,
          ...Object.values(record.identifiers),
          ...record.tags,
        ]
          .filter(Boolean)
          .join(' ')
          .toLowerCase();
        if (!haystack.includes(text)) continue;
      }
      results.push(record);
      if (results.length >= limit) break;
    }
    return results;
  }

  // ---- Graph -------------------------------------------------------------

  upsertNode(node: GraphNode): GraphNode {
    const existing = this.data.nodes[node.id];
    this.data.nodes[node.id] = existing
      ? {
          ...existing,
          ...node,
          provenance: dedupeProvenance([...existing.provenance, ...node.provenance]),
          properties: { ...existing.properties, ...node.properties },
        }
      : node;
    this.dirty = true;
    return this.data.nodes[node.id]!;
  }

  upsertEdge(edge: GraphEdge): GraphEdge {
    this.data.edges[edge.id] = edge;
    this.dirty = true;
    return edge;
  }

  getNode(id: string): GraphNode | undefined {
    return this.data.nodes[id];
  }

  /** Traverse the graph from a node up to `depth` hops. */
  traverse(startId: string, depth = 2): { nodes: GraphNode[]; edges: GraphEdge[] } {
    const seenNodes = new Set<string>();
    const collectedEdges: GraphEdge[] = [];
    const collectedNodes: GraphNode[] = [];
    let frontier = [startId];
    seenNodes.add(startId);

    for (let hop = 0; hop < depth; hop += 1) {
      const next: string[] = [];
      for (const edge of Object.values(this.data.edges)) {
        if (frontier.includes(edge.from) || frontier.includes(edge.to)) {
          collectedEdges.push(edge);
          for (const endpoint of [edge.from, edge.to]) {
            if (!seenNodes.has(endpoint)) {
              seenNodes.add(endpoint);
              next.push(endpoint);
            }
          }
        }
      }
      frontier = next;
      if (frontier.length === 0) break;
    }

    for (const id of seenNodes) {
      const node = this.data.nodes[id];
      if (node) collectedNodes.push(node);
    }
    return { nodes: collectedNodes, edges: collectedEdges };
  }

  /** Find a node by kind + label (case-insensitive). */
  findNode(kind: GraphNodeKind, label: string): GraphNode | undefined {
    const lower = label.toLowerCase();
    return Object.values(this.data.nodes).find(
      (n) => n.kind === kind && n.label.toLowerCase() === lower,
    );
  }
}

let instance: KnowledgeBase | undefined;

/** Drop exact duplicate provenance entries so repeated upserts stay bounded. */
function dedupeProvenance(entries: Provenance[]): Provenance[] {
  const seen = new Set<string>();
  const result: Provenance[] = [];
  for (const entry of entries) {
    const key = JSON.stringify(entry);
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(entry);
  }
  return result;
}

/** Get the process-wide knowledge base instance. */
export function getKnowledgeBase(): KnowledgeBase {
  if (!instance) instance = new KnowledgeBase();
  return instance;
}

/** Reset the singleton — used by tests. */
export function resetKnowledgeBase(): void {
  instance?.flush();
  instance = undefined;
}
