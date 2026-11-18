/**
 * Evidence store, provenance helpers and assertion builder (§7, §9).
 *
 * Every tool collects EvidenceRef objects. Assertions bind evidence to a
 * stated conclusion and carry an explicit epistemic status; the platform must
 * never present a hypothesis as a confirmed finding.
 */

import { randomUUID } from 'node:crypto';

import type {
  Assertion,
  ConfidenceLevel,
  EpistemicStatus,
  EvidenceRef,
  Provenance,
} from './types.js';

/** Create a provenance record with an auto-filled retrieval timestamp. */
export function provenance(input: Omit<Provenance, 'retrievedAt'> & { retrievedAt?: string }): Provenance {
  return { retrievedAt: input.retrievedAt ?? new Date().toISOString(), ...input };
}

/** Collector passed through tool implementations. */
export class EvidenceCollector {
  private readonly items: EvidenceRef[] = [];
  private readonly assertions: Assertion[] = [];
  private readonly warnings: string[] = [];

  add(input: {
    claim: string;
    provenance: Provenance;
    confidence?: ConfidenceLevel;
    locator?: EvidenceRef['locator'];
    data?: unknown;
  }): EvidenceRef {
    const ref: EvidenceRef = {
      id: randomUUID(),
      claim: input.claim,
      provenance: input.provenance,
      confidence: input.confidence ?? 'observed',
      ...(input.locator ? { locator: input.locator } : {}),
      ...(input.data !== undefined ? { data: input.data } : {}),
    };
    this.items.push(ref);
    return ref;
  }

  warn(message: string): void {
    this.warnings.push(message);
  }

  /** Build an assertion with supporting/contradicting evidence. */
  assert(input: {
    statement: string;
    status: EpistemicStatus;
    confidence: ConfidenceLevel;
    producedBy: string;
    supporting?: EvidenceRef[];
    contradicting?: EvidenceRef[];
  }): Assertion {
    const assertion: Assertion = {
      id: randomUUID(),
      statement: input.statement,
      status: input.status,
      confidence: input.confidence,
      supporting: input.supporting ?? [],
      contradicting: input.contradicting ?? [],
      producedBy: input.producedBy,
      createdAt: new Date().toISOString(),
    };
    this.assertions.push(assertion);
    return assertion;
  }

  get evidence(): EvidenceRef[] {
    return [...this.items];
  }

  get assertionList(): Assertion[] {
    return [...this.assertions];
  }

  get warningList(): string[] {
    return [...this.warnings];
  }
}

/** Confidence ranking used when aggregating evidence. */
const CONFIDENCE_RANK: Record<ConfidenceLevel, number> = {
  confirmed: 5,
  observed: 4,
  inferred: 3,
  hypothesis: 2,
  unknown: 1,
};

/** Aggregate the weakest-link confidence across a set of evidence. */
export function aggregateConfidence(items: EvidenceRef[]): ConfidenceLevel {
  if (items.length === 0) return 'unknown';
  const ranked = items
    .map((i) => i.confidence)
    .sort((a, b) => CONFIDENCE_RANK[a] - CONFIDENCE_RANK[b]);
  return ranked[0] ?? 'unknown';
}

/** Whether an epistemic status may be reported as a conclusion. */
export function isConclusive(status: EpistemicStatus): boolean {
  return status === 'verified_fact' || status === 'direct_observation';
}
