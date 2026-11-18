/**
 * Shared helpers for engine tool implementations.
 *
 * Keeps tool authors DRY: every engine uses these to build descriptors,
 * read bounded artifacts, and shape results consistently.
 */

import { readFileSync, statSync } from 'node:fs';

import { z } from 'zod';

import { errors } from '../core/errors.js';
import { ok, type ToolDefinition } from '../core/tool.js';
import { logger } from '../core/logger.js';
import { assertArtifactSize, resolveWorkspacePath } from '../shared/security.js';
import { provenance, type EvidenceCollector } from '../shared/evidence.js';
import type {
  Capability,
  ConfidenceLevel,
  EvidenceRef,
  Provenance,
  RiskClass,
  ToolResult,
} from '../shared/types.js';

/**
 * Build a ToolDefinition with sensible annotation defaults derived from risk.
 */
export function defineTool<TInput, TOutput>(input: {
  name: string;
  title: string;
  engine: string;
  description: string;
  capabilities: Capability[];
  risk: RiskClass;
  inputSchema: z.ZodRawShape;
  outputSchema?: z.ZodRawShape;
  handler: ToolDefinition<TInput, TOutput>['handler'];
}): ToolDefinition<TInput, TOutput> {
  const readOnly = input.risk === 'safe';
  const destructive = input.risk === 'local_mutation' || input.risk === 'isolated_exec';
  return {
    descriptor: {
      name: input.name,
      title: input.title,
      engine: input.engine,
      description: input.description,
      capabilities: input.capabilities,
      risk: input.risk,
      annotations: {
        readOnlyHint: readOnly,
        destructiveHint: destructive,
        idempotentHint: readOnly,
        openWorldHint: input.risk === 'external_fetch',
      },
    },
    inputSchema: input.inputSchema,
    ...(input.outputSchema ? { outputSchema: input.outputSchema } : {}),
    handler: input.handler,
  };
}

/** Read a bounded text artifact from within the workspace. */
export function readTextArtifact(relativeOrAbsolutePath: string, maxBytes?: number): {
  path: string;
  content: string;
  bytes: number;
  truncated: boolean;
} {
  const abs = resolveWorkspacePath(relativeOrAbsolutePath, true);
  const stat = statSync(abs);
  assertArtifactSize(stat.size);
  const limit = maxBytes ?? stat.size;
  const buffer = readFileSync(abs);
  const slice = buffer.subarray(0, limit);
  return {
    path: abs,
    content: slice.toString('utf8'),
    bytes: stat.size,
    truncated: stat.size > limit,
  };
}

/** Read a bounded binary artifact as a Buffer. */
export function readBinaryArtifact(relativeOrAbsolutePath: string, maxBytes?: number): {
  path: string;
  buffer: Buffer;
  bytes: number;
  truncated: boolean;
} {
  const abs = resolveWorkspacePath(relativeOrAbsolutePath, true);
  const stat = statSync(abs);
  assertArtifactSize(stat.size);
  const buffer = readFileSync(abs);
  const limit = maxBytes ?? buffer.length;
  return {
    path: abs,
    buffer: buffer.subarray(0, limit),
    bytes: stat.size,
    truncated: stat.size > limit,
  };
}

/** Deterministic content hash used for dedup and integrity tracking. */
export async function sha256(data: Buffer | string): Promise<string> {
  const { createHash } = await import('node:crypto');
  return `sha256:${createHash('sha256').update(data).digest('hex')}`;
}

/** Timestamped provenance for local artifacts. */
export function localProvenance(domain: string, path: string, note?: string): Provenance {
  return provenance({
    source: 'local-artifact',
    url: `file://${path}`,
    version: domain,
    ...(note ? { note } : {}),
  });
}

/** Timestamped provenance for curated, in-repo intelligence datasets. */
export function curatedProvenance(dataset: string, note?: string): Provenance {
  return provenance({
    source: 'curated-knowledge',
    note: `${dataset}${note ? ` — ${note}` : ''}`,
  });
}

/** Convenience wrapper to finish a tool call cleanly. */
export function finish<T>(params: {
  engine: string;
  tool: string;
  summary: string;
  ctx: { evidence: EvidenceCollector };
  data?: T;
  warnings?: string[];
  startedAt: number;
}): ToolResult<T> {
  return ok<T>({
    engine: params.engine,
    tool: params.tool,
    summary: params.summary,
    ...(params.data !== undefined ? { data: params.data } : {}),
    evidence: params.ctx.evidence.evidence,
    assertions: params.ctx.evidence.assertionList,
    warnings: [...params.ctx.evidence.warningList, ...(params.warnings ?? [])],
    durationMs: Date.now() - params.startedAt,
  });
}

/** Add evidence with a compact call-site. */
export function addEvidence(
  ctx: { evidence: EvidenceCollector },
  input: {
    claim: string;
    prov: Provenance;
    confidence?: ConfidenceLevel;
    locator?: EvidenceRef['locator'];
    data?: unknown;
  },
): EvidenceRef {
  return ctx.evidence.add({
    claim: input.claim,
    provenance: input.prov,
    confidence: input.confidence ?? 'observed',
    ...(input.locator ? { locator: input.locator } : {}),
    ...(input.data !== undefined ? { data: input.data } : {}),
  });
}

/** Common reusable zod fragments. */
export const zodCommon = {
  filePath: z.string().min(1).describe('Path to the artifact, relative to the authorized workspace root.'),
  limit: z.number().int().min(1).max(1000).optional().describe('Maximum number of results to return.'),
  offset: z.number().int().min(0).optional().describe('Pagination offset.'),
  query: z.string().min(1).describe('Free-text query.'),
  maxBytes: z.number().int().min(1).optional().describe('Maximum bytes to read from the artifact.'),
};

export { errors, logger };
