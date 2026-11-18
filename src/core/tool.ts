/**
 * Framework-agnostic tool contract.
 *
 * Engines implement `EngineModule`; the MCP server adapts these definitions
 * onto the official SDK. Keeping the contract framework-agnostic means engines
 * are unit-testable without booting a transport.
 */

import type { ZodRawShape } from 'zod';

import type { EvidenceCollector } from '../shared/evidence.js';
import type { KnowledgeBase } from '../shared/knowledge-base.js';
import type { Logger } from './logger.js';
import type { Assertion, EvidenceRef, ToolDescriptor, ToolResult } from '../shared/types.js';

export interface ToolContext {
  logger: Logger;
  knowledge: KnowledgeBase;
  evidence: EvidenceCollector;
  /** Abort signal wired to the MCP request lifecycle. */
  signal?: AbortSignal;
}

/* eslint-disable @typescript-eslint/no-explicit-any */
export interface ToolDefinition<TInput = any, TOutput = any> {
  descriptor: ToolDescriptor;
  /** Zod raw shape used to build both the JSON schema and the runtime validator. */
  inputSchema: ZodRawShape;
  /** Optional output schema for structured content. */
  outputSchema?: ZodRawShape;
  handler: (input: TInput, ctx: ToolContext) => Promise<ToolResult<TOutput>>;
}

export interface EngineModule {
  /** Stable engine identifier, e.g. "software-engineering". */
  name: string;
  title: string;
  description: string;
  tools: ToolDefinition[];
}

/** Helper to assemble a successful ToolResult with consistent metadata. */
export function ok<T>(input: {
  engine: string;
  tool: string;
  summary: string;
  data?: T;
  evidence?: EvidenceRef[];
  assertions?: Assertion[];
  warnings?: string[];
  durationMs: number;
}): ToolResult<T> {
  return {
    ok: true,
    engine: input.engine,
    tool: input.tool,
    ...(input.data !== undefined ? { data: input.data } : {}),
    summary: input.summary,
    evidence: input.evidence ?? [],
    ...(input.assertions ? { assertions: input.assertions } : {}),
    warnings: input.warnings ?? [],
    durationMs: input.durationMs,
    timestamp: new Date().toISOString(),
  };
}

/** Helper to assemble a blocked/failed ToolResult. */
export function fail(input: {
  engine: string;
  tool: string;
  summary: string;
  reason?: string;
  warnings?: string[];
  durationMs: number;
}): ToolResult<never> {
  return {
    ok: false,
    engine: input.engine,
    tool: input.tool,
    summary: input.summary,
    evidence: [],
    warnings: input.warnings ?? [],
    blocked: true,
    ...(input.reason ? { blockReason: input.reason } : {}),
    durationMs: input.durationMs,
    timestamp: new Date().toISOString(),
  };
}
