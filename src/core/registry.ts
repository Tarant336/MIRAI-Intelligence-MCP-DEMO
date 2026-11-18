/**
 * Tool registry.
 *
 * Engines register their ToolDefinitions here. The registry owns global
 * invariants: unique tool names, consistent naming, and policy pre-screening.
 */

import { logger } from './logger.js';
import { evaluateIntent } from '../shared/security.js';
import type { EngineModule, ToolDefinition } from './tool.js';

const log = logger.child({ component: 'registry' });

const TOOL_NAME_PATTERN = /^[a-z][a-z0-9_]{2,63}$/;

export class ToolRegistry {
  private readonly tools = new Map<string, { def: ToolDefinition; engine: string }>();
  private readonly engines = new Map<string, EngineModule>();

  registerEngine(engine: EngineModule): void {
    if (this.engines.has(engine.name)) {
      throw new Error(`Engine "${engine.name}" is already registered.`);
    }
    this.engines.set(engine.name, engine);
    for (const def of engine.tools) {
      this.registerTool(engine.name, def);
    }
    log.info('engine.registered', { engine: engine.name, tools: engine.tools.length });
  }

  private registerTool(engineName: string, def: ToolDefinition): void {
    const name = def.descriptor.name;
    if (!TOOL_NAME_PATTERN.test(name)) {
      throw new Error(`Tool name "${name}" must match ${TOOL_NAME_PATTERN}.`);
    }
    if (this.tools.has(name)) {
      throw new Error(`Tool "${name}" is already registered (duplicate across engines).`);
    }
    if (def.descriptor.engine !== engineName) {
      throw new Error(
        `Tool "${name}" declares engine "${def.descriptor.engine}" but is registered under "${engineName}".`,
      );
    }
    this.tools.set(name, { def, engine: engineName });
  }

  get(name: string): { def: ToolDefinition; engine: string } | undefined {
    return this.tools.get(name);
  }

  list(): ToolDefinition[] {
    return [...this.tools.values()].map((t) => t.def);
  }

  listByEngine(): Record<string, string[]> {
    const out: Record<string, string[]> = {};
    for (const { def, engine } of this.tools.values()) {
      (out[engine] ??= []).push(def.descriptor.name);
    }
    return out;
  }

  getEngines(): EngineModule[] {
    return [...this.engines.values()];
  }

  /** Pre-screen a tool's declared intent against the security policy. */
  screen(name: string): { allowed: boolean; reason?: string; defensiveAlternative?: string } {
    const entry = this.tools.get(name);
    if (!entry) return { allowed: false, reason: `Unknown tool "${name}".` };
    const decision = evaluateIntent(entry.def.descriptor.description, entry.def.descriptor.risk);
    return {
      allowed: decision.allowed,
      ...(decision.reason ? { reason: decision.reason } : {}),
      ...(decision.defensiveAlternative ? { defensiveAlternative: decision.defensiveAlternative } : {}),
    };
  }

  get size(): number {
    return this.tools.size;
  }
}
