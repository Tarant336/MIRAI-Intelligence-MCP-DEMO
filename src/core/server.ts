/**
 * MCP server assembly (§11, §14 Phase 2).
 *
 * Adapts the framework-agnostic ToolRegistry onto the official
 * `@modelcontextprotocol/sdk` server, wiring the security policy, evidence
 * collection and logging around every tool invocation.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';

import { getConfig } from '../config/index.js';
import { MiraiError, toMiraiError } from './errors.js';
import { logger } from './logger.js';
import { EvidenceCollector } from '../shared/evidence.js';
import { getKnowledgeBase } from '../shared/knowledge-base.js';
import { registerPrompts } from '../prompts/index.js';
import { ToolRegistry } from './registry.js';
import { getSkillRegistry } from '../engines/skills/index.js';
import type { ToolDefinition } from './tool.js';
import type { ToolResult } from '../shared/types.js';

const log = logger.child({ component: 'server' });

function buildContent(result: ToolResult<unknown>): Array<{ type: 'text'; text: string }> {
  return [{ type: 'text', text: result.summary }];
}

/** Convert a serializable result into structured content the SDK can validate. */
function structured(result: ToolResult<unknown>): Record<string, unknown> {
  return {
    ok: result.ok,
    engine: result.engine,
    tool: result.tool,
    ...(result.data !== undefined ? { data: result.data } : {}),
    summary: result.summary,
    evidence: result.evidence,
    ...(result.assertions ? { assertions: result.assertions } : {}),
    warnings: result.warnings,
    ...(result.blocked !== undefined ? { blocked: result.blocked } : {}),
    ...(result.blockReason ? { blockReason: result.blockReason } : {}),
    durationMs: result.durationMs,
    timestamp: result.timestamp,
  };
}

function wrapError(engine: string, tool: string, err: unknown): ToolResult<never> {
  const mirai = toMiraiError(err);
  return {
    ok: false,
    engine,
    tool,
    summary: `[${mirai.code}] ${mirai.message} ${mirai.hint}`,
    evidence: [],
    warnings: [],
    ...(mirai.code === 'POLICY_BLOCKED' ? { blocked: true, blockReason: mirai.message } : {}),
    durationMs: 0,
    timestamp: new Date().toISOString(),
  };
}

export interface ServerDependencies {
  registry: ToolRegistry;
  version: string;
}

/** Build a fully-wired McpServer instance. */
export function createServer(deps: ServerDependencies): McpServer {
  const { registry, version } = deps;
  const server = new McpServer({
    name: 'mirai-intelligence-research-mcp',
    version,
  });

  for (const def of registry.list()) {
    registerTool(server, registry, def);
  }

  // Surface the environment / knowledge snapshot as a resource.
  server.registerResource(
    'knowledge-stats',
    'mirai://knowledge/stats',
    {
      title: 'Knowledge base statistics',
      description: 'Counts of knowledge records, graph nodes and edges currently stored.',
      mimeType: 'application/json',
    },
    async (uri) => {
      const stats = getKnowledgeBase().stats();
      return {
        contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify(stats, null, 2) }],
      };
    },
  );

  // Surface the skills index as a resource.
  server.registerResource(
    'skills-index',
    'mirai://skills/index',
    {
      title: 'Skills Library Index',
      description: 'List of all available skills with their metadata (name, description, engines, tags, tools).',
      mimeType: 'application/json',
    },
    async (uri) => {
      const { registry, root, errors } = getSkillRegistry();
      const skills = registry.list().map((s) => ({
        name: s.name,
        description: s.description,
        version: s.version,
        engines: s.engines,
        tags: s.tags,
        tools: s.tools,
        license: s.license,
        path: s.path,
        bytes: s.bytes,
      }));
      const facets = registry.facets();
      return {
        contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify({ root, total: skills.length, facets, skills, loadErrors: errors }, null, 2) }],
      };
    },
  );

  log.info('server.created', { tools: registry.size });
  registerPrompts(server);
  return server;
}

function registerTool(server: McpServer, registry: ToolRegistry, def: ToolDefinition): void {
  const d = def.descriptor;
  const { engine } = d;

  server.registerTool(
    d.name,
    {
      title: d.title,
      description: d.description,
      inputSchema: def.inputSchema,
      annotations: d.annotations,
    },
    async (args: Record<string, unknown>, extra) => {
      const started = Date.now();
      const evidence = new EvidenceCollector();
      const ctx = {
        logger: log.child({ tool: d.name, engine }),
        knowledge: getKnowledgeBase(),
        evidence,
        ...(extra?.signal ? { signal: extra.signal } : {}),
      };

      // Policy pre-screen before any handler runs.
      const screen = registry.screen(d.name);
      if (!screen.allowed) {
        const result: ToolResult<never> = {
          ok: false,
          engine,
          tool: d.name,
          summary:
            `[POLICY_BLOCKED] ${screen.reason ?? 'Blocked by security policy.'} ` +
            `${screen.defensiveAlternative ?? ''}`.trim(),
          evidence: [],
          warnings: [],
          blocked: true,
          ...(screen.reason ? { blockReason: screen.reason } : {}),
          durationMs: Date.now() - started,
          timestamp: new Date().toISOString(),
        };
        return { content: buildContent(result), structuredContent: structured(result), isError: true };
      }

      try {
        const result = await def.handler(args, ctx);
        result.durationMs = Date.now() - started;
        getKnowledgeBase().flush();
        return {
          content: buildContent(result),
          structuredContent: structured(result),
          ...(result.ok ? {} : { isError: true }),
        };
      } catch (err) {
        const result = wrapError(engine, d.name, err);
        result.durationMs = Date.now() - started;
        log.error('tool.failed', {
          tool: d.name,
          error: err instanceof MiraiError ? err.toJSON() : String(err),
        });
        return { content: buildContent(result), structuredContent: structured(result), isError: true };
      }
    },
  );
}

/** Start the server over stdio. */
export async function startStdioServer(deps: ServerDependencies): Promise<void> {
  const server = createServer(deps);
  const transport = new StdioServerTransport();
  await server.connect(transport);
  log.info('server.connected', { transport: 'stdio', tools: deps.registry.size });
}

export { McpError, ErrorCode };
