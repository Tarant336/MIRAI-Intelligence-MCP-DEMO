#!/usr/bin/env node
/**
 * MIRAI Intelligence & Research MCP — entry point.
 *
 * Boots the platform: registers every engine with the tool registry, then
 * starts the MCP server over the configured transport.
 */

import { getConfig } from './config/index.js';
import { logger } from './core/logger.js';
import { ToolRegistry } from './core/registry.js';
import { startStdioServer } from './core/server.js';
import { platformEngine } from './tools/platform.js';
import { knowledgeEngine } from './engines/knowledge-graph/index.js';
import { datasetsEngine } from './engines/knowledge-graph/datasets.js';
import { softwareEngineeringEngine } from './engines/software-engineering/index.js';
import { malwareIntelligenceEngine } from './engines/malware-intelligence/index.js';
import { zeroDayEngine } from './engines/zero-day/index.js';
import { exploitIntelligenceEngine } from './engines/exploit-intelligence/index.js';
import { attackMethodsEngine } from './engines/attack-methods/index.js';
import { antiDdosEngine } from './engines/anti-ddos/index.js';
import { firmwareIntelligenceEngine } from './engines/firmware-intelligence/index.js';
import { networkForensicsEngine } from './engines/network-forensics/index.js';
import { multiAgentEngine } from './engines/multi-agent/index.js';
import { skillsEngine } from './engines/skills/index.js';
import type { EngineModule } from './core/tool.js';

export const VERSION = '1.0.0';

/** All engines that make up the platform, in dependency order. */
export const ENGINES: EngineModule[] = [
  platformEngine,
  knowledgeEngine,
  datasetsEngine,
  softwareEngineeringEngine,
  malwareIntelligenceEngine,
  zeroDayEngine,
  exploitIntelligenceEngine,
  attackMethodsEngine,
  antiDdosEngine,
  firmwareIntelligenceEngine,
  networkForensicsEngine,
  multiAgentEngine,
  skillsEngine,
];

/** Build a registry containing every engine. */
export function buildRegistry(): ToolRegistry {
  const registry = new ToolRegistry();
  for (const engine of ENGINES) {
    registry.registerEngine(engine);
  }
  return registry;
}

async function main(): Promise<void> {
  const cfg = getConfig();
  const registry = buildRegistry();

  logger.info('mirai.start', {
    version: VERSION,
    transport: cfg.transport,
    engines: ENGINES.length,
    tools: registry.size,
    workspaceRoot: cfg.workspaceRoot,
  });

  if (cfg.transport === 'stdio') {
    await startStdioServer({ registry, version: VERSION });
  } else {
    logger.error('transport.unsupported', { transport: cfg.transport });
    process.exit(1);
  }
}

const isMain = (() => {
  try {
    return process.argv[1] ? process.argv[1].endsWith('index.js') || process.argv[1].endsWith('index.ts') : false;
  } catch {
    return false;
  }
})();

if (isMain) {
  main().catch((err) => {
    logger.error('mirai.fatal', { error: err instanceof Error ? err.message : String(err) });
    process.exit(1);
  });
}
