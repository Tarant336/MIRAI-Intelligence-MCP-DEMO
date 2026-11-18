/**
 * Platform engine — environment discovery and health (Phase 1 & 2).
 */

import { z } from 'zod';

import { getConfig } from '../config/index.js';
import { collectEnvironmentReport } from '../core/environment.js';
import { probeDependencies, summarizeDependencies } from '../core/dependencies.js';
import { logger } from '../core/logger.js';
import { getKnowledgeBase } from '../shared/knowledge-base.js';
import { defineTool, finish } from './helpers.js';
import type { EngineModule } from '../core/tool.js';
import type { DependencyProbe, EnvironmentReport } from '../shared/types.js';

const ENGINE = 'platform';

export const platformEngine: EngineModule = {
  name: ENGINE,
  title: 'Platform Core',
  description: 'Environment discovery, capability probe and platform health reporting.',
  tools: [
    defineTool<Record<string, never>, EnvironmentReport>({
      name: 'environment_report',
      title: 'Environment report',
      engine: ENGINE,
      description:
        'Probe the host environment: OS, runtime, CPU/memory, storage, available toolchains and ' +
        'analysis tools (Ghidra, radare2, binwalk, QEMU, Zeek, Suricata, YARA, etc.), plus network and ' +
        'execution constraints. Use this first to learn which backends are available before planning work.',
      capabilities: ['run_isolated'],
      risk: 'safe',
      inputSchema: {},
      handler: async (_input, ctx) => {
        const started = Date.now();
        const report = await collectEnvironmentReport();
        ctx.evidence.add({
          claim: 'Host environment probed.',
          provenance: { source: 'platform', retrievedAt: new Date().toISOString() },
          confidence: 'observed',
          data: { platform: report.platform, arch: report.arch, cpus: report.cpus },
        });
        const available = Object.entries(report.analysisTools)
          .filter(([, ok]) => ok)
          .map(([name]) => name);
        const depsAvailable = (report.dependencies ?? []).filter((d) => d.status === 'AVAILABLE').length;
        return finish({
          engine: ENGINE,
          tool: 'environment_report',
          startedAt: started,
          ctx,
          data: report,
          summary:
            `Environment: ${report.platform}/${report.arch}, ${report.cpus} CPUs, ` +
            `${report.freeMemoryMb}/${report.totalMemoryMb} MB free.\n` +
            `Analysis tools available (${available.length}): ${available.join(', ') || 'none detected'}.\n` +
            `Probed dependencies: ${depsAvailable}/${(report.dependencies ?? []).length} AVAILABLE ` +
            `(see dependency_diagnostics for per-dependency status).`,
        });
      },
    }),

    defineTool<Record<string, never>, Record<string, unknown>>({
      name: 'health_check',
      title: 'Health check',
      engine: ENGINE,
      description:
        'Report the operational health of the MCP server: registered engines/tools, configuration ' +
        'boundaries (workspace root, isolated execution, public fetch, offensive ops), and knowledge ' +
        'base statistics. Use to self-verify the platform is correctly configured.',
      capabilities: ['read_repo'],
      risk: 'safe',
      inputSchema: {},
      handler: async (_input, ctx) => {
        const started = Date.now();
        const cfg = getConfig();
        const kb = getKnowledgeBase();
        const data = {
          status: 'ok' as const,
          config: {
            workspaceRoot: cfg.workspaceRoot,
            dataDir: cfg.dataDir,
            transport: cfg.transport,
            allowIsolatedExec: cfg.allowIsolatedExec,
            allowPublicFetch: cfg.allowPublicFetch,
            allowOffensiveOps: cfg.allowOffensiveOps,
            execTimeoutMs: cfg.execTimeoutMs,
            maxArtifactBytes: cfg.maxArtifactBytes,
            labAuthorizationConfigured: Boolean(cfg.labAuthorizationToken),
          },
          knowledge: kb.stats(),
        };
        logger.debug('health.check', { workspaceRoot: cfg.workspaceRoot });
        return finish({
          engine: ENGINE,
          tool: 'health_check',
          startedAt: started,
          ctx,
          data,
          summary:
            `Status: ${data.status}. Workspace: ${cfg.workspaceRoot}.\n` +
            `Isolated exec: ${cfg.allowIsolatedExec}, public fetch: ${cfg.allowPublicFetch}, ` +
            `offensive ops: ${cfg.allowOffensiveOps} (locked).\n` +
            `Knowledge: ${data.knowledge.records} records, ${data.knowledge.nodes} nodes, ` +
            `${data.knowledge.edges} edges.`,
        });
      },
    }),

    defineTool<{ required?: string[] }, { dependencies: DependencyProbe[]; required: string[] }>({
      name: 'dependency_diagnostics',
      title: 'Dependency diagnostics',
      engine: ENGINE,
      description:
        'Probe the external analysis dependencies (GCC, Clang, AFL++, Honggfuzz, QEMU ARM/MIPS, ' +
        'Binwalk, 7-Zip, objdump, readelf, strings, nm, Radare2, Ghidra, Git) and report a precise ' +
        'status for each: AVAILABLE, MISSING, VERSION_UNSUPPORTED, CONFIGURATION_ERROR or ' +
        'NOT_REQUIRED. Verifies the executable and its version where possible. Read-only — never ' +
        'installs or downloads anything.',
      capabilities: ['run_isolated'],
      risk: 'safe',
      inputSchema: {
        required: z
          .array(z.string())
          .optional()
          .describe(
            'Dependency ids the caller requires (e.g. ["gcc","clang"]). Missing ids are reported ' +
              'as MISSING; all other missing dependencies are reported as NOT_REQUIRED.',
          ),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const required = input.required ?? [];
        const dependencies = await probeDependencies({ required });
        const counts = summarizeDependencies(dependencies).split('\n')[0] ?? '';

        ctx.evidence.add({
          claim: `Probed ${dependencies.length} external dependencies (${counts}).`,
          provenance: { source: 'platform', retrievedAt: new Date().toISOString() },
          confidence: 'observed',
          data: { required, statuses: dependencies.map((d) => ({ id: d.id, status: d.status })) },
        });

        return finish({
          engine: ENGINE,
          tool: 'dependency_diagnostics',
          startedAt: started,
          ctx,
          data: { dependencies, required },
          summary: summarizeDependencies(dependencies),
        });
      },
    }),
  ],
};

/** Zod schema export kept for documentation/tests. */
export const platformSchemas = { health: z.object({}) };
