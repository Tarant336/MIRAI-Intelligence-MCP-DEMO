/**
 * Attack-Methods engine (§3 + §11 "Tình báo Phương thức Tấn công").
 *
 * ANALYSIS AND DEFENCE ONLY (§10): every tool here documents, classifies,
 * compares and detects observed denial-of-service method families. No tool
 * emits operational attack code, packet-flooding implementations, reflection
 * launchers or spoofing material. Where an offensive artefact would be
 * expected, this engine returns a defensive alternative (detector, parser or
 * mitigation guidance).
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { extname, join } from 'node:path';

import { z } from 'zod';

import { defineTool, finish, addEvidence, curatedProvenance, localProvenance } from '../../tools/helpers.js';
import { errors } from '../../core/errors.js';
import { resolveWorkspacePath } from '../../shared/security.js';
import type { EngineModule } from '../../core/tool.js';
import type { KnowledgeRecord } from '../../shared/knowledge-base.js';
import type { EvidenceRef } from '../../shared/types.js';
import {
  ATTACK_METHOD_CATALOGUE,
  classifyDescription,
  getAttackMethod,
  searchCatalogue,
  seedAttackMethodCatalogue,
  type AttackMethodCatalogueItem,
  type AttackMethodLayer,
} from './catalogue.js';

const ENGINE = 'attack-methods';

const LAYER_ENUM = z.enum([
  'network',
  'transport',
  'application',
  'reflection_amplification',
  'iot_specific',
]);

/* -------------------------------------------------------------------------- */
/* Shared helpers                                                             */
/* -------------------------------------------------------------------------- */

function itemToData(item: AttackMethodCatalogueItem): Record<string, unknown> {
  return {
    id: item.id,
    name: item.name,
    layer: item.layer,
    protocol: item.protocol,
    mechanism: item.mechanism,
    resourceExhausted: item.resourceExhausted,
    preconditions: item.preconditions,
    observableSymptoms: item.observableSymptoms,
    telemetry: item.telemetry,
    packetCharacteristics: item.packetCharacteristics,
    expectedImpact: item.expectedImpact,
    commonFalsePositives: item.commonFalsePositives,
    defensiveDetectionStrategy: item.defensiveDetectionStrategy,
    mitigationTechniques: item.mitigationTechniques,
    references: item.references,
    relatedMalwareFamilies: item.relatedMalwareFamilies,
  };
}

function rankLabel(difficulty: string): string {
  return difficulty.toUpperCase();
}

/** A structure-only detection rule skeleton. Never an attack artefact. */
function suricataShape(item: AttackMethodCatalogueItem): string {
  return [
    `# Suricata detection shape (structure only) — ${item.name}`,
    `# Signal: ${item.defensiveDetectionStrategy.split(/[.;]/)[0]}`,
    'alert <proto> $EXTERNAL_NET any -> $HOME_NET <service_port> (',
    '  msg:"Possible <method> behaviour detected";',
    '  flow:stateless;',
    '  # Threshold is expressed as a policy placeholder, tuned to your baseline:',
    '  threshold: type threshold, track by_src, count <N>, seconds <WINDOW>;',
    '  classtype:attempted-dos; sid:<generate>; rev:1;)',
  ].join('\n');
}

function sigmaShape(item: AttackMethodCatalogueItem): string {
  return [
    `title: Possible ${item.name} Behaviour`,
    'status: experimental',
    'description: Structure-only shape. Correlate with a baseline; not a fixed threshold.',
    'logsource:',
    '  category: <firewall|flow|webserver|dns>',
    'detection:',
    '  selection:',
    '    # Map to the fields exposed by your telemetry, for example:',
    '    event_action: <value>',
    '    metric: <rate_or_cardinality_metric>',
    '  condition: selection | <aggregation_policy>',
    'falsepositives:',
  ]
    .concat(item.commonFalsePositives.map((fp) => `  - ${fp}`))
    .concat(['level: medium', '# pseudocode shape — adapt to your platform'])
    .join('\n');
}

function toDetectionRuleRecord(item: AttackMethodCatalogueItem): KnowledgeRecord {
  const now = new Date().toISOString();
  return {
    id: `delivery-detection:${item.id}`,
    category: 'network_detection_rule',
    title: `Detection guidance — ${item.name}`,
    identifiers: { attack_method: item.id },
    affectedVersions: [],
    fixedVersions: [],
    klass: 'detection-guidance',
    rootCause: item.defensiveDetectionStrategy,
    attackSurface: item.protocol,
    preconditions: [],
    publicExploitState: 'unknown',
    relatedMalwareFamilies: item.relatedMalwareFamilies,
    relatedMiraiVariants: [],
    relatedRecordIds: [`attack-method:${item.id}`],
    verification: 'statically_reviewed',
    confidence: 'inferred',
    license: 'public-research',
    provenance: [
      curatedProvenance('detection-guidance', `Defensive detection shape for ${item.name}`),
    ],
    evidence: [],
    tags: ['detection', 'network', item.layer, item.protocol.toLowerCase()],
    createdAt: now,
    updatedAt: now,
  };
}

function buildComparison(
  items: AttackMethodCatalogueItem[],
): { rows: Record<string, unknown>[]; markdown: string } {
  const rows = items.map((item) => ({
    id: item.id,
    name: item.name,
    networkLayer: item.layer,
    protocol: item.protocol,
    targetedResource: item.targetedResource,
    protocolBehaviour: item.protocolBehaviour,
    defensiveVisibility: item.defensiveVisibility,
    detectionDifficulty: item.detectionDifficulty,
    mitigationDifficulty: item.mitigationDifficulty,
    commonImplementationTraits: item.commonImplementationTraits,
    historicalEvolution: item.historicalEvolution,
    relatedCves: item.relatedCves,
    relatedMisconfigurations: item.relatedMisconfigurations,
  }));

  const header =
    '| Method | Layer | Targeted resource | Detection | Mitigation | Visibility |';
  const divider = '| --- | --- | --- | --- | --- | --- |';
  const body = items.map(
    (i) =>
      `| ${i.name} | ${i.layer} | ${i.targetedResource} | ${rankLabel(
        i.detectionDifficulty,
      )} | ${rankLabel(i.mitigationDifficulty)} | ${i.defensiveVisibility} |`,
  );
  return { rows, markdown: [header, divider, ...body].join('\n') };
}

/* -------------------------------------------------------------------------- */
/* Malware attack-module structural analysis helpers                           */
/* -------------------------------------------------------------------------- */

const TEXT_EXTENSIONS = new Set([
  '.c',
  '.h',
  '.cpp',
  '.cc',
  '.hpp',
  '.py',
  '.sh',
  '.go',
  '.rs',
  '.java',
  '.js',
  '.ts',
  '.txt',
  '.md',
  '.cfg',
  '.conf',
  '.ini',
  '.json',
  '.yaml',
  '.yml',
  '.mk',
  '.ld',
  '.s',
  '.asm',
  '.pl',
  '.lua',
]);

function collectFiles(root: string, maxFiles: number): string[] {
  const out: string[] = [];
  const stack: string[] = [root];
  while (stack.length > 0 && out.length < maxFiles) {
    const dir = stack.pop();
    if (!dir) break;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (out.length >= maxFiles) break;
      if (entry.name === 'node_modules' || entry.name === '.git') continue;
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        stack.push(full);
      } else if (entry.isFile()) {
        const ext = extname(entry.name).toLowerCase();
        if (TEXT_EXTENSIONS.has(ext) || ext === '') out.push(full);
      }
    }
  }
  return out;
}

function looksBinary(content: string): boolean {
  const sample = content.slice(0, 1024);
  return sample.includes('\u0000');
}

interface SourceFunction {
  name: string;
  file: string;
  line: number;
  params: string;
  role: string;
}

const FUNCTION_RE = /(?:^|\n)[ \t]*(?:static[ \t]+)?(?:[A-Za-z_][A-Za-z0-9_]*[\s\*]+)+([A-Za-z_][A-Za-z0-9_]*)[ \t]*\(([^;{}()]*)\)[ \t]*\{/g;

function classifyFunctionRole(name: string): string {
  const n = name.toLowerCase();
  if (/(checksum|csum|_sum|sum16|chksum)/.test(n)) return 'packet-integrity (checksum computation)';
  if (/(rand|random|rnd)/.test(n)) return 'field / payload randomisation';
  if (/(socket|conn|connect|bind)/.test(n)) return 'socket setup / connection handling';
  if (/(send|write|inject|sendto|xmit)/.test(n)) return 'packet emission';
  if (/(gre|tcp|udp|syn|ack|rst|dns|http|igmp|icmp|flood|kill)/.test(n)) {
    return 'attack-method implementation';
  }
  if (/^main$/.test(n)) return 'module entrypoint';
  if (/(config|table|parse|setup|resolve|scan)/.test(n)) return 'configuration handling';
  if (/(init|start|loop|run)/.test(n)) return 'initialisation / control loop';
  return 'support / utility';
}

interface ModuleAnalysis {
  files: string[];
  binarySkipped: string[];
  functions: SourceFunction[];
  markers: Record<string, string[]>;
}

const MARKER_PATTERNS: Record<string, RegExp> = {
  rawSocket: /\b(socket|SOCK_RAW|AF_INET|IPPROTO_TCP|IPPROTO_UDP|IPPROTO_GRE|IPPROTO_ICMP)\b/,
  headerControl: /\b(IP_HDRINCL|setsockopt|SO_BROADCAST|iptables|__attribute__)\b/,
  packetEmission: /\b(sendto|send|write|recvfrom|recv)\s*\(/,
  hpingLikeHelpers: /\b(hping|hping3|libnet|libpcap|pcap_open|scapy)\b/i,
  protocolStructs: /\b(struct\s+(iphdr|ip|tcphdr|udphdr|icmp|igmp)|ipv4_hdr|tcp_header|udp_header)\b/,
  greHelpers: /\b(gre|gre_?ip|gre_?eth|GRE_?IP|GRE_?ETH)\b/,
  stateMachine: /\b(for\s*\(|while\s*\(|loop|attack|do\s*\{)/,
  configHandling: /\b(get_config|config|table\[|lookup|atoi|Atoi|strtol|scanf|stdin|resolve)\b/,
  archConditionals: /\b(ARCH_|__mips__|__mipsel__|__arm__|__aarch64__|__x86_64__|__i386__|mipsel|mips|aarch64|armv7|arm)\b/,
};

function analyzeSourceFiles(files: string[]): ModuleAnalysis {
  const analysis: ModuleAnalysis = { files, binarySkipped: [], functions: [], markers: {} };
  for (const key of Object.keys(MARKER_PATTERNS)) analysis.markers[key] = [];

  for (const file of files) {
    let content: string;
    try {
      content = readFileSync(file, 'utf8');
    } catch {
      continue;
    }
    if (looksBinary(content)) {
      analysis.binarySkipped.push(file);
      continue;
    }

    // Function extraction with line numbers.
    const re = new RegExp(FUNCTION_RE.source, 'g');
    let match: RegExpExecArray | null;
    while ((match = re.exec(content)) !== null) {
      const name = match[1];
      if (!name || name === 'if' || name === 'for' || name === 'while' || name === 'switch') continue;
      const line = content.slice(0, match.index).split('\n').length;
      analysis.functions.push({
        name,
        file,
        line,
        params: (match[2] ?? '').trim(),
        role: classifyFunctionRole(name),
      });
    }

    // Marker scan: record the first occurrence line per marker.
    for (const [key, pattern] of Object.entries(MARKER_PATTERNS)) {
      const idx = content.search(pattern);
      if (idx >= 0) {
        const line = content.slice(0, idx).split('\n').length;
        analysis.markers[key]?.push(`${file}:${line}`);
      }
    }
  }
  return analysis;
}

/* -------------------------------------------------------------------------- */
/* Engine                                                                     */
/* -------------------------------------------------------------------------- */

export const attackMethodsEngine: EngineModule = {
  name: ENGINE,
  title: 'Attack Methods Intelligence',
  description:
    'Documented attack-method families, structural malware attack-module analysis, behaviour reporting, ' +
    'comparison matrices and defensive detection guidance. Analysis and defence only.',
  tools: [
    defineTool<
      { query?: string; layer?: AttackMethodLayer; protocol?: string; limit?: number },
      { total: number; returned: number; results: Record<string, unknown>[]; knowledgeRecords: number }
    >({
      name: 'attack_method_search',
      title: 'Attack method search',
      engine: ENGINE,
      description:
        'Search a curated catalogue of documented DoS attack-method families (§3.1) plus the knowledge base. ' +
        'Returns generic mechanism, exhausted resource, symptoms, telemetry and defensive guidance. ' +
        'Descriptions are qualitative; no operational parameters are provided.',
      capabilities: ['write_knowledge'],
      risk: 'safe',
      inputSchema: {
        query: z.string().min(1).optional().describe('Free-text query over the catalogue and knowledge base.'),
        layer: LAYER_ENUM.optional().describe('Restrict to a specific attack layer.'),
        protocol: z.string().min(1).optional().describe('Restrict to a protocol (e.g. TCP, DNS, HTTP).'),
        limit: z.number().int().min(1).max(100).optional().describe('Maximum results (default 20).'),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const seeded = seedAttackMethodCatalogue(ctx.knowledge);
        const results = searchCatalogue({
          query: input.query,
          layer: input.layer,
          protocol: input.protocol,
          limit: input.limit ?? 20,
        });
        for (const item of results) {
          addEvidence(ctx, {
            claim: `Catalogue entry retrieved: ${item.name} (${item.id}).`,
            prov: curatedProvenance('public-research', `Attack-method family ${item.id}`),
            confidence: 'confirmed',
            data: { id: item.id, layer: item.layer, protocol: item.protocol },
          });
        }
        const data = {
          total: ATTACK_METHOD_CATALOGUE.length,
          returned: results.length,
          results: results.map(itemToData),
          knowledgeRecords: seeded,
        };
        const lines = results.map(
          (i) => `- **${i.name}** (\`${i.id}\`) — ${i.layer}/${i.protocol}: ${i.resourceExhausted}`,
        );
        return finish({
          engine: ENGINE,
          tool: 'attack_method_search',
          startedAt: started,
          ctx,
          data,
          summary:
            `Catalogue covers ${ATTACK_METHOD_CATALOGUE.length} documented method families; ` +
            `${results.length} matched the query.\n` +
            (seeded > 0 ? `Seeded ${seeded} curated records into the knowledge base.\n` : '') +
            (lines.length ? lines.join('\n') : '_No matches._'),
        });
      },
    }),

    defineTool<
      { description: string },
      { candidates: ReturnType<typeof classifyDescription> }
    >({
      name: 'attack_method_classify',
      title: 'Attack method classify',
      engine: ENGINE,
      description:
        'Classify a free-text description of observed behaviour into ranked catalogue candidates with score, ' +
        'rationale and confidence, and recommend defensive detection strategies.',
      capabilities: [],
      risk: 'safe',
      inputSchema: {
        description: z.string().min(3).describe('Free-text description of observed network/service behaviour.'),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        seedAttackMethodCatalogue(ctx.knowledge);
        const candidates = classifyDescription(input.description, 5);
        if (candidates.length === 0) {
          ctx.evidence.warn('No catalogue keywords matched the description; broaden the description.');
        }
        for (const c of candidates) {
          const ref = addEvidence(ctx, {
            claim: `Candidate ${c.name} matched with score ${c.score}.`,
            prov: curatedProvenance('public-research', `Classification via keyword scoring`),
            confidence: c.confidence === 'inferred' ? 'inferred' : 'hypothesis',
            data: { id: c.id, score: c.score, keywords: c.matchedKeywords },
          });
          ctx.evidence.assert({
            statement: `The description is consistent with ${c.name} (score ${c.score}).`,
            status: c.confidence === 'inferred' ? 'researcher_interpretation' : 'hypothesis',
            confidence: c.confidence,
            producedBy: 'attack_method_classify',
            supporting: [ref],
          });
        }
        const lines = candidates.map(
          (c) =>
            `- **${c.name}** (\`${c.id}\`) score=${c.score} [${c.confidence}] — ${c.rationale}\n  - Detection: ${c.defensiveDetectionStrategy}`,
        );
        return finish({
          engine: ENGINE,
          tool: 'attack_method_classify',
          startedAt: started,
          ctx,
          data: { candidates },
          summary:
            `Classified description into ${candidates.length} candidate(s).\n` +
            (lines.length ? lines.join('\n') : '_No confident classification; provide more detail._'),
          warnings: candidates.map((c) => `Candidate ${c.id} is a ${c.confidence} match, not a confirmation.`),
        });
      },
    }),

    defineTool<
      { sourcePath: string; maxFiles?: number },
      {
        root: string;
        filesAnalyzed: number;
        binarySkipped: number;
        functions: SourceFunction[];
        roleMap: Record<string, string[]>;
        packetConstruction: Record<string, string[]>;
        protocolStructs: string[];
        stateMachine: string[];
        configHandling: string[];
        architectureSupport: string[];
        reusePatterns: string[];
        defensiveNotes: string[];
      }
    >({
      name: 'malware_attack_module_analyze',
      title: 'Malware attack-module analyze',
      engine: ENGINE,
      description:
        'Structurally analyse AUTHORIZED malware attack-module source (e.g. Mirai-style modules) without ' +
        'producing or improving attack code: maps functions to roles, identifies raw-socket/packet-construction ' +
        'approach, protocol structs, state machine, config handling, per-architecture differences and reuse ' +
        'patterns. Network access is never required; it explains what the code does and why.',
      capabilities: ['read_repo'],
      risk: 'safe',
      inputSchema: {
        sourcePath: z.string().min(1).describe('Workspace-relative path to the source directory or file.'),
        maxFiles: z.number().int().min(1).max(5000).optional().describe('Maximum files to scan (default 200).'),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const maxFiles = input.maxFiles ?? 200;
        const root = resolveWorkspacePath(input.sourcePath, true);
        const stat = statSync(root);
        const files = stat.isDirectory()
          ? collectFiles(root, maxFiles)
          : TEXT_EXTENSIONS.has(extname(root).toLowerCase()) || extname(root) === ''
            ? [root]
            : [];

        if (files.length === 0) {
          throw errors.notFound(`No analyzable source files under "${input.sourcePath}"`, { root });
        }

        const analysis = analyzeSourceFiles(files);

        // Map functions to roles.
        const roleMap: Record<string, string[]> = {};
        for (const fn of analysis.functions) {
          (roleMap[fn.role] ??= []).push(`${fn.name} @ ${fn.file}:${fn.line}`);
        }

        const packetConstruction: Record<string, string[]> = {};
        for (const [key, hits] of Object.entries(analysis.markers)) {
          if (hits.length > 0) packetConstruction[key] = hits;
        }

        const protocolStructs = analysis.markers.protocolStructs ?? [];
        const stateMachine = analysis.markers.stateMachine ?? [];
        const configHandling = analysis.markers.configHandling ?? [];
        const architectureSupport = analysis.markers.archConditionals ?? [];

        // Reuse detection: duplicate function names across different files.
        const byName = new Map<string, string[]>();
        for (const fn of analysis.functions) {
          (byName.get(fn.name) ?? byName.set(fn.name, []).get(fn.name)!)!.push(fn.file);
        }
        const reusePatterns: string[] = [];
        for (const [name, where] of byName) {
          const unique = [...new Set(where)];
          if (unique.length > 1) reusePatterns.push(`${name} duplicated across ${unique.length} files`);
        }

        const defensiveNotes: string[] = [
          'This report describes structure, not operation: no runnable attack code is emitted.',
          'Use the raw-socket and emission markers to write detectors (raw-socket creation, protocol-47 GRE, unusual TCP flag mixes).',
          'Map the attack methods found to the curated catalogue (attack_method_search) for detection and mitigation guidance.',
        ];

        const fnRefs: EvidenceRef[] = analysis.functions.slice(0, 40).map((fn) =>
          addEvidence(ctx, {
            claim: `Function ${fn.name}() classified as ${fn.role}.`,
            prov: localProvenance('malware-source', fn.file, 'static structural read'),
            confidence: 'observed',
            locator: { file: fn.file, line: fn.line, symbol: fn.name },
          }),
        );

        addEvidence(ctx, {
          claim: `Statically analysed ${files.length} source file(s) under ${root}.`,
          prov: localProvenance('malware-source', root),
          confidence: 'observed',
          data: { files: files.length, functions: analysis.functions.length },
        });

        const rawSocketRef = analysis.markers.rawSocket && analysis.markers.rawSocket.length > 0
          ? addEvidence(ctx, {
              claim: 'Module uses raw sockets / IP-protocol constants (raw packet construction).',
              prov: localProvenance('malware-source', analysis.markers.rawSocket[0] ?? root),
              confidence: 'observed',
              data: { hits: analysis.markers.rawSocket.slice(0, 5) },
            })
          : undefined;

        ctx.evidence.assert({
          statement: `The module implements ${analysis.functions.length} function(s) mapped to ${Object.keys(roleMap).length} role categories.`,
          status: 'direct_observation',
          confidence: 'observed',
          producedBy: 'malware_attack_module_analyze',
          supporting: fnRefs.slice(0, 10),
        });

        if (rawSocketRef) {
          ctx.evidence.assert({
            statement:
              'Packet construction is performed directly (raw sockets / explicit protocol headers), consistent with malware flood modules.',
            status: 'direct_observation',
            confidence: 'observed',
            producedBy: 'malware_attack_module_analyze',
            supporting: [rawSocketRef],
          });
        }

        ctx.evidence.assert({
          statement:
            'Function-role mapping and reuse conclusions are researcher interpretation of the source structure.',
          status: 'researcher_interpretation',
          confidence: 'inferred',
          producedBy: 'malware_attack_module_analyze',
        });

        const data = {
          root,
          filesAnalyzed: files.length,
          binarySkipped: analysis.binarySkipped.length,
          functions: analysis.functions,
          roleMap,
          packetConstruction,
          protocolStructs,
          stateMachine,
          configHandling,
          architectureSupport,
          reusePatterns,
          defensiveNotes,
        };

        const summaryLines = [
          `Analysed ${files.length} file(s); ${analysis.functions.length} function(s) identified.`,
          `Function roles: ${Object.entries(roleMap)
            .map(([role, fns]) => `${role} (${fns.length})`)
            .join(', ')}`,
          `Packet construction markers: ${Object.keys(packetConstruction).join(', ') || 'none detected'}.`,
          `Protocol structs: ${protocolStructs.length}, state-machine markers: ${stateMachine.length}, ` +
            `config-handling markers: ${configHandling.length}, architecture markers: ${architectureSupport.length}.`,
          `Reuse patterns: ${reusePatterns.length ? reusePatterns.join('; ') : 'none across files'}.`,
          '',
          '_Defensive understanding only; no operational attack code is produced._',
        ];

        return finish({
          engine: ENGINE,
          tool: 'malware_attack_module_analyze',
          startedAt: started,
          ctx,
          data,
          summary: summaryLines.join('\n'),
          warnings: analysis.binarySkipped.length
            ? [`${analysis.binarySkipped.length} binary file(s) skipped (text analysis only).`]
            : [],
        });
      },
    }),

    defineTool<
      { methodId?: string; observations?: string[]; pcapPath?: string },
      Record<string, unknown>
    >({
      name: 'attack_behavior_analyze',
      title: 'Attack behavior analyze',
      engine: ENGINE,
      description:
        'Produce the §3.3 behaviour artifact for a documented method: mechanism, exhausted resource, ' +
        'preconditions, symptoms, telemetry, packet characteristics, impact, false positives, detection and ' +
        'mitigation. Directly observed behaviour is separated from theoretical analysis.',
      capabilities: ['read_pcap'],
      risk: 'safe',
      inputSchema: {
        methodId: z.string().min(1).optional().describe('Catalogue method id (e.g. tcp_syn_flood).'),
        observations: z
          .array(z.string().min(1))
          .optional()
          .describe('Directly observed behaviour items from analysis of real telemetry.'),
        pcapPath: z.string().min(1).optional().describe('Optional workspace-relative PCAP for observed evidence.'),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        seedAttackMethodCatalogue(ctx.knowledge);

        const item = input.methodId ? getAttackMethod(input.methodId) : undefined;
        if (!item && (!input.observations || input.observations.length === 0) && !input.pcapPath) {
          throw errors.invalidInput(
            'Provide at least one of: methodId, observations, pcapPath.',
            { methodId: input.methodId ?? null, observations: input.observations?.length ?? 0 },
          );
        }

        // Directly observed evidence.
        const observedRefs: EvidenceRef[] = [];
        for (const obs of input.observations ?? []) {
          const ref = addEvidence(ctx, {
            claim: obs,
            prov: localProvenance('operator-observation', 'analysis-session', 'directly reported'),
            confidence: 'observed',
          });
          observedRefs.push(ref);
        }

        if (input.pcapPath) {
          try {
            const { readBinaryArtifact } = await import('../../tools/helpers.js');
            const artifact = readBinaryArtifact(input.pcapPath, 64);
            const magic = artifact.buffer.subarray(0, 4).toString('hex');
            const knownMagic = new Set(['d4c3b2a1', 'a1b2c3d4', '4d3cb2a1', 'a1b23c4d']);
            const isPcap = knownMagic.has(magic);
            const ref = addEvidence(ctx, {
              claim: `PCAP header inspected (magic=0x${magic}); recognised format: ${isPcap}.`,
              prov: localProvenance('pcap', artifact.path, 'header read only'),
              confidence: 'observed',
              locator: { file: artifact.path, offset: 0, packetBytes: 4 },
            });
            observedRefs.push(ref);
            if (!isPcap) {
              ctx.evidence.warn(`File "${input.pcapPath}" does not carry a recognised libpcap magic number.`);
            }
          } catch (err) {
            ctx.evidence.warn(`Could not read pcapPath: ${(err as Error).message}`);
          }
        }

        const observedBehaviour =
          input.observations && input.observations.length > 0
            ? input.observations
            : [];
        const theoreticalAnalysis = item
          ? {
              mechanism: item.mechanism,
              resourceExhausted: item.resourceExhausted,
              preconditions: item.preconditions,
              observableSymptoms: item.observableSymptoms,
              telemetry: item.telemetry,
              packetCharacteristics: item.packetCharacteristics,
              expectedImpact: item.expectedImpact,
              commonFalsePositives: item.commonFalsePositives,
              defensiveDetectionStrategy: item.defensiveDetectionStrategy,
              mitigationTechniques: item.mitigationTechniques,
              references: item.references,
              relatedMalwareFamilies: item.relatedMalwareFamilies,
            }
          : {};

        if (observedRefs.length > 0) {
          ctx.evidence.assert({
            statement: `${observedRefs.length} behaviour item(s) were directly observed.`,
            status: 'direct_observation',
            confidence: 'observed',
            producedBy: 'attack_behavior_analyze',
            supporting: observedRefs,
          });
        }
        if (item) {
          ctx.evidence.assert({
            statement: `Catalogue mechanism for ${item.name} is documented public research, separated from any direct observation.`,
            status: 'researcher_interpretation',
            confidence: 'confirmed',
            producedBy: 'attack_behavior_analyze',
          });
        }

        const data = {
          methodId: item?.id ?? input.methodId ?? null,
          methodName: item?.name ?? null,
          layer: item?.layer ?? null,
          protocol: item?.protocol ?? null,
          observedBehaviour,
          theoreticalAnalysis,
          separation: {
            directlyObserved: observedBehaviour,
            theoretical: Boolean(item),
            note: 'directlyObserved items come from operator/pcap evidence; theoreticalAnalysis is public-research documentation.',
          },
        };

        const summaryLines = [
          item ? `Method: **${item.name}** (\`${item.id}\`) — ${item.layer}/${item.protocol}` : 'Method: _not specified_',
          item ? `Mechanism: ${item.mechanism}` : '',
          item ? `Resource exhausted: ${item.resourceExhausted}` : '',
          observedBehaviour.length
            ? `\nDirectly observed (${observedBehaviour.length}):\n${observedBehaviour.map((o) => `- ${o}`).join('\n')}`
            : '\n_No directly observed behaviour supplied; report is theoretical only._',
          item
            ? `\nDetection: ${item.defensiveDetectionStrategy}\nMitigation: ${item.mitigationTechniques.join('; ')}`
            : '',
        ];

        return finish({
          engine: ENGINE,
          tool: 'attack_behavior_analyze',
          startedAt: started,
          ctx,
          data,
          summary: summaryLines.filter(Boolean).join('\n'),
        });
      },
    }),

    defineTool<
      { methodIds: string[] },
      { count: number; rows: Record<string, unknown>[]; markdown: string; unknown: string[] }
    >({
      name: 'attack_method_compare',
      title: 'Attack method compare',
      engine: ENGINE,
      description:
        'Build the §3.4 comparison matrix for a set of documented methods: network layer, targeted resource, ' +
        'protocol behaviour, defensive visibility, detection/mitigation difficulty, implementation traits, ' +
        'historical evolution and related CVEs/misconfigurations.',
      capabilities: [],
      risk: 'safe',
      inputSchema: {
        methodIds: z.array(z.string().min(1)).min(1).max(50).describe('Catalogue method ids to compare.'),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        seedAttackMethodCatalogue(ctx.knowledge);
        const found: AttackMethodCatalogueItem[] = [];
        const unknown: string[] = [];
        for (const id of input.methodIds) {
          const item = getAttackMethod(id);
          if (item) found.push(item);
          else unknown.push(id);
        }
        if (found.length === 0) {
          throw errors.notFound(`No catalogue methods matched: ${input.methodIds.join(', ')}`);
        }
        const { rows, markdown } = buildComparison(found);
        addEvidence(ctx, {
          claim: `Compared ${found.length} documented attack methods.`,
          prov: curatedProvenance('public-research', 'Comparison matrix (§3.4)'),
          confidence: 'confirmed',
          data: { methods: found.map((f) => f.id) },
        });
        if (unknown.length) ctx.evidence.warn(`Unknown method ids ignored: ${unknown.join(', ')}`);
        return finish({
          engine: ENGINE,
          tool: 'attack_method_compare',
          startedAt: started,
          ctx,
          data: { count: found.length, rows, markdown, unknown },
          summary:
            `Comparison matrix for ${found.length} method(s).\n\n${markdown}` +
            (unknown.length ? `\n\n_Unknown ids: ${unknown.join(', ')}_` : ''),
        });
      },
    }),

    defineTool<
      { methodIds?: string[]; context?: string },
      { count: number; recommendations: Record<string, unknown>[]; persistedRecords: string[] }
    >({
      name: 'attack_detection_recommend',
      title: 'Attack detection recommend',
      engine: ENGINE,
      description:
        'Generate DEFENSIVE detection recommendations for documented methods: concrete detection signals ' +
        '(rate thresholds described qualitatively), Suricata/Sigma rule SHAPES (structure only, non-destructive), ' +
        'logging/metrics to collect and false-positive tuning advice. Persists network_detection_rule records.',
      capabilities: ['write_knowledge'],
      risk: 'safe',
      inputSchema: {
        methodIds: z.array(z.string().min(1)).optional().describe('Catalogue method ids to cover.'),
        context: z.string().min(1).optional().describe('Deployment context to bias recommendations.'),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        seedAttackMethodCatalogue(ctx.knowledge);

        const targets: AttackMethodCatalogueItem[] =
          input.methodIds && input.methodIds.length > 0
            ? (input.methodIds.map(getAttackMethod).filter(Boolean) as AttackMethodCatalogueItem[])
            : ATTACK_METHOD_CATALOGUE;

        if (targets.length === 0) {
          throw errors.notFound('No catalogue methods matched the requested ids.');
        }

        const recommendations = targets.map((item) => {
          const signals = [
            ...item.telemetry,
            `Baseline deviation in ${item.targetedResource} utilisation.`,
          ];
          return {
            methodId: item.id,
            name: item.name,
            detectionSignals: signals,
            suricataShape: suricataShape(item),
            sigmaShape: sigmaShape(item),
            loggingAndMetrics: item.telemetry,
            falsePositiveTuning: item.commonFalsePositives,
            mitigationTechniques: item.mitigationTechniques,
            context: input.context ?? null,
          };
        });

        const persistedRecords: string[] = [];
        for (const item of targets) {
          const record = toDetectionRuleRecord(item);
          ctx.knowledge.upsertRecord(record);
          persistedRecords.push(record.id);
        }

        addEvidence(ctx, {
          claim: `Produced defensive detection recommendations for ${targets.length} method(s).`,
          prov: curatedProvenance('detection-guidance', input.context ?? 'general deployment'),
          confidence: 'inferred',
          data: { count: targets.length },
        });

        const summaryLines = targets.map(
          (item) =>
            `### ${item.name} (\`${item.id}\`)\n` +
            `Signals: ${item.telemetry.slice(0, 3).join('; ')}.\n` +
            `False positives: ${item.commonFalsePositives.slice(0, 2).join('; ')}.\n` +
            '```\n' +
            suricataShape(item) +
            '\n```',
        );

        return finish({
          engine: ENGINE,
          tool: 'attack_detection_recommend',
          startedAt: started,
          ctx,
          data: { count: recommendations.length, recommendations, persistedRecords },
          summary:
            `Defensive detection recommendations for ${targets.length} method(s). ` +
            `Rule shapes are structure-only (non-destructive detections). ` +
            `Persisted ${persistedRecords.length} network_detection_rule record(s).\n\n` +
            summaryLines.join('\n\n'),
        });
      },
    }),
  ],
};

/** Re-exported for documentation and tests. */
export { ATTACK_METHOD_CATALOGUE } from './catalogue.js';
