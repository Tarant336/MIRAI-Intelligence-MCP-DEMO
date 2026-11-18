/**
 * Multi-agent research engine (§8 + §11).
 *
 * This engine implements the multi-agent *architecture* described in §8: a set
 * of specialist agent roles plus an orchestrator that decomposes tasks, produces
 * structured briefs, merges findings and reconciles conflicting results over the
 * shared evidence base.
 *
 * It does NOT spawn LLM agents. The roles are role definitions and the tools are
 * orchestration over evidence already collected in the knowledge base: plans,
 * briefs, merged finding sets, reconciliation reports, gap analysis and audits.
 * Everything is defensive research support.
 */

import { z } from 'zod';

import { errors } from '../../core/errors.js';
import { addEvidence, curatedProvenance, defineTool, finish } from '../../tools/helpers.js';
import { aggregateConfidence } from '../../shared/evidence.js';
import { getKnowledgeBase, type KnowledgeRecord } from '../../shared/knowledge-base.js';
import type { ConfidenceLevel, EpistemicStatus, EvidenceRef } from '../../shared/types.js';
import type { EngineModule } from '../../core/tool.js';

const ENGINE = 'multi-agent';

/* -------------------------------------------------------------------------- */
/* Tool catalogue                                                              */
/* -------------------------------------------------------------------------- */

/**
 * Catalogue of platform tool names the orchestrator may assign to a sub-task.
 * These are references to tools provided by the platform's engines (grouped by
 * area); the multi-agent engine itself only plans and reasons over evidence.
 */
const TOOL_CATALOGUE: Record<string, string[]> = {
  platform: ['environment_report', 'health_check'],
  knowledge: [
    'knowledge_search',
    'knowledge_ingest',
    'knowledge_update',
    'evidence_graph_query',
    'source_provenance_check',
    'research_report_generate',
    'research_checkpoint',
    'curated_dataset_search',
    'curated_dataset_ingest',
    'curated_dataset_stats',
  ],
  software: [
    'repository_read',
    'repository_search',
    'symbol_search',
    'build_project',
    'run_tests',
    'debug_project',
    'regression_test',
    'code_quality_report',
    'project_memory',
    'documentation_search',
    'dependency_analyze',
    'architecture_analyze',
  ],
  vulnerability: [
    'cve_search',
    'cwe_search',
    'advisory_search',
    'vulnerability_analyze',
    'patch_diff_analyze',
    'exploit_search',
    'exploit_analyze',
    'safe_validation_generate',
  ],
  zero_day: [
    'zero_day_discovery_analyze',
    'vulnerability_hypothesis_generate',
    'vulnerability_hypothesis_rank',
    'source_vulnerability_analyze',
    'binary_vulnerability_analyze',
    'firmware_vulnerability_analyze',
    'static_analysis_run',
    'fuzz_target_identify',
    'fuzz_harness_generate',
    'fuzzing_crash_analyze',
    'crash_root_cause_analyze',
    'vulnerability_verify',
    'patch_root_cause_analyze',
    'vulnerability_variant_hunt',
    'zero_day_lifecycle_update',
    'zero_day_research_report',
  ],
  malware: [
    'malware_search',
    'malware_analyze',
    'mirai_variant_search',
    'yara_rule_search',
    'sigma_rule_search',
    'nuclei_template_search',
    'ai_malware_search',
  ],
  binary: ['elf_analyze', 'binary_strings', 'binary_decompile', 'emulation_plan'],
  firmware: ['firmware_analyze', 'firmware_extract', 'firmware_component_search'],
  network: [
    'pcap_analyze',
    'flow_summarize',
    'protocol_fingerprint',
    'c2_beacon_detect',
    'ioc_extract',
    'network_timeline_reconstruct',
    'network_traffic_analyze',
  ],
  defense: [
    'attack_method_search',
    'anti_ddos_analyze',
    'mitigation_strategy_compare',
    'rate_limit_design',
    'detection_rule_generate',
    'honeypot_status',
  ],
  orchestration: [
    'agent_roles_list',
    'orchestrator_plan',
    'agent_brief_generate',
    'agent_findings_merge',
    'evidence_reconciliation',
    'missing_evidence_identify',
    'research_audit',
  ],
};

function catalogueFor(areas: keyof typeof TOOL_CATALOGUE | Array<keyof typeof TOOL_CATALOGUE>): string[] {
  const list = Array.isArray(areas) ? areas : [areas];
  return list.flatMap((a) => TOOL_CATALOGUE[a] ?? []);
}

/* -------------------------------------------------------------------------- */
/* Agent role definitions (§8)                                                 */
/* -------------------------------------------------------------------------- */

interface AgentRole {
  id: string;
  title: string;
  responsibility: string;
  inputs: string[];
  outputs: string[];
  appropriateFor: string[];
  methods: string[];
  requiredEvidence: string[];
  outputSchema: Record<string, string>;
  verification: string[];
}

const ROLES: AgentRole[] = [
  {
    id: 'software-architect',
    title: 'Software Architect',
    responsibility:
      'Translate the research objective into a concrete, dependency-ordered plan, define module boundaries and interfaces, and decide which specialists are actually required.',
    inputs: ['Research objective', 'Constraints and scope', 'Available platform capabilities'],
    outputs: ['Decomposition plan', 'Module/interface design', 'Risk and dependency list'],
    appropriateFor: ['scoping a complex task', 'designing a tool or pipeline', 'deciding agent count'],
    methods: ['Constraints analysis', 'Interface definition', 'Dependency ordering', 'Reuse-first design'],
    requiredEvidence: ['Stated objective', 'Documented platform capabilities'],
    outputSchema: { plan: 'ordered sub-tasks', interfaces: 'module contracts', dependencies: 'edge list' },
    verification: ['Each sub-task has one owner', 'No sub-task lacks a completion criterion'],
  },
  {
    id: 'senior-source-engineer',
    title: 'Senior Source Engineer',
    responsibility:
      'Implement, modify or refactor source code to satisfy the objective, following the project’s existing patterns and keeping changes minimal and reviewable.',
    inputs: ['Design/interface contract', 'Existing source files'],
    outputs: ['Source changes', 'Build-relevant notes', 'Regression checklist'],
    appropriateFor: ['writing or fixing code', 'adding tests', 'refactoring'],
    methods: ['Read existing code first', 'Small incremental edits', 'Mirror existing style'],
    requiredEvidence: ['File paths and line locators', 'Build/test results'],
    outputSchema: { changes: 'path + summary', tests: 'added/updated', risks: 'list' },
    verification: ['Change compiles', 'Tests pass', 'No unrelated edits'],
  },
  {
    id: 'code-reviewer',
    title: 'Code Reviewer',
    responsibility:
      'Review changes for correctness, maintainability, performance and adherence to project conventions; report structured findings with severity.',
    inputs: ['Diff or changed files', 'Project conventions'],
    outputs: ['Findings list with severity', 'Approve/request-changes verdict'],
    appropriateFor: ['reviewing code changes', 'quality assessment'],
    methods: ['Correctness review', 'Convention check', 'Edge-case inspection'],
    requiredEvidence: ['File + line evidence for every finding'],
    outputSchema: { findings: 'severity + location + rationale', verdict: 'pass/fail' },
    verification: ['Every finding cites a location', 'No speculative findings without evidence'],
  },
  {
    id: 'build-debug-engineer',
    title: 'Build & Debug Engineer',
    responsibility:
      'Make the code build and run, reproduce failures, isolate root causes and confirm fixes with tests.',
    inputs: ['Source tree', 'Build/test commands'],
    outputs: ['Build fixes', 'Reproduction steps', 'Root-cause note'],
    appropriateFor: ['build failures', 'runtime bugs', 'flaky tests'],
    methods: ['Reproduce first', 'Bisect', 'Minimal fix'],
    requiredEvidence: ['Command output', 'Failing/passing test evidence'],
    outputSchema: { reproduction: 'steps', rootCause: 'statement', fix: 'change', verification: 'test result' },
    verification: ['Root cause is demonstrated, not guessed', 'Fix verified by a test'],
  },
  {
    id: 'documentation-researcher',
    title: 'Documentation Researcher',
    responsibility:
      'Gather authoritative documentation and prior art for the objective, and summarise what is established versus what remains unknown.',
    inputs: ['Research question', 'Available documentation/records'],
    outputs: ['Annotated source list', 'Established facts summary', 'Open questions'],
    appropriateFor: ['understanding an API/format', 'finding prior art'],
    methods: ['Primary-source preference', 'Cross-checking multiple sources'],
    requiredEvidence: ['Citation/URL per claim', 'Retrieval timestamps'],
    outputSchema: { sources: 'title + url', facts: 'list', gaps: 'list' },
    verification: ['Every fact is sourced', 'No unsourced assertions'],
  },
  {
    id: 'vulnerability-researcher',
    title: 'Vulnerability Researcher',
    responsibility:
      'Characterise vulnerabilities (CVE/CWE), their root cause, affected products and preconditions, strictly for defensive analysis.',
    inputs: ['Vulnerability identifiers', 'Vendor advisories', 'Patch references'],
    outputs: ['Vulnerability profile', 'Root cause + preconditions', 'Detection/mitigation pointers'],
    appropriateFor: ['CVE analysis', 'patch analysis', 'detection engineering input'],
    methods: ['Advisory corroboration', 'Root-cause reading', 'Version mapping'],
    requiredEvidence: ['Advisory/NVD source', 'Patch or fixed-version reference'],
    outputSchema: { cve: 'identifier', rootCause: 'statement', affected: 'products/versions', fixed: 'versions' },
    verification: ['Identifier verified against an authoritative source', 'No invented versions'],
  },
  {
    id: 'zero-day-discovery-specialist',
    title: 'Zero-Day Discovery Specialist',
    responsibility:
      'Discover and triage previously-unrecognized vulnerability candidates in source, binary or firmware, and track them through the zero-day lifecycle without assuming any candidate is a confirmed vulnerability.',
    inputs: ['Target artifact (source tree, binary or firmware image)', 'Known vulnerability classes', 'Stored knowledge and hypotheses'],
    outputs: ['Candidate discovery report', 'Prioritized vulnerability hypotheses', 'Lifecycle state records'],
    appropriateFor: ['zero-day candidate discovery', 'hypothesis generation and ranking'],
    methods: ['Attack-surface enumeration', 'Pattern/heuristic analysis', 'Hypothesis lifecycle management'],
    requiredEvidence: ['Artifact hash/path', 'File + function + line locator per candidate', 'Confidence and verification status per hypothesis'],
    outputSchema: { candidates: 'list', hypotheses: 'ranked list', lifecycle: 'state per candidate' },
    verification: ['Every candidate links to a concrete location', 'No candidate asserted as verified without evidence'],
  },
  {
    id: 'static-analysis-specialist',
    title: 'Static Analysis Specialist',
    responsibility:
      'Perform static vulnerability analysis over source, binary and firmware: unsafe patterns, data/control-flow reasoning and boundary identification, clearly labelling heuristic findings as hypotheses, not proof.',
    inputs: ['Source/binary/firmware artifact', 'Static analysis tool output'],
    outputs: ['Static analysis findings', 'Trust/input boundary notes', 'Prioritized review list'],
    appropriateFor: ['source vulnerability review', 'binary/firmware static triage'],
    methods: ['Heuristic pattern matching', 'Boundary identification', 'Severity/confidence ranking'],
    requiredEvidence: ['Artifact hash/path', 'File/function/offset locators', 'Tool or rule id for each finding'],
    outputSchema: { findings: 'rule + location + severity', boundaries: 'list', reviewOrder: 'list' },
    verification: ['Each finding cites a location and rule', 'Heuristic results not reported as verified'],
  },
  {
    id: 'fuzzing-crash-analyst',
    title: 'Fuzzing & Crash Analyst',
    responsibility:
      'Identify fuzz targets, generate analysis-only harness skeletons, and triage crashes to distinguish plain bugs from security-relevant vulnerabilities, performing root-cause reconstruction.',
    inputs: ['Fuzzing target/component', 'Crash artifacts', 'Stack traces'],
    outputs: ['Fuzz target and harness plan', 'Crash triage classifications', 'Root-cause reconstruction notes'],
    appropriateFor: ['fuzz target identification', 'crash triage', 'root cause analysis'],
    methods: ['Target enumeration', 'Crash normalization and deduplication', 'Crash classification and root-cause reasoning'],
    requiredEvidence: ['Crash artifact/hash', 'Stack trace and fault location', 'Reproducibility notes'],
    outputSchema: { targets: 'list', crashes: 'classified list', rootCause: 'statement + confidence' },
    verification: ['Crash vs bug vs vulnerability is justified', 'Root cause is demonstrated, not asserted'],
  },
  {
    id: 'vulnerability-root-cause-analyst',
    title: 'Vulnerability Root Cause Analyst',
    responsibility:
      'Reconstruct the technical root cause of a vulnerability or crash from source, binary, patch or crash artifacts, and identify the exact triggering condition and affected code path.',
    inputs: ['Vulnerability/crash artifacts', 'Patch or source/binary'],
    outputs: ['Root-cause reconstruction', 'Triggering preconditions', 'Affected code path'],
    appropriateFor: ['root cause analysis', 'patch analysis', 'crash reconstruction'],
    methods: ['Diff analysis', 'Code-path tracing', 'Precondition reconstruction'],
    requiredEvidence: ['Crash/patch/source locator', 'Stack trace or diff', 'Reproduction conditions'],
    outputSchema: { rootCause: 'statement', preconditions: 'list', affectedPath: 'locations' },
    verification: ['Root cause demonstrated, not asserted', 'Triggering condition is concrete'],
  },
  {
    id: 'exploit-intelligence-analyst',
    title: 'Exploit Intelligence Analyst',
    responsibility:
      'Assess the *state* of public exploitation (none / PoC public / weaponized in the wild) and its defensive implications, without producing offensive capability.',
    inputs: ['Vulnerability profile', 'Public reporting', 'Vendor telemetry summaries'],
    outputs: ['Exploitation state assessment', 'Detection opportunities'],
    appropriateFor: ['prioritising patching', 'detection scoping'],
    methods: ['Corroborate exploitation claims across sources', 'Distinguish PoC from in-the-wild'],
    requiredEvidence: ['Source for each exploitation claim'],
    outputSchema: { state: 'unknown|none|poc_public|weaponized_in_wild', sources: 'list', detection: 'list' },
    verification: ['State is sourced, not assumed', 'PoC never equated with in-the-wild use'],
  },
  {
    id: 'mirai-malware-analyst',
    title: 'Mirai Malware Analyst',
    responsibility:
      'Analyse Mirai-lineage families and variants: lineage, propagation, C2 model and detection artefacts, using curated references and samples.',
    inputs: ['Sample references', 'Curated variant dataset', 'Stored knowledge records'],
    outputs: ['Family/variant profile', 'Propagation + C2 model', 'Detection artefacts'],
    appropriateFor: ['Mirai variant identification', 'botnet family comparison'],
    methods: ['Lineage comparison', 'IOC extraction', 'Cross-reference sample hashes'],
    requiredEvidence: ['Sample hash/identifier', 'Source for family attribution'],
    outputSchema: { family: 'name', lineage: 'derived_from', propagation: 'list', c2: 'model', iocs: 'list' },
    verification: ['Attribution is sourced', 'Distinguish confirmed lineage from inference'],
  },
  {
    id: 'malware-source-code-analyst',
    title: 'Malware Source Code Analyst',
    responsibility:
      'Analyse malware source code in depth: repository structure, module dependency, function-level behaviour and configuration handling, citing exact file/function/symbol locations.',
    inputs: ['Malware source tree', 'Build/configuration files'],
    outputs: ['Source architecture report', 'Function/module analysis', 'Configuration-format analysis'],
    appropriateFor: ['malware source review', 'configuration extraction', 'code reuse detection'],
    methods: ['Structure mapping', 'Function-level reading', 'Configuration parsing'],
    requiredEvidence: ['File/function/symbol locators', 'Build/configuration artifacts'],
    outputSchema: { structure: 'module map', functions: 'list', config: 'format description' },
    verification: ['Every claim cites a source location', 'No behaviour asserted without code evidence'],
  },
  {
    id: 'malware-variant-analyst',
    title: 'Malware Variant Analyst',
    responsibility:
      'Compare malware variants and reconstruct lineage via source, binary and configuration similarity, distinguishing confirmed lineage from inference.',
    inputs: ['Variant samples/sources', 'Family references'],
    outputs: ['Variant comparison matrix', 'Lineage reconstruction', 'Similarity scores'],
    appropriateFor: ['variant comparison', 'family clustering', 'lineage attribution'],
    methods: ['Function-level comparison', 'Configuration diffing', 'Similarity scoring'],
    requiredEvidence: ['Sample/source hashes', 'Diff or similarity evidence'],
    outputSchema: { variants: 'list', lineage: 'tree', similarity: 'scores' },
    verification: ['Lineage is evidence-backed', 'Confirmed vs inferred separated'],
  },
  {
    id: 'reverse-engineering-specialist',
    title: 'Reverse Engineering Specialist',
    responsibility:
      'Statically characterise binaries (architecture, strings, imports, control flow) for defensive understanding; dynamic execution only in an isolated sandbox.',
    inputs: ['Binary sample', 'Analysis tooling'],
    outputs: ['Static analysis report', 'Extracted indicators', 'Behavioural hypotheses'],
    appropriateFor: ['binary triage', 'string/indicator extraction'],
    methods: ['Static-first', 'Emulation in isolation where authorised'],
    requiredEvidence: ['Sample hash', 'Tool output locators (offset/symbol)'],
    outputSchema: { arch: 'string', strings: 'list', indicators: 'list', hypothesis: 'list' },
    verification: ['Static conclusions separated from dynamic', 'Sample handled in isolation'],
  },
  {
    id: 'firmware-analyst',
    title: 'Firmware Analyst',
    responsibility:
      'Analyse embedded firmware images: extraction, filesystem inspection, component/version identification and known-vulnerability mapping.',
    inputs: ['Firmware image', 'Extraction tooling'],
    outputs: ['Firmware inventory', 'Component/version list', 'Vulnerability mapping'],
    appropriateFor: ['router/IoT firmware analysis', 'supply-chain review'],
    methods: ['Image extraction', 'Filesystem inspection', 'Version fingerprinting'],
    requiredEvidence: ['Image hash', 'Extracted component paths'],
    outputSchema: { components: 'name + version', services: 'list', vulnerabilities: 'cve list' },
    verification: ['Versions read from artefacts, not guessed', 'Emulation is isolated'],
  },
  {
    id: 'network-forensics-analyst',
    title: 'Network Forensics Analyst',
    responsibility:
      'Reconstruct network activity from captures: flows, protocols, C2/beacon patterns, IOCs and a timeline.',
    inputs: ['Packet captures / flow records', 'Flow analysis tooling'],
    outputs: ['Flow summary', 'Protocol fingerprints', 'IOC list', 'Timeline'],
    appropriateFor: ['pcap analysis', 'beacon detection', 'traffic timeline'],
    methods: ['Flow aggregation', 'Protocol fingerprinting', 'Periodicity analysis'],
    requiredEvidence: ['Capture reference', 'Flow/packet locators'],
    outputSchema: { flows: 'summary', protocols: 'list', iocs: 'list', timeline: 'events' },
    verification: ['Indicators traceable to packets', 'Benign baseline considered'],
  },
  {
    id: 'protocol-reverse-engineer',
    title: 'Protocol Reverse Engineer',
    responsibility:
      'Reconstruct unknown protocol message structures, encoding, command identifiers and state machines from captures, source or binary, producing a documented protocol specification.',
    inputs: ['Packet captures', 'Protocol implementation source/binary'],
    outputs: ['Message structure', 'State machine', 'Protocol specification'],
    appropriateFor: ['protocol reconstruction', 'C2 protocol research', 'message format inference'],
    methods: ['Field inference', 'State-machine reconstruction', 'Encoding analysis'],
    requiredEvidence: ['Capture/source locators', 'Field boundaries and sample bytes'],
    outputSchema: { messages: 'field layouts', states: 'transition graph', spec: 'document' },
    verification: ['Field boundaries are evidence-based', 'No protocol asserted without samples'],
  },
  {
    id: 'attack-method-research-analyst',
    title: 'Attack-Method Research Analyst',
    responsibility:
      'Describe attack methods at a conceptual/defensive level (what the technique is and how to detect it) WITHOUT providing operational attack capability.',
    inputs: ['Technique references', 'Public reporting'],
    outputs: ['Technique description', 'Detection and mitigation pointers'],
    appropriateFor: ['understanding a technique for defence', 'detection scoping'],
    methods: ['Conceptual description', 'Mapping to detection',
    ],
    requiredEvidence: ['Public source per technique'],
    outputSchema: { technique: 'description', detection: 'list', mitigation: 'list' },
    verification: ['No operational capability produced', 'Defensive framing only'],
  },
  {
    id: 'anti-ddos-research-engineer',
    title: 'Anti-DDoS Research Engineer',
    responsibility:
      'Design and compare DDoS mitigation and rate-limiting strategies appropriate to the observed attack profile.',
    inputs: ['Attack profile', 'Traffic characteristics'],
    outputs: ['Mitigation options compared', 'Rate-limit design', 'Detection rules'],
    appropriateFor: ['mitigation design', 'rate limiting', 'detection engineering'],
    methods: ['Option trade-off analysis', 'Threshold sizing from observed baselines'],
    requiredEvidence: ['Observed attack characteristics', 'Baseline traffic reference'],
    outputSchema: { options: 'compared', recommendation: 'statement', rules: 'list' },
    verification: ['Recommendations follow from observed data', 'False-positive impact considered'],
  },
  {
    id: 'ai-malware-research-analyst',
    title: 'AI-Malware Research Analyst',
    responsibility:
      'Study AI/LLM-assisted malware trends and detection-resilience implications, defensively and without generating malicious capability.',
    inputs: ['Published research', 'Curated references'],
    outputs: ['Trend assessment', 'Detection implications'],
    appropriateFor: ['AI-enabled threat trend analysis', 'detection resilience'],
    methods: ['Literature review', 'Capability/impact assessment'],
    requiredEvidence: ['Published source per claim'],
    outputSchema: { trend: 'description', implications: 'list', sources: 'list' },
    verification: ['Claims are sourced', 'No malicious capability generated'],
  },
  {
    id: 'evidence-verification-auditor',
    title: 'Evidence & Verification Auditor',
    responsibility:
      'Independently audit the evidence base: check provenance, verification state and confidence, and flag cross-source contradictions or unsupported conclusions.',
    inputs: ['Evidence base / knowledge records', 'Assertions'],
    outputs: ['Audit findings', 'Pass/fail assessment', 'Required corrections'],
    appropriateFor: ['final review', 'quality gate before reporting'],
    methods: ['Provenance completeness check', 'Confidence vs claim strength check', 'Contradiction detection'],
    requiredEvidence: ['Record ids', 'Provenance entries'],
    outputSchema: { findings: 'severity + record + issue', verdict: 'pass/fail' },
    verification: ['Every finding cites a record', 'No conclusion outranks its evidence'],
  },
  {
    id: 'threat-intelligence-analyst',
    title: 'Threat Intelligence Analyst',
    responsibility:
      'Correlate threat intelligence across malware, vulnerability, exploit and network sources into evidence-backed assessments, distinguishing fact from hypothesis and inference.',
    inputs: ['Threat data sources', 'Knowledge records'],
    outputs: ['Correlated intelligence report', 'IOC/indicator set', 'Confidence-scored assessments'],
    appropriateFor: ['threat correlation', 'IOC consolidation', 'campaign assessment'],
    methods: ['Cross-source correlation', 'Duplicate detection', 'Confidence scoring'],
    requiredEvidence: ['Source per claim', 'Record identifiers', 'Provenance'],
    outputSchema: { correlations: 'list', iocs: 'list', assessments: 'confidence-scored' },
    verification: ['Every claim sourced', 'Fact/hypothesis/inference distinguished'],
  },
];

const ROLE_BY_ID = new Map(ROLES.map((r) => [r.id, r]));

/* -------------------------------------------------------------------------- */
/* Orchestration workstreams                                                   */
/* -------------------------------------------------------------------------- */

interface Workstream {
  id: string;
  roleId: string;
  title: string;
  /** Objective template; "{{task}}" is replaced with the task text. */
  objective: string;
  method: string;
  requiredTools: string[];
  expectedEvidence: string[];
  completionCriteria: string[];
  dependsOn: string[];
  keywords: string[];
}

const WORKSTREAMS: Workstream[] = [
  {
    id: 'intake',
    roleId: 'software-architect',
    title: 'Scope and plan the task',
    objective: 'Scope the objective "{{task}}", fix the boundaries and produce the dependency-ordered plan.',
    method: 'Clarify objective and constraints, decide which specialists are needed, avoid over-spawning.',
    requiredTools: catalogueFor(['platform', 'knowledge']),
    expectedEvidence: ['Stated objective', 'Assumptions and out-of-scope list'],
    completionCriteria: ['Objective restated', 'Every sub-task has an owner and a completion criterion'],
    dependsOn: [],
    keywords: [],
  },
  {
    id: 'doc-research',
    roleId: 'documentation-researcher',
    title: 'Documentation and prior-art research',
    objective: 'Collect authoritative documentation and prior art relevant to "{{task}}".',
    method: 'Prefer primary sources; cross-check at least two sources per established fact.',
    requiredTools: catalogueFor(['software', 'knowledge']),
    expectedEvidence: ['Annotated source list with URLs', 'Established vs unknown summary'],
    completionCriteria: ['Each fact sourced', 'Open questions listed'],
    dependsOn: ['intake'],
    keywords: ['document', 'docs', 'api', 'understand', 'read', 'spec', 'format', 'protocol'],
  },
  {
    id: 'source-impl',
    roleId: 'senior-source-engineer',
    title: 'Source implementation',
    objective: 'Implement or modify source code to satisfy "{{task}}".',
    method: 'Read existing code first, make minimal edits and mirror project conventions.',
    requiredTools: catalogueFor('software'),
    expectedEvidence: ['Changed file paths', 'Build result'],
    completionCriteria: ['Change compiles', 'Scope limited to the objective'],
    dependsOn: ['intake', 'doc-research'],
    keywords: ['implement', 'code', 'fix', 'feature', 'refactor', 'write', 'module', 'function'],
  },
  {
    id: 'build-debug',
    roleId: 'build-debug-engineer',
    title: 'Build and debug',
    objective: 'Make the project build and behave correctly for "{{task}}", reproducing and isolating failures.',
    method: 'Reproduce, bisect, apply a minimal fix and verify with tests.',
    requiredTools: catalogueFor('software'),
    expectedEvidence: ['Command output', 'Failing/passing test evidence'],
    completionCriteria: ['Reproduction documented', 'Fix verified by a test'],
    dependsOn: ['source-impl'],
    keywords: ['build', 'compile', 'debug', 'test', 'fail', 'error', 'crash', 'regression'],
  },
  {
    id: 'code-review',
    roleId: 'code-reviewer',
    title: 'Code review',
    objective: 'Review changes made for "{{task}}" for correctness, quality and convention adherence.',
    method: 'Line-level review with severity, evidence and an approve/request-changes verdict.',
    requiredTools: catalogueFor('software'),
    expectedEvidence: ['Findings with file/line evidence'],
    completionCriteria: ['Every finding located', 'Verdict recorded'],
    dependsOn: ['source-impl', 'build-debug'],
    keywords: ['review', 'quality', 'audit', 'convention', 'maintainability'],
  },
  {
    id: 'vuln-research',
    roleId: 'vulnerability-researcher',
    title: 'Vulnerability research',
    objective: 'Characterise the vulnerabilities relevant to "{{task}}" (CVE/CWE, root cause, preconditions).',
    method: 'Corroborate advisories, read root cause, map affected/fixed versions.',
    requiredTools: catalogueFor(['vulnerability', 'knowledge']),
    expectedEvidence: ['Advisory/NVD sources', 'Patch or fixed-version reference'],
    completionCriteria: ['Identifiers verified', 'No invented versions'],
    dependsOn: ['intake'],
    keywords: ['vulnerab', 'cve', 'cwe', 'patch', 'advisory', 'security', 'exposure', 'router', 'device'],
  },
  {
    id: 'zero-day-discovery',
    roleId: 'zero-day-discovery-specialist',
    title: 'Zero-day candidate discovery',
    objective: 'Discover and prioritize previously-unrecognized vulnerability candidates relevant to "{{task}}".',
    method: 'Enumerate the attack surface, apply heuristic patterns and generate ranked hypotheses without asserting verification.',
    requiredTools: catalogueFor(['zero_day', 'knowledge']),
    expectedEvidence: ['Artifact hash/path', 'File + function + line locators', 'Ranked hypotheses with confidence'],
    completionCriteria: ['Candidates linked to concrete locations', 'Hypotheses not reported as verified'],
    dependsOn: ['intake'],
    keywords: ['zero-day', 'zero day', '0day', 'undisclosed', 'hypothesis', 'candidate', 'discovery'],
  },
  {
    id: 'static-analysis',
    roleId: 'static-analysis-specialist',
    title: 'Static vulnerability analysis',
    objective: 'Statically analyze the source, binary or firmware relevant to "{{task}}" for unsafe patterns and trust/input boundaries.',
    method: 'Run heuristic static analysis, identify boundaries and rank findings by severity and confidence.',
    requiredTools: catalogueFor(['zero_day', 'binary', 'knowledge']),
    expectedEvidence: ['Artifact hash/path', 'Rule + location per finding', 'Boundary notes'],
    completionCriteria: ['Each finding cites a location and rule', 'Heuristic results labelled as hypotheses'],
    dependsOn: ['zero-day-discovery'],
    keywords: ['static analysis', 'static-analysis', 'codeql', 'semgrep', 'data flow', 'control flow', 'taint', 'unsafe pattern'],
  },
  {
    id: 'fuzz-crash-triage',
    roleId: 'fuzzing-crash-analyst',
    title: 'Fuzzing and crash triage',
    objective: 'Identify fuzz targets, generate analysis-only harness skeletons and triage crashes relevant to "{{task}}".',
    method: 'Enumerate targets, normalize and deduplicate crashes, classify crash vs bug vs vulnerability and reconstruct root cause.',
    requiredTools: catalogueFor(['zero_day', 'knowledge']),
    expectedEvidence: ['Crash artifact/hash', 'Stack trace/fault location', 'Root-cause notes with confidence'],
    completionCriteria: ['Crash classification is justified', 'Root cause is demonstrated, not asserted'],
    dependsOn: ['zero-day-discovery'],
    keywords: ['fuzz', 'afl', 'libfuzzer', 'honggfuzz', 'harness', 'corpus', 'crash', 'segfault', 'triage', 'use-after-free', 'heap corruption', 'stack trace', 'coredump'],
  },
  {
    id: 'root-cause-analysis',
    roleId: 'vulnerability-root-cause-analyst',
    title: 'Vulnerability root cause analysis',
    objective: 'Reconstruct the technical root cause of the vulnerability or crash relevant to "{{task}}".',
    method: 'Trace the code path, diff patches and reconstruct the exact triggering precondition.',
    requiredTools: catalogueFor(['zero_day', 'vulnerability', 'binary', 'knowledge']),
    expectedEvidence: ['Crash/patch/source locator', 'Stack trace or diff', 'Reproduction conditions'],
    completionCriteria: ['Root cause demonstrated', 'Triggering condition concrete'],
    dependsOn: ['fuzz-crash-triage', 'static-analysis'],
    keywords: ['root cause', 'root-cause', 'patch diff', 'crash reconstruction', 'trigger', 'precondition', 'code path'],
  },
  {
    id: 'exploit-intel',
    roleId: 'exploit-intelligence-analyst',
    title: 'Exploitation-state assessment',
    objective: 'Assess the public exploitation state and defensive implications for "{{task}}".',
    method: 'Corroborate exploitation claims; strictly separate PoC from in-the-wild use.',
    requiredTools: catalogueFor(['vulnerability', 'knowledge']),
    expectedEvidence: ['Source per exploitation claim'],
    completionCriteria: ['State is sourced', 'PoC not equated with in-the-wild'],
    dependsOn: ['vuln-research'],
    keywords: ['exploit', 'poc', 'weapon', 'in the wild', 'exploited'],
  },
  {
    id: 'mirai-analysis',
    roleId: 'mirai-malware-analyst',
    title: 'Mirai-lineage malware analysis',
    objective: 'Analyse the Mirai-lineage families and variants relevant to "{{task}}".',
    method: 'Compare lineage, extract IOCs and cross-reference curated references and stored records.',
    requiredTools: catalogueFor(['malware', 'knowledge']),
    expectedEvidence: ['Sample hash/identifier', 'Source for family attribution'],
    completionCriteria: ['Lineage sourced', 'Confirmed vs inferred separated'],
    dependsOn: ['intake'],
    keywords: ['mirai', 'botnet', 'malware', 'family', 'variant', 'gafgyt', 'bashlite', 'iot', 'sample'],
  },
  {
    id: 'malware-source-analysis',
    roleId: 'malware-source-code-analyst',
    title: 'Malware source code analysis',
    objective: 'Analyse the malware source relevant to "{{task}}" in depth (structure, functions, configuration).',
    method: 'Map the repository structure, read functions and parse configuration formats, citing exact locations.',
    requiredTools: catalogueFor(['malware', 'software', 'knowledge']),
    expectedEvidence: ['File/function/symbol locators', 'Configuration format description'],
    completionCriteria: ['Every claim cites a location', 'No behaviour asserted without code evidence'],
    dependsOn: ['intake'],
    keywords: ['malware source', 'source code', 'source analysis', 'repo structure', 'configuration format', 'loader', 'scanner', 'bot source'],
  },
  {
    id: 'malware-variant-comparison',
    roleId: 'malware-variant-analyst',
    title: 'Malware variant comparison and lineage',
    objective: 'Compare the malware variants relevant to "{{task}}" and reconstruct lineage.',
    method: 'Compare functions, configurations and binaries; score similarity and separate confirmed lineage from inference.',
    requiredTools: catalogueFor(['malware', 'binary', 'knowledge']),
    expectedEvidence: ['Sample/source hashes', 'Diff or similarity evidence'],
    completionCriteria: ['Lineage evidence-backed', 'Confirmed vs inferred separated'],
    dependsOn: ['mirai-analysis'],
    keywords: ['variant', 'lineage', 'similarity', 'family', 'fork', 'diff', 'clustering', 'derived'],
  },
  {
    id: 'reverse-eng',
    roleId: 'reverse-engineering-specialist',
    title: 'Binary reverse engineering',
    objective: 'Statically characterise the binaries relevant to "{{task}}".',
    method: 'Static-first analysis; dynamic execution only in an authorised isolated sandbox.',
    requiredTools: catalogueFor(['binary', 'knowledge']),
    expectedEvidence: ['Sample hash', 'Tool output locators'],
    completionCriteria: ['Static vs dynamic conclusions separated', 'Sample handled in isolation'],
    dependsOn: ['mirai-analysis'],
    keywords: ['reverse', 'disassembl', 'decompil', 'binary', 'elf', 'strings', 'architecture'],
  },
  {
    id: 'firmware-analysis',
    roleId: 'firmware-analyst',
    title: 'Firmware analysis',
    objective: 'Analyse the firmware images relevant to "{{task}}".',
    method: 'Extract the image, inspect the filesystem and map component versions to known vulnerabilities.',
    requiredTools: catalogueFor(['firmware', 'knowledge']),
    expectedEvidence: ['Image hash', 'Extracted component paths'],
    completionCriteria: ['Versions read from artefacts', 'Emulation isolated'],
    dependsOn: ['intake'],
    keywords: ['firmware', 'router', 'device', 'embedded', 'image', 'binwalk', 'squashfs'],
  },
  {
    id: 'net-forensics',
    roleId: 'network-forensics-analyst',
    title: 'Network forensics',
    objective: 'Reconstruct the network activity relevant to "{{task}}".',
    method: 'Aggregate flows, fingerprint protocols, detect beaconing and build a timeline.',
    requiredTools: catalogueFor(['network', 'knowledge']),
    expectedEvidence: ['Capture reference', 'Flow/packet locators'],
    completionCriteria: ['Indicators traceable to packets', 'Benign baseline considered'],
    dependsOn: ['intake'],
    keywords: ['pcap', 'traffic', 'network', 'packet', 'forensic', 'flow', 'beacon', 'c2', 'ioc'],
  },
  {
    id: 'protocol-reverse-eng',
    roleId: 'protocol-reverse-engineer',
    title: 'Protocol reverse engineering',
    objective: 'Reconstruct the protocol message structures and state machine relevant to "{{task}}".',
    method: 'Infer field boundaries, encodings and state transitions from captures, source or binary.',
    requiredTools: catalogueFor(['network', 'binary', 'firmware', 'knowledge']),
    expectedEvidence: ['Capture/source locators', 'Field boundaries and sample bytes'],
    completionCriteria: ['Field boundaries evidence-based', 'No protocol asserted without samples'],
    dependsOn: ['intake'],
    keywords: ['protocol', 'message format', 'state machine', 'encoding', 'packet layout', 'command id', 'decoder'],
  },
  {
    id: 'attack-methods',
    roleId: 'attack-method-research-analyst',
    title: 'Attack-method review (defensive)',
    objective: 'Describe, at a defensive/conceptual level, the attack methods relevant to "{{task}}".',
    method: 'Conceptual description mapped to detection and mitigation; no operational capability.',
    requiredTools: catalogueFor(['defense', 'knowledge']),
    expectedEvidence: ['Public source per technique'],
    completionCriteria: ['Defensive framing only'],
    dependsOn: ['intake'],
    keywords: ['attack', 'technique', 'amplification', 'reflection', 'ttp', 'method'],
  },
  {
    id: 'anti-ddos',
    roleId: 'anti-ddos-research-engineer',
    title: 'Anti-DDoS mitigation design',
    objective: 'Design and compare DDoS mitigation and rate-limiting strategies for "{{task}}".',
    method: 'Trade-off analysis and threshold sizing from observed baselines.',
    requiredTools: catalogueFor(['defense', 'knowledge']),
    expectedEvidence: ['Observed attack characteristics', 'Traffic baseline reference'],
    completionCriteria: ['Recommendations follow from data', 'False-positive impact considered'],
    dependsOn: ['attack-methods', 'net-forensics'],
    keywords: ['ddos', 'dos', 'mitigat', 'rate limit', 'rate-limit', 'defen', 'scrub', 'protection', 'flood'],
  },
  {
    id: 'ai-malware',
    roleId: 'ai-malware-research-analyst',
    title: 'AI-malware trend analysis',
    objective: 'Analyse AI/LLM-assisted malware trends and detection implications for "{{task}}".',
    method: 'Literature review and capability/impact assessment; no malicious capability.',
    requiredTools: catalogueFor(['malware', 'knowledge']),
    expectedEvidence: ['Published source per claim'],
    completionCriteria: ['Claims sourced', 'No malicious capability generated'],
    dependsOn: ['mirai-analysis'],
    keywords: ['ai', 'llm', 'machine learning', 'neural', 'generated', 'deep learning'],
  },
  {
    id: 'threat-intel',
    roleId: 'threat-intelligence-analyst',
    title: 'Threat intelligence correlation',
    objective: 'Correlate threat intelligence across sources relevant to "{{task}}" into evidence-backed assessments.',
    method: 'Cross-correlate malware/vulnerability/exploit/network data, detect duplicates and score confidence.',
    requiredTools: catalogueFor(['knowledge', 'malware', 'network', 'vulnerability']),
    expectedEvidence: ['Source per claim', 'Record identifiers', 'Provenance'],
    completionCriteria: ['Every claim sourced', 'Fact/hypothesis/inference distinguished'],
    dependsOn: ['intake'],
    keywords: ['threat intel', 'correlat', 'ioc', 'indicator', 'campaign', 'attribution', 'tactic', 'ttp'],
  },
  {
    id: 'evidence-audit',
    roleId: 'evidence-verification-auditor',
    title: 'Evidence and verification audit',
    objective: 'Independently audit the evidence base produced for "{{task}}" and issue a pass/fail verdict.',
    method: 'Check provenance completeness, confidence vs claim strength and cross-source contradictions.',
    requiredTools: catalogueFor(['knowledge', 'orchestration']),
    expectedEvidence: ['Record ids', 'Provenance and verification states'],
    completionCriteria: ['Every finding cites evidence', 'No conclusion outranks its evidence'],
    dependsOn: ['*'],
    keywords: [],
  },
];

const WORKSTREAM_BY_ID = new Map(WORKSTREAMS.map((w) => [w.id, w]));

/** Compute the dependency-ordered phase of each workstream (longest path). */
function computePhases(items: Array<{ id: string; dependsOn: string[] }>): Map<string, number> {
  const ids = new Set(items.map((i) => i.id));
  const phase = new Map<string, number>();
  const visiting = new Set<string>();
  const resolve = (id: string): number => {
    const cached = phase.get(id);
    if (cached !== undefined) return cached;
    if (visiting.has(id)) return 0; // cycle guard
    visiting.add(id);
    const item = items.find((i) => i.id === id);
    const deps = (item?.dependsOn ?? []).filter((d) => ids.has(d));
    const value = deps.length === 0 ? 0 : 1 + Math.max(...deps.map(resolve));
    visiting.delete(id);
    phase.set(id, value);
    return value;
  };
  for (const item of items) resolve(item.id);
  return phase;
}

/* -------------------------------------------------------------------------- */
/* Topic derivation (for findings merge / reconciliation grouping)             */
/* -------------------------------------------------------------------------- */

const TOPIC_KEYWORDS: Record<string, string[]> = {
  'zero-day': ['zero-day', 'zero day', '0day', 'zero_day', 'undisclosed', 'hypothesis'],
  fuzz: ['fuzz', 'afl', 'libfuzzer', 'honggfuzz', 'harness', 'corpus'],
  crash: ['crash', 'segfault', 'coredump', 'stack trace', 'triage', 'use-after-free', 'heap corruption'],
  vulnerability: ['cve', 'cwe', 'vulnerab', 'advisory', 'patch'],
  exploit: ['exploit', 'poc', 'payload', 'weapon'],
  malware: ['mirai', 'botnet', 'malware', 'family', 'variant', 'gafgyt', 'bashlite'],
  network: ['pcap', 'packet', 'traffic', 'beacon', 'c2', 'flow', 'ioc', 'network'],
  firmware: ['firmware', 'router', 'device', 'embedded', 'image'],
  ddos: ['ddos', 'flood', 'amplification', 'mitigation', 'rate limit', 'rate-limit'],
  detection: ['yara', 'sigma', 'detection', 'rule', 'signature', 'nuclei'],
  source: ['function', 'module', 'code', 'repo', 'build', 'test'],
};

function deriveTopic(text: string): string {
  const lower = text.toLowerCase();
  for (const [topic, keywords] of Object.entries(TOPIC_KEYWORDS)) {
    if (keywords.some((k) => lower.includes(k))) return topic;
  }
  return 'general';
}

function epistemicFromConfidence(confidence: ConfidenceLevel): EpistemicStatus {
  switch (confidence) {
    case 'confirmed':
      return 'verified_fact';
    case 'observed':
      return 'direct_observation';
    case 'inferred':
      return 'researcher_interpretation';
    case 'hypothesis':
      return 'hypothesis';
    default:
      return 'unverified_claim';
  }
}

const CONFIDENCE_RANK: Record<ConfidenceLevel, number> = {
  confirmed: 5,
  observed: 4,
  inferred: 3,
  hypothesis: 2,
  unknown: 1,
};

/** Fetch knowledge-base records for a topic, by tag then by free text. */
function recordsForTopic(topic: string): KnowledgeRecord[] {
  const kb = getKnowledgeBase();
  const byTag = kb.searchRecords({ tags: [topic], limit: 200 });
  if (byTag.length > 0) return byTag;
  return kb.searchRecords({ text: topic, limit: 200 });
}

/* -------------------------------------------------------------------------- */
/* Semantic comparison for findings merge (P0.1)                               */
/* -------------------------------------------------------------------------- */

/** Words that carry no discriminating meaning for statement comparison. */
const SEMANTIC_STOPWORDS = new Set([
  'a', 'an', 'the', 'is', 'are', 'was', 'were', 'be', 'been', 'being', 'this', 'that', 'these',
  'those', 'it', 'its', 'of', 'to', 'for', 'in', 'on', 'with', 'by', 'and', 'or', 'as', 'at',
  'from', 'which', 'who', 'also', 'may', 'might', 'can', 'could', 'would', 'should', 'will',
  'has', 'have', 'had', 'do', 'does', 'did', 'into', 'about', 'than', 'then',
]);

/** Negation / privation markers used to detect opposing claims. */
const NEGATION_TOKENS = new Set([
  'not', 'no', 'never', 'without', 'cannot', 'cant', 'doesnt', 'dont', 'didnt', 'isnt', 'arent',
  'wont', 'fails', 'failed', 'lacks', 'lack', 'lacking', 'absent', 'none', 'neither', 'nor',
  'unable', 'unsupported', 'excludes', 'excluding',
]);

/** Known, mutually exclusive malware families (basis for classification conflicts). */
const KNOWN_FAMILIES = new Set([
  'mirai', 'gafgyt', 'bashlite', 'satori', 'okiru', 'masuta', 'wicked', 'reaper', 'iotroop',
  'mukashi', 'mozi', 'qbot', 'hajime', 'tsunami', 'lightaidra', 'aidra', 'lizkebab', 'torlus',
]);

/** Verbs/markers that signal a classification assertion. */
const CLASSIFICATION_MARKERS = new Set([
  'is', 'are', 'was', 'were', 'variant', 'variants', 'family', 'belongs', 'belong', 'belonging',
  'classified', 'identify', 'identified', 'derived', 'based', 'descended', 'lineage', 'strain',
]);

/** Simple antonym pairs used to detect opposing properties. */
const ANTONYM_PAIRS: ReadonlyArray<readonly [string, string]> = [
  ['increase', 'decrease'], ['increases', 'decreases'], ['increased', 'decreased'],
  ['enable', 'disable'], ['enables', 'disables'], ['enabled', 'disabled'],
  ['present', 'absent'], ['contains', 'lacks'], ['contain', 'lack'],
  ['before', 'after'], ['precedes', 'follows'], ['always', 'never'],
  ['supported', 'unsupported'], ['valid', 'invalid'], ['succeeds', 'fails'],
  ['open', 'closed'], ['accepts', 'rejects'], ['allows', 'denies'],
];

function normalizeWords(text: string): string[] {
  return text.toLowerCase().replace(/[^a-z0-9\s]/g, ' ').split(/\s+/).filter(Boolean);
}

function wordSet(text: string): Set<string> {
  return new Set(
    normalizeWords(text).filter((t) => !SEMANTIC_STOPWORDS.has(t) && !NEGATION_TOKENS.has(t)),
  );
}

function jaccard(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 && b.size === 0) return 1;
  let inter = 0;
  for (const t of a) if (b.has(t)) inter += 1;
  const union = a.size + b.size - inter;
  return union === 0 ? 1 : inter / union;
}

function hasNegation(text: string): boolean {
  return normalizeWords(text).some((t) => NEGATION_TOKENS.has(t));
}

function antonymConflict(a: string, b: string): readonly [string, string] | null {
  const aw = new Set(normalizeWords(a));
  const bw = new Set(normalizeWords(b));
  for (const [x, y] of ANTONYM_PAIRS) {
    if ((aw.has(x) && bw.has(y)) || (aw.has(y) && bw.has(x))) return [x, y];
  }
  return null;
}

function classificationFamilies(text: string): string[] {
  return normalizeWords(text).filter((w) => KNOWN_FAMILIES.has(w));
}

function hasClassificationMarker(text: string): boolean {
  return normalizeWords(text).some((w) => CLASSIFICATION_MARKERS.has(w));
}

type ContradictionKind =
  | 'opposing_claim'
  | 'antonym'
  | 'incompatible_classification'
  | 'evidence_disagreement';

interface MergeFinding {
  roleId: string;
  statement: string;
  evidence?: string[];
  confidence: ConfidenceLevel;
}

interface Contradiction {
  kind: ContradictionKind;
  a: { roleId: string; statement: string; confidence: ConfidenceLevel };
  b: { roleId: string; statement: string; confidence: ConfidenceLevel };
  reason: string;
  requiredEvidence: string[];
}

const RESTATEMENT_THRESHOLD = 0.8;
const OPPOSITION_THRESHOLD = 0.6;

/**
 * Decide whether two findings of the same topic contradict each other.
 * Returns the contradiction descriptor, or null when the pair is consistent
 * (restatement, unrelated, or merely a different confidence level).
 */
function classifyContradiction(x: MergeFinding, y: MergeFinding): Contradiction | null {
  const sim = jaccard(wordSet(x.statement), wordSet(y.statement));
  const base = {
    a: { roleId: x.roleId, statement: x.statement, confidence: x.confidence },
    b: { roleId: y.roleId, statement: y.statement, confidence: y.confidence },
  };

  // Opposing claim: identical subject/predicate content, one side negated.
  if (sim >= OPPOSITION_THRESHOLD && hasNegation(x.statement) !== hasNegation(y.statement)) {
    return {
      ...base,
      kind: 'opposing_claim',
      reason: 'One finding negates the other while sharing the same subject and predicate content.',
      requiredEvidence: [
        `A primary observation that directly confirms or refutes: "${x.statement}".`,
        'An independent reproduction recorded together with the exact command and output used.',
      ],
    };
  }

  // Restatement: same meaning (include/exclude negation consistently) is not a conflict.
  if (sim >= RESTATEMENT_THRESHOLD && hasNegation(x.statement) === hasNegation(y.statement)) {
    const evX = x.evidence ?? [];
    const evY = y.evidence ?? [];
    const disjoint = evX.length > 0 && evY.length > 0 && !evX.some((e) => evY.includes(e));
    if (disjoint) {
      return {
        ...base,
        kind: 'evidence_disagreement',
        reason: 'Findings state the same claim but cite disjoint evidence sets.',
        requiredEvidence: [
          'Reconcile the two evidence sets and record which artefacts actually support the claim.',
        ],
      };
    }
    return null;
  }

  // Antonym opposition about the same subject.
  const ant = antonymConflict(x.statement, y.statement);
  if (ant && sim >= OPPOSITION_THRESHOLD) {
    return {
      ...base,
      kind: 'antonym',
      reason: `Findings assert opposite properties ("${ant[0]}" vs "${ant[1]}") about the same subject.`,
      requiredEvidence: [
        `Evidence distinguishing "${ant[0]}" from "${ant[1]}" for this subject.`,
      ],
    };
  }

  // Incompatible family classification of the same artefact.
  const famX = classificationFamilies(x.statement);
  const famY = classificationFamilies(y.statement);
  if (
    famX.length > 0 &&
    famY.length > 0 &&
    !famX.some((f) => famY.includes(f)) &&
    hasClassificationMarker(x.statement) &&
    hasClassificationMarker(y.statement) &&
    sim >= 0.3
  ) {
    return {
      ...base,
      kind: 'incompatible_classification',
      reason: `Findings classify the same artefact as different, mutually exclusive families (${famX[0]} vs ${famY[0]}).`,
      requiredEvidence: [
        `A primary sample hash or binary analysis that places the artefact in either ${famX[0]} or ${famY[0]}.`,
        'Comparison of family-specific strings and behaviour (C2 protocol, exploit set) with published family signatures.',
      ],
    };
  }

  return null;
}

/* -------------------------------------------------------------------------- */
/* Engine                                                                      */
/* -------------------------------------------------------------------------- */

export const multiAgentEngine: EngineModule = {
  name: ENGINE,
  title: 'Multi-Agent Research Orchestration',
  description:
    'Role definitions and orchestration for the §8 multi-agent research architecture: task ' +
    'decomposition, specialist briefs, findings merge, conflict reconciliation, gap identification ' +
    'and evidence audits over the shared knowledge base. Produces structure, not autonomous agents.',
  tools: [
    defineTool({
      name: 'agent_roles_list',
      title: 'List specialist agent roles',
      engine: ENGINE,
      description:
        'Return the specialist research roles of the §8 architecture with their responsibility, ' +
        'inputs, outputs and the classes of task each role is appropriate for.',
      capabilities: [],
      risk: 'safe',
      inputSchema: {},
      handler: async (_input, ctx) => {
        const started = Date.now();
        const roles = ROLES.map((r) => ({
          id: r.id,
          title: r.title,
          responsibility: r.responsibility,
          inputs: r.inputs,
          outputs: r.outputs,
          appropriateFor: r.appropriateFor,
        }));
        addEvidence(ctx, {
          claim: `Listed ${roles.length} specialist agent roles.`,
          prov: curatedProvenance('multi-agent-roles'),
          confidence: 'confirmed',
        });
        const markdown = [
          '# Specialist agent roles',
          '',
          ...roles.map((r) => `- **${r.title}** (\`${r.id}\`) — ${r.responsibility}`),
        ].join('\n');
        return finish({
          engine: ENGINE,
          tool: 'agent_roles_list',
          startedAt: started,
          ctx,
          data: { count: roles.length, roles },
          summary: markdown,
        });
      },
    }),

    defineTool({
      name: 'orchestrator_plan',
      title: 'Decompose a task into an agent plan',
      engine: ENGINE,
      description:
        'Decompose a complex task into a dependency-ordered plan of sub-tasks, each assigned to one of ' +
        'the specialist roles with an objective, method, required tools, expected evidence and ' +
        'completion criteria. Reports which sub-tasks can run in parallel. Avoids over-spawning agents ' +
        'for simple tasks.',
      capabilities: [],
      risk: 'safe',
      inputSchema: {
        task: z.string().min(3).describe('The complex task to decompose.'),
        constraints: z.array(z.string()).optional().describe('Explicit constraints the plan must respect.'),
        maxAgents: z
          .number()
          .int()
          .min(1)
          .max(20)
          .optional()
          .describe('Maximum number of sub-agents/sub-tasks (default 8).'),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const i = input as { task: string; constraints?: string[]; maxAgents?: number };
        const task = i.task.trim();
        if (!task) throw errors.invalidInput('Task must not be empty.');
        const maxAgents = i.maxAgents ?? 8;
        const taskLower = task.toLowerCase();

        const coreIds = ['intake', 'evidence-audit'];
        const nonCore = WORKSTREAMS.filter((w) => !coreIds.includes(w.id));
        const matched = nonCore.filter((w) => w.keywords.some((k) => taskLower.includes(k)));

        const notes: string[] = [];
        let selectedNonCore: Workstream[];
        if (matched.length === 0) {
          // Simple / low-signal task: keep the agent footprint minimal (§8).
          const fallbackIds = task.length > 80 ? ['doc-research', 'vuln-research'] : ['vuln-research'];
          selectedNonCore = fallbackIds
            .map((id) => WORKSTREAM_BY_ID.get(id))
            .filter((w): w is Workstream => Boolean(w));
          notes.push(
            'No specialised research domain was detected in the task text; a minimal agent set is ' +
              'recommended (do not overspawn agents for simple tasks).',
          );
        } else {
          selectedNonCore = matched;
        }

        const intake = WORKSTREAM_BY_ID.get('intake')!;
        const audit = WORKSTREAM_BY_ID.get('evidence-audit')!;
        let selected: Workstream[] = [intake, ...selectedNonCore, audit];

        const dropped: string[] = [];
        if (selected.length > maxAgents) {
          const keep = Math.max(2, maxAgents - 2);
          const keptNonCore = selectedNonCore.slice(0, keep);
          dropped.push(...selectedNonCore.slice(keep).map((w) => w.id));
          selected = [intake, ...keptNonCore, audit];
          notes.push(
            `Plan exceeded maxAgents=${maxAgents}; ${dropped.length} lower-priority sub-task(s) were ` +
              `deferred. Increase maxAgents to run them.`,
          );
        }

        const selectedIds = selected.map((w) => w.id);
        const planItems = selected.map((w) => {
          const deps = w.dependsOn[0] === '*' ? selectedIds.filter((id) => id !== w.id) : w.dependsOn;
          return { ...w, resolvedDeps: deps.filter((d) => selectedIds.includes(d)) };
        });

        const phases = computePhases(planItems.map((p) => ({ id: p.id, dependsOn: p.resolvedDeps })));
        const maxPhase = Math.max(0, ...[...phases.values()]);

        const phased = [];
        for (let phase = 0; phase <= maxPhase; phase += 1) {
          const subtasks = planItems
            .filter((p) => phases.get(p.id) === phase)
            .map((p) => ({
              id: p.id,
              roleId: p.roleId,
              roleTitle: ROLE_BY_ID.get(p.roleId)?.title ?? p.roleId,
              title: p.title,
              objective: p.objective.replace(/\{\{task\}\}/g, task),
              method: p.method,
              requiredTools: p.requiredTools,
              expectedEvidence: p.expectedEvidence,
              completionCriteria: p.completionCriteria,
              dependsOn: p.resolvedDeps,
            }));
          if (subtasks.length > 0) {
            phased.push({ phase: phase + 1, parallel: subtasks.length > 1, subtasks });
          }
        }

        const maxParallel = Math.max(...phased.map((p) => p.subtasks.length));

        addEvidence(ctx, {
          claim: `Generated a ${planItems.length}-sub-task orchestration plan across ${phased.length} phase(s).`,
          prov: curatedProvenance('orchestrator-plan'),
          confidence: 'observed',
          data: { subtasks: planItems.length, phases: phased.length, maxParallel },
        });

        const markdown = [
          `# Orchestration plan`,
          '',
          `**Task:** ${task}`,
          `**Sub-tasks:** ${planItems.length} • **Phases:** ${phased.length} • **Max parallelism:** ${maxParallel}`,
          i.constraints?.length ? `**Constraints:** ${i.constraints.join('; ')}` : '',
          '',
          ...phased.flatMap((p) => [
            `## Phase ${p.phase}${p.parallel ? ' (parallel)' : ''}`,
            ...p.subtasks.map(
              (s) =>
                `- **${s.title}** → _${s.roleTitle}_\n  - Objective: ${s.objective}\n  - Tools: ${s.requiredTools.join(', ') || 'none'}\n  - Done when: ${s.completionCriteria.join('; ')}`,
            ),
            '',
          ]),
          ...(notes.length ? ['## Notes', ...notes.map((n) => `- ${n}`)] : []),
        ]
          .filter((line) => line !== '')
          .join('\n');

        return finish({
          engine: ENGINE,
          tool: 'orchestrator_plan',
          startedAt: started,
          ctx,
          data: {
            task,
            constraints: i.constraints ?? [],
            maxAgents,
            complexity: {
              matchedDomains: matched.length,
              subtasks: planItems.length,
              phases: phased.length,
              maxParallel,
              recommendedAgents: planItems.length,
            },
            phases: phased,
            dropped,
            notes,
            toolCatalogue: Object.keys(TOOL_CATALOGUE),
          },
          warnings: notes.length ? notes : undefined,
          summary: markdown,
        });
      },
    }),

    defineTool({
      name: 'agent_brief_generate',
      title: 'Generate a specialist brief',
      engine: ENGINE,
      description:
        'Produce the structured brief the orchestrator would hand to a specialist role for a given ' +
        'objective: inputs, methods, required evidence, output schema and verification requirements.',
      capabilities: [],
      risk: 'safe',
      inputSchema: {
        roleId: z.string().min(1).describe('Role id from agent_roles_list.'),
        objective: z.string().min(3).describe('What this agent must accomplish.'),
        context: z.string().optional().describe('Optional context the agent needs.'),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const i = input as { roleId: string; objective: string; context?: string };
        const role = ROLE_BY_ID.get(i.roleId);
        if (!role) {
          throw errors.notFound(
            `Agent role "${i.roleId}"`,
            { validRoleIds: ROLES.map((r) => r.id) },
          );
        }
        const brief = {
          roleId: role.id,
          roleTitle: role.title,
          responsibility: role.responsibility,
          objective: i.objective,
          context: i.context ?? null,
          inputs: role.inputs,
          methods: role.methods,
          requiredEvidence: role.requiredEvidence,
          outputSchema: role.outputSchema,
          verification: role.verification,
          guardrails: [
            'Report only what the evidence supports; never present a hypothesis as a confirmed finding.',
            'Attach provenance (source URL / file locator / sample hash) to every claim.',
            'Defensive posture only: do not produce operational offensive capability.',
          ],
        };
        addEvidence(ctx, {
          claim: `Generated brief for role "${role.id}" targeting: ${i.objective}`,
          prov: curatedProvenance('agent-brief'),
          confidence: 'observed',
        });
        const markdown = [
          `# Brief — ${role.title}`,
          '',
          `**Objective:** ${i.objective}`,
          i.context ? `**Context:** ${i.context}` : '',
          '',
          `## Responsibility`,
          role.responsibility,
          '',
          `## Inputs`,
          ...role.inputs.map((x) => `- ${x}`),
          '',
          `## Methods`,
          ...role.methods.map((x) => `- ${x}`),
          '',
          `## Required evidence`,
          ...role.requiredEvidence.map((x) => `- ${x}`),
          '',
          `## Output schema`,
          ...Object.entries(role.outputSchema).map(([k, v]) => `- \`${k}\`: ${v}`),
          '',
          `## Verification`,
          ...role.verification.map((x) => `- ${x}`),
        ]
          .filter((line) => line !== '')
          .join('\n');
        return finish({
          engine: ENGINE,
          tool: 'agent_brief_generate',
          startedAt: started,
          ctx,
          data: brief,
          summary: markdown,
        });
      },
    }),

    defineTool({
      name: 'agent_findings_merge',
      title: 'Merge findings from multiple agents',
      engine: ENGINE,
      description:
        'Merge structured findings from several agents: group by topic, compute the weakest-link ' +
        'confidence with aggregateConfidence semantics, preserve each finding’s provenance and flag ' +
        'groups whose confidence levels diverge (needing reconciliation).',
      capabilities: [],
      risk: 'safe',
      inputSchema: {
        findings: z
          .array(
            z.object({
              roleId: z.string().min(1),
              statement: z.string().min(1),
              evidence: z.array(z.string()).optional(),
              confidence: z.enum(['confirmed', 'observed', 'inferred', 'hypothesis', 'unknown']),
            }),
          )
          .min(1)
          .describe('Findings produced by specialist agents.'),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const i = input as {
          findings: Array<{
            roleId: string;
            statement: string;
            evidence?: string[];
            confidence: ConfidenceLevel;
          }>;
        };

        const refs: EvidenceRef[] = i.findings.map((f, index) => ({
          id: `${f.roleId}-${index}`,
          claim: f.statement,
          provenance: curatedProvenance('agent-findings'),
          confidence: f.confidence,
        }));

        const groups = new Map<string, { findings: typeof i.findings; refs: EvidenceRef[] }>();
        i.findings.forEach((f, index) => {
          const topic = deriveTopic(f.statement);
          const entry = groups.get(topic) ?? { findings: [], refs: [] };
          entry.findings.push(f);
          entry.refs.push(refs[index]!);
          groups.set(topic, entry);
        });

        const mergedGroups = [...groups.entries()].map(([topic, group]) => {
          const distinct = new Set(group.findings.map((f) => f.confidence));
          const contradictions: Contradiction[] = [];
          const duplicates: Array<{ roleIds: [string, string]; statements: [string, string] }> = [];
          for (let x = 0; x < group.findings.length; x += 1) {
            for (let y = x + 1; y < group.findings.length; y += 1) {
              const a = group.findings[x]!;
              const b = group.findings[y]!;
              const found = classifyContradiction(a, b);
              if (found) {
                contradictions.push(found);
              } else if (
                jaccard(wordSet(a.statement), wordSet(b.statement)) >= RESTATEMENT_THRESHOLD &&
                hasNegation(a.statement) === hasNegation(b.statement)
              ) {
                duplicates.push({ roleIds: [a.roleId, b.roleId], statements: [a.statement, b.statement] });
              }
            }
          }
          const baseConfidence = aggregateConfidence(group.refs);
          const mergedConfidence: ConfidenceLevel =
            contradictions.length > 0 && CONFIDENCE_RANK[baseConfidence] > CONFIDENCE_RANK['inferred']
              ? 'inferred'
              : baseConfidence;
          return {
            topic,
            count: group.findings.length,
            mergedConfidence,
            confidenceLevels: [...distinct],
            divergent: distinct.size > 1 || contradictions.length > 0,
            reconciliationRequired: contradictions.length > 0,
            contradictions,
            duplicates,
            requiredEvidence: [...new Set(contradictions.flatMap((c) => c.requiredEvidence))],
            findings: group.findings.map((f) => ({
              roleId: f.roleId,
              statement: f.statement,
              confidence: f.confidence,
              evidence: f.evidence ?? [],
            })),
          };
        });

        const overall = aggregateConfidence(
          mergedGroups.map((g) => ({
            id: g.topic,
            claim: g.topic,
            provenance: curatedProvenance('findings-merge'),
            confidence: g.mergedConfidence,
          })),
        );
        const divergentTopics = mergedGroups.filter((g) => g.divergent).map((g) => g.topic);
        const conflictedTopics = mergedGroups.filter((g) => g.reconciliationRequired).map((g) => g.topic);
        const allContradictions = mergedGroups.flatMap((g) =>
          g.contradictions.map((c) => ({ topic: g.topic, ...c })),
        );
        const weakest = mergedGroups.reduce<{ topic: string; confidence: ConfidenceLevel } | null>(
          (acc, g) => {
            if (!acc || CONFIDENCE_RANK[g.mergedConfidence] < CONFIDENCE_RANK[acc.confidence]) {
              return { topic: g.topic, confidence: g.mergedConfidence };
            }
            return acc;
          },
          null,
        );

        addEvidence(ctx, {
          claim: `Merged ${i.findings.length} finding(s) into ${mergedGroups.length} topic group(s); overall confidence ${overall}; ${allContradictions.length} semantic contradiction(s).`,
          prov: curatedProvenance('findings-merge'),
          confidence: overall,
          data: {
            groups: mergedGroups.length,
            divergentTopics,
            conflictedTopics,
            contradictions: allContradictions.length,
          },
        });

        const warnings: string[] = [];
        if (divergentTopics.length) {
          warnings.push(
            `Divergent confidence in topic(s): ${divergentTopics.join(', ')} — run evidence_reconciliation.`,
          );
        }
        if (conflictedTopics.length) {
          warnings.push(
            `Semantic contradictions in topic(s): ${conflictedTopics.join(', ')} (${allContradictions.length}) — confidence downgraded pending evidence_reconciliation.`,
          );
        }

        const markdown = [
          '# Merged findings',
          '',
          `**Findings:** ${i.findings.length} • **Topic groups:** ${mergedGroups.length} • **Overall confidence:** ${overall}`,
          weakest ? `**Weakest link:** ${weakest.topic} (${weakest.confidence})` : '',
          divergentTopics.length ? `**Requires reconciliation:** ${divergentTopics.join(', ')}` : '',
          allContradictions.length ? `**Contradictions detected:** ${allContradictions.length}` : '',
          '',
          ...mergedGroups.flatMap((g) => [
            `## ${g.topic} — merged confidence: ${g.mergedConfidence}${g.divergent ? ' (divergent)' : ''}`,
            ...g.findings.map(
              (f) => `- [${f.confidence}] (${f.roleId}) ${f.statement}${f.evidence.length ? ` — evidence: ${f.evidence.join(', ')}` : ''}`,
            ),
            ...(g.duplicates.length
              ? [`- ${g.duplicates.length} duplicate/restated finding pair(s) within this topic.`]
              : []),
            ...g.contradictions.map(
              (c) =>
                `- CONTRADICTION (${c.kind}): (${c.a.roleId}) "${c.a.statement}" vs (${c.b.roleId}) "${c.b.statement}" — ${c.reason}`,
            ),
            ...(g.requiredEvidence.length
              ? ['- Needed to resolve:', ...g.requiredEvidence.map((e) => `  - ${e}`)]
              : []),
            '',
          ]),
        ]
          .filter((line) => line !== '')
          .join('\n');

        return finish({
          engine: ENGINE,
          tool: 'agent_findings_merge',
          startedAt: started,
          ctx,
          data: {
            merged: {
              count: i.findings.length,
              overallConfidence: overall,
              weakestLink: weakest,
              divergentTopics,
              conflictedTopics,
              contradictions: allContradictions,
              groups: mergedGroups,
            },
          },
          warnings: warnings.length ? warnings : undefined,
          summary: markdown,
        });
      },
    }),

    defineTool({
      name: 'evidence_reconciliation',
      title: 'Reconcile conflicting results',
      engine: ENGINE,
      description:
        'Reconcile conflicting results for a topic: identify conflicts, list supporting vs contradicting ' +
        'evidence for each assertion, and state exactly what additional evidence would resolve each ' +
        'conflict. If no assertions are supplied, assertions are derived from knowledge-base records ' +
        'tagged with the topic.',
      capabilities: ['write_knowledge'],
      risk: 'safe',
      inputSchema: {
        topic: z.string().min(1).describe('The topic being reconciled.'),
        assertions: z
          .array(
            z.object({
              statement: z.string().min(1),
              status: z.enum([
                'verified_fact',
                'direct_observation',
                'researcher_interpretation',
                'hypothesis',
                'unverified_claim',
              ]),
              confidence: z.enum(['confirmed', 'observed', 'inferred', 'hypothesis', 'unknown']),
              supporting: z.array(z.string()),
              contradicting: z.array(z.string()),
            }),
          )
          .optional()
          .describe('Assertions to reconcile; omit to derive them from the knowledge base.'),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const i = input as {
          topic: string;
          assertions?: Array<{
            statement: string;
            status: EpistemicStatus;
            confidence: ConfidenceLevel;
            supporting: string[];
            contradicting: string[];
          }>;
        };

        let source: 'input' | 'knowledge-base';
        let assertions = i.assertions ?? [];
        if (i.assertions && i.assertions.length > 0) {
          source = 'input';
        } else {
          source = 'knowledge-base';
          const records = recordsForTopic(i.topic);
          assertions = records.map((r) => ({
            statement: `${r.title} (${r.category})`,
            status: epistemicFromConfidence(r.confidence),
            confidence: r.confidence,
            supporting: r.provenance.map((p) => p.url ?? `${p.source}${p.note ? ` (${p.note})` : ''}`),
            contradicting: r.verification === 'disputed' ? ['Verification state is "disputed".'] : [],
          }));
        }

        if (assertions.length === 0) {
          throw errors.notFound(
            `Evidence for topic "${i.topic}"`,
            { hint: 'Provide assertions explicitly or ingest records tagged with the topic first.' },
          );
        }

        const reconciled = assertions.map((a) => {
          let status: 'uncontested' | 'conflict' | 'contested' | 'unsupported';
          if (a.supporting.length === 0 && a.contradicting.length === 0) status = 'unsupported';
          else if (a.contradicting.length === 0) status = 'uncontested';
          else if (a.contradicting.length >= a.supporting.length) status = 'contested';
          else status = 'conflict';
          const requiredEvidence =
            a.contradicting.length > 0
              ? [
                  'An independent, primary source (advisory, packet capture, binary sample or vendor telemetry) that directly addresses the disputed point.',
                  `A recorded reproduction or observation that distinguishes the two competing claims about "${a.statement}".`,
                ]
              : [];
          return {
            statement: a.statement,
            decidedStatus: status,
            confidence: a.confidence,
            supporting: a.supporting,
            contradicting: a.contradicting,
            requiredAdditionalEvidence: requiredEvidence,
          };
        });

        const conflicts = reconciled.filter((r) => r.contradicting.length > 0);
        const unsupported = reconciled.filter((r) => r.decidedStatus === 'unsupported');
        const assessment =
          conflicts.length === 0 && unsupported.length === 0
            ? 'No conflicts detected; all assertions are supported. No additional evidence is required.'
            : `${conflicts.length} conflicting and ${unsupported.length} unsupported assertion(s) require additional evidence.`;

        addEvidence(ctx, {
          claim: `Reconciled ${reconciled.length} assertion(s) for topic "${i.topic}" (${source}).`,
          prov: curatedProvenance('evidence-reconciliation', i.topic),
          confidence: 'observed',
          data: { conflicts: conflicts.length, unsupported: unsupported.length },
        });

        const assertion = ctx.evidence.assert({
          statement: `For topic "${i.topic}": ${assessment}`,
          status: conflicts.length > 0 ? 'researcher_interpretation' : 'direct_observation',
          confidence: conflicts.length > 0 ? 'inferred' : 'observed',
          producedBy: 'evidence_reconciliation',
        });

        const markdown = [
          `# Evidence reconciliation — ${i.topic}`,
          '',
          `**Assertions:** ${reconciled.length} (source: ${source}) • **Conflicts:** ${conflicts.length} • **Unsupported:** ${unsupported.length}`,
          '',
          ...reconciled.flatMap((r) => [
            `## ${r.decidedStatus.toUpperCase()} — ${r.statement}`,
            `- Confidence: ${r.confidence}`,
            r.supporting.length ? `- Supporting: ${r.supporting.join('; ')}` : '- Supporting: (none recorded)',
            r.contradicting.length ? `- Contradicting: ${r.contradicting.join('; ')}` : '',
            r.requiredAdditionalEvidence.length
              ? `- Needed to resolve: ${r.requiredAdditionalEvidence.join(' ')}`
              : '',
            '',
          ]),
          `## Assessment`,
          assessment,
        ]
          .filter((line) => line !== '')
          .join('\n');

        return finish({
          engine: ENGINE,
          tool: 'evidence_reconciliation',
          startedAt: started,
          ctx,
          data: {
            topic: i.topic,
            source,
            assertion,
            reconciled,
            conflicts: conflicts.map((c) => c.statement),
            unsupported: unsupported.map((u) => u.statement),
            assessment,
          },
          summary: markdown,
        });
      },
    }),

    defineTool({
      name: 'missing_evidence_identify',
      title: 'Identify missing evidence',
      engine: ENGINE,
      description:
        'Given what is established for a topic, enumerate what is MISSING: unverified claims, absent ' +
        'provenance, gaps between hypothesis and verification, and concrete next research actions. ' +
        'Returns a prioritized list. If established claims are not supplied they are derived from the ' +
        'knowledge base for the topic.',
      capabilities: [],
      risk: 'safe',
      inputSchema: {
        topic: z.string().min(1).describe('The topic to analyse.'),
        established: z.array(z.string()).optional().describe('Claims already established.'),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const i = input as { topic: string; established?: string[] };
        const records = recordsForTopic(i.topic);
        const established =
          i.established && i.established.length > 0
            ? i.established
            : records
                .filter((r) => r.confidence === 'confirmed' || r.confidence === 'observed')
                .map((r) => r.title);

        const noProvenance = records.filter((r) => r.provenance.length === 0);
        const unverified = records.filter((r) => r.verification === 'unverified');
        const lowConfidence = records.filter(
          (r) => r.confidence === 'hypothesis' || r.confidence === 'unknown',
        );
        const noLicense = records.filter((r) => !r.license);

        const nextActions: Array<{ priority: 'high' | 'medium' | 'low'; action: string; rationale: string }> = [];
        if (lowConfidence.length > 0) {
          nextActions.push({
            priority: 'high',
            action: `Verify or downgrade ${lowConfidence.length} hypothesis/unknown claim(s): ${lowConfidence
              .map((r) => r.title)
              .join('; ')}`,
            rationale: 'Hypotheses must not be reported as conclusions and need corroborating evidence.',
          });
        }
        if (noProvenance.length > 0) {
          nextActions.push({
            priority: 'high',
            action: `Attach provenance to ${noProvenance.length} record(s): ${noProvenance
              .map((r) => r.title)
              .join('; ')}`,
            rationale: 'A claim without a source cannot be independently verified.',
          });
        }
        if (unverified.length > 0) {
          nextActions.push({
            priority: 'medium',
            action: `Perform static/lab review of ${unverified.length} unverified record(s) for topic "${i.topic}".`,
            rationale: 'Unverified records should be reviewed before they inform decisions.',
          });
        }
        if (records.length === 0) {
          nextActions.push({
            priority: 'high',
            action: `Ingest primary sources for topic "${i.topic}" (advisories, captures, samples) into the knowledge base.`,
            rationale: 'No evidence is currently recorded for this topic.',
          });
        }
        if (noLicense.length > 0) {
          nextActions.push({
            priority: 'low',
            action: `Record licences/terms for ${noLicense.length} source(s) to support safe reuse.`,
            rationale: 'Licensing affects redistribution and reproducibility.',
          });
        }
        if (nextActions.length === 0) {
          nextActions.push({
            priority: 'low',
            action: `Extend coverage of topic "${i.topic}" with independent corroborating sources.`,
            rationale: 'Established findings are sourced but would benefit from corroboration.',
          });
        }

        const order = { high: 0, medium: 1, low: 2 } as const;
        nextActions.sort((a, b) => order[a.priority] - order[b.priority]);

        addEvidence(ctx, {
          claim: `Identified ${nextActions.length} evidence gap(s) for topic "${i.topic}".`,
          prov: curatedProvenance('missing-evidence', i.topic),
          confidence: 'observed',
        });

        const markdown = [
          `# Missing evidence — ${i.topic}`,
          '',
          `**Established:** ${established.length}`,
          `**Records examined:** ${records.length}`,
          '',
          '## Gaps',
          `- Unverified: ${unverified.length}`,
          `- Absent provenance: ${noProvenance.length}`,
          `- Hypothesis/unknown: ${lowConfidence.length}`,
          `- Missing licence: ${noLicense.length}`,
          '',
          '## Next research actions (prioritized)',
          ...nextActions.map((a) => `- [${a.priority}] ${a.action} — ${a.rationale}`),
        ].join('\n');

        return finish({
          engine: ENGINE,
          tool: 'missing_evidence_identify',
          startedAt: started,
          ctx,
          data: {
            topic: i.topic,
            established,
            gaps: {
              unverified: unverified.map((r) => r.id),
              absentProvenance: noProvenance.map((r) => r.id),
              lowConfidence: lowConfidence.map((r) => r.id),
              missingLicence: noLicense.map((r) => r.id),
            },
            nextActions,
          },
          summary: markdown,
        });
      },
    }),

    defineTool({
      name: 'research_audit',
      title: 'Evidence & verification audit',
      engine: ENGINE,
      description:
        'Act as the Evidence & Verification Auditor: audit knowledge records for missing provenance, ' +
        'unverified status, low-confidence records presented as conclusions and cross-source ' +
        'contradictions. Returns findings with severity and a pass/fail assessment.',
      capabilities: [],
      risk: 'safe',
      inputSchema: {
        topic: z.string().optional().describe('Audit records tagged/matching this topic.'),
        recordIds: z.array(z.string()).optional().describe('Explicit knowledge record ids to audit.'),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const i = input as { topic?: string; recordIds?: string[] };
        const kb = getKnowledgeBase();

        let records: KnowledgeRecord[] = [];
        if (i.recordIds && i.recordIds.length > 0) {
          records = i.recordIds
            .map((id) => kb.getRecord(id))
            .filter((r): r is KnowledgeRecord => Boolean(r));
        } else if (i.topic) {
          records = recordsForTopic(i.topic);
        }
        if (records.length === 0) {
          throw errors.invalidInput(
            'Provide either recordIds or a topic that resolves to at least one record.',
            { topic: i.topic ?? null, recordIds: i.recordIds ?? [] },
          );
        }

        const findings: Array<{ severity: 'high' | 'medium' | 'low'; recordId: string; issue: string }> = [];
        for (const r of records) {
          if (r.provenance.length === 0) {
            findings.push({ severity: 'high', recordId: r.id, issue: 'Missing provenance (no source recorded).' });
          }
          if (r.verification === 'unverified') {
            findings.push({ severity: 'medium', recordId: r.id, issue: 'Verification state is "unverified".' });
          }
          if (r.verification === 'disputed') {
            findings.push({ severity: 'high', recordId: r.id, issue: 'Verification state is "disputed".' });
          }
          if (r.confidence === 'hypothesis' || r.confidence === 'unknown') {
            findings.push({
              severity: 'medium',
              recordId: r.id,
              issue: `Confidence is "${r.confidence}" and must not be reported as a conclusion.`,
            });
          }
          if (!r.license && r.category === 'dataset') {
            findings.push({ severity: 'low', recordId: r.id, issue: 'Dataset record has no licence recorded.' });
          }
        }

        // Cross-source contradictions: same identifier value, different confidence.
        const byIdentifier = new Map<string, KnowledgeRecord[]>();
        for (const r of records) {
          for (const [scheme, value] of Object.entries(r.identifiers)) {
            const key = `${scheme}:${value}`.toLowerCase();
            const list = byIdentifier.get(key) ?? [];
            list.push(r);
            byIdentifier.set(key, list);
          }
        }
        for (const [key, list] of byIdentifier.entries()) {
          const distinct = new Set(list.map((r) => r.confidence));
          if (list.length > 1 && distinct.size > 1) {
            findings.push({
              severity: 'high',
              recordId: list[0]!.id,
              issue: `Cross-source contradiction: identifier "${key}" appears with conflicting confidence (${[...distinct].join(', ')}).`,
            });
          }
        }

        const high = findings.filter((f) => f.severity === 'high').length;
        const medium = findings.filter((f) => f.severity === 'medium').length;
        const low = findings.filter((f) => f.severity === 'low').length;
        const verdict: 'pass' | 'fail' = high === 0 ? 'pass' : 'fail';

        addEvidence(ctx, {
          claim: `Audited ${records.length} record(s): verdict ${verdict} (${high} high, ${medium} medium, ${low} low).`,
          prov: curatedProvenance('research-audit'),
          confidence: 'observed',
          data: { records: records.length, high, medium, low },
        });
        ctx.evidence.assert({
          statement: `Evidence audit of ${records.length} record(s) produced verdict "${verdict}".`,
          status: 'direct_observation',
          confidence: 'observed',
          producedBy: 'research_audit',
        });

        const markdown = [
          `# Research audit`,
          '',
          `**Records audited:** ${records.length} • **Verdict:** ${verdict.toUpperCase()}`,
          `**Findings:** ${high} high, ${medium} medium, ${low} low`,
          '',
          '## Findings',
          ...(findings.length
            ? findings.map((f) => `- [${f.severity}] \`${f.recordId}\` — ${f.issue}`)
            : ['- No issues found.']),
        ].join('\n');

        return finish({
          engine: ENGINE,
          tool: 'research_audit',
          startedAt: started,
          ctx,
          data: {
            audited: records.length,
            verdict,
            counts: { high, medium, low, total: findings.length },
            findings,
          },
          summary: markdown,
        });
      },
    }),
  ],
};
