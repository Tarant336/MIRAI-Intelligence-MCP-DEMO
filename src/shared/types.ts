/**
 * MIRAI Intelligence & Research MCP — Shared type definitions.
 *
 * These types encode the platform-wide contracts: evidence, provenance,
 * confidence levels, engines and tool descriptors. Every engine MUST use
 * these types so that evidence can be correlated across the whole graph.
 */

/** Confidence taxonomy required by §9 of the platform specification. */
export type ConfidenceLevel =
  | 'confirmed' // verified fact (source code, official advisory)
  | 'observed' // directly observed (packet capture, runtime log)
  | 'inferred' // reasoned interpretation of evidence
  | 'hypothesis' // unverified working theory
  | 'unknown'; // explicitly not determined

/** Epistemic status used by the evidence graph (§7). */
export type EpistemicStatus =
  | 'verified_fact'
  | 'direct_observation'
  | 'researcher_interpretation'
  | 'hypothesis'
  | 'unverified_claim';

/** Provenance record attached to every knowledge artifact (§9). */
export interface Provenance {
  /** Originating source identifier, e.g. "nvd", "github", "local-repo". */
  source: string;
  /** Canonical URL when available. */
  url?: string;
  /** Publication date (ISO-8601) when known. */
  publishedAt?: string;
  /** Retrieval timestamp (ISO-8601). */
  retrievedAt: string;
  /** Relevant version / commit / release tag. */
  version?: string;
  /** Commit hash when the source is a git repository. */
  commit?: string;
  /** License of the source material when known. */
  license?: string;
  /** Free-form note on how the artifact was acquired. */
  note?: string;
}

/** Evidence reference: a single supporting or contradicting data point. */
export interface EvidenceRef {
  id: string;
  /** Human-readable claim this evidence supports. */
  claim: string;
  /** Where the evidence came from. */
  provenance: Provenance;
  /** Confidence attached to this specific evidence item. */
  confidence: ConfidenceLevel;
  /** Optional path/line/offset inside the source artifact. */
  locator?: {
    file?: string;
    line?: number;
    offset?: number;
    symbol?: string;
    packetBytes?: number;
  };
  /** Arbitrary structured payload produced by the tool that collected it. */
  data?: unknown;
}

/** A research assertion: a conclusion with supporting and contradicting evidence. */
export interface Assertion {
  id: string;
  statement: string;
  status: EpistemicStatus;
  confidence: ConfidenceLevel;
  supporting: EvidenceRef[];
  contradicting: EvidenceRef[];
  /** Tool or engine that produced the assertion. */
  producedBy: string;
  createdAt: string;
}

/** Uniform result envelope returned by every MCP tool. */
export interface ToolResult<T = unknown> {
  ok: boolean;
  engine: string;
  tool: string;
  /** Machine-readable structured payload. */
  data?: T;
  /** Human-readable summary / markdown. */
  summary: string;
  /** Evidence collected during execution. */
  evidence: EvidenceRef[];
  /** Assertions produced (with epistemic status). */
  assertions?: Assertion[];
  /** Non-fatal warnings. */
  warnings: string[];
  /** Whether the operation was blocked by the security boundary. */
  blocked?: boolean;
  /** Reason for a block. */
  blockReason?: string;
  durationMs: number;
  timestamp: string;
}

/** Capabilities that tools may require. Used by the security boundary. */
export type Capability =
  | 'read_repo'
  | 'write_repo'
  | 'run_build'
  | 'run_tests'
  | 'network_read'
  | 'network_public_fetch'
  | 'read_binary'
  | 'read_firmware'
  | 'read_pcap'
  | 'run_isolated'
  | 'write_knowledge';

/** Risk classification used to gate tool execution. */
export type RiskClass =
  | 'safe' // read-only analysis, no side effects
  | 'local_mutation' // writes within the authorized workspace
  | 'isolated_exec' // executes inside an isolated sandbox
  | 'external_fetch' // fetches public resources
  | 'prohibited'; // never permitted by policy

/** Tool descriptor registered with the MCP server. */
export interface ToolDescriptor {
  name: string;
  title: string;
  engine: string;
  description: string;
  capabilities: Capability[];
  risk: RiskClass;
  /** MCP annotations. */
  annotations: {
    readOnlyHint: boolean;
    destructiveHint: boolean;
    idempotentHint: boolean;
    openWorldHint: boolean;
  };
}

/**
 * External dependency status (§6). Every dependency probe resolves to exactly
 * one of these, so callers never have to assume a tool is present:
 *  - AVAILABLE           — executable found and usable (version verified when possible).
 *  - MISSING             — required executable not found on PATH.
 *  - VERSION_UNSUPPORTED — executable found but its version is below the required minimum.
 *  - CONFIGURATION_ERROR — executable found but could not be executed/verified.
 *  - NOT_REQUIRED        — optional executable not found (not needed by the caller).
 */
export type DependencyStatus =
  | 'AVAILABLE'
  | 'MISSING'
  | 'VERSION_UNSUPPORTED'
  | 'CONFIGURATION_ERROR'
  | 'NOT_REQUIRED';

/** Structured result of probing a single external dependency (§6). */
export interface DependencyProbe {
  /** Stable dependency id, e.g. "gcc", "qemu-arm". */
  id: string;
  title: string;
  status: DependencyStatus;
  /** Resolved executable name when the tool was found on PATH. */
  executable?: string;
  /** Detected version when the version probe succeeded and parsed. */
  version?: string;
  /** Minimum version required, when the definition declares one. */
  minVersion?: string;
  /** Exit code of the version probe, when one was executed. */
  exitCode?: number | null;
  detail: string;
  installHint: string;
  /** Whether the caller marked this dependency as required for the operation. */
  required: boolean;
}

/** Environment report produced in Phase 1 (§14). */
export interface EnvironmentReport {
  os: string;
  platform: string;
  arch: string;
  nodeVersion: string;
  pythonVersion?: string;
  cpus: number;
  totalMemoryMb: number;
  freeMemoryMb: number;
  cwd: string;
  workspaceRoot: string;
  toolchains: Record<string, string | undefined>;
  analysisTools: Record<string, boolean>;
  /** External dependency diagnostics (§6). */
  dependencies?: DependencyProbe[];
  networkRestricted: boolean;
  storageFreeMb?: number;
  generatedAt: string;
}
