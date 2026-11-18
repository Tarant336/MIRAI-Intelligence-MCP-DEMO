❤️ Support My Work

If you find my projects useful, please consider supporting me with a donation.

Your support helps me maintain my projects, improve existing features, and develop more useful open-source tools.

Every donation, no matter how small, is greatly appreciated. Thank you for your kindness and support!

💰 Donate via USDT (TRC20)
Network: TRON (TRC20)
Currency: USDT
Wallet Address: TENRVUreWCFdGzceVsG6Lwr2EQtKytQQ2b

Thank you for supporting open-source development! ❤️
====================================================================================================
# MIRAI Intelligence & Research MCP

An autonomous, evidence-driven research and software-engineering platform implemented as a
**Model Context Protocol (MCP) server** in **TypeScript**.

The platform unifies three core intelligence engines on top of one shared evidence layer:

- **Engine A — Technical Software Engineering Intelligence** (`software-engineering`)
- **Engine B — Botnet, Mirai & Malware Intelligence** (`malware-intelligence`)
- **Engine C — Exploit & Vulnerability Intelligence** (`exploit-intelligence`)
- **Engine D — Zero-Day Research** (`zero-day-research`)

plus supporting engines: `attack-methods`, `anti-ddos`, `firmware-intelligence`,
`network-forensics`, `knowledge-and-evidence`, `datasets`, `multi-agent`, `platform`,
**and `skills` — a versioned library of reusable techniques**.

---

## 1. Status

| Item | Result |
|---|---|
| Registered engines | **13** |
| Registered MCP tools | **113** |
| MCP prompts | **6** |
| MCP resources | **2** |
| Multi-agent roles / workstreams | **23 / 23** |
| Skills in library | **36** |
| Typecheck (`tsc --noEmit`) | 0 errors |
| Build (`tsc`) | success |
| Test suite (vitest) | **178/178 pass** (12 files) |
| End-to-end stdio check | success (113 tools, 6 prompts) |

---

## 2. Install and run

```bash
npm install
npm run build          # compile to dist/
npm start              # run the MCP server over stdio
npm run dev            # development mode (tsx watch)
npm run verify         # typecheck + full test suite
npm run stdio-check    # real JSON-RPC handshake over stdin/stdout
npm run inspector      # open MCP Inspector
```

### Register with an MCP client (example JSON config)

```json
{
  "mcpServers": {
    "mirai-intelligence": {
      "command": "node",
      "args": ["/absolute/path/to/mirai-mcp/dist/index.js"],
      "env": {
        "MIRAI_WORKSPACE": "/absolute/path/to/your/workspace",
        "MIRAI_LOG_LEVEL": "info"
      }
    }
  }
}
```

---

## 3. Configuration

Configuration is merged in this order: `MIRAI_*` environment variables → `mirai.config.json`
(or `MIRAI_CONFIG`) → defaults.

| Variable | Default | Meaning |
|---|---|---|
| `MIRAI_WORKSPACE` | `process.cwd()` | Directory boundary for reads/writes |
| `MIRAI_DATA_DIR` | `~/.mirai-mcp` | Knowledge base storage location |
| `MIRAI_LOG_LEVEL` | `info` | `debug` \| `info` \| `warn` \| `error` |
| `MIRAI_ALLOW_PUBLIC_FETCH` | `true` | Allow public network access (read-only) |
| `MIRAI_ALLOW_ISOLATED_EXEC` | `true` | Allow command execution inside the isolated sandbox |
| `MIRAI_EXEC_TIMEOUT_MS` | `120000` | Hard timeout per sandboxed command |
| `MIRAI_EXEC_MAX_OUTPUT_BYTES` | `4194304` | Output size cap |
| `MIRAI_MAX_ARTIFACT_BYTES` | `268435456` | Cap for artifacts read into memory |
| `MIRAI_LAB_TOKEN` | *(unset)* | Required token for active lab testing |
| `MIRAI_TRANSPORT` | `stdio` | `stdio` (HTTP not enabled) |

> `allowOffensiveOps` is **always `false`** and cannot be enabled through configuration (hard-coded
> in [config/index.ts](src/config/index.ts)).

### Dependency diagnostics

The platform **never assumes** external tools are installed. Every dependency is probed
(read-only — it never downloads or installs anything) and reported as one of:

`AVAILABLE` · `MISSING` · `VERSION_UNSUPPORTED` · `CONFIGURATION_ERROR` · `NOT_REQUIRED`

Probed dependencies: **GCC, Clang, AFL++, Honggfuzz, QEMU ARM/MIPS, Binwalk, 7-Zip, objdump,
readelf, strings, nm, Radare2, Ghidra, Git.** (See
[dependencies.ts](src/core/dependencies.ts).)

- The `dependency_diagnostics` tool (engine `platform`) lists each dependency's status; pass
  `required: ["aflplusplus", ...]` to mark dependencies your workflow needs.
- `environment_report` embeds the same probe results.
- A tool that depends on an unavailable dependency **throws `TOOL_MISSING`** with per-dependency
  install hints — it never returns a fake success.
- `node scripts/dependency-report.mjs` writes host status to `scripts/_dependency-report.json`
  (does not fail the build; missing dependencies are recorded as **BLOCKED**, never PASS).

---

## 4. Architecture

```
src/
├── index.ts                     # entry point: registers all engines + starts the server
├── config/index.ts              # merged configuration, safe defaults
├── core/
│   ├── server.ts                # MCP SDK adapter: policy gate → handler → evidence
│   ├── registry.ts              # ToolRegistry: unique names, policy pre-screening
│   ├── tool.ts                  # EngineModule / ToolDefinition / ToolContext
│   ├── errors.ts                # MiraiError with actionable `code` + `hint`
│   ├── logger.ts                # structured logging over stderr (keeps stdio clean)
│   └── environment.ts           # Phase 1 — environment discovery
├── shared/
│   ├── security.ts              # security boundary: path containment, capability gating
│   ├── exec.ts                  # execution sandbox: argv-only, timeout, output cap
│   ├── evidence.ts              # EvidenceCollector, provenance, aggregateConfidence
│   ├── knowledge-base.ts        # knowledge store + evidence graph (atomic JSON)
│   ├── curated-datasets.ts      # curated reference data (real sources only)
│   └── types.ts                 # shared type contracts
├── skills/                      # Skills Library system (independent of engines)
│   ├── types.ts                 # SkillManifest, SkillSelection, type contracts
│   ├── frontmatter.ts           # YAML front-matter parser (no external dependency)
│   ├── loader.ts                # auto-discovery of skills/<name>/SKILL.md, validate + parse
│   └── registry.ts              # SkillRegistry: unique names, search, multi-select
├── prompts/index.ts             # 6 MCP prompt workflows
├── tools/
│   ├── helpers.ts               # defineTool / finish / addEvidence / artifact readers
│   └── platform.ts              # engine `platform`
└── engines/                     # 13 independent engines
```

### Tool execution flow

1. `ToolRegistry` pre-screens the tool descriptor through `evaluateIntent` (blocks forbidden
   capabilities).
2. `server.ts` checks `registry.screen(name)`; if blocked it returns `blocked: true` together with
   a **defensive alternative** instead of a generic refusal.
3. The handler runs with a `ToolContext` (logger, knowledge base, `EvidenceCollector`).
4. Results are wrapped in a **uniform** `ToolResult`: `ok`, `data`, `summary`, `evidence`,
   `assertions`, `warnings`, `blocked`, `durationMs`, `timestamp`.
5. After every call the knowledge base is `flush()`ed (atomic write).

---

## 5. Catalogue of 113 MCP tools

### `platform` (3)
`environment_report` · `health_check` · `dependency_diagnostics`

### `knowledge-and-evidence` (7)
`knowledge_search` · `knowledge_ingest` · `evidence_graph_query` · `source_provenance_check` ·
`research_report_generate` · `knowledge_update` · `research_checkpoint`

### `datasets` (3)
`curated_dataset_search` · `curated_dataset_ingest` · `curated_dataset_stats`

### `software-engineering` (17)
`engineering_toolchain_probe` · `repository_analyze` · `repository_search` · `symbol_search` ·
`dependency_analyze` · `documentation_search` · `architecture_analyze` · `source_generate` ·
`source_modify` · `source_review` · `source_refactor` · `build_project` · `run_tests` ·
`debug_project` · `regression_test` · `code_quality_report` · `project_memory`

### `malware-intelligence` (10)
`malware_sample_analyze` · `malware_family_compare` · `mirai_variant_analyze` ·
`malware_source_analyze` · `binary_similarity` · `malware_behavior_report` ·
`c2_protocol_analyze` · `ai_malware_indicator_analyze` · `honeypot_telemetry_analyze` ·
`botnet_lifecycle_stage_search`

### `zero-day-research` (16)
`zero_day_discovery_analyze` · `vulnerability_hypothesis_generate` · `vulnerability_hypothesis_rank` ·
`source_vulnerability_analyze` · `binary_vulnerability_analyze` · `firmware_vulnerability_analyze` ·
`static_analysis_run` · `fuzz_target_identify` · `fuzz_harness_generate` · `fuzzing_crash_analyze` ·
`crash_root_cause_analyze` · `vulnerability_verify` · `patch_root_cause_analyze` ·
`vulnerability_variant_hunt` · `zero_day_lifecycle_update` · `zero_day_research_report`

### `exploit-intelligence` (14)
`knowledge_source_registry` · `cve_search` · `cwe_search` · `advisory_search` ·
`exploit_reference_search` · `nuclei_template_search` · `yara_rule_search` · `sigma_rule_search` ·
`knowledge_source_sync` · `exploit_metadata_analyze` · `vulnerability_root_cause` ·
`patch_diff_analyze` · `safe_validation_generate` · `vulnerability_pipeline_report`

### `attack-methods` (6)
`attack_method_search` · `attack_method_classify` · `malware_attack_module_analyze` ·
`attack_behavior_analyze` · `attack_method_compare` · `attack_detection_recommend`

### `anti-ddos` (10)
`anti_ddos_research` · `defense_architecture_analyze` · `network_traffic_analyze` · `pcap_analyze` ·
`ddos_detection_design` · `detection_rule_generate` · `rate_limit_design` ·
`mitigation_strategy_compare` · `defense_test_plan` · `defense_performance_analyze`

### `firmware-intelligence` (8)
`firmware_analyze` · `firmware_extract` · `firmware_filesystem_analyze` · `elf_analyze` ·
`firmware_component_scan` · `emulation_plan` · `firmware_patch_diff` · `firmware_integrity_check`

### `network-forensics` (9)
`pcap_flow_analyze` · `pcap_dns_analyze` · `pcap_http_analyze` · `pcap_tls_metadata_analyze` ·
`c2_beacon_detect` · `ioc_extract` · `network_timeline_reconstruct` · `protocol_fingerprint` ·
`flow_summarize`

### `multi-agent` (7)
`agent_roles_list` · `orchestrator_plan` · `agent_brief_generate` · `agent_findings_merge` ·
`evidence_reconciliation` · `missing_evidence_identify` · `research_audit`

> Architecture §8/§11: **23 specialist roles** and **23 workstreams** are validated against
> dependencies; `agent_roles_list` lists roles, `orchestrator_plan` decomposes a task into
> parallelisable phases, and `agent_findings_merge` + `evidence_reconciliation` merge findings and
> reconcile evidence.

### `skills` (3)
`skill_list` · `skill_get` · `skill_select`

### MCP prompts (6)
`autonomous_task` · `malware_research_workflow` · `vulnerability_research_workflow` ·
`anti_ddos_defense_workflow` · `software_engineering_workflow` · `skill_workflow`

### MCP resources
`mirai://knowledge/stats` — knowledge base statistics as JSON.
`mirai://skills/index` — full Skills library listing (JSON: total, facets, per-skill metadata).

---

## 6. Skills library (engine `skills`)

The `skills` engine provides a **versioned technique library** that lets an agent discover,
inspect and combine multiple skills to solve complex tasks. Each skill is a `SKILL.md` file at
`skills/<name>/SKILL.md` following a standard schema:

- **YAML front matter**: `name`, `description`, `version`, `engines[]`, `tags[]`, `tools[]`, `license`
- **Body (Markdown)**: Purpose, Prerequisites, Inputs/Outputs, Procedure, Examples, Known
  limitations, Verification criteria, Provenance

### 36 skills available (version 1.0.0)

Each skill is a `skills/<name>/SKILL.md` with complete front matter and the standard body. Current
list:

`anti-ddos-defense` · `api-reverse-engineering` · `attack-source-engineering` ·
`automated-testing` · `binary-vulnerability-analysis` · `build-and-debug` · `code-review` ·
`evidence-based-research` · `evidence-validation-and-reconciliation` ·
`exploit-mechanism-research` · `exploit-source-analysis` · `exploit-source-code-analysis` ·
`firmware-analysis` · `firmware-zero-day-research` · `fuzzing-and-crash-triage` ·
`malware-configuration-extraction` · `malware-reverse-engineering` ·
`malware-source-code-analysis` · `malware-variant-comparison` ·
`memory-corruption-research` · `mirai-api-c2-protocol-analysis` ·
`mirai-botnet-lineage-analysis` · `mirai-c2-protocol-research` · `mirai-deep-source-analysis` ·
`mirai-variant-intelligence` · `patch-diff-and-variant-hunting` · `pcap-network-forensics` ·
`protocol-reverse-engineering` · `repository-analysis` · `research-tool-development` ·
`software-architecture` · `source-vulnerability-analysis` · `static-analysis-research` ·
`threat-intelligence-correlation` ·
`vulnerability-root-cause-analysis` · `zero-day-vulnerability-discovery`

### MCP tools

| Tool | Description |
|---|---|
| `skill_list` | List skills, filter by engine/tag, return facets |
| `skill_get` | Fetch the full skill content (front matter + body) |
| `skill_select` | Select and combine skills for a task → ranked recommendations + tool plan + workflow |

### MCP resource

`mirai://skills/index` — JSON: `{ root, total, facets: {engines, tags}, skills: [...] }`

### MCP prompt

`skill_workflow` — 8-step guide: list → select → get → execute tool plan → checkpoint → missing
evidence → reconciliation → final report.

### Quick usage

```json
// 1. Browse the library
{ "tool": "skill_list", "input": { "engine": "malware-intelligence", "limit": 10 } }

// 2. Pick skills for a task
{ "tool": "skill_select", "input": { "task": "analyze mirai botnet sample c2 protocol", "limit": 3 } }

// 3. Read skill details
{ "tool": "skill_get", "input": { "name": "mirai-api-c2-protocol-analysis" } }
```

---

## 7. Evidence model

Every conclusion carries **provenance** and **confidence**; hypotheses are never presented as
confirmed findings.

- `ConfidenceLevel`: `confirmed` → `observed` → `inferred` → `hypothesis` → `unknown`
- `EpistemicStatus`: `verified_fact` · `direct_observation` · `researcher_interpretation` ·
  `hypothesis` · `unverified_claim`
- `EvidenceRef` contains `claim`, `provenance` (source/url/publishedAt/retrievedAt/version/commit/license),
  `confidence`, `locator` (file/line/symbol/offset) and `data`.
- `Assertion` groups `supporting` + `contradicting` evidence.
- `aggregateConfidence()` computes confidence along the **weakest link**.
- `KnowledgeCategory` is **strictly separated**: `advisory`, `detection_template`,
  `fingerprint_template`, `exploit_poc`, `exploit_module`, `yara_rule`, `sigma_rule`,
  `network_detection_rule`, `remediation_guidance`, `patch_reference`, `research_paper`,
  `attack_method`, `defense_technology`, `dataset`, `firmware_component`, `malware_family`,
  `mirai_variant`, `c2_protocol_spec`, `malware_sample_ref`.
- `VerificationState`: `unverified` · `statically_reviewed` · `lab_validated_non_destructive` ·
  `disputed` — **a published PoC is not automatically treated as verified**.

---

## 8. Security boundary (§10)

Allowed: malware source and binary analysis, reverse engineering, root-cause analysis, safe PoC
analysis, non-destructive validation, isolated lab simulation, firmware analysis, PCAP analysis,
detection engineering, DDoS defence deployment, defensive automation, source development and
patching, regression testing, honeypot/sinkhole research.

**Not allowed** (hard-coded, cannot be enabled through configuration): deployable botnets,
automated recruitment/infection, worm propagation, malware persistence, unauthorised exploitation,
credential theft/brute force, botnet C2, operational DDoS code, distributed flooding,
reflection/amplification launchers, source spoofing, evasion code aimed at third-party products,
automated exploitation of public targets.

Enforcement:

- [security.ts](src/shared/security.ts) — `evaluateIntent()` matches forbidden capability patterns
  and returns a **defensive alternative**; `resolveWorkspacePath()` blocks path traversal outside
  the workspace; `requireLabAuthorization()` requires a token for active testing.
- [exec.ts](src/shared/exec.ts) — commands run as **argv (never through a shell)**, with hard
  timeout, output cap and `cwd` confined to the workspace.
- [registry.ts](src/core/registry.ts) — pre-screens every tool before its handler runs.

---

## 9. Testing

```
tests/
├── smoke.test.ts               # registry integrity + real execution of representative tools
├── skills.test.ts              # skill loader, registry, skill selection
├── multi-agent.test.ts         # roles, orchestrator plan, briefs, findings merge, reconciliation
├── mcp-protocol.test.ts        # real Client ↔ Server over InMemoryTransport
├── firmware-extract.test.ts    # cpio/tar parsing + firmware extraction regressions
├── binary-similarity.test.ts   # binary similarity engine
├── c2-protocol.test.ts         # C2 protocol analysis
├── crash-root-cause.test.ts    # crash triage
├── curated-datasets.test.ts    # curated dataset integrity
├── dependencies.test.ts        # dependency probing
├── source-vulnerability.test.ts # source vulnerability analysis
└── stdio-check.test.ts         # stdio handshake
```

`tests/mcp-protocol.test.ts` also verifies the **policy gate**: with
`MIRAI_ALLOW_PUBLIC_FETCH=false`, `cve_search` returns `blocked: true` instead of touching the
network.

```bash
npm run verify
```

---

## 10. Adding a new engine

```ts
// src/engines/my-engine/index.ts
import type { EngineModule } from '../../core/tool.js';
import { defineTool, finish } from '../../tools/helpers.js';
import { z } from 'zod';

const ENGINE = 'my-engine';

export const myEngine: EngineModule = {
  name: ENGINE,
  title: 'My Engine',
  description: 'Engine description.',
  tools: [
    defineTool({
      name: 'my_tool',
      title: 'My tool',
      engine: ENGINE,
      description: 'Tool description.',
      capabilities: ['read_repo'],
      risk: 'safe',
      inputSchema: { path: z.string() },
      handler: async (input, ctx) => {
        const started = Date.now();
        const { path } = input as { path: string };
        return finish({
          engine: ENGINE, tool: 'my_tool', startedAt: started, ctx,
          data: { path },
          summary: `Processed ${path}.`,
        });
      },
    }),
  ],
};
```

Mandatory constraints: relative imports must end with `.js`; tool names must match
`/^[a-z][a-z0-9_]{2,63}$/` and be globally unique; `descriptor.engine` must equal
`EngineModule.name`. Then add the engine to the `ENGINES` array in [index.ts](src/index.ts).

---

## 11. Known limitations

- HTTP transport is not implemented (stdio only).
- Deep analysis (Ghidra headless, QEMU emulation, Zeek/Suricata) depends on external tools in
  `PATH`; when missing, the platform falls back to pure-JS analysis (PCAP/ELF/firmware carving) and
  states so in the result. Per-dependency status is exposed by `dependency_diagnostics`; a missing
  dependency yields a structured `TOOL_MISSING` error and must not be treated as executed.
- `emulation_plan` only **produces a plan**; it never executes untrusted firmware emulation.
- `defense_test_plan` only produces a plan; active traffic testing requires `MIRAI_LAB_TOKEN`.
- Curated data in `curated-datasets.ts` contains only verified public events; uncertain items were
  dropped rather than inferred.

---

## License

MIT — see [LICENSE](LICENSE).

**Core philosophy: Understand deeply. Research rigorously. Engineer intelligently. Verify everything. Defend effectively.**
