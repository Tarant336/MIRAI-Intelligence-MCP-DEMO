/**
 * MCP prompt templates.
 *
 * Prompts encode the platform's autonomous working rules (§15) and the
 * multi-agent research workflow (§8) so that clients can invoke them directly.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

export interface PromptDefinition {
  name: string;
  title: string;
  description: string;
  argsSchema: z.ZodRawShape;
  build: (args: Record<string, string | undefined>) => string;
}

const AUTONOMOUS_RULES = `Autonomous working rules (§15):
1. Identify the relevant engine(s) first.
2. Inspect existing project context before acting.
3. Search available knowledge before guessing.
4. State exactly what evidence is missing.
5. Fetch official sources when needed.
6. Produce an implementation/research plan.
7. Execute the appropriate tools.
8. Verify every output.
9. Record significant findings with provenance.
10. Emit a concise but technically complete report.

Never claim a compile/test succeeded unless it actually ran.
Never claim an exploit is exploitable merely because a CVE exists.
Never claim a sample uses AI without supporting evidence.
Never confuse attack-method ANALYSIS with the authority to EXECUTE attacks.`;

const EVIDENCE_RULES = `Evidence rules (§9, §10):
- Prefer, in order: source code > official vendor docs > official advisories > peer-reviewed
  research > reproducible technical research > reputable security orgs > community repos > secondary commentary.
- For every significant conclusion record: claim, source, URL, publication date, retrieval date,
  relevant version, code/doc location, supporting evidence, confidence, contradicting evidence, research status.
- Never fabricate CVEs, malware capabilities, attack methods, exploitation success, API behaviour,
  build results, test results, AI integration, or product capabilities.
- If evidence is insufficient, say that it is not known.`;

export const PROMPTS: PromptDefinition[] = [
  {
    name: 'autonomous_task',
    title: 'Autonomous engineering / research task',
    description:
      'Run a complex task end-to-end using the platform\'s autonomous working rules, with evidence tracking and verification.',
    argsSchema: {
      task: z.string().describe('The task or research question to accomplish.'),
      constraints: z.string().optional().describe('Optional constraints, scope or acceptance criteria.'),
    },
    build: (args) =>
      [
        `# Task`,
        args.task ?? '(no task provided)',
        args.constraints ? `\n# Constraints\n${args.constraints}` : '',
        '',
        AUTONOMOUS_RULES,
        '',
        EVIDENCE_RULES,
        '',
        `Start by calling \`health_check\` and \`environment_report\` to learn the platform state, ` +
          `then plan with \`orchestrator_plan\` if the task is complex.`,
      ]
        .filter(Boolean)
        .join('\n'),
  },
  {
    name: 'malware_research_workflow',
    title: 'IoT malware / Mirai research workflow',
    description:
      'Structured, defense-oriented workflow for analysing an authorized IoT malware / Mirai-family sample.',
    argsSchema: {
      samplePath: z.string().describe('Workspace-relative path to the sample, source tree or firmware.'),
      objective: z.string().optional().describe('What you want to determine about the sample.'),
    },
    build: (args) =>
      [
        `# IoT malware research workflow`,
        `Sample: ${args.samplePath ?? '(unspecified)'}`,
        args.objective ? `Objective: ${args.objective}` : '',
        '',
        `Steps:`,
        `1. \`environment_report\` — confirm available analysis tools (Ghidra, radare2, binwalk, QEMU, YARA).`,
        `2. \`malware_sample_analyze\` — format, architecture, strings, packer hints, hash.`,
        `3. \`binary_similarity\` against any known references to support family attribution.`,
        `4. \`mirai_variant_analyze\` — test the architecture/behaviour checklist against ACTUAL evidence.`,
        `5. \`c2_protocol_analyze\` — reconstruct the C2 protocol specification defensively.`,
        `6. \`malware_behavior_report\` — map observations to the botnet lifecycle stages.`,
        `7. \`ai_malware_indicator_analyze\` — classify any AI indicators into categories 1–5; default to category 5 for plain automation.`,
        `8. \`attack_method_search\` / \`attack_behavior_analyze\` — document (never implement) attack methods observed.`,
        `9. \`attack_detection_recommend\` — produce defensive detection guidance.`,
        `10. \`research_report_generate\` — assemble an evidence-only report with provenance and confidence.`,
        '',
        `Attribution must be supported by code- and behaviour-level evidence. Do NOT assume every IoT botnet is a Mirai variant.`,
        '',
        EVIDENCE_RULES,
      ]
        .filter(Boolean)
        .join('\n'),
  },
  {
    name: 'vulnerability_research_workflow',
    title: 'Exploit & vulnerability research workflow',
    description:
      'Structured workflow for root-cause analysis, patch diffing and defensive validation of a vulnerability.',
    argsSchema: {
      cveId: z.string().optional().describe('CVE identifier, e.g. CVE-2017-17215.'),
      sourcePath: z.string().optional().describe('Workspace path to the vulnerable source, if available.'),
      patchedPath: z.string().optional().describe('Workspace path to the patched source, if available.'),
    },
    build: (args) =>
      [
        `# Vulnerability research workflow`,
        args.cveId ? `CVE: ${args.cveId}` : '',
        args.sourcePath ? `Vulnerable source: ${args.sourcePath}` : '',
        args.patchedPath ? `Patched source: ${args.patchedPath}` : '',
        '',
        `Steps:`,
        `1. \`cve_search\` / \`advisory_search\` — retrieve the advisory and record provenance.`,
        `2. \`cwe_search\` — classify the weakness.`,
        `3. \`vulnerability_root_cause\` — determine WHY the flaw exists.`,
        `4. \`patch_diff_analyze\` — diff vulnerable vs patched and classify the fix.`,
        `5. \`safe_validation_generate\` — produce a NON-DESTRUCTIVE regression test.`,
        `6. \`run_tests\` — verify the regression test actually passes/fails as expected.`,
        `7. \`vulnerability_pipeline_report\` — assemble the unified §C6 report.`,
        '',
        `A detection template is not an exploit. A published PoC is not verified. An advisory is not proof a specific family used it.`,
        '',
        EVIDENCE_RULES,
      ]
        .filter(Boolean)
        .join('\n'),
  },
  {
    name: 'anti_ddos_defense_workflow',
    title: 'Anti-DDoS design & verification workflow',
    description: 'Design, generate and validate defensive DDoS mitigations inside an isolated lab.',
    argsSchema: {
      system: z.string().describe('Description of the system or service to protect.'),
      layer: z.string().optional().describe('Primary layer: network | application | dns_infra | detection.'),
    },
    build: (args) =>
      [
        `# Anti-DDoS defense workflow`,
        `System: ${args.system ?? '(unspecified)'}`,
        args.layer ? `Layer: ${args.layer}` : '',
        '',
        `Steps:`,
        `1. \`anti_ddos_research\` — survey defensive technology for the layer.`,
        `2. \`defense_architecture_analyze\` — inspect existing local configs.`,
        `3. \`pcap_analyze\` / \`network_traffic_analyze\` — characterise observed traffic defensively.`,
        `4. \`ddos_detection_design\` — design the detection system and baselines.`,
        `5. \`detection_rule_generate\` — emit Suricata/Sigma/YARA/Zeek detection artifacts.`,
        `6. \`rate_limit_design\` — design rate limiting and concurrency caps.`,
        `7. \`mitigation_strategy_compare\` — compare mitigation options.`,
        `8. \`defense_test_plan\` — produce a SAFE, rate-limited, lab-only test plan (requires MIRAI_LAB_TOKEN for active testing).`,
        `9. \`defense_performance_analyze\` — evaluate detection rate, FP/FN, latency, throughput, CPU/memory.`,
        '',
        `NEVER produce unthrottled generators, distributed load generators, source spoofing, reflection/amplification launchers, or public-target stress tools.`,
        '',
        EVIDENCE_RULES,
      ]
        .filter(Boolean)
        .join('\n'),
  },
  {
    name: 'software_engineering_workflow',
    title: 'Large-scale software engineering workflow',
    description:
      'Understand a repository, plan changes, implement, build, test, fix and report — autonomously.',
    argsSchema: {
      repositoryPath: z.string().describe('Workspace-relative path to the repository root.'),
      goal: z.string().describe('The engineering goal.'),
    },
    build: (args) =>
      [
        `# Software engineering workflow`,
        `Repository: ${args.repositoryPath ?? '(unspecified)'}`,
        `Goal: ${args.goal ?? '(unspecified)'}`,
        '',
        `Steps:`,
        `1. \`engineering_toolchain_probe\` — confirm available toolchains.`,
        `2. \`repository_analyze\` + \`architecture_analyze\` — understand structure and imports.`,
        `3. \`dependency_analyze\` + \`documentation_search\` — confirm versions and APIs.`,
        `4. \`project_memory\` (action=get) — load prior decisions for THIS repository only.`,
        `5. Plan the change; then \`source_generate\` / \`source_modify\` / \`source_refactor\`.`,
        `6. \`build_project\` — build and parse compiler diagnostics.`,
        `7. \`run_tests\` / \`regression_test\` — verify.`,
        `8. \`debug_project\` — if something fails, iterate: read error → root cause → fix → re-verify.`,
        `9. \`source_review\` + \`code_quality_report\` — quality gate.`,
        `10. \`project_memory\` (action=set) — persist decisions, build commands, errors and fixes.`,
        '',
        `Never modify a repository before understanding the relevant existing implementation.`,
        `Never claim a build or test succeeded unless the command actually ran and exited 0.`,
      ]
        .filter(Boolean)
        .join('\n'),
  },
  {
    name: 'skill_workflow',
    title: 'Skills-driven complex task workflow',
    description:
      'Given a complex task, discover relevant skills, select and combine them into an ordered tool plan, and execute the workflow.',
    argsSchema: {
      task: z.string().describe('The complex task to accomplish.'),
      maxSkills: z.number().int().min(1).max(10).optional().describe('Maximum skills to select (default 3).'),
      engines: z.array(z.string()).optional().describe('Restrict to skills using these engines.'),
    },
    build: (args) =>
      [
        `# Skills-driven complex task workflow`,
        `Task: ${args.task ?? '(unspecified)'}`,
        args.maxSkills ? `Max skills: ${args.maxSkills}` : '',
        args.engines ? `Engines: ${(args.engines as unknown as string[]).join(', ')}` : '',
        '',
        `Steps:`,
        `1. \`skill_list\` — browse the Skills Library (optionally filtered by engine/tag).`,
        `2. \`skill_select\` — rank and combine the most relevant skills for the task, producing an ordered tool plan and workflow.`,
        `3. For each selected skill: \`skill_get\` — read the full skill body (purpose, prerequisites, procedure, examples, limitations, verification criteria).`,
        `4. Execute the tool plan step by step, using the engine tools specified by the skills.`,
        `5. Checkpoint progress with \`research_checkpoint\` after each major step.`,
        `6. If evidence is missing, use \`missing_evidence_identify\` and gather more data.`,
        `7. Reconcile any conflicting findings with \`evidence_reconciliation\`.`,
        `8. Generate a final report with \`research_report_generate\` containing all claims, provenance and confidence.`,
        '',
        `Rules:`,
        `- Never skip reading the full skill body (skill_get) before executing its recommended tools.`,
        `- Every conclusion must have provenance and a confidence level.`,
        `- Contradictions between skills must be recorded, not suppressed.`,
        `- If no skill matches, fall back to direct engine tools and document why.`,
      ]
        .filter(Boolean)
        .join('\n'),
  },
];

/** Register all prompts on the MCP server. */
export function registerPrompts(server: McpServer): void {
  for (const prompt of PROMPTS) {
    server.registerPrompt(
      prompt.name,
      {
        title: prompt.title,
        description: prompt.description,
        argsSchema: prompt.argsSchema,
      },
      (args) => ({
        messages: [
          {
            role: 'user' as const,
            content: { type: 'text' as const, text: prompt.build(args as Record<string, string | undefined>) },
          },
        ],
      }),
    );
  }
}
