---
name: attack-source-engineering
description: "Research, design and develop analysis and defensive tooling grounded in attack-method intelligence. Analysis and defensive tooling only; no offensive capability."
version: 1.0.0
engines: [attack-methods, software-engineering, knowledge-and-evidence]
tags: [attack-methods, tooling, defensive, source-engineering, research]
tools: [attack_method_search, attack_method_classify, attack_behavior_analyze, malware_attack_module_analyze, source_generate, source_review, build_project, run_tests]
license: internal
---

# Attack Source Engineering

## Purpose
Translate attack-method intelligence into concrete analysis and defensive tooling: understand an attack
technique, then design, generate, review, build and test a supporting tool. Strictly analysis/defensive.

## Supported versions
- Attack methods and behaviours described by the platform's attack-methods engine.
- Tooling built with the software-engineering engine.

## Prerequisites
- A target attack technique or defensive problem.
- Clear understanding that generated code must be analysis or defensive, never offensive.

## Inputs and outputs
- Input: attack method/behaviour, tooling objective.
- Output: attack-method analysis, tool design, generated/reviewed source, build/test results, evidence.

## Required tools
- `attack_method_search` / `attack_method_classify` — identify and classify the technique.
- `attack_behavior_analyze` / `malware_attack_module_analyze` — analyse behaviour.
- `source_generate` — scaffold the tool.
- `source_review` — review the implementation.
- `build_project` / `run_tests` — verify the tool builds and tests pass.

## Procedure
1. Identify the technique with `attack_method_search` and classify it.
2. Analyse behaviour with `attack_behavior_analyze` and `malware_attack_module_analyze`.
3. Design and generate the tool with `source_generate`.
4. Review with `source_review`, then build and test.
5. Record results with provenance.

## Examples
- A DDoS reflection technique → build a detection/analysis helper, not a launcher.
- A malware attack module → develop a parser that documents its behaviour.

## Known limitations
- Generated tooling must stay within the security boundary (analysis/defensive only).
- Behavioural analysis is limited to available intelligence.

## Verification criteria
- The tool's purpose is analysis or defensive and stays in scope.
- Build and test results are recorded, not assumed.
- Every claim cites an attack-method source or code location.

## Provenance
- Platform methodology: MIRAI specification §6 (Attack Source Engineering) and §14 (Security Boundaries).
- Record build/test output and tool source as provenance.
