---
name: research-tool-development
description: "Develop, test and maintain small research and analysis tools, from scaffold through review, build and regression testing. Defensive research tooling only."
version: 1.0.0
engines: [software-engineering, knowledge-and-evidence]
tags: [tooling, development, testing, source-engineering, research]
tools: [source_generate, source_modify, source_review, source_refactor, build_project, run_tests, regression_test, code_quality_report]
license: internal
---

# Research Tool Development

## Purpose
Build and maintain small, focused tools that support research and analysis: parsers, diff helpers, report
generators and similar utilities. The workflow covers scaffold, implementation, review, build and regression.

## Supported versions
- New tools and iterative changes to existing research tools.
- Language-agnostic via the software-engineering engine.

## Prerequisites
- A clear tooling objective and acceptance criteria.
- An understanding that tools must be analysis/defensive only.

## Inputs and outputs
- Input: objective, target repository, acceptance criteria.
- Output: generated/modified source, review findings, build/test results, quality report, evidence.

## Required tools
- `source_generate` / `source_modify` — create or change the tool.
- `source_review` — review the implementation.
- `source_refactor` — improve structure when needed.
- `build_project` / `run_tests` / `regression_test` — verify behaviour.
- `code_quality_report` — assess quality.

## Procedure
1. Scaffold or modify the tool with `source_generate`/`source_modify`.
2. Review with `source_review`; refactor if needed.
3. Build with `build_project` and run `run_tests`.
4. Add a regression test with `regression_test` for the change.
5. Assess with `code_quality_report` and record results.

## Examples
- A PCAP field parser → scaffold, implement, build and add a regression test.
- A report generator → modify, review and verify output with tests.

## Known limitations
- Tools must remain within the security boundary (analysis/defensive).
- Verification is limited to the tests that are actually written and run.

## Verification criteria
- Build and test output is recorded, not assumed.
- The tool's scope is analysis/defensive.
- Changes are covered by a regression test.

## Provenance
- Platform methodology: MIRAI specification §6 (Attack Source Engineering) and §15 (Testing & QA).
- Record build/test output as provenance.
