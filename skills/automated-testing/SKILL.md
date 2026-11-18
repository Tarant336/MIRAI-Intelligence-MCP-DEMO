---
name: automated-testing
description: Author and run unit, integration, regression and property tests, and convert a reproduced defect into a durable regression test. Use when adding coverage or verifying a fix.
version: 1.0.0
engines: [software-engineering]
tags: [testing, unit, integration, regression, coverage, vitest, assertions]
tools: [run_tests, regression_test, source_generate, source_modify, debug_project, code_quality_report]
license: internal
---

# Automated Testing

## Purpose
Design and implement meaningful automated tests — unit, integration, regression and property-based — that
actually run and assert real behaviour, and lock in fixes with regression tests.

## Supported versions
- Test frameworks detected from the project (e.g. vitest, jest, pytest, go test).
- Runs only inside the isolated-execution sandbox.

## Prerequisites
- Isolated execution enabled.
- Knowledge of the public contract being tested (interfaces/return types).

## Inputs and outputs
- Input: target module/behaviour, existing test layout, defect to lock in.
- Output: new test files, executed results (pass/fail counts), coverage notes.

## Required tools
- `run_tests` — execute the suite and report results.
- `regression_test` — run targeted regression tests.
- `source_generate` / `source_modify` — add/extend test cases.
- `debug_project` — diagnose failing tests.
- `code_quality_report` — identify untested hotspots.

## Procedure
1. Locate the existing test layout and conventions (never introduce a competing framework).
2. For a defect: reproduce it as a failing test first.
3. Implement/extend tests that assert observable behaviour, not implementation details.
4. Run `run_tests`; iterate until green.
5. Lock the fix with `regression_test`; record results in the repository memory.

## Examples
- Reproduce a parsing bug with a table-driven test, then fix and confirm the test flips.
- Add integration coverage that boots the component with an in-memory transport.

## Known limitations
- Tests assert observed behaviour; they cannot prove absence of all defects.
- Flaky/timing-dependent tests are flagged, not hidden.
- Coverage numbers are indicative, not a correctness guarantee.

## Verification criteria
- The test command actually executed and reported pass counts.
- New behaviour has at least one focused test; a fixed defect has a regression test.
- No test is marked passing without a real run.

## Provenance
- Platform methodology: §A4, §A6 of the MIRAI specification.
- Framework conventions from the target project's own configuration.
