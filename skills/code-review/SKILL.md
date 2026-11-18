---
name: code-review
description: Review code for correctness, memory safety, concurrency defects, injection risks, crypto misuse, resource leaks and dependency vulnerabilities — with actionable, located findings. Use when reviewing a diff or a file.
version: 1.0.0
engines: [software-engineering]
tags: [review, quality, memory-safety, race-condition, deadlock, injection, crypto, leaks]
tools: [source_review, code_quality_report, repository_search, symbol_search, dependency_analyze]
license: internal
---

# Code Review

## Purpose
Produce actionable, evidence-backed code review findings across correctness, security and maintainability:
memory safety, race conditions, deadlocks, resource leaks, unsafe input handling, injection, broken
authz/authn, crypto misuse, dependency vulnerabilities and performance bottlenecks.

## Supported versions
- Multi-language review; severity classification is language-agnostic.

## Prerequisites
- Read access to the target file/diff and its direct dependencies.
- Advisory/dependency data available (offline cache or public fetch enabled) for vulnerability checks.

## Inputs and outputs
- Input: file path or diff, focus areas, severity threshold.
- Output: located findings (file + symbol/line), severity, rationale, suggested fix, confidence.

## Required tools
- `source_review` — structured findings with locators.
- `code_quality_report` — aggregate metrics and hotspots.
- `repository_search` / `symbol_search` — trace callers/callees to assess impact.
- `dependency_analyze` — flag vulnerable/outdated dependencies.

## Procedure
1. Read the target and its immediate dependencies; never review in isolation.
2. Trace reachability of each suspected issue via `repository_search`/`symbol_search`.
3. Classify severity and confidence; separate observable defects from hypotheses.
4. Check dependencies for known vulnerabilities via `dependency_analyze`.
5. Attach a concrete, minimal fix suggestion with a file/symbol reference for each finding.

## Examples
- Unbounded read into a fixed buffer → memory-safety finding with the exact call site and a bounded fix.
- Missing authorization check on a handler → authz finding with the reachable path.
- Outdated dependency with a known advisory → dependency finding referencing the advisory.

## Known limitations
- Interprocedural data-flow is approximated; some findings are marked as hypotheses.
- A published advisory does not by itself prove exploitability — that must be evidenced separately.
- Not a substitute for compiler/static-analyzer output; those are used as corroborating evidence.

## Verification criteria
- Every finding carries a file locator (and symbol/line where possible) and a confidence level.
- No finding is reported as confirmed without supporting code evidence.
- Fix suggestions are minimal and reference the exact location.

## Provenance
- Platform methodology: §A5 of the MIRAI specification.
- Vulnerability data from official advisories (NVD/CISA/GitHub Advisory/OSV) when fetched, with retrieval timestamps.
