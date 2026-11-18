---
name: fuzzing-and-crash-triage
description: Identify fuzz targets, generate analysis-only harness skeletons, and triage crashes to distinguish bugs from security vulnerabilities. Use for authorized lab research only; harnesses are never built or executed here.
version: 1.0.0
engines: [zero-day-research]
tags: [fuzzing, crash, triage, root-cause, harness, afl, libfuzzer, zero-day]
tools: [fuzz_target_identify, fuzz_harness_generate, fuzzing_crash_analyze, crash_root_cause_analyze]
license: internal
---

# Fuzzing and Crash Triage

## Purpose
Plan fuzzing work and analyze crash artifacts: identify promising targets, produce analysis-only harness
skeletons, and classify each crash as a plain bug or a security-relevant vulnerability, then reconstruct the
root cause. No harness is built or executed by this skill.

## Supported versions
- Fuzzing target identification and crash triage across source and binary components.

## Prerequisites
- A component/artifact to fuzz and, for crash triage, crash artifacts with stack traces.
- An isolated lab environment if real fuzzing is performed outside this skill.
- External dependencies (probed via `dependency_diagnostics`, ids) are optional and only
  needed if you intend to build/run fuzzing yourself: `gcc` / `clang` (compile harnesses),
  `aflplusplus` / `honggfuzz` (fuzzers). They are never installed automatically.

## Lifecycle states (kept distinct, never collapsed into one PASS)
1. Harness generated — this skill produces the skeleton.
2. Harness compiled — requires `gcc`/`clang`; **not** done by this skill.
3. Fuzzer executed — requires `aflplusplus`/`honggfuzz`; **not** done by this skill.
4. Coverage collected, 5. crash observed, 6. crash reproduced, 7. root cause verified —
   each is a separate, independently evidenced state. Fuzzing is never reported as run
   without real compile + execution logs.

## Inputs and outputs
- Input: component or crash artifact, optional fault/stack-trace text.
- Output: fuzz targets, harness skeletons, crash classifications, root-cause notes.

## Required tools
- `fuzz_target_identify` — enumerate attack-surface inputs and candidate fuzz targets.
- `fuzz_harness_generate` — generate an analysis-only harness skeleton (no build/run).
- `fuzzing_crash_analyze` — normalize, deduplicate and classify crash artifacts.
- `crash_root_cause_analyze` — reconstruct the likely root cause from the crash signal/stack.

## Procedure
1. Identify targets with `fuzz_target_identify`.
2. Generate harness skeletons with `fuzz_harness_generate`.
3. For each crash artifact, run `fuzzing_crash_analyze` to deduplicate and classify.
4. For security-relevant crashes, run `crash_root_cause_analyze`.
5. Record evidence and keep classification (bug vs vulnerability) explicit.

## Examples
- A parser function → identify input entry points, generate a libFuzzer skeleton, triage a NULL-deref crash.
- A protocol decoder → identify packet fields, generate an AFL++ skeleton, classify a heap overflow crash.

## Known limitations
- This skill does not build, execute or run fuzzing; harness output is a template for isolated use elsewhere.
- Crash vs bug vs vulnerability classification is heuristic and requires corroboration.

## Verification criteria
- Every crash has a hash/artifact reference and a classification rationale.
- Root cause is stated as a hypothesis until independently verified.

## Provenance
- Platform methodology: MIRAI specification §4.4–§4.5 and §8.
- Crash artifact hashes and stack-trace locators must be recorded.
