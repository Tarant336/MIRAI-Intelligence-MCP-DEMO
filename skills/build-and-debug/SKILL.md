---
name: build-and-debug
description: Build a project and autonomously debug failures — parse compiler/linker diagnostics, find root causes and iterate to a green build. Use when a build or link step fails.
version: 1.0.0
engines: [software-engineering]
tags: [build, compile, linker, debug, diagnostics, logs, root-cause]
tools: [engineering_toolchain_probe, build_project, debug_project, run_tests, regression_test, project_memory]
license: internal
---

# Build & Debug

## Purpose
Drive a failing build to a verified green state: probe the toolchain, compile, parse diagnostics, isolate
the root cause, apply a minimal fix and re-verify — never claiming success without an executed command.

## Supported versions
- Build systems detected from the project (tsc/npm, make/cmake, cargo, maven/gradle, go, etc.).
- Compilers invoked only inside the configured isolated-execution sandbox.

## Prerequisites
- Isolated execution enabled (`MIRAI_ALLOW_ISOLATED_EXEC`).
- A known build command (from the project or `project_memory`).

## Inputs and outputs
- Input: project path, target/command, prior error context.
- Output: parsed diagnostics, root-cause statement, applied fix, exit codes and logs.

## Required tools
- `engineering_toolchain_probe` — confirm compilers/build tools.
- `build_project` — run the build and parse diagnostics.
- `debug_project` — isolate the failing unit and propose the minimal fix.
- `run_tests` / `regression_test` — confirm no regression after the fix.
- `project_memory` — recall and store build commands, errors and successful fixes.

## Procedure
1. Load the last-known build command from `project_memory`; else probe the toolchain.
2. Run `build_project`; capture exit code and diagnostics verbatim.
3. Isolate the first *causal* error (not the first symptom).
4. Apply the minimal fix; re-run the build.
5. Run `regression_test`; then store the resolved error and fix in `project_memory`.

## Examples
- Undefined symbol at link time → verify the symbol exists (`symbol_search`) → add the missing unit.
- Type error cascade → fix the root type, rebuild, confirm the cascade clears.

## Known limitations
- Only commands actually executed are reported; failures are never glossed over.
- Some errors require environment changes that must be surfaced to the operator, not silently applied.
- Build cost/latency is bounded by configured timeouts.

## Verification criteria
- `build_project` exits 0 and the log confirms a completed build.
- `regression_test` passes after the fix.
- The stored build command reproduces the green result.

## Provenance
- Platform methodology: §A4, §A6, §A7 of the MIRAI specification.
- Corpus of common compiler/linker errors maintained in the Technical Skills Library (§A6).
