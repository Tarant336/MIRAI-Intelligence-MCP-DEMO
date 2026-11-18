---
name: repository-analysis
description: Understand an unfamiliar codebase — structure, modules, symbols, dependencies, architecture and entry points — before making changes. Use when onboarding to a repository or planning a change.
version: 1.0.0
engines: [software-engineering]
tags: [repository, indexing, symbols, imports, call-graph, architecture, onboarding]
tools: [repository_analyze, repository_search, symbol_search, dependency_analyze, architecture_analyze, code_quality_report, project_memory]
license: internal
---

# Repository Analysis

## Purpose
Build a faithful mental model of a repository before editing it. Covers structural inventory, symbol
indexing, import/call-graph tracing, entry-point identification and architectural inconsistency detection.

## Supported versions
- Language-agnostic static inspection; symbol extraction is heuristic per language.
- No external indexer required for the core path.

## Prerequisites
- Repository root inside the authorized workspace.
- Read capability; no writes are performed by this skill.

## Inputs and outputs
- Input: repository path, optional focus paths, file cap.
- Output: module/file inventory, symbol map, dependency edges, entry points, duplicates and inconsistencies.

## Required tools
- `repository_analyze` — inventory files, languages, build systems, entry points.
- `repository_search` — literal/regex search across the tree.
- `symbol_search` — locate functions, classes, interfaces, types.
- `dependency_analyze` — declared vs installed dependencies.
- `architecture_analyze` — layering, cycles, coupling, duplication.
- `code_quality_report` — summarize structural risk.
- `project_memory` — load prior decisions for *this* repository only.

## Procedure
1. Run `repository_analyze` to enumerate structure, build systems and entry points.
2. Use `symbol_search` to build a symbol index for the areas of interest.
3. Trace imports/calls with `repository_search` and `architecture_analyze`.
4. Compare declared vs installed dependencies with `dependency_analyze`.
5. Record the discovered architecture with `project_memory` for later tasks.
6. Never modify the repository before this understanding is complete.

## Examples
- "Where is request routing handled?" → `symbol_search` for the router → `repository_search` for callers.
- "What is the entry point?" → `repository_analyze` entry-point list → confirm with `repository_search`.

## Known limitations
- Dynamic dispatch, reflection and metaprogramming are only partially resolvable statically.
- Symbol extraction can miss generated or macro-expanded code.
- Repository context must never be mixed across unrelated repositories.

## Verification criteria
- Every claimed entry point and key symbol is backed by an actual file/line locator.
- Dependency versions are read from lockfiles/manifests, not assumed.
- Findings carry provenance (`file://` locator) and a confidence level.

## Provenance
- Platform methodology: §A1, §A7 of the MIRAI specification.
- Repository facts are derived from the target tree at analysis time, never fabricated.
