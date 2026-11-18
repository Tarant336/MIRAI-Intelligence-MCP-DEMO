---
name: mirai-deep-source-analysis
description: "Analyse the Mirai botnet source tree in depth: repository structure, modules, build and configuration handling, propagation and C2 logic, citing exact file, function and symbol locations. Defensive research only."
version: 1.0.0
engines: [malware-intelligence, software-engineering, knowledge-and-evidence]
tags: [mirai, botnet, malware, source-code, c2, reverse-engineering, research]
tools: [malware_source_analyze, c2_protocol_analyze, mirai_variant_analyze, malware_behavior_report, repository_search, symbol_search, repository_analyze, knowledge_ingest]
license: internal
---

# Mirai Deep Source Analysis

## Purpose
Read a Mirai source tree as structured research material: map the repository and module layout, trace the
build/configuration path, and reconstruct propagation and C2 behaviour from code. Every conclusion must point
to a concrete file, function or symbol.

## Supported versions
- Mirai and Mirai-derived source trees provided by the user.
- Read-only analysis; no modification, no build execution beyond documented, isolated use.

## Prerequisites
- A source tree (repository path or extracted archive) under the user's authorization.
- A target focus (e.g. C2, propagation, build flags, loader) when known.

## Inputs and outputs
- Input: repository path, optional module or function focus.
- Output: structure map, module/function analysis, configuration handling, behaviour reconstruction, evidence.

## Required tools
- `malware_source_analyze` — analyse malware source structure and behaviour.
- `c2_protocol_analyze` — reconstruct the C2 protocol embedded in the source.
- `mirai_variant_analyze` — compare against known Mirai variant signals.
- `malware_behavior_report` — assemble a behaviour summary.
- `repository_search` / `symbol_search` / `repository_analyze` — locate and inspect code.
- `knowledge_ingest` — persist each finding with provenance.

## Procedure
1. Map the repository with `repository_analyze` and identify modules.
2. Locate build and configuration handling; note default credentials and compile-time flags.
3. Trace propagation and C2 functions with `symbol_search` and `malware_source_analyze`.
4. Reconstruct protocol details with `c2_protocol_analyze`.
5. Ingest every claim with file/function/symbol locators and confidence.

## Examples
- A Mirai source tree → map scanner, loader and CNC modules; identify hardcoded defaults.
- A derived variant → locate the changed propagation logic and configuration deltas.

## Known limitations
- Source-level analysis only; runtime behaviour must be validated separately and safely.
- Obfuscation or generated code reduces confidence in symbolic reconstruction.

## Verification criteria
- Every claim cites a file/function/symbol location.
- No behaviour is asserted without a code location or configuration artifact.
- Findings distinguish fact from inference.

## Provenance
- Platform methodology: MIRAI specification §3 (Mirai Intelligence) and §7 (Malware/Reverse Engineering).
- Record repository path and revision as provenance for every finding.
