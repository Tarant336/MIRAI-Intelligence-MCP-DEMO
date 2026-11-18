---
name: static-analysis-research
description: Perform heuristic static vulnerability analysis over source and binaries to identify unsafe patterns, rank findings, and produce a prioritized review list. Use for authorized defensive research only.
version: 1.0.0
engines: [zero-day-research]
tags: [static-analysis, vulnerability, heuristic, source, binary, zero-day]
tools: [static_analysis_run, source_vulnerability_analyze, binary_vulnerability_analyze]
license: internal
---

# Static Analysis Research

## Purpose
Systematically scan source and binary artifacts for vulnerability-relevant patterns, rank the results by
severity and confidence, and output a review list for deeper hypothesis-driven analysis. All results are
clearly labelled as heuristic hypotheses, never as verified findings.

## Supported versions
- Source files and ELF/PE binaries; pattern-based detection only.

## Prerequisites
- An artifact to scan and, for binary inputs, its hash recorded for provenance.
- The understanding that static analysis here is heuristic, not symbolic or data-flow proof.
- External dependencies (probed via `dependency_diagnostics`, ids) are optional and only
  enrich binary inspection: `objdump`, `readelf`, `strings`, `nm`. When absent they report
  `MISSING` and the built-in pure-JS pattern scanner is used instead.

## Inputs and outputs
- Input: source path or binary path, optional class filter.
- Output: ranked findings (rule + location + severity), boundary notes, prioritized review order.

## Required tools
- `static_analysis_run` — run heuristic patterns over the artifact and rank findings.
- `source_vulnerability_analyze` — focused source-level review of the top findings.
- `binary_vulnerability_analyze` — focused binary-level review of strings/sections and unsafe markers.

## Procedure
1. Run `static_analysis_run` on the artifact.
2. Review the top-ranked findings with the appropriate source/binary analyzer.
3. Record rule, location and confidence for each finding.
4. Output a prioritized list for hypothesis generation or manual review.

## Examples
- Scan a C daemon for `strcpy`/`sprintf`/`system` sinks and rank by reachability heuristics.
- Scan an ELF for hardcoded secrets, weak crypto strings and suspicious format-string references.

## Known limitations
- Heuristic patterns produce false positives and miss data-flow-dependent bugs.
- Findings are hypotheses until independently verified.

## Verification criteria
- Every finding has a rule identifier, location and severity.
- No finding is presented as confirmed solely from a pattern match.

## Provenance
- Platform methodology: MIRAI specification §4.3 (Static & Binary Research).
- Artifact hash/path must be recorded for every result.
