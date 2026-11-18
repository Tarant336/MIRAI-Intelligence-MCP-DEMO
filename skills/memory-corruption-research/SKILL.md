---
name: memory-corruption-research
description: "Research memory-corruption vulnerability classes (buffer overflows, use-after-free, integer issues) in source and binary, with hypothesis generation and verification. Defensive research only."
version: 1.0.0
engines: [exploit-intelligence, zero-day-research, knowledge-and-evidence]
tags: [memory-corruption, vulnerability, cwe, static-analysis, research]
tools: [vulnerability_root_cause, cwe_search, source_vulnerability_analyze, binary_vulnerability_analyze, patch_diff_analyze, static_analysis_run, crash_root_cause_analyze]
license: internal
---

# Memory Corruption Research

## Purpose
Research memory-corruption weakness classes across source and binary: buffer overflows, use-after-free,
integer overflows and related flaws. The output is ranked hypotheses, not confirmed vulnerabilities.

## Supported versions
- Source trees, ELF binaries and crash artifacts provided by the user.
- Static and lightweight dynamic-signal analysis.

## Prerequisites
- A source tree, binary or crash artifact.
- A target weakness class (e.g. CWE-787, CWE-416) when known.

## Inputs and outputs
- Input: artifact path, optional CWE focus.
- Output: candidate locations, ranked hypotheses, root-cause notes, verification status, evidence.

## Required tools
- `cwe_search` — classify weakness classes.
- `source_vulnerability_analyze` / `binary_vulnerability_analyze` — find candidates.
- `static_analysis_run` — run static checks for unsafe patterns.
- `crash_root_cause_analyze` — reconstruct crash cause when a crash artifact exists.
- `vulnerability_root_cause` — explain candidate flaws.
- `patch_diff_analyze` — confirm via fix when a patch exists.

## Procedure
1. Choose the weakness class with `cwe_search`.
2. Enumerate candidates with `source_vulnerability_analyze` / `binary_vulnerability_analyze`.
3. Run `static_analysis_run` for unsafe patterns.
4. For crashes, reconstruct cause with `crash_root_cause_analyze`.
5. Explain and rank candidates with `vulnerability_root_cause`; confirm via `patch_diff_analyze` if available.

## Examples
- A C source tree → find unsafe copies and integer-allocation patterns (CWE-787/190).
- A crashing binary → reconstruct the memory error behind the crash.

## Known limitations
- Static pattern matches are leads, not proof of exploitable memory corruption.
- No exploitability conclusion without a verified reproduction.

## Verification criteria
- Each candidate cites a file/function/offset.
- Hypotheses are ranked with confidence and verification status.
- No candidate is reported as a confirmed vulnerability without evidence.

## Provenance
- Platform methodology: MIRAI specification §4 (Zero-Day) and §5 (Advanced Exploit Research).
- Record artifact hash/path as provenance.
