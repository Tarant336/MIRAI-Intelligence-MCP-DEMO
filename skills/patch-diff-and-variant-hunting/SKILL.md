---
name: patch-diff-and-variant-hunting
description: "Diff vulnerable versus patched code to isolate the fix, then hunt for the same or related flaws in variants and other codebases. Defensive research only."
version: 1.0.0
engines: [exploit-intelligence, zero-day-research, firmware-intelligence, knowledge-and-evidence]
tags: [patch-diff, variant-hunting, vulnerability, firmware, research]
tools: [patch_diff_analyze, firmware_patch_diff, vulnerability_variant_hunt, patch_root_cause_analyze, vulnerability_verify, cve_search]
license: internal
---

# Patch Diff and Variant Hunting

## Purpose
Use patch differences to understand a fix, then hunt for the same or similar flaw elsewhere — across source,
binaries and firmware variants. The goal is discovering unpatched instances, not exploiting them.

## Supported versions
- Vulnerable and patched source/binary/firmware pairs provided by the user.
- Cross-artifact variant hunting.

## Prerequisites
- A vulnerable/patched pair or a known fix.
- Authorization to analyse the target artifacts.

## Inputs and outputs
- Input: vulnerable/patched artifacts, optional target corpus.
- Output: fix classification, affected locations, variant candidates, verification status, evidence.

## Required tools
- `cve_search` — retrieve vulnerability context.
- `patch_diff_analyze` / `firmware_patch_diff` — diff the fix.
- `patch_root_cause_analyze` — explain the fixed flaw.
- `vulnerability_variant_hunt` — find similar flaws in other artifacts.
- `vulnerability_verify` — check candidate consistency.

## Procedure
1. Retrieve context with `cve_search`.
2. Diff the pair with `patch_diff_analyze` or `firmware_patch_diff`.
3. Reconstruct the root cause with `patch_root_cause_analyze`.
4. Hunt variants with `vulnerability_variant_hunt`.
5. Verify candidate consistency with `vulnerability_verify`.

## Examples
- A patched CGI binary vs its vulnerable predecessor → isolate the bounds-check fix, then scan firmware variants.
- A fixed library → locate the changed function and hunt for the same pattern elsewhere.

## Known limitations
- Patch diffing requires a meaningful vulnerable/patched pair.
- Variant candidates are hypotheses until verified; false positives are expected.

## Verification criteria
- The fix is classified and located precisely.
- Each variant candidate cites a concrete location.
- Candidates are not reported as confirmed without verification.

## Provenance
- Platform methodology: MIRAI specification §4 (Zero-Day) and §5 (Advanced Exploit Research).
- Record artifact hashes and patch sources as provenance.
