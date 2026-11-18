---
name: firmware-zero-day-research
description: Analyze a firmware image for vulnerability-relevant components and unsafe patterns, identify known components, and raise zero-day hypotheses. Use for authorized firmware defensive research only.
version: 1.0.0
engines: [zero-day-research, firmware-intelligence]
tags: [firmware, embedded, iot, vulnerability, zero-day, binary]
tools: [firmware_vulnerability_analyze, binary_vulnerability_analyze]
license: internal
---

# Firmware Zero-Day Research

## Purpose
Analyze a supplied firmware image for filesystem/format markers, known embedded components and unsafe patterns
that may indicate vulnerability candidates. Findings are hypotheses, not confirmed vulnerabilities.

## Supported versions
- Firmware images (uImage, squashfs, cramfs, gzip, xz, zip, cpio and related); heuristic analysis only.

## Prerequisites
- A firmware image and its hash for provenance.
- Authorization to perform defensive firmware analysis; no network or emulation execution.
- External dependencies (probed via `dependency_diagnostics`, ids) are optional:
  `binwalk`, `sevenzip`, `objdump` / `readelf`. When absent they report `MISSING`;
  this skill still returns string/marker-based results and labels them heuristic.

## Inputs and outputs
- Input: firmware image path.
- Output: format/components inventory, unsafe markers, known-component notes, hypotheses.

## Required tools
- `firmware_vulnerability_analyze` — detect image format, known components and unsafe markers.
- `binary_vulnerability_analyze` — deepen binary-level analysis of embedded components.

## Procedure
1. Record the image hash and run `firmware_vulnerability_analyze`.
2. Review detected format and known components (busybox, dropbear, lighttpd, dnsmasq, telnetd, etc.).
3. Follow up on suspicious components with `binary_vulnerability_analyze`.
4. Convert findings into hypotheses for root-cause or verification work.

## Examples
- A router image → detect squashfs + busybox/dropbear, then flag unsafe patterns in embedded binaries.
- A camera image → detect a web server component and raise parser-vulnerability hypotheses.

## Known limitations
- Extraction/emulation is out of scope unless real tooling is available; this skill only reports markers.
- Component identification is string-based and can produce false positives.

## Verification criteria
- Every finding cites the image hash and a detected marker or component.
- Findings are hypotheses, not verified vulnerabilities.

## Provenance
- Platform methodology: MIRAI specification §4.3 and §9.
- Image hash and detection timestamps must be recorded.
