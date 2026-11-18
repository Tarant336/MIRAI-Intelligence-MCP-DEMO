---
name: firmware-analysis
description: Statically analyse IoT/embedded firmware — container extraction, filesystem analysis, ELF/architecture identification, component and vulnerability discovery, integrity and patch comparison. Use for authorized firmware research.
version: 1.0.0
engines: [firmware-intelligence, malware-intelligence]
tags: [firmware, iot, embedded, mips, arm, filesystem, emulation, components]
tools: [firmware_analyze, firmware_extract, firmware_filesystem_analyze, elf_analyze, firmware_component_scan, emulation_plan, firmware_patch_diff, firmware_integrity_check]
license: internal
---

# Firmware Analysis

## Purpose
Understand the embedded systems that IoT malware targets: container formats, filesystems, architectures,
init/services, libraries and vulnerable components — linking findings to CVE/advisory evidence.

## Supported versions
- Containers/FS: squashfs, jffs2, ubifs, cramfs, ext, TRX, U-Boot uImage, DLOB, CHK, tar, gzip/xz/bzip2/zstd.
- Architectures: ARM, MIPS/MIPSEL, PowerPC, x86 (identification via ELF headers).

## Prerequisites
- An authorized firmware image or extracted filesystem in the workspace.
- Optional external dependencies (probed via `dependency_diagnostics`, ids):
  `binwalk` (signature scan), `sevenzip` (archive extraction), `objdump` / `readelf`
  (ELF inspection), `qemu-arm` / `qemu-mips` (emulation). When any is absent it is
  reported `MISSING` and the platform falls back to its built-in JS
  carving/ELF parsers — extraction results are then heuristic and are labelled so.
- Emulation tools (QEMU) availability confirmed before any emulation; emulation
  stays isolated. No emulation is claimed unless an execution log exists.

## Inputs and outputs
- Input: firmware path or extracted root, component list to scan.
- Output: detected formats, filesystem layout, architecture, init/services, libraries, vulnerable components, integrity result.

## Required tools
- `firmware_analyze` — container/format detection, entropy, embedded strings.
- `firmware_extract` — carve/list embedded filesystems and compressed regions.
- `firmware_filesystem_analyze` — inspect the extracted root filesystem.
- `elf_analyze` — per-binary architecture, hardening features (NX/PIE/RELRO/canary).
- `firmware_component_scan` — identify components/versions against known CVEs.
- `emulation_plan` — plan isolated emulation (never execute unknown firmware outside isolation).
- `firmware_patch_diff` — compare firmware versions to localise fixes.
- `firmware_integrity_check` — verify hashes/signatures and detect tampering.

## Procedure
1. Detect container/format and entropy with `firmware_analyze`.
2. Extract/carve the filesystem and inspect it with `firmware_extract` + `firmware_filesystem_analyze`.
3. Identify architecture and hardening with `elf_analyze`.
4. Scan components for known vulnerabilities with `firmware_component_scan`.
5. When comparing versions, use `firmware_patch_diff`; verify integrity with `firmware_integrity_check`.
6. If dynamic analysis is needed, produce an isolated plan with `emulation_plan`.

## Examples
- SquashFS image → extract → identify MIPS binaries → detect busybox/openssl versions → map to CVEs.
- Two firmware revisions → diff to localise a patched service.

## Known limitations
- Obfuscated/encrypted blobs and vendor-specific containers may resist extraction.
- Component-version detection is heuristic when banners are stripped.
- Unknown firmware is never executed outside isolation.

## Verification criteria
- Detected formats/architectures are backed by magic/header evidence.
- Component vulnerabilities cite the CVE/advisory source.
- Integrity results reference computed hashes.

## Provenance
- Platform methodology: §5 of the MIRAI specification.
- Vulnerability data from official advisories and vendor firmware notes when fetched.
