---
name: mirai-api-c2-protocol-analysis
description: Analyse Mirai-lineage C2/loader protocols and bot lifecycle from authorized samples and captures — message layout, registry commands, scan/report flow and detection opportunities. Use for defensive IoT botnet protocol research.
version: 1.0.0
engines: [malware-intelligence, network-forensics]
tags: [mirai, c2, protocol, botnet, beacon, variant, iot, telemetry]
tools: [malware_sample_analyze, c2_protocol_analyze, mirai_variant_analyze, botnet_lifecycle_stage_search, c2_beacon_detect, pcap_flow_analyze, honeypot_telemetry_analyze]
license: internal
---

# Mirai API & C2 Protocol Analysis

## Purpose
Reconstruct, defensively, how Mirai-lineage bots speak to their command-and-control infrastructure: the
C2 message layout, the loader/report/scanner flow and the observable behaviours that enable detection.

## Supported versions
- Applies to Mirai and documented Mirai-descendant families in the curated dataset.
- Offline analysis of authorized samples and captures only.

## Prerequisites
- An authorized sample (source or binary) and/or PCAP captures containing C2 traffic.
- No live interaction with real C2 infrastructure.

## Inputs and outputs
- Input: sample path, PCAP path, family hypothesis (optional).
- Output: C2 message specification (defensive), lifecycle stage mapping, beacon indicators, detection ideas.

## Required tools
- `malware_sample_analyze` — format, architecture, embedded strings, C2 hints.
- `c2_protocol_analyze` — reconstruct the C2 command/message layout.
- `mirai_variant_analyze` — test architecture/behaviour checklists against actual evidence.
- `botnet_lifecycle_stage_search` — map observations to lifecycle stages.
- `c2_beacon_detect` — identify periodic beaconing patterns.
- `pcap_flow_analyze` — characterise C2 flows.
- `honeypot_telemetry_analyze` — interpret observed bot interactions.

## Procedure
1. Identify format/architecture and embedded indicators with `malware_sample_analyze`.
2. Reconstruct the C2 message layout with `c2_protocol_analyze`; validate across samples.
3. Confirm or reject the family hypothesis with `mirai_variant_analyze` (evidence required).
4. Map the observed behaviour to lifecycle stages with `botnet_lifecycle_stage_search`.
5. Detect periodic C2 with `c2_beacon_detect`; correlate flows with `pcap_flow_analyze`.
6. Emit defensive detection guidance; never a working client or infection path.

## Examples
- Reconstruct the 2-byte command header and 4-byte length framing of a Mirai-descendant C2 protocol.
- Confirm beaconing interval from capture timing rather than assumption.

## Known limitations
- Encryption/obfuscation may prevent full message reconstruction; unresolved fields are marked unknown.
- A family attribution requires code-level or behavioural evidence — never assumed from appearance.
- "AI-powered" claims are never asserted without supporting evidence.

## Verification criteria
- Every protocol field is backed by a sample locator or a capture observation.
- Attribution claims cite concrete matching evidence.
- Detection suggestions derive only from verified observations.

## Provenance
- Platform methodology: §B1, §B2, §B4, §B5, §6 of the MIRAI specification.
- Family knowledge from the curated Mirai-lineage dataset; public claims require corroborating evidence.
