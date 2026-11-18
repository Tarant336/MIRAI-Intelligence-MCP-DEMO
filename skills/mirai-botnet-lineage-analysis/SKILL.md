---
name: mirai-botnet-lineage-analysis
description: "Reconstruct the evolution and lineage of Mirai botnets from source, samples, honeypot telemetry and C2 signals, distinguishing confirmed lineage from hypothesis."
version: 1.0.0
engines: [malware-intelligence, network-forensics, knowledge-and-evidence]
tags: [mirai, botnet, lineage, honeypot, c2, research]
tools: [mirai_variant_analyze, botnet_lifecycle_stage_search, c2_protocol_analyze, honeypot_telemetry_analyze, malware_behavior_report, knowledge_search]
license: internal
---

# Mirai Botnet Lineage Analysis

## Purpose
Reconstruct how a Mirai botnet and its variants evolved over time: parent/child relationships, lifecycle stage,
C2 changes and propagation shifts. Lineage claims are only as strong as the evidence that supports them.

## Supported versions
- Mirai source, samples, PCAPs and honeypot telemetry provided by the user.
- Correlation of lifecycle-stage and C2 signals.

## Prerequisites
- One or more artifacts (source, samples, captures or telemetry) from the botnet.
- Existing knowledge records when a prior lineage baseline is available.

## Inputs and outputs
- Input: artifacts plus optional prior lineage records.
- Output: lineage graph, lifecycle-stage placement, C2 evolution, confidence-scored relationships.

## Required tools
- `mirai_variant_analyze` — identify variant signals.
- `botnet_lifecycle_stage_search` — determine lifecycle stage.
- `c2_protocol_analyze` — reconstruct C2 details and changes.
- `honeypot_telemetry_analyze` — incorporate observed bot behaviour.
- `malware_behavior_report` — summarise behaviour.
- `knowledge_search` — retrieve prior lineage records.

## Procedure
1. Retrieve prior lineage records with `knowledge_search`.
2. Analyse each artifact with `mirai_variant_analyze` and `malware_behavior_report`.
3. Determine lifecycle stage with `botnet_lifecycle_stage_search`.
4. Reconstruct C2 evolution with `c2_protocol_analyze` and honeypot telemetry.
5. Record lineage edges with provenance; mark unconfirmed edges as hypotheses.

## Examples
- A honeypot capture → connect observed bot behaviour to a specific Mirai variant and stage.
- A source/sample pair → place a variant in a known lineage and identify the C2 deltas.

## Known limitations
- Lineage is inferred from imperfect signals; absence of evidence is not evidence of absence.
- Honeypot telemetry reflects observed traffic, not the whole botnet.

## Verification criteria
- Each lineage edge has a source and confidence.
- Confirmed lineage is separated from hypothesis and inference.
- Missing evidence is recorded rather than filled with assumption.

## Provenance
- Platform methodology: MIRAI specification §3 (Mirai Intelligence) and §7 (Malware/Reverse Engineering).
- Record artifact hashes and telemetry timestamps as provenance.
