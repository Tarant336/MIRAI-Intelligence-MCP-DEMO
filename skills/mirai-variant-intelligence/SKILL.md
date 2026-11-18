---
name: mirai-variant-intelligence
description: "Track, classify and correlate Mirai variants using lineage, signature and behavioural signals, producing evidence-backed variant intelligence. Defensive research only."
version: 1.0.0
engines: [malware-intelligence, exploit-intelligence, knowledge-and-evidence]
tags: [mirai, variant, lineage, yara, signature, malware, research]
tools: [mirai_variant_analyze, malware_family_compare, binary_similarity, yara_rule_search, malware_behavior_report, botnet_lifecycle_stage_search, knowledge_ingest]
license: internal
---

# Mirai Variant Intelligence

## Purpose
Build an evidence-backed view of Mirai variant relationships: which samples belong to which lineage, how they
drift behaviourally, and what signatures distinguish them. Every relationship is a claim with provenance.

## Supported versions
- Mirai samples, source trees and detection rules provided by the user.
- Offline-first signature and similarity analysis.

## Prerequisites
- Sample or source artifacts, and optionally a corpus of YARA rules.
- Clear authorization for the artifacts under analysis.

## Inputs and outputs
- Input: samples/source, optional YARA rule corpus, optional lifecycle stage focus.
- Output: variant clusters, lineage graph, distinguishing signatures, confidence-scored relationships.

## Required tools
- `mirai_variant_analyze` — analyse a sample against known Mirai variant signals.
- `malware_family_compare` — compare families and features.
- `binary_similarity` — measure binary similarity between samples.
- `yara_rule_search` — retrieve matching detection rules.
- `malware_behavior_report` — summarise behavioural differences.
- `botnet_lifecycle_stage_search` — place the variant in the botnet lifecycle.
- `knowledge_ingest` — persist findings with provenance.

## Procedure
1. Analyse each sample with `mirai_variant_analyze` and `malware_behavior_report`.
2. Measure pairwise similarity with `binary_similarity` and `malware_family_compare`.
3. Retrieve matching rules with `yara_rule_search`.
4. Cluster variants and record lineage relationships with confidence.
5. Ingest the lineage graph with provenance and contradicting-evidence notes.

## Examples
- A set of Mirai samples → cluster by shared code and identify the originating lineage.
- A new variant → locate behavioural drift from the parent and propose distinguishing signatures.

## Known limitations
- Similarity is not identity; two close samples may still be distinct variants.
- Confidence reflects evidence strength, not ground-truth lineage.

## Verification criteria
- Every lineage edge cites a similarity or signature source.
- Unproven relationships are labelled as hypotheses.
- Contradictions between signatures are recorded, not suppressed.

## Provenance
- Platform methodology: MIRAI specification §3 (Mirai Intelligence) and §7 (Malware/Reverse Engineering).
- Record sample hashes and rule identifiers as provenance.
