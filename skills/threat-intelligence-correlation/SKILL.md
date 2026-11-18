---
name: threat-intelligence-correlation
description: "Correlate threat intelligence across malware, vulnerability, exploit and network sources into evidence-backed assessments, with provenance and confidence scoring."
version: 1.0.0
engines: [knowledge-and-evidence, malware-intelligence, exploit-intelligence, network-forensics]
tags: [threat-intelligence, correlation, ioc, provenance, research]
tools: [knowledge_search, knowledge_ingest, evidence_graph_query, source_provenance_check, ioc_extract, cve_search, malware_behavior_report, research_report_generate]
license: internal
---

# Threat Intelligence Correlation

## Purpose
Correlate threat intelligence across domains — malware, vulnerabilities, exploits and network indicators —
into evidence-backed assessments. The output separates fact, hypothesis and inference and scores confidence.

## Supported versions
- Multiple evidence sources across the platform engines.
- Correlation with provenance and confidence scoring.

## Prerequisites
- Existing knowledge records and/or new artifacts (samples, captures, advisories).
- A clear research question or campaign focus.

## Inputs and outputs
- Input: research question, source records/artifacts.
- Output: correlations, consolidated IOC set, confidence-scored assessments, report, evidence.

## Required tools
- `knowledge_search` / `evidence_graph_query` — retrieve and traverse records.
- `knowledge_ingest` — persist new correlations.
- `source_provenance_check` — validate provenance completeness.
- `ioc_extract` — extract indicators from network artifacts.
- `cve_search` / `malware_behavior_report` — gather vulnerability and malware context.
- `research_report_generate` — assemble the assessment.

## Procedure
1. Gather records with `knowledge_search` and `evidence_graph_query`.
2. Extract indicators with `ioc_extract` and enrich with `cve_search`/`malware_behavior_report`.
3. Detect duplicates and cross-source links.
4. Validate provenance with `source_provenance_check`.
5. Ingest correlations and generate the confidence-scored report.

## Examples
- A CVE plus a malware sample and a capture → link component, family and network indicators.
- Multiple feeds → deduplicate IOCs and reconcile conflicting attribution claims.

## Known limitations
- Correlation confidence reflects source strength, not ground truth.
- Absence of a link is not evidence of non-relation.

## Verification criteria
- Every claim has a source with provenance.
- Fact, hypothesis and inference are distinguished.
- Conflicting attribution is recorded, not averaged away.

## Provenance
- Platform methodology: MIRAI specification §10 (Threat Intelligence & Knowledge).
- Record source identifiers and retrieval timestamps as provenance.
