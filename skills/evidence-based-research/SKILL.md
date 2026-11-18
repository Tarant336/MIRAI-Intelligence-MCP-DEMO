---
name: evidence-based-research
description: Conduct rigorous, reproducible research — separate fact from interpretation, track provenance and confidence, reconcile conflicting evidence and emit reports. Use to structure any multi-source investigation.
version: 1.0.0
engines: [knowledge-and-evidence, multi-agent, datasets]
tags: [evidence, provenance, confidence, research, verification, knowledge-graph, audit, datasets]
tools: [knowledge_search, knowledge_ingest, evidence_graph_query, source_provenance_check, research_report_generate, research_checkpoint, curated_dataset_search, orchestrator_plan, agent_findings_merge, evidence_reconciliation, missing_evidence_identify, research_audit]
license: internal
---

# Evidence-Based Research

## Purpose
Enforce the platform's evidentiary discipline: every significant conclusion carries a claim, source, URL,
dates, version, locator, confidence, contradicting evidence and research status — with strict separation of
confirmed facts, direct observations, interpretation, hypothesis and unverified claims.

## Supported versions
- Method-level; applies across all engines and datasets.

## Prerequisites
- Access to the shared knowledge base and (optionally) curated datasets.
- For multi-agent work, the orchestrator roles from the multi-agent engine.

## Inputs and outputs
- Input: research question, candidate sources, prior checkpoints.
- Output: knowledge records, evidence-graph relations, reconciled findings, missing-evidence list, report, audit.

## Required tools
- `knowledge_search` / `knowledge_ingest` — store and retrieve records with provenance.
- `evidence_graph_query` — traverse claim↔evidence relations.
- `source_provenance_check` — validate provenance completeness.
- `research_report_generate` — assemble an evidence-only report.
- `research_checkpoint` — persist task state and findings.
- `curated_dataset_search` — consult hand-reviewed reference datasets.
- `orchestrator_plan` / `agent_findings_merge` / `evidence_reconciliation` — combine multi-agent findings.
- `missing_evidence_identify` / `research_audit` — surface gaps and audit the research.

## Procedure
1. Prefer sources in order: source code > official vendor docs > official advisories > peer-reviewed >
   reproducible research > reputable orgs > community repos > secondary commentary.
2. Ingest each finding with full provenance and a confidence level.
3. Model relationships (e.g. CVE → component → firmware → family → behaviour → detection → mitigation).
4. Reconcile conflicting evidence; never average away a contradiction.
5. Identify missing evidence; checkpoint and audit.
6. Emit a report whose conclusions are limited to what the evidence supports.

## Examples
- Correlate a CVE with a firmware component and a malware family, marking unproven links as hypotheses.
- Reconcile two sources that disagree on a version range; record both with provenance.

## Known limitations
- Confidence reflects evidence strength, not ground truth.
- Dataset bias/coverage limits generality; a single dataset never represents all IoT devices.
- Never fabricate CVEs, capabilities, attack methods, exploitation success, build/test results or AI integration.

## Verification criteria
- Every conclusion has provenance with retrieval timestamps and a confidence level.
- Contradictions are recorded, not suppressed.
- Claims without sufficient evidence are labelled `not known`.

## Provenance
- Platform methodology: §7, §9, §12, §15 of the MIRAI specification.
- Source priority list and epistemic taxonomy as defined in the specification.
