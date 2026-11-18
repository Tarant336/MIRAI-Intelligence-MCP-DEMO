---
name: evidence-validation-and-reconciliation
description: "Validate the provenance and completeness of research findings, reconcile conflicting evidence and audit the final result against the evidence base."
version: 1.0.0
engines: [knowledge-and-evidence, multi-agent]
tags: [evidence, reconciliation, validation, audit, provenance, research]
tools: [source_provenance_check, evidence_graph_query, evidence_reconciliation, missing_evidence_identify, research_audit, agent_findings_merge, research_checkpoint]
license: internal
---

# Evidence Validation and Reconciliation

## Purpose
Enforce evidentiary discipline on a research result: verify provenance, surface missing evidence, reconcile
contradictions and audit the conclusion against what the evidence actually supports.

## Supported versions
- Any multi-source or multi-agent research result.
- Method-level; applies across engines.

## Prerequisites
- Research findings with prior knowledge records and checkpoints.
- A final conclusion or candidate report to validate.

## Inputs and outputs
- Input: findings, prior checkpoints, candidate conclusions.
- Output: provenance status, reconciliation report, missing-evidence list, audit, evidence.

## Required tools
- `source_provenance_check` — validate provenance completeness.
- `evidence_graph_query` — traverse claim/evidence relations.
- `evidence_reconciliation` — reconcile conflicting findings.
- `missing_evidence_identify` — surface gaps.
- `research_audit` — audit the result.
- `agent_findings_merge` — merge multi-agent findings.
- `research_checkpoint` — persist the validated state.

## Procedure
1. Merge findings with `agent_findings_merge`.
2. Validate provenance with `source_provenance_check`.
3. Traverse relations with `evidence_graph_query`.
4. Reconcile conflicts with `evidence_reconciliation`; never suppress a contradiction.
5. Identify gaps with `missing_evidence_identify`, checkpoint, and audit with `research_audit`.

## Examples
- Two agents disagree on a version range → record both with provenance, not a merged guess.
- A report conclusion → audit whether every claim is supported by an evidence record.

## Known limitations
- Validation is as strong as the evidence already collected.
- A conclusion unsupported by evidence is flagged, not rescued.

## Verification criteria
- Every conclusion has provenance or is labelled unsupported.
- Contradictions are recorded, not averaged.
- Missing evidence is explicitly listed.

## Provenance
- Platform methodology: MIRAI specification §11 (Multi-Agent) and §12 (Skills Library).
- Record record identifiers and checkpoint state as provenance.
