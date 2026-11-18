---
name: software-architecture
description: Design and evaluate software architecture — boundaries, interfaces, layering, data flow and trade-offs — and align implementation with architectural decisions. Use when planning a system or assessing structural soundness.
version: 1.0.0
engines: [software-engineering, knowledge-and-evidence]
tags: [architecture, design, layering, coupling, cohesion, interface, trade-offs]
tools: [repository_analyze, architecture_analyze, dependency_analyze, source_review, code_quality_report, knowledge_ingest, project_memory]
license: internal
---

# Software Architecture

## Purpose
Define and critique system structure: module boundaries, interfaces, dependency direction and data flow,
explicitly weighing trade-offs and recording architectural decisions with rationale.

## Supported versions
- Framework-agnostic; applicable to TypeScript/Node, C/C++, Rust, Python, Go and others.

## Prerequisites
- An existing repository model (run `repository-analysis` first when onboarding).
- Knowledge of the project's non-functional requirements (performance, safety, concurrency).

## Inputs and outputs
- Input: repository path, proposed or existing component; constraints.
- Output: architecture description, dependency-direction map, identified risks, recorded decisions (ADRs).

## Required tools
- `repository_analyze` / `architecture_analyze` — current structure and coupling.
- `dependency_analyze` — dependency graph and version alignment.
- `source_review` / `code_quality_report` — structural smells and bottlenecks.
- `knowledge_ingest` — persist architectural decisions as knowledge records.
- `project_memory` — persist decisions per repository.

## Procedure
1. Map current components and their dependency direction.
2. Identify cycles, layering violations and high-coupling hotspots.
3. Propose target boundaries/interfaces; state the trade-offs explicitly.
4. Validate the proposal against constraints (memory, latency, concurrency, safety).
5. Record each decision with rationale via `knowledge_ingest` and `project_memory`.

## Examples
- Introduce a boundary between transport and domain logic; verify with `architecture_analyze`.
- Replace a fragile circular dependency with an interface; confirm no new cycle remains.

## Known limitations
- Static analysis cannot fully capture runtime/singleton coupling.
- Architecture recommendations are contingent on stated priorities; they are not universal.
- Do not present an assumed design as an observed fact — label proposals as hypotheses.

## Verification criteria
- Each claimed dependency edge is backed by an import/symbol locator.
- Each decision has a stated trade-off and an evidenced rationale.
- Proposed changes are validated against the measured current structure.

## Provenance
- Platform methodology: §A1, §A3, §A6, §A7 of the MIRAI specification.
- Architectural patterns referenced from official framework/provider documentation when cited.
