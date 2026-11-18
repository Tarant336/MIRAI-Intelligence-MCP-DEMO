---
name: api-reverse-engineering
description: Reconstruct an undocumented API or wire protocol from clients, capture and specification — schemas, message formats, state machines and versioning. Use when documenting an interface from observed behaviour.
version: 1.0.0
engines: [software-engineering, network-forensics]
tags: [api, protocol, reverse-engineering, fingerprint, http, schema, state-machine]
tools: [documentation_search, dependency_analyze, repository_analyze, protocol_fingerprint, pcap_http_analyze, pcap_flow_analyze, c2_protocol_analyze]
license: internal
---

# API Reverse Engineering

## Purpose
Derive an accurate, defensive specification of an API or wire protocol from client code, captured traffic
and any partial documentation — message schemas, framing, sequencing, error handling and versioning.

## Supported versions
- Transports: HTTP/HTTPS, TCP/UDP, TLS-wrapped and custom binary framing.
- Analysis is passive/offline; no live third-party interaction is required.

## Prerequisites
- Either client source in the workspace, a PCAP of the traffic, or captured request/response samples.
- For C2-style protocols, only authorized samples may be analysed.

## Inputs and outputs
- Input: client source path and/or PCAP path, endpoint hints.
- Output: endpoint catalogue, request/response schemas, framing rules, state machine, version notes, confidence.

## Required tools
- `documentation_search` — retrieve official docs if any exist (prefer authoritative sources).
- `dependency_analyze` / `repository_analyze` — locate client code and generated stubs.
- `protocol_fingerprint` — classify the protocol/implementation from traffic.
- `pcap_http_analyze` / `pcap_flow_analyze` — extract request/response structure and flows.
- `c2_protocol_analyze` — reconstruct binary command/control message layout defensively.

## Procedure
1. Prefer authoritative documentation; use it to seed the schema before reverse engineering.
2. Extract message structures from client code and/or PCAP.
3. Infer framing, field widths and endianness; validate against multiple samples.
4. Reconstruct sequencing as an explicit state machine.
5. Record each inferred field with provenance and confidence; flag gaps as unknown.

## Examples
- HTTP API: enumerate endpoints from `pcap_http_analyze`, confirm fields against client code.
- Binary C2: derive header layout from `c2_protocol_analyze` and cross-check across captures.

## Known limitations
- Fields inferred from a single sample are hypotheses; encryption/compression may hide structure.
- Behaviour absent from captures cannot be claimed — it is marked as unknown.
- Never produce an operational client for a third-party target; the output is documentation only.

## Verification criteria
- Every schema field is supported by at least one observed sample or code locator.
- Framing/endianness claims are consistent across multiple samples.
- Unresolved elements are explicitly labelled unknown.

## Provenance
- Platform methodology: §A1, §A2, §6 of the MIRAI specification.
- Protocol facts derive from the analysed artifacts; no protocol capability is fabricated.
