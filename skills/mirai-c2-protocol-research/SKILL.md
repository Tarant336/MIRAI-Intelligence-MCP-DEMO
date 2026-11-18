---
name: mirai-c2-protocol-research
description: "Reconstruct the Mirai C2 protocol: message structures, command identifiers, encoding and state machine, from source, samples and packet captures."
version: 1.0.0
engines: [malware-intelligence, network-forensics, knowledge-and-evidence]
tags: [mirai, c2, protocol, pcap, reverse-engineering, research]
tools: [c2_protocol_analyze, pcap_analyze, protocol_fingerprint, flow_summarize, network_timeline_reconstruct, malware_source_analyze]
license: internal
---

# Mirai C2 Protocol Research

## Purpose
Reconstruct the Mirai C2 protocol as a documented specification: message layouts, command identifiers,
encoding and the client/server state machine. Field boundaries must be evidence-based, not asserted.

## Supported versions
- Mirai source, samples and offline PCAPs provided by the user.
- Reconstruction from code and captured traffic.

## Prerequisites
- A source tree, sample, or PCAP containing C2 traffic.
- Authorization to analyse the artifacts.

## Inputs and outputs
- Input: source/sample/capture, optional focus command or session.
- Output: message structure, command identifiers, state machine, protocol specification, evidence.

## Required tools
- `c2_protocol_analyze` — reconstruct C2 message structure from code/sample.
- `pcap_analyze` — inspect captured traffic.
- `protocol_fingerprint` — identify protocol and fields from packets.
- `flow_summarize` — summarise sessions.
- `network_timeline_reconstruct` — order observed events.
- `malware_source_analyze` — read the protocol implementation in source.

## Procedure
1. Locate the protocol implementation with `malware_source_analyze`.
2. Reconstruct message structure with `c2_protocol_analyze`.
3. Corroborate with `pcap_analyze` and `protocol_fingerprint`.
4. Reconstruct the state machine from session order with `flow_summarize` and `network_timeline_reconstruct`.
5. Document field boundaries with sample bytes and offsets.

## Examples
- A Mirai source tree → derive command identifiers and the login/command exchange.
- A C2 PCAP → infer message layout and confirm against source-derived fields.

## Known limitations
- Encrypted or compressed traffic limits reconstruction; encrypted fields are marked unknown.
- Packet-level inference is a hypothesis until corroborated by source or more captures.

## Verification criteria
- Field boundaries cite sample bytes or source locations.
- No protocol detail is asserted without code or capture evidence.
- Unknown or encrypted regions are explicitly labelled.

## Provenance
- Platform methodology: MIRAI specification §3 (Mirai Intelligence) and §9 (Protocol/Binary/Firmware).
- Record capture file and source revision as provenance.
