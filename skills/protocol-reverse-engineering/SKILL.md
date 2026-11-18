---
name: protocol-reverse-engineering
description: "Reconstruct unknown network protocol message structures, encoding, command identifiers and state machines from captures, source or binary. Defensive research only."
version: 1.0.0
engines: [network-forensics, firmware-intelligence, malware-intelligence, knowledge-and-evidence]
tags: [protocol, reverse-engineering, pcap, c2, firmware, research]
tools: [protocol_fingerprint, flow_summarize, pcap_flow_analyze, c2_protocol_analyze, elf_analyze, emulation_plan]
license: internal
---

# Protocol Reverse Engineering

## Purpose
Reconstruct an unknown protocol as a documented specification: field boundaries, encodings, command
identifiers and the state machine. Every field boundary must be evidence-based.

## Supported versions
- Offline PCAPs, source and binaries provided by the user.
- Protocol reconstruction for C2 and embedded-device protocols.

## Prerequisites
- A capture, source or binary that carries the protocol.
- Authorization to analyse the artifacts.

## Inputs and outputs
- Input: capture/source/binary, optional focus session or command.
- Output: message layouts, command identifiers, state machine, specification, evidence.

## Required tools
- `protocol_fingerprint` — identify protocol and fields.
- `flow_summarize` — summarise sessions.
- `pcap_flow_analyze` — inspect packet flows.
- `c2_protocol_analyze` — reconstruct C2 message structure.
- `elf_analyze` / `emulation_plan` — support binary-based reconstruction.

## Procedure
1. Fingerprint the protocol with `protocol_fingerprint`.
2. Inspect sessions with `pcap_flow_analyze` and `flow_summarize`.
3. Reconstruct message structure with `c2_protocol_analyze` where applicable.
4. If binary-based, inspect with `elf_analyze` and plan emulation.
5. Document fields with sample bytes and offsets; label unknown regions.

## Examples
- An embedded-device protocol capture → infer field boundaries and the command/response state machine.
- A C2 binary → reconstruct command identifiers and encoding from code.

## Known limitations
- Encrypted or compressed fields are marked unknown, not guessed.
- Packet-level inference is a hypothesis until corroborated by source or more captures.

## Verification criteria
- Field boundaries cite sample bytes or source locations.
- No protocol detail is asserted without evidence.
- Unknown regions are explicitly labelled.

## Provenance
- Platform methodology: MIRAI specification §9 (Protocol/Binary/Firmware).
- Record capture file and source/binary hash as provenance.
