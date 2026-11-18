---
name: pcap-network-forensics
description: Investigate recorded network traffic — flows, DNS, HTTP, TLS metadata, C2 beaconing, IOC extraction and timeline reconstruction — and correlate findings with malware and advisories. Use for offline network forensics.
version: 1.0.0
engines: [network-forensics]
tags: [pcap, network, forensics, dns, http, tls, beacon, ioc, timeline, flows]
tools: [pcap_flow_analyze, pcap_dns_analyze, pcap_http_analyze, pcap_tls_metadata_analyze, c2_beacon_detect, ioc_extract, network_timeline_reconstruct, protocol_fingerprint, flow_summarize]
license: internal
---

# PCAP & Network Forensics

## Purpose
Reconstruct what happened on the wire from a capture: flows and endpoints, DNS/HTTP/TLS behaviour, periodic
C2 beaconing, extracted indicators of compromise and a coherent timeline — with corroborated findings.

## Supported versions
- PCAP and PCAPNG, parsed with a built-in reader (no external analyzer required for the core path).
- External tools (Zeek, Suricata, tshark) used as corroborating evidence when present.

## Prerequisites
- A capture file inside the authorized workspace.
- Read capability; analysis is strictly offline.

## Inputs and outputs
- Input: PCAP path, focus (dns/http/tls/beacon/ioc/timeline), optional IOC seed list.
- Output: flow summaries, protocol observations, beacon scores, IOC list, reconstructed timeline.

## Required tools
- `pcap_flow_analyze` / `flow_summarize` — flow statistics and top talkers.
- `pcap_dns_analyze` — queries, NXDOMAIN patterns, DGA-like names.
- `pcap_http_analyze` — requests, user-agents, hosts, file transfers.
- `pcap_tls_metadata_analyze` — SNI/ALPN/record metadata (no decryption).
- `c2_beacon_detect` — periodicity/jitter analysis for command-and-control.
- `ioc_extract` — extract and normalise indicators (IP/domain/URL/hash).
- `network_timeline_reconstruct` — order events into a timeline.
- `protocol_fingerprint` — classify protocol implementations from traffic.

## Procedure
1. Build flow statistics and top talkers with `pcap_flow_analyze`.
2. Analyse DNS, HTTP and TLS metadata; note anomalies.
3. Score periodic behaviour with `c2_beacon_detect`.
4. Extract IOCs and normalise them with `ioc_extract`.
5. Reconstruct the timeline and fingerprint notable protocols.
6. Correlate indicators with malware/firmware/CVE knowledge before concluding.

## Examples
- Detect a bot checking in every ~60 s with low jitter → beaconing candidate.
- Periodic DNS to high-entropy names → DGA hypothesis (labelled as hypothesis).

## Known limitations
- TLS/QUIC payloads are not decrypted; only metadata is available.
- Capture artefacts (timing, truncation, offload) can bias statistics.
- Correlations to malware are hypotheses unless backed by code/host evidence.

## Verification criteria
- Each indicator traces to a packet/flow with counts and timestamps.
- Beacon claims cite measured interval and jitter, not assumption.
- Correlated conclusions reference their supporting evidence and confidence.

## Provenance
- Platform methodology: §6 of the MIRAI specification.
- External analyzer output (Zeek/Suricata/tshark) treated as untrusted and corroborated.
