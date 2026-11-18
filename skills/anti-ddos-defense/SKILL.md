---
name: anti-ddos-defense
description: Research, design, generate and safely verify DDoS defenses — detection, rate limiting, mitigation and lab-restricted testing. Use for defensive DDoS engineering and validation.
version: 1.0.0
engines: [anti-ddos, attack-methods]
tags: [ddos, defense, mitigation, detection, rate-limit, suricata, sigma, waf, lab-only]
tools: [anti_ddos_research, defense_architecture_analyze, network_traffic_analyze, pcap_analyze, ddos_detection_design, detection_rule_generate, rate_limit_design, mitigation_strategy_compare, defense_test_plan, defense_performance_analyze]
license: internal
---

# Anti-DDoS Defense

## Purpose
Understand and build better DDoS defenses: technology research, architecture review, offline traffic
analysis, detection design, mitigation comparison and verifiable, strictly lab-restricted testing.

## Supported versions
- Layers: network/transport, application, DNS/infrastructure, advanced anomaly detection.
- Detection artifacts: Suricata, Sigma, YARA, Zeek; product landscape (Cloudflare, AWS Shield, GCP Armor,
  Akamai Prolexic, Radware, NETSCOUT Arbor, FastNetMon, CrowdSec, NGINX, HAProxy).

## Prerequisites
- Offline PCAPs or design documents in the workspace for analysis.
- Active/lab testing requires an explicit authorization token (`MIRAI_LAB_TOKEN`) and an isolated lab.

## Inputs and outputs
- Input: protected system description, layer, PCAP path, existing configs.
- Output: technology survey, architecture findings, detection designs, detection rules, rate-limit design,
  mitigation comparison, safe test plan, performance evaluation.

## Required tools
- `anti_ddos_research` — survey defensive technology for the layer.
- `defense_architecture_analyze` — review existing local defense configuration.
- `network_traffic_analyze` / `pcap_analyze` — characterise traffic defensively.
- `ddos_detection_design` — design detection and baselines.
- `detection_rule_generate` — emit Suricata/Sigma/YARA/Zeek rules.
- `rate_limit_design` — design rate limits and concurrency caps.
- `mitigation_strategy_compare` — compare mitigation options with trade-offs.
- `defense_test_plan` — produce a SAFE, rate-limited, lab-only test plan.
- `defense_performance_analyze` — detection rate, FP/FN, latency, throughput, CPU/memory.

## Procedure
1. Survey technology and review existing architecture defensively.
2. Characterise traffic from PCAPs.
3. Design detection + baselines; generate detection rules.
4. Design rate limiting and compare mitigation strategies.
5. Produce a safe, isolated test plan (authorization required for active testing).
6. Evaluate performance and manage false positives.

## Examples
- Design an application-layer rate limiter with per-key quotas and burst handling.
- Emit a Suricata rule set for a documented reflection pattern (defensive, detection-only).

## Known limitations
- Detection tuning depends on measured baselines; bypasses are described only defensively.
- Product internals are not claimed without evidence.
- NEVER produce unthrottled generators, distributed load, source spoofing, reflection/amplification
  launchers, or public-target stress tools.

## Verification criteria
- Every mitigation claim cites a source or a measured artifact.
- Active tests cite the authorization token, duration and traffic caps.
- Detection artifacts validate structurally (parse/compile) before being reported as generated.

## Provenance
- Platform methodology: §4, §3.3, §3.4 of the MIRAI specification.
- Product/vendor facts from official public documentation when fetched.
