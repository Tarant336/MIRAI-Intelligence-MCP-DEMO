/**
 * Curated anti-DDoS defence catalogue (§4.1, §4.2).
 *
 * DEFENSIVE MATERIAL ONLY: this file documents defensive technologies,
 * product capabilities (from PUBLIC documentation only) and mitigation
 * strategies. It contains no attack configuration and no operational attack
 * guidance. Where a bypass weakness is described it is framed defensively
 * (what a defender should harden), never as an attack technique.
 */

import type { KnowledgeRecord } from '../../shared/knowledge-base.js';
import type { KnowledgeBase } from '../../shared/knowledge-base.js';
import { curatedProvenance } from '../../tools/helpers.js';

export type DefenseLayer = 'network' | 'application' | 'dns_infra' | 'detection';

export interface DefenseTechnology {
  id: string;
  name: string;
  layer: DefenseLayer;
  group: string;
  description: string;
  detectionApproach: string;
  mitigationMechanisms: string[];
  strengths: string[];
  limitations: string[];
  deploymentNotes: string[];
  references: string[];
}

export const DEFENSE_TECHNOLOGIES: DefenseTechnology[] = [
  // ---- Network-layer defences ------------------------------------------
  {
    id: 'traffic_filtering',
    name: 'Traffic Filtering',
    layer: 'network',
    group: 'Network-layer',
    description:
      'Stateless/stateful packet inspection that drops traffic not matching expected protocol, port and behaviour profiles.',
    detectionApproach: 'Signature and policy matching on packet headers and flow state.',
    mitigationMechanisms: ['Header/port allow-listing', 'Protocol sanity checks', 'Drop unknown flows at the edge'],
    strengths: ['Cheap at high volume', 'Predictable latency', 'Effective against obvious malformed floods'],
    limitations: ['Cannot separate well-formed floods from legitimate traffic', 'Needs maintenance as services change'],
    deploymentNotes: ['Place at the network edge and before stateful devices', 'Keep policies minimal to avoid FP'],
    references: ['NIST SP 800-189', 'IETF RFC 2827/BCP38'],
  },
  {
    id: 'acl',
    name: 'Access Control Lists (ACL)',
    layer: 'network',
    group: 'Network-layer',
    description: 'Ordered permit/deny rules applied on routers, switches and firewalls to constrain reachability.',
    detectionApproach: 'Not a detector; a static enforcement control.',
    mitigationMechanisms: ['Deny by default', 'Restrict management planes', 'Block unwanted protocols/ports'],
    strengths: ['Simple and deterministic', 'Widely supported'],
    limitations: ['Static; ineffective against traffic that matches allowed profiles'],
    deploymentNotes: ['Apply at borders and management interfaces', 'Log denies for visibility'],
    references: ['Router/firewall vendor documentation'],
  },
  {
    id: 'rate_limiting',
    name: 'Rate Limiting',
    layer: 'network',
    group: 'Network-layer',
    description: 'Caps the rate of packets/connections/requests per dimension (source, destination, route).',
    detectionApproach: 'Metering counters compared against configured policies.',
    mitigationMechanisms: ['Token bucket', 'Leaky bucket', 'Sliding window', 'Connection-rate caps'],
    strengths: ['Protects capacity', 'Tunable dimension-by-dimension'],
    limitations: ['Threshold selection risk of false positives', 'Distributed sources each stay under a per-source cap'],
    deploymentNotes: ['Prefer per-destination plus per-source dimensions', 'Tune from a baseline, review regularly'],
    references: ['NGINX/HAProxy rate-limit documentation', 'RFC 2697/2698 (srTCM/trTCM)'],
  },
  {
    id: 'connection_limiting',
    name: 'Connection Limiting',
    layer: 'network',
    group: 'Network-layer',
    description: 'Caps concurrent connections and connection-establishment rate to protect server concurrency budgets.',
    detectionApproach: 'Tracking active connection counts per source/service.',
    mitigationMechanisms: ['Per-source concurrent caps', 'Establishment-rate caps', 'Idle timeouts'],
    strengths: ['Directly protects worker/descriptor limits'],
    limitations: ['NAT can concentrate legitimate clients behind one source'],
    deploymentNotes: ['Set caps above observed legitimate peak per source', 'Combine with idle timeouts'],
    references: ['NGINX limit_conn', 'HAProxy maxconn'],
  },
  {
    id: 'syn_cookies',
    name: 'TCP SYN Cookies',
    layer: 'network',
    group: 'Network-layer',
    description: 'Stateless SYN-ACK handling so the server does not allocate state until the handshake completes.',
    detectionApproach: 'Kernel counters showing cookie activation under backlog pressure.',
    mitigationMechanisms: ['Stateless handshake', 'Backlog protection'],
    strengths: ['Eliminates half-open state exhaustion cheaply'],
    limitations: ['Reduced TCP option support', 'Does not help against completed-connection floods'],
    deploymentNotes: ['Enable with tuned syncookie thresholds', 'Monitor activation as an attack signal'],
    references: ['IETF RFC 4987'],
  },
  {
    id: 'tcp_state_protection',
    name: 'TCP State Protection',
    layer: 'network',
    group: 'Network-layer',
    description: 'Tuning and pro-active protection of TCP state tables (backlog, conntrack, timeouts, SYN proxy).',
    detectionApproach: 'State-table utilisation and insertion-failure telemetry.',
    mitigationMechanisms: ['Backlog tuning', 'Conntrack sizing', 'SYN proxy', 'Aggressive idle timeouts'],
    strengths: ['Protects stateful devices from state exhaustion'],
    limitations: ['Tuning is workload-specific', 'May increase latency if too aggressive'],
    deploymentNotes: ['Trend utilisation and keep headroom', 'Validate timeouts against real client behaviour'],
    references: ['Linux conntrack tuning guides', 'Vendor firewall tuning docs'],
  },
  {
    id: 'segmentation',
    name: 'Network Segmentation',
    layer: 'network',
    group: 'Network-layer',
    description: 'Divides the network into zones so an attack against one segment does not exhaust shared resources for others.',
    detectionApproach: 'Zone-level telemetry with per-zone baselines.',
    mitigationMechanisms: ['Blast-radius reduction', 'Policy boundaries between zones'],
    strengths: ['Limits collateral impact', 'Improves containment'],
    limitations: ['Design and operational overhead'],
    deploymentNotes: ['Isolate public-facing services', 'Keep management planes separate'],
    references: ['NIST SP 800-125/800-41'],
  },
  {
    id: 'firewall_policy',
    name: 'Firewall Policy',
    layer: 'network',
    group: 'Network-layer',
    description: 'Stateful policy governing allowed flows, sequencing inspection and rate limits.',
    detectionApproach: 'Policy-matched logs and counters.',
    mitigationMechanisms: ['Deny-by-default', 'Per-application policy', 'Zone policy'],
    strengths: ['Centralised, auditable control'],
    limitations: ['Stateful throughput limits under extreme volume'],
    deploymentNotes: ['Keep policy intent explicit', 'Ensure logging rate-limits do not hide attacks'],
    references: ['Vendor firewall best-practice guides'],
  },
  {
    id: 'bgp_blackholing',
    name: 'BGP Blackholing (RTBH)',
    layer: 'network',
    group: 'Network-layer',
    description: 'Advertises a victim prefix to a discard next-hop so attack traffic is dropped upstream, protecting the rest of the network.',
    detectionApproach: 'Flow/volumetric monitoring triggers the trigger route.',
    mitigationMechanisms: ['Remotely-triggered blackhole', 'Discard next-hop advertisements'],
    strengths: ['Fast, upstream mitigation of volumetric attacks', 'Protects non-victim services'],
    limitations: ['Collateral loss: the victim is fully blackholed', 'Requires no-export community discipline'],
    deploymentNotes: ['Use sparingly and with a documented trigger policy', 'Combine with scrubbing for restoration'],
    references: ['RFC 3882/7999 (RTBH)', 'NOG operator guidance'],
  },
  {
    id: 'bgp_flowspec',
    name: 'BGP FlowSpec',
    layer: 'network',
    group: 'Network-layer',
    description: 'Distributes fine-grained traffic-filtering (and rate-limiting) rules to routers via BGP so mitigation can be scoped to an attack signature.',
    detectionApproach: 'Attack classification feeds FlowSpec rule generation.',
    mitigationMechanisms: ['Scoped dropping', 'Rate-limiting actions', 'Redirect to scrubbing'],
    strengths: ['More surgical than blackholing', 'Automatable'],
    limitations: ['Router support/vendor variance', 'Rule-scoping mistakes can drop legitimate traffic'],
    deploymentNotes: ['Validate rules in a lab before automation', 'Use conservative match scopes'],
    references: ['RFC 5575/8955 (FlowSpec)'],
  },
  {
    id: 'traffic_scrubbing',
    name: 'Traffic Scrubbing',
    layer: 'network',
    group: 'Network-layer',
    description: 'Diverts traffic through a scrubbing centre that removes attack traffic and returns clean traffic to the origin.',
    detectionApproach: 'Volumetric/anomaly detection plus signature profiles in the scrubbing tier.',
    mitigationMechanisms: ['Anomaly filtering', 'Protocol validation', 'Rate pressure rebalancing', 'Clean-traffic return'],
    strengths: ['Handles volumetric attacks without touching origin capacity'],
    limitations: ['Diversion latency and added path', 'Signature coverage gaps'],
    deploymentNotes: ['Pre-establish diversion (BGP/anycast/lift-and-shift) contracts', 'Test diversion regularly'],
    references: ['Vendor scrubbing documentation'],
  },
  {
    id: 'anycast',
    name: 'Anycast Dispersion',
    layer: 'network',
    group: 'Network-layer',
    description: 'Advertises the same service address from many locations so traffic is absorbed across sinks and attacks are diluted geographically.',
    detectionApproach: 'Per-site telemetry aggregated centrally.',
    mitigationMechanisms: ['Attack dilution', 'Local absorption', 'BGP-based sink withdrawal'],
    strengths: ['Scales capacity with sites', 'Reduces single-target concentration'],
    limitations: ['Per-flow consistency considerations', 'Requires careful BGP/health operations'],
    deploymentNotes: ['Use for stateless services and DNS shine-through', 'Monitor per-PoP health'],
    references: ['RFC 4786 (Operation of Anycast Services)'],
  },

  // ---- Application-layer defences --------------------------------------
  {
    id: 'waf',
    name: 'Web Application Firewall',
    layer: 'application',
    group: 'Application-layer',
    description: 'Inspects HTTP(S) requests/responses for application-layer attacks and anomalies.',
    detectionApproach: 'Rule/signature matching plus anomaly scoring on request features.',
    mitigationMechanisms: ['Request blocking/challenge', 'Virtual patching', 'Rate/policy enforcement'],
    strengths: ['Deep application insight', 'Fast virtual patching'],
    limitations: ['Tuning cost', 'Encrypted-traffic coupling', 'Potential latency'],
    deploymentNotes: ['Tune rules and monitor FP before blocking', 'Ensure TLS termination/visibility'],
    references: ['OWASP ModSecurity Core Rule Set', 'OWASP CRS documentation'],
  },
  {
    id: 'http_request_inspection',
    name: 'HTTP Request Inspection',
    layer: 'application',
    group: 'Application-layer',
    description: 'Header/body/method analysis to validate request structure and detect malformed or abusive patterns.',
    detectionApproach: 'Structural validation and header consistency checks.',
    mitigationMechanisms: ['Reject malformed requests', 'Normalise encodings', 'Apply method policy'],
    strengths: ['Cheap, catches malformed floods'],
    limitations: ['Well-formed floods evade structure checks'],
    deploymentNotes: ['Enforce strict header/timeout policy', 'Log rejected request reasons'],
    references: ['RFC 9110 (HTTP Semantics)'],
  },
  {
    id: 'behavioural_analysis',
    name: 'Behavioural Analysis',
    layer: 'application',
    group: 'Application-layer',
    description: 'Models normal client behaviour (session, navigation, timing) to distinguish humans/legitimate clients from automation.',
    detectionApproach: 'Feature extraction and scoring versus behavioural baselines.',
    mitigationMechanisms: ['Risk-based scoring', 'Adaptive challenges', 'Session invalidation'],
    strengths: ['Adapts to evolving attacks', 'High precision when tuned'],
    limitations: ['Needs data/history', 'Drift requires retraining'],
    deploymentNotes: ['Start in monitor mode', 'Review FP regularly'],
    references: ['Vendor bot-management documentation', 'OWASP automated threats'],
  },
  {
    id: 'bot_detection',
    name: 'Bot Detection',
    layer: 'application',
    group: 'Application-layer',
    description: 'Identifies automated clients via fingerprints, challenge responses, TLS/JS fingerprints and reputation.',
    detectionApproach: 'Fingerprint matching, challenge solving, reputation feeds.',
    mitigationMechanisms: ['Challenge', 'Block', 'Throttle', 'Tag for step-up'],
    strengths: ['Targets automation specifically'],
    limitations: ['Sophisticated clients mimic browsers', 'Privacy/compliance considerations'],
    deploymentNotes: ['Use graduated responses', 'Consider accessibility and legal constraints'],
    references: ['Vendor documentation', 'OWASP automated threats'],
  },
  {
    id: 'request_quotas',
    name: 'Request Quotas',
    layer: 'application',
    group: 'Application-layer',
    description: 'Enforces per-client quotas across a time window for application endpoints.',
    detectionApproach: 'Quota counters and violation telemetry.',
    mitigationMechanisms: ['Throttle', 'Reject with retry-after', 'Quarantine offenders'],
    strengths: ['Fair-share protection for shared capacity'],
    limitations: ['Quota sizing trade-offs', 'Distributed clients stay under quota'],
    deploymentNotes: ['Combine with per-account and global limits'],
    references: ['API gateway vendor docs'],
  },
  {
    id: 'api_rate_limiting',
    name: 'API Rate Limiting',
    layer: 'application',
    group: 'Application-layer',
    description: 'Protects API surfaces with per-key/per-route rate limits and cost budgets.',
    detectionApproach: 'Key-based metering and cost accounting.',
    mitigationMechanisms: ['Per-key limits', 'Cost-weighted quotas', 'Burst handling'],
    strengths: ['Protects backend from API abuse', 'Enables fair use'],
    limitations: ['Key management', 'Anonymous traffic harder to attribute'],
    deploymentNotes: ['Weight limits by endpoint cost', 'Provide clear client feedback'],
    references: ['API gateway documentation', 'RFC 6585 (429)'],
  },
  {
    id: 'challenge_mechanisms',
    name: 'Challenge Mechanisms',
    layer: 'application',
    group: 'Application-layer',
    description: 'Proof-of-work/interactive challenges that raise the cost of automation without blocking legitimate users.',
    detectionApproach: 'Risk scoring triggers challenges selectively.',
    mitigationMechanisms: ['Interactive/JS/crypto challenges', 'Step-up authentication'],
    strengths: ['Filters automation with low user friction when tuned'],
    limitations: ['Accessibility concerns', 'Can be solved by farms'],
    deploymentNotes: ['Apply selectively on suspicion', 'Provide accessible alternatives'],
    references: ['Vendor challenge documentation'],
  },
  {
    id: 'session_protection',
    name: 'Session Protection',
    layer: 'application',
    group: 'Application-layer',
    description: 'Binds sessions to client characteristics and enforces session lifecycle rules to resist hijacking/abuse.',
    detectionApproach: 'Session anomaly detection (binding mismatch, velocity).',
    mitigationMechanisms: ['Token binding', 'Rotation', 'Anomaly-triggered re-authentication'],
    strengths: ['Hardens application state against abuse'],
    limitations: ['Over-strict binding breaks roaming clients'],
    deploymentNotes: ['Balance security and usability', 'Log binding anomalies'],
    references: ['OWASP Session Management Cheat Sheet'],
  },
  {
    id: 'resource_limiting',
    name: 'Application Resource Limiting',
    layer: 'application',
    group: 'Application-layer',
    description: 'Bounds per-request/per-tenant resource usage (query cost, memory, execution time) so abuse cannot exhaust the backend.',
    detectionApproach: 'Resource telemetry per request/tenant.',
    mitigationMechanisms: ['Timeouts', 'Result-size caps', 'Query cost limits', 'Concurrency budgets'],
    strengths: ['Protects expensive code paths'],
    limitations: ['Application-specific tuning'],
    deploymentNotes: ['Implement at the data layer as a backstop'],
    references: ['Application performance tuning guides'],
  },
  {
    id: 'reverse_proxy',
    name: 'Reverse Proxy',
    layer: 'application',
    group: 'Application-layer',
    description: 'Fronts origin servers, buffering/normalising requests and absorbing slow/incomplete connections.',
    detectionApproach: 'Proxy access/error telemetry and timeouts.',
    mitigationMechanisms: ['Buffering', 'Timeout enforcement', 'Connection pooling', 'Policy enforcement'],
    strengths: ['Shields origins from slow/malformed traffic', 'Central policy point'],
    limitations: ['Proxy itself becomes a target', 'Needs capacity headroom'],
    deploymentNotes: ['Tune timeouts and buffer sizes', 'Protect the proxy tier as a critical asset'],
    references: ['NGINX/HAProxy/Envoy documentation'],
  },
  {
    id: 'cdn_protection',
    name: 'CDN-based Protection',
    layer: 'application',
    group: 'Application-layer',
    description: 'Distributes and absorbs traffic at edge locations while offering caching, WAF and bot mitigation.',
    detectionApproach: 'Edge-collected telemetry with global baselines.',
    mitigationMechanisms: ['Edge absorption', 'Caching', 'Edge WAF/bot rules', 'Origin shielding'],
    strengths: ['Large capacity', 'Global distribution', 'Fast onboarding'],
    limitations: ['Origin must be shielded', 'Cache-bypass paths reduce protection'],
    deploymentNotes: ['Restrict origin to CDN IP ranges', 'Cache aggressively where possible'],
    references: ['CDN vendor documentation'],
  },

  // ---- DNS and infrastructure ------------------------------------------
  {
    id: 'dns_abuse_protection',
    name: 'DNS Abuse Protection',
    layer: 'dns_infra',
    group: 'DNS / Infrastructure',
    description: 'Protects DNS services from abuse (query floods, random-subdomain abuse) while preserving resolution.',
    detectionApproach: 'Query-rate and cache-miss/NXDOMAIN anomaly detection.',
    mitigationMechanisms: ['Response-rate limiting', 'Query filtering', 'Anycast dispersion'],
    strengths: ['Preserves a critical dependency'],
    limitations: ['RRL tuning can drop legitimate retransmissions'],
    deploymentNotes: ['Tune RRL for recursive vs authoritative roles'],
    references: ['RFC 8484 context', 'Operator RRL guidance'],
  },
  {
    id: 'recursive_resolver_protection',
    name: 'Recursive Resolver Protection',
    layer: 'dns_infra',
    group: 'DNS / Infrastructure',
    description: 'Hardens recursive resolvers against abuse and open-resolver misuse.',
    detectionApproach: 'Cache-hit ratio, query-type distribution, source cardinality.',
    mitigationMechanisms: ['Access control', 'Rate limiting', 'Cache tuning', 'DNSSEC validation'],
    strengths: ['Prevents the resolver becoming a reflector/abused resource'],
    limitations: ['Restricting access can break users if scoped wrongly'],
    deploymentNotes: ['Do not run an open resolver; restrict to authorised clients'],
    references: ['CISA open-resolver guidance', 'RFC 5358'],
  },
  {
    id: 'authoritative_dns_resilience',
    name: 'Authoritative DNS Resilience',
    layer: 'dns_infra',
    group: 'DNS / Infrastructure',
    description: 'Ensures authoritative DNS stays available under load through redundancy, anycast and RRL.',
    detectionApproach: 'Per-authoritative query and error telemetry.',
    mitigationMechanisms: ['Multi-provider redundancy', 'Anycast', 'RRL', 'TTL strategy'],
    strengths: ['Keeps names resolvable during attacks'],
    limitations: ['Multi-provider complexity', 'Consistency management'],
    deploymentNotes: ['Use multiple providers and monitor delegation health'],
    references: ['DNS operator best practices'],
  },
  {
    id: 'dns_rate_limiting',
    name: 'DNS Rate Limiting',
    layer: 'dns_infra',
    group: 'DNS / Infrastructure',
    description: 'Limits query rates per source/name to blunt DNS-flood and random-subdomain behaviour.',
    detectionApproach: 'Per-source/per-name rate metering.',
    mitigationMechanisms: ['Per-source limits', 'Slip/truncation', 'Deferred answers'],
    strengths: ['Reduces load while preserving service'],
    limitations: ['Sizing must respect legitimate multi-query clients'],
    deploymentNotes: ['Use RRL "slip" to keep some legitimate traffic'],
    references: ['RFC 8484 / operator guidance'],
  },
  {
    id: 'infra_redundancy',
    name: 'Infrastructure Redundancy',
    layer: 'dns_infra',
    group: 'DNS / Infrastructure',
    description: 'Avoids single points of failure via multi-region, multi-provider and multi-path design.',
    detectionApproach: 'Health checking and synthetic monitoring.',
    mitigationMechanisms: ['Active/passive failover', 'Multi-provider DNS/transit', 'Redundant links'],
    strengths: ['Survives failures and targeted attacks'],
    limitations: ['Cost/complexity', 'Configuration drift risk'],
    deploymentNotes: ['Automate health-based failover and test it'],
    references: ['Site-reliability/high-availability guidance'],
  },
  {
    id: 'capacity_planning',
    name: 'Capacity Planning',
    layer: 'dns_infra',
    group: 'DNS / Infrastructure',
    description: 'Provisions headroom so normal peaks and moderate attacks do not exhaust capacity.',
    detectionApproach: 'Utilisation trending against headroom policy.',
    mitigationMechanisms: ['Headroom targets', 'Autoscaling', 'Load shedding policies'],
    strengths: ['Prevents exhaustion before mitigation engages'],
    limitations: ['Cost of idle headroom'],
    deploymentNotes: ['Define headroom so detection has time to act'],
    references: ['Capacity planning literature'],
  },
  {
    id: 'failover',
    name: 'Failover',
    layer: 'dns_infra',
    group: 'DNS / Infrastructure',
    description: 'Automatically shifts traffic to healthy components when a target degrades.',
    detectionApproach: 'Health probes and SLO-based triggers.',
    mitigationMechanisms: ['DNS/anycast failover', 'Load-balancer failover', 'Transit failover'],
    strengths: ['Maintains availability during partial attacks'],
    limitations: ['Failover target must have capacity', 'Detection lag'],
    deploymentNotes: ['Ensure failover targets can absorb shifted load'],
    references: ['Load-balancing/HA documentation'],
  },
  {
    id: 'service_isolation',
    name: 'Service Isolation',
    layer: 'dns_infra',
    group: 'DNS / Infrastructure',
    description: 'Separates critical services so attack against one does not starve others.',
    detectionApproach: 'Per-service telemetry and quotas.',
    mitigationMechanisms: ['Dedicated resources', 'Tenant isolation', 'Queue separation'],
    strengths: ['Contains blast radius'],
    limitations: ['Resource fragmentation'],
    deploymentNotes: ['Isolate internet-facing critical services'],
    references: ['SRE isolation patterns'],
  },

  // ---- Advanced detection ----------------------------------------------
  {
    id: 'statistical_anomaly_detection',
    name: 'Statistical Anomaly Detection',
    layer: 'detection',
    group: 'Detection & Analytics',
    description: 'Flags deviations from expected distributions using statistical tests rather than fixed thresholds.',
    detectionApproach: 'Z-score/EWMA/deviation scoring over metrics and flows.',
    mitigationMechanisms: ['Generates alerts that feed mitigation automation'],
    strengths: ['Adapts to changing baselines'],
    limitations: ['Sensitive to baseline poisoning', 'Needs clean data'],
    deploymentNotes: ['Use robust statistics and guard the baseline'],
    references: ['Anomaly-detection literature'],
  },
  {
    id: 'baseline_learning',
    name: 'Baseline Learning',
    layer: 'detection',
    group: 'Detection & Analytics',
    description: 'Builds normal-behaviour models per service and time-of-day to contextualise detection.',
    detectionApproach: 'Long-window aggregation to establish expected ranges.',
    mitigationMechanisms: ['Provides context for thresholds'],
    strengths: ['Reduces false positives', 'Context-aware alerting'],
    limitations: ['Slow to adapt to legitimate change', 'Seasonality handling'],
    deploymentNotes: ['Exclude known attack windows from baseline training'],
    references: ['Time-series baseline practices'],
  },
  {
    id: 'time_series_analysis',
    name: 'Time-Series Analysis',
    layer: 'detection',
    group: 'Detection & Analytics',
    description: 'Forecasting and seasonality decomposition over metrics to detect abnormal trends.',
    detectionApproach: 'ARIMA/ETS/seasonal decomposition and residuals.',
    mitigationMechanisms: ['Trend-based alerting'],
    strengths: ['Strong for periodic traffic'],
    limitations: ['Model maintenance', 'Cold-start'],
    deploymentNotes: ['Validate residual thresholds before alerting'],
    references: ['Time-series forecasting literature'],
  },
  {
    id: 'flow_based_detection',
    name: 'Flow-Based Detection',
    layer: 'detection',
    group: 'Detection & Analytics',
    description: 'Analyzes flow records (e.g. NetFlow/IPFIX/sFlow) for volumetric and behavioural anomalies without full packets.',
    detectionApproach: 'Flow feature extraction (bytes, packets, cardinality, flags).',
    mitigationMechanisms: ['High-volume detection feeding mitigation'],
    strengths: ['Scalable', 'Privacy-friendly (no payload)'],
    limitations: ['No payload detail', 'Sampling blind spots'],
    deploymentNotes: ['Ensure adequate sampling and exporter coverage'],
    references: ['RFC 7011 (IPFIX)', 'NetFlow documentation'],
  },
  {
    id: 'behavioural_classification',
    name: 'Behavioural Classification',
    layer: 'detection',
    group: 'Detection & Analytics',
    description: 'Classifies traffic by behavioural patterns (timing, cardinality, protocol use) into benign/attack categories.',
    detectionApproach: 'Feature engineering plus rule/ML classifiers.',
    mitigationMechanisms: ['Attack-class labels drive scoped mitigation'],
    strengths: ['Distinguishes attack types', 'Feeds automation'],
    limitations: ['Concept drift', 'Label quality'],
    deploymentNotes: ['Retrain and validate periodically'],
    references: ['Network traffic classification literature'],
  },
  {
    id: 'ml_traffic_classification',
    name: 'ML Traffic Classification',
    layer: 'detection',
    group: 'Detection & Analytics',
    description: 'Machine-learning models over flow/packet features to detect and classify attacks.',
    detectionApproach: 'Supervised/unsupervised models on engineered features.',
    mitigationMechanisms: ['Confidence-scored detection signals'],
    strengths: ['Can capture complex patterns'],
    limitations: ['Adversarial robustness', 'Explainability', 'Data/label needs'],
    deploymentNotes: ['Pair with human review; monitor drift and adversarial inputs'],
    references: ['NIDS ML literature', 'Adversarial ML for security'],
  },
  {
    id: 'false_positive_management',
    name: 'False-Positive Management',
    layer: 'detection',
    group: 'Detection & Analytics',
    description: 'Systematic tuning, suppression and feedback loops to control alert noise and mitigation errors.',
    detectionApproach: 'Alert outcome tracking and FP/FN measurement.',
    mitigationMechanisms: ['Allow-listing', 'Threshold tuning', 'Graduated responses'],
    strengths: ['Keeps mitigation trustworthy'],
    limitations: ['Ongoing operational effort'],
    deploymentNotes: ['Instrument FP/FN and review weekly'],
    references: ['SOC operations guidance'],
  },
  {
    id: 'multi_signal_correlation',
    name: 'Multi-Signal Correlation',
    layer: 'detection',
    group: 'Detection & Analytics',
    description: 'Correlates network, application and infrastructure signals to raise confidence and reduce FP.',
    detectionApproach: 'Cross-domain correlation rules and scoring.',
    mitigationMechanisms: ['Higher-confidence automated mitigation'],
    strengths: ['Fewer false positives', 'Context-rich alerts'],
    limitations: ['Data-integration complexity'],
    deploymentNotes: ['Correlate rate, cardinality, latency and error signals'],
    references: ['Alert-correlation literature'],
  },
];

/* -------------------------------------------------------------------------- */
/* §4.2 Product intelligence (from PUBLIC documentation only)                  */
/* -------------------------------------------------------------------------- */

export interface DefenseProduct {
  id: string;
  name: string;
  category: string;
  architecture: string;
  detectionApproach: string;
  supportedProtocols: string;
  mitigationMechanisms: string[];
  deploymentRequirements: string;
  performanceConsiderations: string;
  knownLimitations: string[];
  publicDocs: string[];
  availableApisIntegrations: string[];
}

export const DEFENSE_PRODUCTS: DefenseProduct[] = [
  {
    id: 'cloudflare_ddos',
    name: 'Cloudflare DDoS Protection',
    category: 'Cloud/edge service',
    architecture: 'Global anycast edge network with automated and managed mitigation tiers.',
    detectionApproach: 'Always-on network/application anomaly detection with managed rules.',
    supportedProtocols: 'Network (L3/L4) and application (L7/DNS) protocols.',
    mitigationMechanisms: ['Edge absorption', 'Scrubbing', 'WAF/bot rules', 'Rate limiting', 'Origin shielding'],
    deploymentRequirements: 'Delegate DNS or proxy traffic through the edge; restrict origin to edge ranges.',
    performanceConsiderations: 'Edge caching reduces origin load; latency depends on PoP proximity.',
    knownLimitations: ['Cache-bypass paths have less protection', 'Rules require tuning'],
    publicDocs: ['Cloudflare public documentation'],
    availableApisIntegrations: ['REST API', 'Terraform provider', 'Logpush'],
  },
  {
    id: 'aws_shield',
    name: 'AWS Shield',
    category: 'Cloud provider service',
    architecture: 'Integrated with AWS edge (CloudFront/Route 53) and Shield Advanced response team.',
    detectionApproach: 'Always-on network-flow monitoring plus web-ACL integration.',
    supportedProtocols: 'L3/L4 and L7 (with WAF integration).',
    mitigationMechanisms: ['Automatic L3/L4 mitigations', 'Shield Response Team', 'WAF rule enforcement'],
    deploymentRequirements: 'Usage within AWS; Shield Advanced for enhanced protections and cost protection.',
    performanceConsiderations: 'Edge-integrated; minimal added latency within AWS.',
    knownLimitations: ['Best within AWS perimeter', 'Advanced features cost extra'],
    publicDocs: ['AWS public documentation'],
    availableApisIntegrations: ['AWS API/CLI', 'CloudFormation', 'Terraform'],
  },
  {
    id: 'gcp_armor',
    name: 'Google Cloud Armor',
    category: 'Cloud provider service',
    architecture: 'Integrated with Cloud Load Balancing and edge (GFE) infrastructure.',
    detectionApproach: 'WAF rules and adaptive protection based on traffic learning.',
    supportedProtocols: 'L7 (HTTP/S); L3/L4 via Google edge absorption.',
    mitigationMechanisms: ['Security policies', 'Rate-based rules', 'Adaptive protection', 'Bot management (with reCAPTCHA)'],
    deploymentRequirements: 'Cloud Load Balancing fronting backends.',
    performanceConsiderations: 'Edge enforcement; low added latency.',
    knownLimitations: ['Tied to GCP load balancing', 'Rule complexity'],
    publicDocs: ['GCP public documentation'],
    availableApisIntegrations: ['gcloud/API', 'Terraform'],
  },
  {
    id: 'akamai_prolexic',
    name: 'Akamai Prolexic',
    category: 'Scrubbing service',
    architecture: 'Dedicated scrubbing centres with BGP/anycast diversion.',
    detectionApproach: 'Volumetric and signature-based detection in the scrubbing tier.',
    supportedProtocols: 'L3/L4 with application-layer add-ons.',
    mitigationMechanisms: ['BGP/anycast diversion', 'Scrubbing', 'Custom signatures'],
    deploymentRequirements: 'Routing diversion configured in advance.',
    performanceConsiderations: 'Diversion adds path latency during mitigation.',
    knownLimitations: ['Diversion setup complexity', 'Signature maintenance'],
    publicDocs: ['Akamai public documentation'],
    availableApisIntegrations: ['Prolexic portal APIs', 'SIEM integrations'],
  },
  {
    id: 'radware_defensepro',
    name: 'Radware DefensePro',
    category: 'On-prem/VM appliance',
    architecture: 'Inline behavioural DoS protection appliance.',
    detectionApproach: 'Behavioural analysis with automatic signatures.',
    supportedProtocols: 'L3/L4 with L7 modules.',
    mitigationMechanisms: ['Behavioural blocking', 'Rate limiting', 'Signature-based filtering'],
    deploymentRequirements: 'Inline deployment with sufficient throughput capacity.',
    performanceConsiderations: 'Inline latency; sizing for peak throughput.',
    knownLimitations: ['Inline capacity limits', 'Behavioural model tuning'],
    publicDocs: ['Radware public documentation'],
    availableApisIntegrations: ['Appliance APIs', 'SIEM/SOAR integrations'],
  },
  {
    id: 'netscout_arbor',
    name: 'NETSCOUT Arbor (AED/APS/TMS)',
    category: 'Detection + scrubbing suite',
    architecture: 'Distributed detection (TMS/AED) with centralised scrubbing.',
    detectionApproach: 'Anomaly/volumetric detection with threat intelligence.',
    supportedProtocols: 'L3/L4 with L7 capabilities.',
    mitigationMechanisms: ['Out-of-band mitigation', 'Scrubbing', 'FlowSpec/RTBH automation'],
    deploymentRequirements: 'Sensors for visibility plus scrubbing capacity.',
    performanceConsiderations: 'Out-of-band design keeps inline latency low; scrubbing path latency during mitigation.',
    knownLimitations: ['Integration effort', 'Sensor coverage required'],
    publicDocs: ['NETSCOUT public documentation'],
    availableApisIntegrations: ['REST APIs', 'SOAR playbooks'],
  },
  {
    id: 'fastnetmon',
    name: 'FastNetMon',
    category: 'Open-source/community DDoS detector',
    architecture: 'Software detector consuming NetFlow/IPFIX/sFlow and/or mirror traffic.',
    detectionApproach: 'Threshold and behaviour-based detection with multiple notification hooks.',
    supportedProtocols: 'L3/L4 flow analysis.',
    mitigationMechanisms: ['Triggers RTBH/FlowSpec', 'BGP/ExaBGP scripts', 'External API calls'],
    deploymentRequirements: 'Flow exporters or traffic mirroring to the detector host.',
    performanceConsiderations: 'Scales with flow volume; community vs commercial tiers.',
    knownLimitations: ['Flow-sampling blind spots', 'Scripting left to operator'],
    publicDocs: ['FastNetMon public documentation (GitHub)'],
    availableApisIntegrations: ['CLI', 'Webhook', 'BGP integrations'],
  },
  {
    id: 'crowdsec',
    name: 'CrowdSec',
    category: 'Open-source collaborative IPS',
    architecture: 'Agent + parser + scenario engine with optional community blocklist.',
    detectionApproach: 'Log parsing and behavioural scenarios.',
    supportedProtocols: 'Application logs (web, auth, services) plus some network scenarios.',
    mitigationMechanisms: ['Remediation components (firewall, nginx, etc.)', 'Community blocklists'],
    deploymentRequirements: 'Install agent on hosts/log sources; configure remediation.',
    performanceConsiderations: 'Log-processing overhead; lightweight agents.',
    knownLimitations: ['Primarily log-driven', 'Scenario tuning needed'],
    publicDocs: ['CrowdSec public documentation'],
    availableApisIntegrations: ['cscli', 'REST API', 'bouncers/remediation components'],
  },
  {
    id: 'suricata',
    name: 'Suricata',
    category: 'Open-source NIDS/IPS',
    architecture: 'Multi-threaded signature/anomaly engine with EVE JSON output.',
    detectionApproach: 'Rules (signatures) plus protocol parsers and threshold/rate detection.',
    supportedProtocols: 'Broad protocol support (TCP/UDP/ICMP, DNS, HTTP, TLS metadata, etc.).',
    mitigationMechanisms: ['Detection primarily; IPS mode can drop/reject.'],
    deploymentRequirements: 'Tap or inline placement; rule management.',
    performanceConsiderations: 'Throughput depends on threads/hardware; use flow/stream tuning.',
    knownLimitations: ['Rule-writing effort', 'False positives need tuning'],
    publicDocs: ['Suricata public documentation'],
    availableApisIntegrations: ['EVE JSON', 'Redis', 'Rule management tools'],
  },
  {
    id: 'zeek',
    name: 'Zeek',
    category: 'Open-source network security monitor',
    architecture: 'Event-driven monitor producing rich transaction logs.',
    detectionApproach: 'Script-based analysis over parsed protocol events.',
    supportedProtocols: 'Broad protocol analysis with per-protocol logs.',
    mitigationMechanisms: ['Detection/telemetry; enforcement via integrations.'],
    deploymentRequirements: 'Tap placement; script management.',
    performanceConsiderations: 'CPU-bound; tune scripts and worker count.',
    knownLimitations: ['Not inline', 'Scripting expertise needed'],
    publicDocs: ['Zeek public documentation'],
    availableApisIntegrations: ['Logs (TSV/JSON)', 'Intel framework', 'Cluster frameworks'],
  },
  {
    id: 'haproxy',
    name: 'HAProxy',
    category: 'Load balancer / proxy',
    architecture: 'High-performance TCP/HTTP proxy with server-side protections.',
    detectionApproach: 'Not an attack detector; supports observability via stats/logs.',
    supportedProtocols: 'TCP and HTTP/S.',
    mitigationMechanisms: ['Rate limiting', 'Connection limits', 'Timeouts', 'Request validation', 'Stick tables'],
    deploymentRequirements: 'Frontend/backend configuration; capacity sizing.',
    performanceConsiderations: 'Very high throughput; tune threads/conns.',
    knownLimitations: ['Operational config complexity', 'Not a signature detector'],
    publicDocs: ['HAProxy public documentation'],
    availableApisIntegrations: ['Runtime API', 'Prometheus exporter'],
  },
  {
    id: 'nginx',
    name: 'NGINX',
    category: 'Web server / reverse proxy',
    architecture: 'Event-driven web server and reverse proxy.',
    detectionApproach: 'Logs and metrics for observability; not a detector itself.',
    supportedProtocols: 'HTTP/S and TCP/UDP stream proxying.',
    mitigationMechanisms: ['limit_req', 'limit_conn', 'client timeouts', 'Buffering', 'Caching'],
    deploymentRequirements: 'Configuration per vhost/location.',
    performanceConsiderations: 'High throughput; tune worker_connections/buffers.',
    knownLimitations: ['Rate-limit granularity per zone', 'Needs careful timeout tuning'],
    publicDocs: ['NGINX public documentation'],
    availableApisIntegrations: ['stub_status', 'Prometheus exporter'],
  },
];

export const PRODUCT_DISCLAIMER =
  'Product details are drawn from PUBLIC documentation only. This platform does NOT claim access to any ' +
  'proprietary internal implementation; capabilities may change between releases and should be verified ' +
  'against current vendor documentation.';

/* -------------------------------------------------------------------------- */
/* §4.1/§4.2 mitigation strategy comparison matrix                             */
/* -------------------------------------------------------------------------- */

export type CompareRisk = 'low' | 'medium' | 'high';

export interface MitigationStrategy {
  id: string;
  name: string;
  layer: DefenseLayer;
  coverage: string;
  latencyImpact: string;
  falsePositiveRisk: CompareRisk;
  deploymentCost: CompareRisk;
  complexity: CompareRisk;
  scalability: string;
  /** Bypass/evasion weaknesses described DEFENSIVELY (what the defender should harden). */
  defensiveWeaknessNotes: string;
  operationalConsiderations: string[];
}

export const MITIGATION_STRATEGIES: MitigationStrategy[] = [
  {
    id: 'network_filtering_acl',
    name: 'Network filtering / ACL',
    layer: 'network',
    coverage: 'Malformed and unexpected traffic.',
    latencyImpact: 'Minimal (line-rate).',
    falsePositiveRisk: 'low',
    deploymentCost: 'low',
    complexity: 'low',
    scalability: 'Very high.',
    defensiveWeaknessNotes: 'Well-formed attack traffic matches allowed profiles; keep policies minimal and monitor for drift.',
    operationalConsiderations: ['Review policies with services', 'Log denies for visibility'],
  },
  {
    id: 'rate_limiting',
    name: 'Rate limiting / connection limiting',
    layer: 'network',
    coverage: 'Volumetric and connection-based floods.',
    latencyImpact: 'Low.',
    falsePositiveRisk: 'medium',
    deploymentCost: 'low',
    complexity: 'low',
    scalability: 'High.',
    defensiveWeaknessNotes: 'Distributed sources each stay under per-source caps; add per-destination and global dimensions.',
    operationalConsiderations: ['Tune from baseline', 'Provide retry feedback'],
  },
  {
    id: 'syn_cookies_state',
    name: 'SYN cookies / TCP state protection',
    layer: 'network',
    coverage: 'Half-open and state-exhaustion floods.',
    latencyImpact: 'Low.',
    falsePositiveRisk: 'low',
    deploymentCost: 'low',
    complexity: 'low',
    scalability: 'High.',
    defensiveWeaknessNotes: 'Completed-connection floods are unaffected; pair with connection limits.',
    operationalConsiderations: ['Monitor cookie activation', 'Tune timeouts'],
  },
  {
    id: 'scrubbing',
    name: 'Traffic scrubbing',
    layer: 'network',
    coverage: 'Volumetric attacks (broad).',
    latencyImpact: 'Medium (diversion path).',
    falsePositiveRisk: 'medium',
    deploymentCost: 'high',
    complexity: 'medium',
    scalability: 'Very high (vendor capacity).',
    defensiveWeaknessNotes: 'Signature coverage gaps let crafted traffic through; validate profiles and pre-stage diversion.',
    operationalConsiderations: ['Pre-establish diversion', 'Test regularly'],
  },
  {
    id: 'blackhole_flowspec',
    name: 'BGP blackholing / FlowSpec',
    layer: 'network',
    coverage: 'Volumetric; FlowSpec can be scoped.',
    latencyImpact: 'Low to none.',
    falsePositiveRisk: 'medium',
    deploymentCost: 'low',
    complexity: 'medium',
    scalability: 'Very high.',
    defensiveWeaknessNotes: 'Blackholing costs victim availability; use FlowSpec scoping and conservative match rules.',
    operationalConsiderations: ['Documented trigger policy', 'Guard against bad rules'],
  },
  {
    id: 'anycast',
    name: 'Anycast dispersion',
    layer: 'network',
    coverage: 'Volumetric; dilutes geographically.',
    latencyImpact: 'None to low.',
    falsePositiveRisk: 'low',
    deploymentCost: 'medium',
    complexity: 'high',
    scalability: 'Very high.',
    defensiveWeaknessNotes: 'Per-flow consistency needs care; monitor per-PoP health for withdrawal.',
    operationalConsiderations: ['Use for stateless/DNS services', 'Health-based withdraw'],
  },
  {
    id: 'waf_app',
    name: 'WAF / application inspection',
    layer: 'application',
    coverage: 'Application-layer attacks.',
    latencyImpact: 'Low to medium.',
    falsePositiveRisk: 'medium',
    deploymentCost: 'medium',
    complexity: 'medium',
    scalability: 'High with tuning.',
    defensiveWeaknessNotes: 'Well-formed floods and encodings evade rules; pair with behavioural/bot analysis and keep TLS visible.',
    operationalConsiderations: ['Tune before blocking', 'Review FP'],
  },
  {
    id: 'bot_behavioural',
    name: 'Bot / behavioural protection + challenges',
    layer: 'application',
    coverage: 'Automation and behavioural abuse.',
    latencyImpact: 'Low to medium.',
    falsePositiveRisk: 'medium',
    deploymentCost: 'medium',
    complexity: 'high',
    scalability: 'High.',
    defensiveWeaknessNotes: 'Sophisticated clients mimic browsers; use graduated challenges and periodic review.',
    operationalConsiderations: ['Accessibility compliance', 'Monitor FP'],
  },
  {
    id: 'cdn_edge',
    name: 'CDN / edge protection',
    layer: 'application',
    coverage: 'Network + application (broad).',
    latencyImpact: 'Low (often improves latency).',
    falsePositiveRisk: 'low',
    deploymentCost: 'medium',
    complexity: 'low',
    scalability: 'Very high.',
    defensiveWeaknessNotes: 'Origin must be locked to edge ranges; cache-bypass paths reduce protection.',
    operationalConsiderations: ['Shield origin', 'Cache aggressively'],
  },
  {
    id: 'ml_detection',
    name: 'Statistical / ML detection',
    layer: 'detection',
    coverage: 'Novel and behavioural attacks.',
    latencyImpact: 'None (out-of-band).',
    falsePositiveRisk: 'medium',
    deploymentCost: 'medium',
    complexity: 'high',
    scalability: 'High with pipelines.',
    defensiveWeaknessNotes: 'Baselines can drift or be poisoned; guard the baseline and monitor adversarial inputs.',
    operationalConsiderations: ['Human review', 'Retraining cadence'],
  },
  {
    id: 'multi_signal',
    name: 'Multi-signal correlation + FP management',
    layer: 'detection',
    coverage: 'Improves precision across all layers.',
    latencyImpact: 'None (analytics).',
    falsePositiveRisk: 'low',
    deploymentCost: 'medium',
    complexity: 'high',
    scalability: 'High.',
    defensiveWeaknessNotes: 'Correlation depends on data quality; ensure complete, timely telemetry.',
    operationalConsiderations: ['Track FP/FN', 'Feedback loops'],
  },
];

/* -------------------------------------------------------------------------- */

export interface DefenseSearchQuery {
  topic?: string;
  product?: string;
  layer?: DefenseLayer;
}

export function searchDefenseTechnologies(input: DefenseSearchQuery): DefenseTechnology[] {
  const topic = input.topic?.toLowerCase().trim();
  return DEFENSE_TECHNOLOGIES.filter((tech) => {
    if (input.layer && tech.layer !== input.layer) return false;
    if (topic) {
      const haystack = [tech.id, tech.name, tech.group, tech.description, tech.detectionApproach, ...tech.mitigationMechanisms]
        .join(' ')
        .toLowerCase();
      if (!haystack.includes(topic)) {
        const tokens = topic.split(/\s+/).filter((t) => t.length >= 3);
        if (!tokens.some((t) => haystack.includes(t))) return false;
      }
    }
    return true;
  });
}

export function searchDefenseProducts(product?: string): DefenseProduct[] {
  if (!product) return DEFENSE_PRODUCTS;
  const q = product.toLowerCase();
  return DEFENSE_PRODUCTS.filter(
    (p) => p.id.includes(q) || p.name.toLowerCase().includes(q) || p.category.toLowerCase().includes(q),
  );
}

export function toDefenseKnowledgeRecord(tech: DefenseTechnology): KnowledgeRecord {
  const now = new Date().toISOString();
  return {
    id: `defense-technology:${tech.id}`,
    category: 'defense_technology',
    title: tech.name,
    identifiers: { defense_technology: tech.id },
    affectedVersions: [],
    fixedVersions: [],
    klass: tech.group,
    rootCause: tech.detectionApproach,
    attackSurface: tech.layer,
    preconditions: [],
    publicExploitState: 'none',
    relatedMalwareFamilies: [],
    relatedMiraiVariants: [],
    relatedRecordIds: [],
    verification: 'statically_reviewed',
    confidence: 'confirmed',
    license: 'public-research',
    provenance: [curatedProvenance('public-research', `Anti-DDoS technology: ${tech.name}`)],
    evidence: [],
    tags: ['defense-technology', tech.layer, tech.group.toLowerCase().replace(/[^a-z0-9]+/g, '-')],
    createdAt: now,
    updatedAt: now,
  };
}

let seeded = false;

/** Seed defence-technology records into the knowledge base (idempotent per process). */
export function seedDefenseCatalogue(knowledge: KnowledgeBase): number {
  if (seeded) return 0;
  for (const tech of DEFENSE_TECHNOLOGIES) {
    knowledge.upsertRecord(toDefenseKnowledgeRecord(tech));
  }
  seeded = true;
  return DEFENSE_TECHNOLOGIES.length;
}
