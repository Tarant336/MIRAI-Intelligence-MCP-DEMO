/**
 * Curated attack-method catalogue (§3.1 – §3.4).
 *
 * This is a DEFENSIVE knowledge base: it documents the *families* of denial
 * of service behaviour that has been observed in public research, together
 * with the defensive visibility, detection strategy and mitigations for each.
 *
 * SECURITY: entries intentionally describe mechanisms QUALITATIVELY. They
 * contain no operational parameters, no packet-building recipes, no source
 * spoofing instructions and no amplification sizing guidance. This is
 * analysis and defence material only (§10).
 */

import type { KnowledgeRecord } from '../../shared/knowledge-base.js';
import type { KnowledgeBase } from '../../shared/knowledge-base.js';
import { curatedProvenance } from '../../tools/helpers.js';

export type AttackMethodLayer =
  | 'network'
  | 'transport'
  | 'application'
  | 'reflection_amplification'
  | 'iot_specific';

export type Difficulty = 'low' | 'medium' | 'high';

export interface AttackMethodCatalogueItem {
  id: string;
  name: string;
  layer: AttackMethodLayer;
  protocol: string;
  aliases: string[];
  /** Generic description of the behaviour (no operational parameters). */
  mechanism: string;
  /** Which resource is consumed/saturated. */
  resourceExhausted: string;
  preconditions: string[];
  observableSymptoms: string[];
  telemetry: string[];
  /** Qualitative packet characteristics — NOT a construction recipe. */
  packetCharacteristics: string[];
  expectedImpact: string;
  commonFalsePositives: string[];
  defensiveDetectionStrategy: string;
  mitigationTechniques: string[];
  references: string[];
  relatedMalwareFamilies: string[];
  /** §3.4 comparison fields. */
  targetedResource: string;
  protocolBehaviour: string;
  defensiveVisibility: string;
  detectionDifficulty: Difficulty;
  mitigationDifficulty: Difficulty;
  commonImplementationTraits: string[];
  historicalEvolution: string;
  relatedCves: string[];
  relatedMisconfigurations: string[];
  /** Classification keywords used by the free-text classifier. */
  keywords: string[];
}

/** The curated catalogue, covering §3.1 categories. */
export const ATTACK_METHOD_CATALOGUE: AttackMethodCatalogueItem[] = [
  {
    id: 'tcp_syn_flood',
    name: 'TCP SYN Flood',
    layer: 'transport',
    protocol: 'TCP',
    aliases: ['syn flood', 'tcp syn flood', 'half-open flood'],
    mechanism:
      'A large volume of TCP segments carrying only the SYN flag is directed at a service, initiating many connection requests that are never completed.',
    resourceExhausted: 'TCP connection state table and the listening socket backlog queue (half-open connections).',
    preconditions: [
      'Target exposes a TCP service (for example HTTP, SSH or telnet).',
      'Attacker has enough aggregate send capacity, or uses randomised source addressing.',
      'No SYN-cookie / SYN-proxy / connection-limit protection in front of the service.',
    ],
    observableSymptoms: [
      'Accept/backlog queue overflow counters increasing.',
      'Legitimate clients experience connect timeouts or refusals.',
      'Large number of connections stuck in SYN-RECEIVED state.',
      'Service CPU and kernel network-stack pressure rises.',
    ],
    telemetry: [
      'Flow records showing a high SYN count with very few ACK segments.',
      'SYN:ACK ratio far outside the normal baseline.',
      'Per-destination unique source-IP cardinality spike.',
      'Conntrack / connection-table utilisation growth.',
    ],
    packetCharacteristics: [
      'Dominance of small TCP segments that carry only the SYN flag.',
      'A large number of distinct source addresses, frequently inconsistent with real TCP behaviour.',
      'Repetition toward a single destination service with minimal follow-up traffic.',
    ],
    expectedImpact: 'Service unavailability for legitimate users; connection queue saturation and timeouts.',
    commonFalsePositives: [
      'Legitimate connection storms after an outage or mass retry.',
      'Vulnerability scanners and monitoring probes.',
      'Load-balancer or uptime health checks with short-lived connections.',
      'NAT concentration that changes observed source-IP cardinality.',
    ],
    defensiveDetectionStrategy:
      'Baseline the SYN:ACK ratio and unique-source cardinality per destination; alert on statistically significant deviation combined with backlog saturation instead of a single raw threshold.',
    mitigationTechniques: [
      'Enable TCP SYN cookies.',
      'Per-source connection and rate limits; tune listen backlog.',
      'Upstream SYN proxy / traffic scrubbing.',
      'Anycast dispersion and added capacity.',
    ],
    references: [
      'IETF RFC 4987 — TCP SYN Flooding Attacks and Common Mitigations',
      'Cloudflare Learning Center — SYN flood',
      'CISA/US-CERT guidance on network-layer DDoS',
    ],
    relatedMalwareFamilies: ['Mirai', 'BASHLITE (Gafgyt)', 'Satori'],
    targetedResource: 'TCP connection state / backlog',
    protocolBehaviour: 'TCP handshake initiation without completion',
    defensiveVisibility: 'High — visible at both flow and packet level',
    detectionDifficulty: 'low',
    mitigationDifficulty: 'low',
    commonImplementationTraits: [
      'Raw sockets with explicit IP/TCP header construction.',
      'Randomised source addressing.',
      'Small, frequently identical segment sizes.',
    ],
    historicalEvolution:
      'A classic denial-of-service primitive since the 1990s; later reused almost unchanged by IoT botnets.',
    relatedCves: [],
    relatedMisconfigurations: ['SYN-cookie protection disabled', 'Undersized listen backlog'],
    keywords: ['syn', 'tcp', 'half-open', 'handshake', 'backlog', 'spoof'],
  },
  {
    id: 'tcp_ack_flood',
    name: 'TCP ACK Flood',
    layer: 'transport',
    protocol: 'TCP',
    aliases: ['ack flood', 'tcp ack flood'],
    mechanism:
      'A high rate of TCP segments with the ACK flag is sent toward a service so that the receiver must process state lookups for segments that match no real connection.',
    resourceExhausted: 'CPU spent on packet classification and connection lookup; firewall/load-balancer session tables.',
    preconditions: [
      'Target accepts TCP traffic on an exposed port.',
      'Attacker can emit enough segments to exceed the target processing budget.',
    ],
    observableSymptoms: [
      'Firewall or load-balancer session-table churn.',
      'Elevated CPU attributable to network-stack processing.',
      'Randomised ACK segments arriving outside any established connection context.',
    ],
    telemetry: [
      'High ACK-segment rate with low accompanying payload.',
      'Many segments that match no known connection tuple.',
      'Per-destination segment-rate deviation from baseline.',
    ],
    packetCharacteristics: [
      'Small TCP segments with only the ACK flag set.',
      'Often a wide spread of source addresses and ports.',
      'Segments that do not belong to any observed three-way handshake.',
    ],
    expectedImpact: 'Processing-budget exhaustion causing degraded or unavailable service.',
    commonFalsePositives: [
      'Legitimate high-throughput flows with many small acknowledgements.',
      'Asymmetric routing that hides the handshake from the sensor.',
      'Tunnelled or offloaded traffic that appears as unexpected ACKs.',
    ],
    defensiveDetectionStrategy:
      'Track ACK segments without a corresponding observed connection and per-destination ACK rate; correlate with CPU and session-table pressure.',
    mitigationTechniques: [
      'Stateful filtering that drops non-handshake ACKs.',
      'Rate limiting and connection tracking limits.',
      'Upstream scrubbing and anycast dispersion.',
    ],
    references: ['Cloudflare Learning Center — ACK flood', 'NIST SP 800-189 (resilient protocols)'],
    relatedMalwareFamilies: ['BASHLITE (Gafgyt)', 'Mirai variants'],
    targetedResource: 'Packet-processing budget / session tables',
    protocolBehaviour: 'TCP acknowledgements outside connection context',
    defensiveVisibility: 'Medium — requires stateful correlation',
    detectionDifficulty: 'medium',
    mitigationDifficulty: 'medium',
    commonImplementationTraits: ['Raw sockets', 'Randomised or spoofed source tuples', 'Uniform small segments'],
    historicalEvolution: 'Emerged as SYN-cookie mitigations made pure SYN floods less effective.',
    relatedCves: [],
    relatedMisconfigurations: ['Stateless ACL that only matches SYN'],
    keywords: ['ack', 'tcp', 'stateful', 'session table', 'firewall'],
  },
  {
    id: 'tcp_rst_flood',
    name: 'TCP RST Flood',
    layer: 'transport',
    protocol: 'TCP',
    aliases: ['rst flood', 'tcp reset flood'],
    mechanism:
      'A volume of TCP segments carrying the RST flag is sent toward a service so that connections and middleboxes must process teardown logic at scale.',
    resourceExhausted: 'Connection state and middlebox teardown processing; legitimate connections may be reset.',
    preconditions: [
      'Target or an in-path device processes TCP reset semantics.',
      'Sufficient segment rate to force resets or overwhelm teardown handling.',
    ],
    observableSymptoms: [
      'Abnormal number of connections terminated by RST.',
      'Session-table churn and client-visible connection resets.',
    ],
    telemetry: [
      'RST-segment rate spike versus baseline.',
      'Connections terminated without FIN exchange.',
    ],
    packetCharacteristics: [
      'Small TCP segments with the RST flag set.',
      'Wide spread of source tuples.',
      'Interleaving with valid traffic to disrupt established sessions.',
    ],
    expectedImpact: 'Connection instability; degraded or unavailable service; possible legitimate-session disruption.',
    commonFalsePositives: [
      'Port scanners and closed-port responses.',
      'Firewall or load-balancer resets on policy actions.',
      'Misconfigured applications that reset idle sessions.',
    ],
    defensiveDetectionStrategy:
      'Baseline the RST rate; alert on RST-dominant teardown patterns and concurrent session-table churn.',
    mitigationTechniques: ['Stateful inspection', 'Rate limiting', 'Upstream scrubbing'],
    references: ['Cloudflare Learning Center — TCP reset flood'],
    relatedMalwareFamilies: ['Mirai variants'],
    targetedResource: 'Connection state / teardown processing',
    protocolBehaviour: 'Forced TCP teardown',
    defensiveVisibility: 'Medium',
    detectionDifficulty: 'medium',
    mitigationDifficulty: 'low',
    commonImplementationTraits: ['Raw sockets', 'Spoofed source tuples'],
    historicalEvolution: 'Reused alongside other TCP floods as a secondary disruption vector.',
    relatedCves: [],
    relatedMisconfigurations: ['Aggressive idle-session RST behaviour'],
    keywords: ['rst', 'reset', 'tcp', 'teardown', 'connection'],
  },
  {
    id: 'udp_flood',
    name: 'UDP Flood',
    layer: 'transport',
    protocol: 'UDP',
    aliases: ['udp flood', 'udp packet flood'],
    mechanism:
      'A high volume of UDP datagrams is directed at a service so the receiver spends bandwidth and CPU processing datagrams, including generating ICMP port-unreachable replies.',
    resourceExhausted: 'Link bandwidth, host packet rate and protocol-stack processing; ICMP reply generation.',
    preconditions: [
      'Target has UDP-exposed services or generates ICMP errors for closed ports.',
      'Attacker has aggregate bandwidth to saturate the target link or host.',
    ],
    observableSymptoms: [
      'Link interface saturation and receive-drop counters rising.',
      'Large volume of ICMP port-unreachable traffic if ports are closed.',
      'Elevated per-host packet rate.',
    ],
    telemetry: [
      'UDP packet rate and byte rate versus baseline.',
      'Dominant destination port and payload-size distribution.',
      'Source-IP cardinality.',
    ],
    packetCharacteristics: [
      'High rate of UDP datagrams, often with uniform payload sizes.',
      'Uniform or randomised source tuples.',
      'Frequently directed at a single destination port or random port range.',
    ],
    expectedImpact: 'Interface saturation; packet loss for legitimate traffic; service unavailability.',
    commonFalsePositives: [
      'Legitimate high-volume UDP services (streaming, DNS, VoIP, telemetry).',
      'Broken clients retransmitting application-level data.',
      'Misconfigured services flooding a collector.',
    ],
    defensiveDetectionStrategy:
      'Baseline per-destination UDP rate and payload-size distribution; alert on sustained rate deviation combined with interface drops and source-cardinality anomalies.',
    mitigationTechniques: [
      'UDP rate limiting and allow-listing of expected ports.',
      'Disable unnecessary ICMP error generation.',
      'Upstream scrubbing and anycast dispersion.',
    ],
    references: ['Cloudflare Learning Center — UDP flood', 'CISA/US-CERT network-layer DDoS guidance'],
    relatedMalwareFamilies: ['Mirai', 'BASHLITE (Gafgyt)', 'Muhstik'],
    targetedResource: 'Bandwidth / packet processing',
    protocolBehaviour: 'Connectionless datagram saturation',
    defensiveVisibility: 'High',
    detectionDifficulty: 'low',
    mitigationDifficulty: 'medium',
    commonImplementationTraits: ['Plain datagram sockets or raw sockets', 'Uniform payload generation'],
    historicalEvolution: 'The simplest and most persistent flood primitive; widely reused.',
    relatedCves: [],
    relatedMisconfigurations: ['Open UDP services without rate limits', 'UDP amplification exposure'],
    keywords: ['udp', 'datagram', 'flood', 'bandwidth', 'icmp'],
  },
  {
    id: 'fragmentation_abuse',
    name: 'IP Fragmentation Abuse',
    layer: 'network',
    protocol: 'IP (IPv4/IPv6)',
    aliases: ['fragmentation flood', 'ip fragment attack', 'ipv6 fragment flood'],
    mechanism:
      'Large numbers of IP fragments (or deliberately crafted fragment patterns) are sent so the receiver must reassemble and conserve fragment-reassembly buffers, or must process overlapping fragments.',
    resourceExhausted: 'IP reassembly buffers and CPU spent on reassembly / overlap handling.',
    preconditions: [
      'Target must reassemble fragments or forward them.',
      'Fragments with unusual sizes or offsets are accepted without policy.',
    ],
    observableSymptoms: [
      'Reassembly failures and fragment-buffer exhaustion.',
      'Elevated CPU for packet reassembly.',
      'Fragment-shaped traffic without a matching complete datagram.',
    ],
    telemetry: [
      'Fragment rate and reassembly-buffer utilisation.',
      'Counts of incomplete reassembly attempts.',
    ],
    packetCharacteristics: [
      'Packets with small offsets forming many fragments of a datagram.',
      'Overlapping or unusually small non-final fragments.',
      'Fragments that never assemble into a complete payload.',
    ],
    expectedImpact: 'Resource exhaustion in reassembly; degraded throughput; possible filter evasion considerations for defenders.',
    commonFalsePositives: [
      'Legitimate large UDP or tunnelled traffic that requires fragmentation.',
      'MTU-discovery edge cases.',
    ],
    defensiveDetectionStrategy:
      'Monitor reassembly-buffer utilisation and fragment rate; alert on incomplete reassembly and abnormal fragment-size distributions.',
    mitigationTechniques: [
      'Fragment-size and reassembly limits.',
      'Drop or normalise anomalous fragments at the edge.',
      'MTU tuning to avoid legitimate fragmentation.',
    ],
    references: [
      'RFC 1858 — Security Considerations for IP Fragment Filtering',
      'RFC 8900 — IP Fragmentation Considered Fragile',
    ],
    relatedMalwareFamilies: ['BASHLITE (Gafgyt)', 'Mirai variants'],
    targetedResource: 'IP reassembly buffers',
    protocolBehaviour: 'Fragmented datagram reassembly',
    defensiveVisibility: 'Medium',
    detectionDifficulty: 'medium',
    mitigationDifficulty: 'low',
    commonImplementationTraits: ['Raw sockets with fragment-control fields', 'Custom fragment sizing'],
    historicalEvolution: 'Long-standing technique; repeatedly reappears in botnet modules.',
    relatedCves: [],
    relatedMisconfigurations: ['Unbounded reassembly buffers'],
    keywords: ['fragment', 'reassembly', 'ip', 'mtu', 'overlap'],
  },
  {
    id: 'gre_flood',
    name: 'GRE Flood',
    layer: 'network',
    protocol: 'GRE (IP protocol 47)',
    aliases: ['gre flood', 'gre ip flood'],
    mechanism:
      'A high volume of GRE-encapsulated packets is sent so the receiver must decapsulate and process tunnelled payloads, consuming CPU and requiring tunnel-state handling.',
    resourceExhausted: 'Decapsulation CPU and tunnel/state handling capacity.',
    preconditions: [
      'Receiver permits GRE or lacks a policy to drop unwanted GRE.',
      'Sufficient rate to force decapsulation processing.',
    ],
    observableSymptoms: [
      'GRE-encapsulated packets directed at a host that does not use GRE.',
      'Elevated CPU for decapsulation / unknown-protocol handling.',
    ],
    telemetry: ['GRE packet rate versus baseline.', 'Counts of GRE packets without an established tunnel.'],
    packetCharacteristics: [
      'IP protocol 47 packets, often with embedded inner IP headers.',
      'Uniform outer/inner size patterns.',
      'Wide source-address spread.',
    ],
    expectedImpact: 'CPU/decapsulation exhaustion; potential bandwidth amplification depending on encapsulation.',
    commonFalsePositives: ['Legitimate GRE tunnels and routing protocols.', 'VPN or overlay-network traffic.'],
    defensiveDetectionStrategy:
      'Baseline GRE traffic and alert on GRE toward hosts without established tunnels or on rate anomalies.',
    mitigationTechniques: [
      'Drop GRE at the edge except for authorised tunnel endpoints.',
      'Rate limiting on non-tunnel GRE.',
    ],
    references: ['RFC 2784 — Generic Routing Encapsulation (GRE)'],
    relatedMalwareFamilies: ['Mirai (GRE variants)', 'Muhstik'],
    targetedResource: 'Decapsulation CPU / tunnel state',
    protocolBehaviour: 'Tunnel encapsulation',
    defensiveVisibility: 'Medium',
    detectionDifficulty: 'medium',
    mitigationDifficulty: 'low',
    commonImplementationTraits: ['Raw sockets with GRE header construction', 'Fixed inner payloads'],
    historicalEvolution: 'Added to IoT botnets as a way to consume CPU while appearing as tunnel traffic.',
    relatedCves: [],
    relatedMisconfigurations: ['GRE permitted from any source'],
    keywords: ['gre', 'tunnel', 'encapsulation', 'protocol 47', 'decapsulation'],
  },
  {
    id: 'connection_exhaustion',
    name: 'Connection Exhaustion',
    layer: 'transport',
    protocol: 'TCP',
    aliases: ['connection exhaustion', 'socket exhaustion', 'file-descriptor exhaustion'],
    mechanism:
      'A large number of long-lived or slowly-progressing full TCP connections is opened so that the server consumes its connection, thread or file-descriptor budget.',
    resourceExhausted: 'Server connection count, worker threads/processes, file descriptors and application memory.',
    preconditions: [
      'Service allows many concurrent connections from few or many sources.',
      'No connection limit or idle timeout is enforced.',
    ],
    observableSymptoms: [
      'Connection count and file-descriptor usage near configured limits.',
      'New legitimate connections refused.',
      'Worker/thread pool saturation.',
    ],
    telemetry: [
      'Per-service concurrent connection count versus baseline.',
      'File-descriptor utilisation and accept-queue depth.',
    ],
    packetCharacteristics: [
      'Many established connections that transmit little or no payload.',
      'Slow or absent application-level progress.',
      'Connections from a limited or broad source set held open for long periods.',
    ],
    expectedImpact: 'Service unavailability once limits are reached; resource starvation for legitimate users.',
    commonFalsePositives: [
      'Legitimate clients with long-lived or idle connections (websockets, pooling).',
      'Load-generator or monitoring sessions.',
    ],
    defensiveDetectionStrategy:
      'Monitor concurrent-connection and file-descriptor utilisation against capacity; alert on growth with low application progress.',
    mitigationTechniques: [
      'Per-source connection limits and idle timeouts.',
      'Reverse-proxy connection pooling.',
      'Resource quotas per tenant.',
    ],
    references: ['Cloudflare Learning Center — connection-exhaustion attacks'],
    relatedMalwareFamilies: ['BASHLITE (Gafgyt)'],
    targetedResource: 'Connection / descriptor budget',
    protocolBehaviour: 'Many concurrent established connections',
    defensiveVisibility: 'High',
    detectionDifficulty: 'low',
    mitigationDifficulty: 'low',
    commonImplementationTraits: ['Many parallel connection attempts', 'Minimal application progress'],
    historicalEvolution: 'Evolved from low-and-slow strategies to bypass volumetric detection.',
    relatedCves: [],
    relatedMisconfigurations: ['Unlimited concurrency', 'Long or absent idle timeouts'],
    keywords: ['connection', 'exhaustion', 'socket', 'file descriptor', 'concurrent'],
  },
  {
    id: 'protocol_state_exhaustion',
    name: 'Protocol State Exhaustion',
    layer: 'transport',
    protocol: 'TCP / stateful protocols',
    aliases: ['state exhaustion', 'conntrack exhaustion', 'state table exhaustion'],
    mechanism:
      'Traffic is crafted to fill finite protocol state tables (for example conntrack entries, session tables or TLS handshake state) so stateful devices cannot track new legitimate flows.',
    resourceExhausted: 'Stateful-device state tables (conntrack, firewall session tables, proxy state).',
    preconditions: [
      'A stateful intermediary (firewall, load balancer, NAT) sits in path.',
      'State entries persist long enough to be accumulated.',
    ],
    observableSymptoms: [
      'Conntrack / session-table high-water-mark alarms.',
      'New flows dropped while device reports table exhaustion.',
      'Inconsistent treatment of legitimate flows.',
    ],
    telemetry: [
      'State-table utilisation and insertion-failure counters.',
      'Flow-creation rate versus expiry rate.',
    ],
    packetCharacteristics: [
      'Many short-lived or ambiguous flows to exhaust the table.',
      'Traffic patterns that maximize state entries per byte.',
    ],
    expectedImpact: 'Stateful devices become a bottleneck; collateral loss for legitimate traffic.',
    commonFalsePositives: ['Legitimate connection churn during peak load.', 'Short-lived high-cardinality flows.'],
    defensiveDetectionStrategy:
      'Trend state-table utilisation and insertion failures; alert before hard exhaustion with capacity headroom policy.',
    mitigationTechniques: [
      'Tune timeouts and table sizes.',
      'Per-source state limits.',
      'Distribute state across nodes / use stateless fast paths where possible.',
    ],
    references: ['NIST SP 800-189', 'Vendor guidance on conntrack tuning'],
    relatedMalwareFamilies: ['BASHLITE (Gafgyt)', 'Mirai variants'],
    targetedResource: 'Stateful-device state tables',
    protocolBehaviour: 'Maximising state entries per unit traffic',
    defensiveVisibility: 'Medium — device-internal metric',
    detectionDifficulty: 'medium',
    mitigationDifficulty: 'medium',
    commonImplementationTraits: ['High flow-creation rate', 'Ambiguous or incomplete flows'],
    historicalEvolution: 'Grew as defenders deployed more stateful inspection.',
    relatedCves: [],
    relatedMisconfigurations: ['Undersized state tables', 'Long state timeouts'],
    keywords: ['state', 'conntrack', 'session table', 'stateful', 'exhaustion'],
  },
  {
    id: 'http_request_flood',
    name: 'HTTP Request Flood',
    layer: 'application',
    protocol: 'HTTP',
    aliases: ['http flood', 'http request flood', 'layer 7 flood'],
    mechanism:
      'A high volume of syntactically valid HTTP requests is sent, often targeting resource-intensive endpoints, so the application must process more requests than it can serve.',
    resourceExhausted: 'Application workers, database and CPU for request processing.',
    preconditions: [
      'Target exposes an HTTP application with processable endpoints.',
      'Attacker can issue requests that resemble legitimate traffic.',
    ],
    observableSymptoms: [
      'Request-rate spike relative to baseline.',
      'Worker/CPU saturation and rising response latency.',
      'Skew toward costly endpoints.',
    ],
    telemetry: [
      'HTTP request rate, method and status-code distribution.',
      'Requests per connection and User-Agent diversity.',
      'Endpoint/path cardinality and cache-hit ratio.',
    ],
    packetCharacteristics: [
      'Many short TCP connections each carrying few requests, or high requests-per-connection.',
      'Repetitive request lines and headers.',
      'Low User-Agent diversity or implausible header combinations.',
    ],
    expectedImpact: 'Application service degradation or unavailability; backend/database overload.',
    commonFalsePositives: [
      'Legitimate traffic spikes, crawlers and API clients.',
      'Retry storms from upstream failures.',
      'Monitoring and synthetic checks.',
    ],
    defensiveDetectionStrategy:
      'Baseline request rate per endpoint and per client; combine rate deviation with behavioural signals (UA diversity, header plausibility, session behaviour) rather than request counts alone.',
    mitigationTechniques: [
      'WAF with behavioural and bot detection.',
      'Request quotas and API rate limits.',
      'Caching, challenge mechanisms and CDN protection.',
    ],
    references: [
      'OWASP Automated Threats to Web Applications (OAT-011)',
      'Cloudflare Learning Center — HTTP flood',
    ],
    relatedMalwareFamilies: ['Mirai (HTTP module)', 'Qbot', 'IoT botnets with HTTP modules'],
    targetedResource: 'Application request-processing capacity',
    protocolBehaviour: 'Valid application-layer requests',
    defensiveVisibility: 'Medium — requires application telemetry to separate from legitimate load',
    detectionDifficulty: 'high',
    mitigationDifficulty: 'medium',
    commonImplementationTraits: ['Repeated request templates', 'Limited header diversity'],
    historicalEvolution: 'Grew as network-layer floods became easier to mitigate.',
    relatedCves: [],
    relatedMisconfigurations: ['Unprotected expensive endpoints', 'Absent rate limiting'],
    keywords: ['http', 'request', 'layer 7', 'application', 'waf', 'flood'],
  },
  {
    id: 'https_resource_exhaustion',
    name: 'HTTPS Resource Exhaustion',
    layer: 'application',
    protocol: 'HTTPS / TLS',
    aliases: ['tls exhaustion', 'ssl renegotiation flood', 'tls handshake flood'],
    mechanism:
      'Traffic is crafted to force expensive cryptographic operations (handshakes or renegotiation) so the server spends disproportionate CPU on TLS processing relative to the bytes received.',
    resourceExhausted: 'CPU for asymmetric cryptography and TLS handshake state.',
    preconditions: [
      'Target terminates TLS.',
      'Expensive TLS operations are not offloaded or amortised.',
    ],
    observableSymptoms: [
      'Handshake-rate spike and CPU concentrated in TLS operations.',
      'Handshake failures and increased TLS latency.',
    ],
    telemetry: [
      'TLS handshake rate, handshake-failure rate and session resumption ratio.',
      'CPU time attributable to cryptographic operations.',
    ],
    packetCharacteristics: [
      'Numerous incomplete or repeated TLS handshakes.',
      'Small ClientHello-like datagrams in high volume.',
      'Low session-resumption utilisation.',
    ],
    expectedImpact: 'CPU exhaustion degrading TLS service; legitimate handshakes delayed or refused.',
    commonFalsePositives: [
      'Legitimate reconnection storms.',
      'Bulk clients that disable session resumption.',
    ],
    defensiveDetectionStrategy:
      'Baseline handshake rate and CPU-per-handshake; alert on handshake-rate deviation with low resumption and elevated crypto CPU.',
    mitigationTechniques: [
      'Session resumption / TLS tickets.',
      'TLS offload accelerators and handshake rate limits.',
      'Front the service with CDN/edge TLS termination.',
    ],
    references: ['Cloudflare Learning Center — SSL/TLS attacks', 'RFC 8446 — TLS 1.3'],
    relatedMalwareFamilies: ['Qbot', 'IoT botnets with TLS modules'],
    targetedResource: 'Cryptographic CPU / handshake state',
    protocolBehaviour: 'Repeated expensive TLS handshakes',
    defensiveVisibility: 'Medium',
    detectionDifficulty: 'medium',
    mitigationDifficulty: 'medium',
    commonImplementationTraits: ['Handshake loops', 'No resumption support in generated clients'],
    historicalEvolution: 'Expanded with universal TLS adoption.',
    relatedCves: [],
    relatedMisconfigurations: ['Session resumption disabled', 'No TLS offload'],
    keywords: ['tls', 'ssl', 'https', 'handshake', 'renegotiation', 'crypto'],
  },
  {
    id: 'slow_request_attack',
    name: 'Slow Request Attack',
    layer: 'application',
    protocol: 'HTTP',
    aliases: ['slowloris', 'slow http', 'r-u-dead-yet', 'slow read'],
    mechanism:
      'Many connections are opened and requests or responses are made to progress extremely slowly, so server worker slots/threads are held open without completing transactions.',
    resourceExhausted: 'Server concurrency slots / worker threads bound to incomplete transactions.',
    preconditions: [
      'Server keeps a worker per connection with generous timeouts.',
      'Low concurrency limits are not enforced.',
    ],
    observableSymptoms: [
      'High idle connection count with incomplete requests.',
      'Worker-slot saturation at low actual throughput.',
    ],
    telemetry: [
      'Connection concurrency with request-completion ratio.',
      'Request/response completion latency tails.',
    ],
    packetCharacteristics: [
      'Low-rate traffic consisting of partial requests or headers.',
      'Very slow client progress across many connections.',
    ],
    expectedImpact: 'Server concurrency exhaustion; denial of service with minimal bandwidth.',
    commonFalsePositives: [
      'Slow legitimate mobile/embedded clients.',
      'Long-poll or streaming clients.',
    ],
    defensiveDetectionStrategy:
      'Track per-connection transaction progress and idle time; alert on high concurrency with low completion throughput.',
    mitigationTechniques: [
      'Aggressive header/body and idle timeouts.',
      'Per-source connection caps.',
      'Reverse proxies that buffer/normalise requests.',
    ],
    references: ['OWASP Slow HTTP DoS', 'Cloudflare Learning Center — slowloris'],
    relatedMalwareFamilies: ['BASHLITE (Gafgyt) conceptual variants', 'IoT botnets'],
    targetedResource: 'Server concurrency slots',
    protocolBehaviour: 'Deliberately slow application transactions',
    defensiveVisibility: 'Medium',
    detectionDifficulty: 'medium',
    mitigationDifficulty: 'low',
    commonImplementationTraits: ['Partial request emission', 'Many parallel slow connections'],
    historicalEvolution: 'Classic low-bandwidth DoS technique reused by botnets.',
    relatedCves: [],
    relatedMisconfigurations: ['Undefined request timeouts', 'Unlimited concurrency'],
    keywords: ['slow', 'slowloris', 'timeout', 'concurrency', 'partial request'],
  },
  {
    id: 'web_app_resource_exhaustion',
    name: 'Web Application Resource Exhaustion',
    layer: 'application',
    protocol: 'HTTP / application logic',
    aliases: ['application exhaustion', 'algorithmic complexity', 'expensive endpoint abuse'],
    mechanism:
      'Requests are chosen to trigger the most expensive application code paths (deep queries, large result sets, heavy computation) so the application exhausts CPU, database or memory.',
    resourceExhausted: 'Application CPU, database capacity and memory for expensive operations.',
    preconditions: [
      'Application exposes endpoints whose cost is far higher than their request size.',
      'No quota or cost model protects those endpoints.',
    ],
    observableSymptoms: [
      'Backend/database load rising faster than request rate.',
      'Long-tail latency on specific endpoints.',
    ],
    telemetry: [
      'Per-endpoint request rate and backend query cost.',
      'Database connection-pool and query-latency metrics.',
    ],
    packetCharacteristics: [
      'Requests concentrated on known computationally expensive endpoints.',
      'Small request payloads producing large backend work.',
    ],
    expectedImpact: 'Backend/database exhaustion; application unavailability.',
    commonFalsePositives: ['Legitimate reports/exports and batch jobs.', 'Crawler access to costly pages.'],
    defensiveDetectionStrategy:
      'Instrument per-endpoint cost and alert on cost-weighted rate deviation from baseline.',
    mitigationTechniques: [
      'Cost-aware quotas and caching for expensive endpoints.',
      'Pagination and result-size limits.',
      'Database read replicas and query optimisation.',
    ],
    references: ['OWASP Automated Threats (OAT-008/011)'],
    relatedMalwareFamilies: ['IoT botnets with HTTP modules'],
    targetedResource: 'Application/backend CPU, DB capacity',
    protocolBehaviour: 'Valid requests targeting high-cost code paths',
    defensiveVisibility: 'Medium',
    detectionDifficulty: 'high',
    mitigationDifficulty: 'medium',
    commonImplementationTraits: ['Targeting specific costly endpoints'],
    historicalEvolution: 'Evolved alongside the move to API-driven applications.',
    relatedCves: [],
    relatedMisconfigurations: ['Unauthenticated expensive endpoints', 'Missing quotas'],
    keywords: ['application', 'expensive', 'database', 'endpoint', 'resource'],
  },
  {
    id: 'dns_query_flood',
    name: 'DNS Query Flood',
    layer: 'application',
    protocol: 'DNS',
    aliases: ['dns flood', 'dns query flood', 'random subdomain attack'],
    mechanism:
      'A high volume of DNS queries (often for random or non-existent subdomains) is sent so recursive resolvers or authoritative servers must perform lookups they cannot cache.',
    resourceExhausted: 'Resolver/authoritative query-processing capacity and cache efficiency.',
    preconditions: [
      'Target operates a DNS resolver or authoritative server.',
      'Queries bypass cache (random names) or target expensive lookups.',
    ],
    observableSymptoms: [
      'Resolver query rate and cache-miss ratio spike.',
      'Recursive/upstream resolution load rising.',
    ],
    telemetry: [
      'Query rate, cache-hit ratio and NXDOMAIN ratio.',
      'Unique-name-to-cache-entry ratio.',
    ],
    packetCharacteristics: [
      'High rate of DNS queries, frequently for random subdomains.',
      'Low cache-reuse and high NXDOMAIN responses.',
    ],
    expectedImpact: 'Resolver/authoritative exhaustion; degraded resolution for legitimate clients.',
    commonFalsePositives: ['Legitimate traffic with high unique-name diversity.', 'Crawlers and IoT churn.'],
    defensiveDetectionStrategy:
      'Baseline query rate and cache-hit ratio; alert on cache-miss/NXDOMAIN spikes and unique-name cardinality.',
    mitigationTechniques: [
      'Response-rate limiting (RRL) for authoritative servers.',
      'Resolver query rate limiting and cache tuning.',
      'Anycast and increased resolution capacity.',
    ],
    references: ['RFC 8484/7873 context', 'NS1/Cloudflare guidance on DNS water torture'],
    relatedMalwareFamilies: ['Mirai (DNS water torture)', 'IoT botnets'],
    targetedResource: 'DNS query-processing capacity',
    protocolBehaviour: 'Cache-bypassing high-variance queries',
    defensiveVisibility: 'High',
    detectionDifficulty: 'medium',
    mitigationDifficulty: 'medium',
    commonImplementationTraits: ['Random subdomain generation', 'Direct resolver queries'],
    historicalEvolution: 'Became prominent as a low-bandwidth way to stress resolvers.',
    relatedCves: [],
    relatedMisconfigurations: ['Resolver open to the world', 'No response-rate limiting'],
    keywords: ['dns', 'query', 'resolver', 'random subdomain', 'water torture', 'nxdomain'],
  },
  {
    id: 'dns_reflection_amplification',
    name: 'DNS Reflection / Amplification',
    layer: 'reflection_amplification',
    protocol: 'DNS/UDP',
    aliases: ['dns amplification', 'dns reflection', 'dns any amplification'],
    mechanism:
      'Queries with a spoofed source address are sent to open resolvers so that the larger responses are directed at a victim (a reflection and amplification effect driven by response/request size asymmetry).',
    resourceExhausted: 'Victim link bandwidth (and upstream transit) via reflected response volume.',
    preconditions: [
      'Open DNS resolvers reachable by the attacker.',
      'Ability to send queries with a source address of the victim (spoofing) — a prerequisite defenders must neutralize.',
    ],
    observableSymptoms: [
      'Unsolicited DNS responses arriving at the victim.',
      'Very large responses relative to any client query pattern.',
    ],
    telemetry: [
      'Inbound DNS response rate and byte rate at the victim.',
      'Response-size distribution and ANY/TXT query share.',
      'Source-address cardinality of responses.',
    ],
    packetCharacteristics: [
      'Unsolicited inbound DNS responses larger than typical queries.',
      'Many distinct responder addresses sending to one victim.',
      'Predominance of large-record queries/responses.',
    ],
    expectedImpact: 'Bandwidth saturation at the victim; collateral impact upstream.',
    commonFalsePositives: ['Legitimate large DNS responses and DNSSEC.', 'Caching resolvers answering a real client.'],
    defensiveDetectionStrategy:
      'Detect unsolicited inbound DNS responses and abnormal response-size distributions; correlate with many-source-to-one-destination patterns. Deploy BCP38 ingress/egress filtering to reduce spoofing feasibility.',
    mitigationTechniques: [
      'Close open resolvers; response-rate limiting.',
      'Ingress/egress anti-spoofing (BCP38/BCP84).',
      'DNS scrubbing and anycast.',
    ],
    references: [
      'US-CERT TA13-088A — DNS Amplification Attacks',
      'CISA/US-CERT TA14-017A — UDP-Based Amplification Attacks',
      'BCP38 / BCP84 anti-spoofing',
    ],
    relatedMalwareFamilies: ['Mirai', 'Satori', 'Aisuru'],
    targetedResource: 'Victim bandwidth',
    protocolBehaviour: 'Spoofed-source query with larger response',
    defensiveVisibility: 'High for responses at the victim; spoofing is a prerequisite to detect at the source network',
    detectionDifficulty: 'medium',
    mitigationDifficulty: 'medium',
    commonImplementationTraits: ['Open resolvers as reflectors', 'Source spoofing prerequisite'],
    historicalEvolution: 'Long-standing amplification class; repeatedly rediscovered with new record types.',
    relatedCves: [],
    relatedMisconfigurations: ['Open recursive resolver', 'Missing anti-spoofing'],
    keywords: ['dns', 'amplification', 'reflection', 'open resolver', 'spoof', 'any'],
  },
  {
    id: 'ntp_reflection_amplification',
    name: 'NTP Reflection / Amplification',
    layer: 'reflection_amplification',
    protocol: 'NTP/UDP',
    aliases: ['ntp amplification', 'ntp monlist', 'ntp reflection'],
    mechanism:
      'Legacy monitoring-style NTP requests with a spoofed source are sent to NTP servers that reply with much larger responses directed at the victim.',
    resourceExhausted: 'Victim bandwidth via amplified NTP responses.',
    preconditions: [
      'Network-exposed NTP servers with legacy/verbose monitoring commands enabled.',
      'Spoofing of the victim source address.',
    ],
    observableSymptoms: ['Large inbound NTP responses at the victim from many servers.'],
    telemetry: ['Inbound NTP response rate/size.', 'Source-server cardinality.'],
    packetCharacteristics: [
      'Unsolicited large NTP responses.',
      'Many distinct server sources to one victim.',
    ],
    expectedImpact: 'Bandwidth saturation at the victim.',
    commonFalsePositives: ['Legitimate NTP synchronisation traffic (small, solicited).'],
    defensiveDetectionStrategy:
      'Alert on unsolicited inbound NTP responses and abnormal response sizes; require anti-spoofing and disable legacy monitoring commands on servers.',
    mitigationTechniques: [
      'Disable legacy NTP monitoring (monlist).',
      'Rate limiting and access control on NTP.',
      'Anti-spoofing (BCP38) and upstream scrubbing.',
    ],
    references: ['CISA/US-CERT TA14-013A — NTP Amplification Attacks'],
    relatedMalwareFamilies: ['Mirai variants', 'IoT botnets'],
    targetedResource: 'Victim bandwidth',
    protocolBehaviour: 'Verbose solicited response misdirected via spoofing',
    defensiveVisibility: 'High at victim',
    detectionDifficulty: 'low',
    mitigationDifficulty: 'medium',
    commonImplementationTraits: ['Legacy NTP monitoring as reflector'],
    historicalEvolution: 'Peaked around 2014; remains relevant where NTP is misconfigured.',
    relatedCves: ['CVE-2013-5211'],
    relatedMisconfigurations: ['NTP monlist enabled'],
    keywords: ['ntp', 'amplification', 'reflection', 'monlist', 'spoof'],
  },
  {
    id: 'ssdp_reflection_amplification',
    name: 'SSDP Reflection / Amplification',
    layer: 'reflection_amplification',
    protocol: 'SSDP/UDP',
    aliases: ['ssdp amplification', 'upnp ssdp reflection'],
    mechanism:
      'Discovery-chaining SSDP search requests with a spoofed source are sent to internet-exposed devices, which reply with larger responses toward the victim.',
    resourceExhausted: 'Victim bandwidth; also indicates exposed consumer/IoT devices.',
    preconditions: [
      'Internet-exposed SSDP/UPnP services.',
      'Spoofing of the victim source address.',
    ],
    observableSymptoms: ['Inbound SSDP response bursts at the victim.'],
    telemetry: ['Inbound SSDP response rate.', 'Source-device cardinality.'],
    packetCharacteristics: [
      'Unsolicited inbound SSDP responses, typically larger than the request.',
      'Many distinct device sources.',
    ],
    expectedImpact: 'Bandwidth saturation; exposure of misconfigured consumer devices.',
    commonFalsePositives: ['Legitimate local SSDP discovery (should not cross the internet edge).'],
    defensiveDetectionStrategy:
      'Block SSDP/UPnP at the internet edge and alert on inbound SSDP responses; require anti-spoofing upstream.',
    mitigationTechniques: [
      'Block SSDP/UPnP at network borders.',
      'Anti-spoofing and egress filtering on device networks.',
      'Upstream scrubbing.',
    ],
    references: ['CISA/US-CERT TA14-017A — UDP-Based Amplification Attacks'],
    relatedMalwareFamilies: ['Mirai', 'IoT botnets'],
    targetedResource: 'Victim bandwidth',
    protocolBehaviour: 'Discovery request with amplified response',
    defensiveVisibility: 'High at victim',
    detectionDifficulty: 'low',
    mitigationDifficulty: 'medium',
    commonImplementationTraits: ['Internet-exposed UPnP devices as reflectors'],
    historicalEvolution: 'Rises with the number of exposed consumer/IoT devices.',
    relatedCves: [],
    relatedMisconfigurations: ['UPnP/SSDP exposed to the internet'],
    keywords: ['ssdp', 'upnp', 'amplification', 'reflection', 'discovery'],
  },
  {
    id: 'cldap_reflection_amplification',
    name: 'CLDAP Reflection / Amplification',
    layer: 'reflection_amplification',
    protocol: 'CLDAP/UDP',
    aliases: ['cldap amplification', 'connectionless ldap reflection'],
    mechanism:
      'Connectionless LDAP search requests with a spoofed source are sent to reflective directory servers, which reply with larger responses toward the victim.',
    resourceExhausted: 'Victim bandwidth.',
    preconditions: [
      'Internet-exposed CLDAP/LDAP services.',
      'Spoofing of the victim source address.',
    ],
    observableSymptoms: ['Inbound CLDAP responses at the victim.'],
    telemetry: ['Inbound CLDAP response rate/size.', 'Source-server cardinality.'],
    packetCharacteristics: ['Unsolicited inbound CLDAP responses, larger than the request.'],
    expectedImpact: 'Bandwidth saturation at the victim.',
    commonFalsePositives: ['Legitimate directory traffic (rarely crosses the public edge unsolicited).'],
    defensiveDetectionStrategy:
      'Restrict CLDAP/LDAP to trusted networks and alert on inbound CLDAP responses; require anti-spoofing.',
    mitigationTechniques: [
      'Firewall directory services from the internet.',
      'Anti-spoofing and upstream scrubbing.',
    ],
    references: ['US-CERT TA14-017A — UDP-Based Amplification Attacks'],
    relatedMalwareFamilies: ['IoT botnets'],
    targetedResource: 'Victim bandwidth',
    protocolBehaviour: 'Connectionless directory search with amplified response',
    defensiveVisibility: 'High at victim',
    detectionDifficulty: 'low',
    mitigationDifficulty: 'medium',
    commonImplementationTraits: ['Exposed directory servers as reflectors'],
    historicalEvolution: 'Surfaced as attackers reused exposed enterprise services.',
    relatedCves: [],
    relatedMisconfigurations: ['CLDAP exposed to the internet'],
    keywords: ['cldap', 'ldap', 'amplification', 'reflection', 'directory'],
  },
  {
    id: 'memcached_reflection_amplification',
    name: 'Memcached Reflection / Amplification',
    layer: 'reflection_amplification',
    protocol: 'Memcached/UDP',
    aliases: ['memcached amplification', 'memcached reflection'],
    mechanism:
      'Stat requests with a spoofed source are sent to internet-exposed Memcached servers, which reply with cached values of much larger size toward the victim.',
    resourceExhausted: 'Victim bandwidth; a record amplification factor.',
    preconditions: [
      'Internet-exposed Memcached UDP service (misconfiguration).',
      'Spoofing of the victim source address.',
    ],
    observableSymptoms: ['Extremely large inbound UDP responses at the victim from many sources.'],
    telemetry: ['Inbound UDP response rate/size at the victim.', 'Source-address cardinality.'],
    packetCharacteristics: [
      'Unsolicited large UDP responses at the victim.',
      'Very high response-to-request size asymmetry.',
    ],
    expectedImpact: 'Severe bandwidth saturation; one of the highest observed amplification classes.',
    commonFalsePositives: ['None expected for unsolicited internet Memcached responses.'],
    defensiveDetectionStrategy:
      'Alert on inbound UDP to unexpected high ports with large unsolicited responses; ensure Memcached is never exposed (bind to localhost, disable UDP).',
    mitigationTechniques: [
      'Never expose Memcached to the internet; disable UDP.',
      'Anti-spoofing (BCP38) and upstream scrubbing.',
      'Host-level firewall allow-listing.',
    ],
    references: [
      'US-CERT TA18-106A — Memcached Reflection/Amplification',
      'CISA alert on Memcached abuse (2018)',
    ],
    relatedMalwareFamilies: ['IRS botnet', 'Satori', 'Mirai variants'],
    targetedResource: 'Victim bandwidth',
    protocolBehaviour: 'Single small request with very large cached response',
    defensiveVisibility: 'High at victim',
    detectionDifficulty: 'low',
    mitigationDifficulty: 'low',
    commonImplementationTraits: ['Exposed Memcached UDP as reflector'],
    historicalEvolution: 'Produced record-breaking attack volumes in 2018.',
    relatedCves: [],
    relatedMisconfigurations: ['Memcached bound to 0.0.0.0 with UDP enabled'],
    keywords: ['memcached', 'amplification', 'reflection', 'udp', 'cache'],
  },
  {
    id: 'iot_plain_udp_flood',
    name: 'IoT Plain UDP Flood (botnet module)',
    layer: 'iot_specific',
    protocol: 'UDP',
    aliases: ['plain udp', 'mirai udp', 'udp plain module'],
    mechanism:
      'An IoT attack module emits plain UDP datagrams toward a target using a raw socket; it is a simple bandwidth-oriented primitive that reuses randomised payload sizes.',
    resourceExhausted: 'Target bandwidth and packet-processing.',
    preconditions: [
      'Bot has network access and a raw or datagram socket.',
      'Target reachable over UDP.',
    ],
    observableSymptoms: ['High UDP rate from many geographically dispersed sources.'],
    telemetry: ['UDP packet rate and payload-size distribution.', 'Source cardinality.'],
    packetCharacteristics: [
      'Uniform-ish random payload sizes from bots.',
      'Many dispersed sources.',
      'Minimal application semantics.',
    ],
    expectedImpact: 'Bandwidth saturation at the victim.',
    commonFalsePositives: ['Legitimate high-volume UDP.'],
    defensiveDetectionStrategy:
      'Detect distributed UDP rate anomalies with high source-IP cardinality and low payload diversity per source.',
    mitigationTechniques: ['UDP rate limiting', 'Upstream scrubbing', 'Anycast dispersion'],
    references: ['Public Mirai source-code analyses (defensive research)'],
    relatedMalwareFamilies: ['Mirai', 'Muhstik', 'BASHLITE (Gafgyt)'],
    targetedResource: 'Victim bandwidth',
    protocolBehaviour: 'Connectionless datagram emission from many bots',
    defensiveVisibility: 'High',
    detectionDifficulty: 'low',
    mitigationDifficulty: 'medium',
    commonImplementationTraits: [
      'Single-purpose C module compiled per CPU architecture.',
      'Randomised payload generation helpers.',
      'Central attack-loop driven by a bot command.',
    ],
    historicalEvolution: 'A core primitive of the original Mirai and its many descendants.',
    relatedCves: [],
    relatedMisconfigurations: ['Open UDP exposure'],
    keywords: ['mirai', 'udp', 'iot', 'botnet module', 'plain', 'raw socket'],
  },
  {
    id: 'iot_gre_ip_gre_flood',
    name: 'IoT GRE-Encapsulated Flood (botnet module)',
    layer: 'iot_specific',
    protocol: 'GRE/IP',
    aliases: ['gre ip', 'gre eth', 'mirai gre', 'greip'],
    mechanism:
      'An IoT attack module builds GRE-encapsulated packets (optionally Ethernet-encapsulated) to consume receiver CPU during decapsulation, expanding the original UDP-only capability set.',
    resourceExhausted: 'Receiver CPU for decapsulation; bandwidth.',
    preconditions: [
      'Bot can emit GRE (raw socket / protocol 47).',
      'Target lacks policy dropping unwanted GRE.',
    ],
    observableSymptoms: ['GRE packets from many dispersed sources toward one target.'],
    telemetry: ['GRE packet rate.', 'Source cardinality.'],
    packetCharacteristics: [
      'IP protocol 47 (GRE) packets, optionally with embedded Ethernet frames.',
      'Fixed inner payload patterns across bots.',
    ],
    expectedImpact: 'CPU exhaustion and bandwidth consumption; harder to filter generically.',
    commonFalsePositives: ['Legitimate tunnel traffic.'],
    defensiveDetectionStrategy:
      'Alert on GRE toward hosts without authorised tunnels and on GRE rate/cardinality anomalies.',
    mitigationTechniques: ['Drop unexpected GRE at the edge.', 'Rate limiting.', 'Upstream scrubbing.'],
    references: ['Public Mirai variant analyses (defensive research)'],
    relatedMalwareFamilies: ['Mirai (GRE variants)', 'Muhstik'],
    targetedResource: 'Receiver CPU / bandwidth',
    protocolBehaviour: 'Tunnel encapsulation flood',
    defensiveVisibility: 'Medium',
    detectionDifficulty: 'medium',
    mitigationDifficulty: 'low',
    commonImplementationTraits: ['Hand-rolled GRE header construction', 'Per-architecture module'],
    historicalEvolution: 'Added by variants to bypass pure UDP filtering.',
    relatedCves: [],
    relatedMisconfigurations: ['Perimeter permits GRE from any source'],
    keywords: ['mirai', 'gre', 'iot', 'encapsulation', 'botnet module'],
  },
  {
    id: 'iot_tcp_raw_flood',
    name: 'IoT Raw TCP Flood (botnet module)',
    layer: 'iot_specific',
    protocol: 'TCP',
    aliases: ['mirai tcp', 'raw tcp module', 'syn/ack/rst mix'],
    mechanism:
      'An IoT attack module crafts TCP segments directly (with flag combinations such as SYN, ACK or RST) using raw sockets, often varying flags and source tuples to maximise disruptive effect.',
    resourceExhausted: 'Target connection state / processing budget.',
    preconditions: [
      'Bot runs privileged enough to use raw sockets with header control.',
      'Target accepts the relevant TCP traffic.',
    ],
    observableSymptoms: ['Raw TCP floods with mixed flags from many dispersed sources.'],
    telemetry: ['TCP flag distribution and per-destination segment rate.', 'Source cardinality.'],
    packetCharacteristics: [
      'Segments built with explicit flag choices and often spoofed tuples.',
      'Mixed or unusual flag combinations across the campaign.',
    ],
    expectedImpact: 'Connection-state exhaustion; service disruption.',
    commonFalsePositives: ['Legitimate TCP behaviour under stress.'],
    defensiveDetectionStrategy:
      'Baseline the TCP flag mix and connection-state utilisation per destination; alert on unusual flag combinations and cardinality spikes.',
    mitigationTechniques: ['SYN cookies', 'Stateful filtering', 'Rate limiting', 'Upstream scrubbing'],
    references: ['Public Mirai source-code analyses (defensive research)'],
    relatedMalwareFamilies: ['Mirai', 'Satori'],
    targetedResource: 'TCP connection state',
    protocolBehaviour: 'Hand-crafted TCP segments with mixed flags',
    defensiveVisibility: 'High',
    detectionDifficulty: 'medium',
    mitigationDifficulty: 'low',
    commonImplementationTraits: [
      'Raw-socket header construction with checksum computation.',
      'Randomised source tuple helpers.',
      'Multiple flag-specific code paths in one module family.',
    ],
    historicalEvolution: 'The original Mirai shipped several TCP flag variants; later families extended them.',
    relatedCves: [],
    relatedMisconfigurations: ['Missing SYN cookies / state limits'],
    keywords: ['mirai', 'tcp', 'raw socket', 'syn', 'ack', 'iot', 'flag'],
  },
  {
    id: 'iot_http_flood',
    name: 'IoT HTTP Flood (botnet module)',
    layer: 'iot_specific',
    protocol: 'HTTP',
    aliases: ['mirai http', 'http module', 'http flood module'],
    mechanism:
      'An IoT attack module opens connections and issues repeated HTTP requests (often to costly endpoints) so the application is exhausted while traffic resembles legitimate requests.',
    resourceExhausted: 'Application request-processing capacity.',
    preconditions: [
      'Target exposes an HTTP application.',
      'Bots can complete TCP/TLS handshakes to reach it.',
    ],
    observableSymptoms: ['HTTP request rate spike sourced from many dispersed client addresses.'],
    telemetry: [
      'HTTP method distribution and requests-per-connection.',
      'User-Agent diversity and path cardinality.',
    ],
    packetCharacteristics: [
      'Repeated request templates with limited header variety.',
      'Low User-Agent diversity and repetitive paths.',
      'Many short-lived connections or high requests-per-connection.',
    ],
    expectedImpact: 'Application degradation or unavailability.',
    commonFalsePositives: ['Legitimate spikes and crawlers.'],
    defensiveDetectionStrategy:
      'Combine request-rate deviation with behavioural signals (UA diversity, header plausibility, path cardinality) rather than raw counts.',
    mitigationTechniques: ['WAF/bot detection', 'Request quotas', 'CDN and caching', 'Challenge mechanisms'],
    references: ['OWASP Automated Threats (OAT-011)', 'Public Mirai variant analyses (defensive research)'],
    relatedMalwareFamilies: ['Mirai', 'Qbot', 'IoT botnets'],
    targetedResource: 'Application request capacity',
    protocolBehaviour: 'Valid application requests from many bots',
    defensiveVisibility: 'Medium',
    detectionDifficulty: 'high',
    mitigationDifficulty: 'medium',
    commonImplementationTraits: ['Hard-coded request templates', 'Minimal header variety'],
    historicalEvolution: 'Added to botnets as network-layer mitigation improved.',
    relatedCves: [],
    relatedMisconfigurations: ['Unprotected costly endpoints'],
    keywords: ['mirai', 'http', 'iot', 'request', 'botnet module', 'user-agent'],
  },
];

/** Index the catalogue by id for O(1) lookup. */
export const ATTACK_METHOD_BY_ID: Map<string, AttackMethodCatalogueItem> = new Map(
  ATTACK_METHOD_CATALOGUE.map((item) => [item.id, item]),
);

export function getAttackMethod(id: string): AttackMethodCatalogueItem | undefined {
  return ATTACK_METHOD_BY_ID.get(id);
}

/** Build the effective keyword set for an entry (explicit keywords + derived tokens). */
export function methodKeywords(item: AttackMethodCatalogueItem): Set<string> {
  const set = new Set<string>();
  const add = (text: string): void => {
    for (const token of text.toLowerCase().split(/[^a-z0-9]+/)) {
      if (token.length >= 3) set.add(token);
    }
  };
  add(item.name);
  add(item.protocol);
  add(item.layer.replace(/_/g, ' '));
  add(item.mechanism);
  add(item.resourceExhausted);
  item.aliases.forEach(add);
  item.keywords.forEach((k) => add(k));
  item.observableSymptoms.forEach(add);
  item.relatedMalwareFamilies.forEach(add);
  return set;
}

export interface AttackMethodSearchQuery {
  query?: string;
  layer?: AttackMethodLayer;
  protocol?: string;
  limit?: number;
}

/** Search the built-in catalogue by free text, layer and protocol. */
export function searchCatalogue(input: AttackMethodSearchQuery): AttackMethodCatalogueItem[] {
  const limit = Math.min(Math.max(input.limit ?? 20, 1), 100);
  const text = input.query?.toLowerCase().trim();
  const protocol = input.protocol?.toLowerCase().trim();

  const scored: Array<{ item: AttackMethodCatalogueItem; score: number }> = [];
  for (const item of ATTACK_METHOD_CATALOGUE) {
    if (input.layer && item.layer !== input.layer) continue;
    if (protocol && !item.protocol.toLowerCase().includes(protocol) && !item.name.toLowerCase().includes(protocol)) {
      continue;
    }
    let score = 1;
    if (text) {
      const haystack = [
        item.id,
        item.name,
        item.protocol,
        item.layer,
        item.mechanism,
        item.resourceExhausted,
        item.defensiveDetectionStrategy,
        ...item.aliases,
        ...item.keywords,
        ...item.relatedMalwareFamilies,
      ]
        .join(' ')
        .toLowerCase();
      if (!haystack.includes(text)) {
        const tokens = text.split(/\s+/).filter((t) => t.length >= 3);
        const matched = tokens.filter((t) => haystack.includes(t)).length;
        if (matched === 0) continue;
        score = 1 + matched / Math.max(tokens.length, 1);
      } else {
        score = 3;
      }
    }
    scored.push({ item, score });
  }
  scored.sort((a, b) => b.score - a.score || a.item.name.localeCompare(b.item.name));
  return scored.slice(0, limit).map((s) => s.item);
}

export interface ClassifiedCandidate {
  id: string;
  name: string;
  layer: AttackMethodLayer;
  protocol: string;
  score: number;
  rationale: string;
  confidence: 'inferred' | 'hypothesis' | 'unknown';
  matchedKeywords: string[];
  defensiveDetectionStrategy: string;
}

/** Classify a free-text description into ranked catalogue candidates. */
export function classifyDescription(description: string, limit = 5): ClassifiedCandidate[] {
  const tokens = new Set(
    description
      .toLowerCase()
      .split(/[^a-z0-9]+/)
      .filter((t) => t.length >= 3),
  );
  const results: ClassifiedCandidate[] = [];

  for (const item of ATTACK_METHOD_CATALOGUE) {
    const keywords = methodKeywords(item);
    const matched: string[] = [];
    for (const token of tokens) {
      if (keywords.has(token)) matched.push(token);
    }
    if (matched.length === 0) continue;
    const score = Math.min(1, matched.length / Math.max(3, Math.min(tokens.size, 12)));
    const confidence: ClassifiedCandidate['confidence'] =
      score >= 0.55 ? 'inferred' : score >= 0.25 ? 'hypothesis' : 'unknown';
    results.push({
      id: item.id,
      name: item.name,
      layer: item.layer,
      protocol: item.protocol,
      score: Number(score.toFixed(3)),
      rationale: `Matched ${matched.length} keyword(s): ${matched.slice(0, 8).join(', ')}.`,
      confidence,
      matchedKeywords: matched,
      defensiveDetectionStrategy: item.defensiveDetectionStrategy,
    });
  }

  results.sort((a, b) => b.score - a.score);
  return results.slice(0, Math.min(Math.max(limit, 1), 20));
}

/** Build a KnowledgeRecord for a catalogue entry. */
export function toKnowledgeRecord(item: AttackMethodCatalogueItem): KnowledgeRecord {
  const now = new Date().toISOString();
  return {
    id: `attack-method:${item.id}`,
    category: 'attack_method',
    title: item.name,
    identifiers: { mirai_method: item.id },
    affectedVersions: [],
    fixedVersions: [],
    klass: item.layer,
    rootCause: item.mechanism,
    attackSurface: item.protocol,
    preconditions: item.preconditions,
    publicExploitState: 'weaponized_in_wild',
    relatedMalwareFamilies: item.relatedMalwareFamilies,
    relatedMiraiVariants: [],
    relatedRecordIds: [],
    verification: 'statically_reviewed',
    confidence: 'confirmed',
    license: 'public-research',
    provenance: [
      curatedProvenance('public-research', `Curated attack-method family: ${item.name} (defensive catalog)`),
    ],
    evidence: [],
    tags: ['attack-method', item.layer, item.protocol.toLowerCase(), 'ddos', 'defensive-catalog'],
    createdAt: now,
    updatedAt: now,
  };
}

let seeded = false;

/**
 * Seed the curated catalogue into the knowledge base. Idempotent per process;
 * upsert is also idempotent on disk. Returns the number of records written.
 */
export function seedAttackMethodCatalogue(knowledge: KnowledgeBase): number {
  if (seeded) return 0;
  for (const item of ATTACK_METHOD_CATALOGUE) {
    knowledge.upsertRecord(toKnowledgeRecord(item));
  }
  seeded = true;
  return ATTACK_METHOD_CATALOGUE.length;
}
