/**
 * Anti-DDoS engine (§4 + §11 "Kỹ thuật Chống DDoS").
 *
 * DEFENSIVE ONLY (§10, §3.2, §4.4): every tool measures, detects, designs or
 * documents defensive controls. Traffic generation, if it appears at all, is
 * confined to a PLAN for strictly localhost/isolated, rate- and duration-bounded
 * testing gated by the configured lab authorization token. This engine never
 * implements a packet flood, a reflection launcher, source spoofing, a
 * distributed load generator or an unthrottled stress tool.
 */

import { mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, extname, join } from 'node:path';

import { z } from 'zod';

import { getConfig } from '../../config/index.js';
import { errors } from '../../core/errors.js';
import { runCommand, toolOnPathSync } from '../../shared/exec.js';
import {
  addEvidence,
  curatedProvenance,
  defineTool,
  finish,
  localProvenance,
  readBinaryArtifact,
  readTextArtifact,
  sha256,
} from '../../tools/helpers.js';
import { requireLabAuthorization, resolveWorkspacePath } from '../../shared/security.js';
import type { EngineModule } from '../../core/tool.js';
import type { ConfidenceLevel, EvidenceRef } from '../../shared/types.js';
import type { KnowledgeRecord } from '../../shared/knowledge-base.js';
import {
  DEFENSE_PRODUCTS,
  MITIGATION_STRATEGIES,
  PRODUCT_DISCLAIMER,
  searchDefenseTechnologies,
  searchDefenseProducts,
  seedDefenseCatalogue,
  type DefenseLayer,
} from './catalogue.js';
import {
  parsePcap,
  parseTsharkProtocolHierarchy,
  type DecodedPacket,
  type PcapSummary,
} from './pcap.js';

const ENGINE = 'anti-ddos';

const LAYER_ENUM = z.enum(['network', 'application', 'dns_infra', 'detection']);

/* -------------------------------------------------------------------------- */
/* Numeric helpers                                                            */
/* -------------------------------------------------------------------------- */

function mean(values: number[]): number {
  if (values.length === 0) return 0;
  return values.reduce((a, b) => a + b, 0) / values.length;
}

function stddev(values: number[]): number {
  if (values.length < 2) return 0;
  const m = mean(values);
  const variance = values.reduce((a, b) => a + (b - m) ** 2, 0) / (values.length - 1);
  return Math.sqrt(variance);
}

function coefficientOfVariation(values: number[]): number {
  const m = mean(values);
  if (m === 0) return Number.POSITIVE_INFINITY;
  return stddev(values) / m;
}

function round(value: number, digits = 4): number {
  return Number(value.toFixed(digits));
}

function countBy<T>(items: T[], key: (item: T) => string | undefined): Map<string, number> {
  const map = new Map<string, number>();
  for (const item of items) {
    const k = key(item);
    if (k === undefined) continue;
    map.set(k, (map.get(k) ?? 0) + 1);
  }
  return map;
}

function topEntries(map: Map<string, number>, n: number): Array<{ value: string; count: number }> {
  return [...map.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([value, count]) => ({ value, count }));
}

/* -------------------------------------------------------------------------- */
/* Detection verdicts                                                         */
/* -------------------------------------------------------------------------- */

type Verdict = 'no_signal' | 'weak_signal' | 'strong_signal' | 'insufficient_data';

interface DetectorVerdict {
  detector: string;
  applicable: boolean;
  verdict: Verdict;
  confidence: ConfidenceLevel;
  measured: Record<string, unknown>;
  thresholdsRationale: string;
  falsePositiveNotes: string[];
  mitigationAdvice: string[];
}

function durationOf(packets: DecodedPacket[]): number | null {
  if (packets.length < 2) return null;
  const ts = packets.map((p) => p.ts);
  const min = Math.min(...ts);
  const max = Math.max(...ts);
  const d = max - min;
  return d > 0 ? d : null;
}

/** SYN flood detector: validates handshake anomalies and half-open estimation. */
function detectSynFlood(packets: DecodedPacket[]): DetectorVerdict {
  const tcp = packets.filter((p) => p.protocol === 'TCP' && p.tcp);
  const synOnly = tcp.filter((p) => p.tcp?.syn && !p.tcp?.ack);
  const synAck = tcp.filter((p) => p.tcp?.syn && p.tcp?.ack);

  if (tcp.length === 0) {
    return {
      detector: 'syn_flood',
      applicable: false,
      verdict: 'insufficient_data',
      confidence: 'unknown',
      measured: { tcpPackets: 0 },
      thresholdsRationale: 'No TCP traffic present in the capture.',
      falsePositiveNotes: [],
      mitigationAdvice: [],
    };
  }

  const synRatio = synOnly.length / tcp.length;
  const synToSynAck = synAck.length > 0 ? synOnly.length / synAck.length : Number.POSITIVE_INFINITY;
  const halfOpenEstimate = Math.max(synOnly.length - synAck.length, 0);

  // Unique source IPs per destination IP for SYN-only traffic.
  const perDst = new Map<string, Set<string>>();
  for (const p of synOnly) {
    (perDst.get(p.dstIp) ?? perDst.set(p.dstIp, new Set()).get(p.dstIp)!).add(p.srcIp);
  }
  let maxUniqueSrc = 0;
  let maxDst = '';
  for (const [dst, set] of perDst) {
    if (set.size > maxUniqueSrc) {
      maxUniqueSrc = set.size;
      maxDst = dst;
    }
  }

  let verdict: Verdict = 'no_signal';
  if (synRatio > 0.35 && synOnly.length >= 50) verdict = 'strong_signal';
  else if (synRatio > 0.2 && synOnly.length >= 20) verdict = 'weak_signal';

  const confidence: ConfidenceLevel =
    verdict === 'strong_signal' ? 'inferred' : verdict === 'weak_signal' ? 'hypothesis' : 'observed';

  return {
    detector: 'syn_flood',
    applicable: true,
    verdict,
    confidence,
    measured: {
      tcpPackets: tcp.length,
      synOnly: synOnly.length,
      synAck: synAck.length,
      synOnlyRatio: round(synRatio),
      synToSynAckRatio: Number.isFinite(synToSynAck) ? round(synToSynAck) : 'infinity',
      estimatedHalfOpen: halfOpenEstimate,
      uniqueSourceIpsPerDst: { dst: maxDst, uniqueSources: maxUniqueSrc },
    },
    thresholdsRationale:
      'A SYN-only ratio above ~0.35 with many SYN-only frames and a SYN:ACK ratio far above the ~1:1 handshake ' +
      'norm is consistent with a SYN flood. Thresholds are heuristic and must be validated against the local baseline.',
    falsePositiveNotes: [
      'Asymmetric capture point that only sees SYNs (not SYN-ACKs).',
      'Port scanners or health checks with short connection lifetimes.',
      'Legitimate connection storms after an outage.',
    ],
    mitigationAdvice: ['Enable SYN cookies', 'Per-source connection limits', 'SYN proxy / upstream scrubbing'],
  };
}

/** UDP flood detector: rate, dominant port, payload uniformity, source cardinality. */
function detectUdpFlood(packets: DecodedPacket[]): DetectorVerdict {
  const udp = packets.filter((p) => p.protocol === 'UDP');
  if (udp.length === 0) {
    return {
      detector: 'udp_flood',
      applicable: false,
      verdict: 'insufficient_data',
      confidence: 'unknown',
      measured: { udpPackets: 0 },
      thresholdsRationale: 'No UDP traffic present in the capture.',
      falsePositiveNotes: [],
      mitigationAdvice: [],
    };
  }
  const duration = durationOf(udp);
  const pps = duration ? udp.length / duration : null;
  const dstPorts = countBy(udp, (p) => String(p.dstPort));
  const dominant = topEntries(dstPorts, 1)[0];
  const dominantShare = dominant ? dominant.count / udp.length : 0;
  const payloads = udp.map((p) => p.payloadLength);
  const cv = coefficientOfVariation(payloads);
  const uniformity = Number.isFinite(cv) ? Math.max(0, 1 - cv) : 1;
  const uniqueSrc = new Set(udp.map((p) => p.srcIp)).size;

  let verdict: Verdict = 'no_signal';
  if ((pps !== null && pps > 500) || (uniformity > 0.9 && udp.length >= 100 && uniqueSrc > 20)) {
    verdict = 'strong_signal';
  } else if ((pps !== null && pps > 100) || uniformity > 0.7) {
    verdict = 'weak_signal';
  }

  return {
    detector: 'udp_flood',
    applicable: true,
    verdict,
    confidence: verdict === 'strong_signal' ? 'inferred' : 'hypothesis',
    measured: {
      udpPackets: udp.length,
      udpPps: pps !== null ? round(pps, 2) : null,
      dominantDstPort: dominant?.value ?? null,
      dominantDstPortShare: round(dominantShare),
      payloadCoefficientOfVariation: Number.isFinite(cv) ? round(cv) : 'infinity',
      payloadUniformity: round(uniformity),
      uniqueSourceIps: uniqueSrc,
    },
    thresholdsRationale:
      'High UDP packet rate, a dominant destination port, high payload-size uniformity (low coefficient of variation) ' +
      'and elevated source cardinality together indicate a UDP flood. Exact rates depend on link/service capacity.',
    falsePositiveNotes: [
      'Legitimate high-volume UDP services (DNS, streaming, VoIP, telemetry).',
      'Application-level retransmission storms.',
    ],
    mitigationAdvice: ['UDP rate limiting', 'Allow-list expected ports', 'Upstream scrubbing / anycast'],
  };
}

/** HTTP flood detector: method mix, requests per connection, UA diversity, path cardinality. */
function detectHttpFlood(packets: DecodedPacket[]): DetectorVerdict {
  const http = packets.filter((p) => p.http);
  if (http.length === 0) {
    return {
      detector: 'http_flood',
      applicable: false,
      verdict: 'insufficient_data',
      confidence: 'unknown',
      measured: { httpRequests: 0 },
      thresholdsRationale: 'No HTTP requests identified (payload may be encrypted or capture starts mid-stream).',
      falsePositiveNotes: [],
      mitigationAdvice: [],
    };
  }
  const methods = countBy(http, (p) => p.http?.method);
  const connections = new Set(
    http.map((p) => `${p.srcIp}:${p.srcPort}->${p.dstIp}:${p.dstPort}`),
  );
  const requestsPerConnection = http.length / Math.max(connections.size, 1);
  const uas = new Set(http.map((p) => p.http?.userAgent ?? '(none)'));
  const missingUa = http.filter((p) => !p.http?.userAgent).length;
  const paths = new Set(http.map((p) => p.http?.path));

  let verdict: Verdict = 'no_signal';
  if ((uas.size <= 3 && http.length >= 50) || requestsPerConnection > 10) verdict = 'strong_signal';
  else if (uas.size <= 5 || requestsPerConnection > 5) verdict = 'weak_signal';

  return {
    detector: 'http_flood',
    applicable: true,
    verdict,
    confidence: verdict === 'strong_signal' ? 'inferred' : 'hypothesis',
    measured: {
      httpRequests: http.length,
      methodDistribution: Object.fromEntries(methods),
      connections: connections.size,
      requestsPerConnection: round(requestsPerConnection),
      distinctUserAgents: uas.size,
      requestsWithoutUserAgent: missingUa,
      distinctPaths: paths.size,
    },
    thresholdsRationale:
      'Low User-Agent diversity, a high requests-per-connection ratio and limited path variety suggest automated request ' +
      'generation. Raw request counts alone are unreliable; combine with application-side telemetry.',
    falsePositiveNotes: [
      'Legitimate API clients that send a single User-Agent.',
      'Keep-alive connections legitimately carrying many requests.',
      'Crawlers and monitoring probes.',
    ],
    mitigationAdvice: ['WAF/bot detection', 'Request quotas & API rate limits', 'CDN caching & challenges'],
  };
}

/** DNS amplification detector: response sizing, qtype share, byte ratio, spoofing hints. */
function detectDnsAmplification(packets: DecodedPacket[]): DetectorVerdict {
  const dns = packets.filter((p) => p.dns);
  if (dns.length === 0) {
    return {
      detector: 'dns_amplification',
      applicable: false,
      verdict: 'insufficient_data',
      confidence: 'unknown',
      measured: { dnsPackets: 0 },
      thresholdsRationale: 'No DNS traffic identified in the capture.',
      falsePositiveNotes: [],
      mitigationAdvice: [],
    };
  }
  const requests = dns.filter((p) => !p.dns?.isResponse);
  const responses = dns.filter((p) => p.dns?.isResponse);
  const requestBytes = requests.reduce((a, p) => a + p.payloadLength, 0);
  const responseBytes = responses.reduce((a, p) => a + p.payloadLength, 0);
  const byteRatio = requestBytes > 0 ? responseBytes / requestBytes : Number.POSITIVE_INFINITY;

  const qtypes = countBy(requests, (p) => (p.dns?.qtype !== undefined ? String(p.dns.qtype) : undefined));
  const anyTxt = requests.filter((p) => p.dns?.qtype === 255 || p.dns?.qtype === 16).length;
  const anyTxtShare = requests.length > 0 ? anyTxt / requests.length : 0;

  // Reflection hint: many distinct "server" sources sending responses to few dst IPs.
  const respDst = new Map<string, Set<string>>();
  for (const p of responses) {
    (respDst.get(p.dstIp) ?? respDst.set(p.dstIp, new Set()).get(p.dstIp)!).add(p.srcIp);
  }
  let maxServers = 0;
  let victim = '';
  for (const [dst, set] of respDst) {
    if (set.size > maxServers) {
      maxServers = set.size;
      victim = dst;
    }
  }
  const oddSrcPorts = responses.filter((p) => p.srcPort !== 53).length;

  let verdict: Verdict = 'no_signal';
  if ((Number.isFinite(byteRatio) && byteRatio > 3 && responses.length >= 30) || anyTxtShare > 0.2) {
    verdict = 'strong_signal';
  } else if ((Number.isFinite(byteRatio) && byteRatio > 1.5) || maxServers > 20) {
    verdict = 'weak_signal';
  }

  return {
    detector: 'dns_amplification',
    applicable: true,
    verdict,
    confidence: verdict === 'strong_signal' ? 'inferred' : 'hypothesis',
    measured: {
      dnsRequests: requests.length,
      dnsResponses: responses.length,
      responseToRequestByteRatio: Number.isFinite(byteRatio) ? round(byteRatio) : 'infinity',
      requestQtypeDistribution: Object.fromEntries(qtypes),
      anyOrTxtQueryShare: round(anyTxtShare),
      uniqueServersPerVictim: { victim, servers: maxServers },
      responsesFromNon53SourcePort: oddSrcPorts,
    },
    thresholdsRationale:
      'A response-to-request byte ratio well above 1, a high share of ANY/TXT queries and many distinct servers sending ' +
      'to one destination are consistent with reflection/amplification. Byte asymmetry alone can occur with DNSSEC.',
    falsePositiveNotes: [
      'Legitimate large DNS responses and DNSSEC-signed answers.',
      'Caching resolvers answering a real client (normal asymmetry).',
      'Capture point seeing only the response side.',
    ],
    mitigationAdvice: [
      'Close open resolvers; enable response-rate limiting (RRL).',
      'Deploy ingress/egress anti-spoofing (BCP38/BCP84).',
      'Anycast DNS and scrubbing.',
    ],
  };
}

/** Beacon detector: inter-arrival regularity (coefficient of variation) per destination. */
function detectBeacon(packets: DecodedPacket[]): DetectorVerdict {
  const withDst = packets.filter((p) => p.dstIp && p.dstIp !== '?');
  if (withDst.length < 5) {
    return {
      detector: 'beacon',
      applicable: false,
      verdict: 'insufficient_data',
      confidence: 'unknown',
      measured: { packets: withDst.length },
      thresholdsRationale: 'Too few packets to evaluate inter-arrival regularity.',
      falsePositiveNotes: [],
      mitigationAdvice: [],
    };
  }
  const groups = new Map<string, number[]>();
  for (const p of withDst) {
    const key = `${p.dstIp}:${p.dstPort}`;
    (groups.get(key) ?? groups.set(key, []).get(key)!).push(p.ts);
  }

  const candidates: Array<{ dst: string; count: number; cv: number; meanInterval: number }> = [];
  for (const [dst, times] of groups) {
    if (times.length < 5) continue;
    const sorted = [...times].sort((a, b) => a - b);
    const deltas: number[] = [];
    for (let i = 1; i < sorted.length; i += 1) {
      const d = sorted[i]! - sorted[i - 1]!;
      if (d > 0) deltas.push(d);
    }
    if (deltas.length < 4) continue;
    const cv = coefficientOfVariation(deltas);
    candidates.push({ dst, count: times.length, cv: round(cv), meanInterval: round(mean(deltas), 3) });
  }

  candidates.sort((a, b) => a.cv - b.cv);
  const best = candidates[0];
  let verdict: Verdict = 'no_signal';
  if (best && best.cv < 0.15 && best.count >= 10) verdict = 'strong_signal';
  else if (best && best.cv < 0.4) verdict = 'weak_signal';

  return {
    detector: 'beacon',
    applicable: true,
    verdict,
    confidence: verdict === 'strong_signal' ? 'inferred' : 'hypothesis',
    measured: {
      evaluatedDestinations: candidates.length,
      mostRegularDestination: best?.dst ?? null,
      mostRegularCv: best?.cv ?? null,
      mostRegularMeanIntervalSeconds: best?.meanInterval ?? null,
      candidates: candidates.slice(0, 5),
    },
    thresholdsRationale:
      'A low coefficient of variation (< ~0.15) of inter-arrival deltas to one destination indicates regular, ' +
      'jittered-timer-like communication (beaconing). High-volume floods rarely produce such regularity.',
    falsePositiveNotes: [
      'Heartbeats, NTP, monitoring and keep-alive protocols produce regular intervals by design.',
      'Scheduled backups and polling clients.',
    ],
    mitigationAdvice: [
      'Correlate with payload/flow behaviour before alerting.',
      'Maintain an allow-list of known periodic services.',
    ],
  };
}

function runDetectors(packets: DecodedPacket[], focus: string): DetectorVerdict[] {
  const all: Record<string, DetectorVerdict> = {
    syn_flood: detectSynFlood(packets),
    udp_flood: detectUdpFlood(packets),
    http_flood: detectHttpFlood(packets),
    dns_amplification: detectDnsAmplification(packets),
    beacon: detectBeacon(packets),
  };
  if (focus === 'general') return Object.values(all);
  const selected = all[focus];
  return selected ? [selected] : Object.values(all);
}

/* -------------------------------------------------------------------------- */
/* Knowledge helpers                                                          */
/* -------------------------------------------------------------------------- */

function makeRuleRecord(input: {
  id: string;
  category: KnowledgeRecord['category'];
  title: string;
  purpose: string;
  format: string;
  tags: string[];
}): KnowledgeRecord {
  const now = new Date().toISOString();
  return {
    id: input.id,
    category: input.category,
    title: input.title,
    identifiers: { format: input.format },
    affectedVersions: [],
    fixedVersions: [],
    klass: 'detection-rule',
    rootCause: input.purpose,
    attackSurface: input.format,
    preconditions: [],
    publicExploitState: 'none',
    relatedMalwareFamilies: [],
    relatedMiraiVariants: [],
    relatedRecordIds: [],
    verification: 'statically_reviewed',
    confidence: 'inferred',
    license: 'operator-authored',
    provenance: [curatedProvenance('operator', `Detection rule generated for: ${input.purpose}`)],
    evidence: [],
    tags: ['detection', input.format, ...input.tags],
    createdAt: now,
    updatedAt: now,
  };
}

/* -------------------------------------------------------------------------- */
/* Config-file walking (defense_architecture_analyze)                         */
/* -------------------------------------------------------------------------- */

const CONFIG_EXTENSIONS = new Set(['.conf', '.cfg', '.yaml', '.yml', '.json', '.txt', '.rules', '.lua', '.list']);
const CONFIG_NAME_HINTS = [
  'nginx',
  'haproxy',
  'suricata',
  'zeek',
  'bro',
  'iptables',
  'nftables',
  'nft',
  'waf',
  'cloudflare',
  'shield',
  'armor',
  'cds',
];

function walkConfigFiles(root: string, maxFiles: number): string[] {
  const out: string[] = [];
  const stack: string[] = [root];
  while (stack.length > 0 && out.length < maxFiles) {
    const dir = stack.pop();
    if (!dir) break;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (out.length >= maxFiles) break;
      if (entry.name === 'node_modules' || entry.name === '.git') continue;
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        stack.push(full);
      } else if (entry.isFile()) {
        const lower = entry.name.toLowerCase();
        const ext = extname(lower);
        if (CONFIG_EXTENSIONS.has(ext) || CONFIG_NAME_HINTS.some((h) => lower.includes(h))) {
          out.push(full);
        }
      }
    }
  }
  return out;
}

interface KeywordRule {
  key: string;
  label: string;
  pattern: RegExp;
  platforms: string[];
}

const PROTECTION_KEYWORDS: KeywordRule[] = [
  { key: 'limit_req', label: 'Request rate limiting (limit_req)', pattern: /\blimit_req\b/, platforms: ['nginx'] },
  { key: 'limit_conn', label: 'Connection limiting (limit_conn)', pattern: /\blimit_conn\b/, platforms: ['nginx'] },
  {
    key: 'client_body_timeout',
    label: 'Client body timeout',
    pattern: /\bclient_body_timeout\b/,
    platforms: ['nginx'],
  },
  {
    key: 'client_header_timeout',
    label: 'Client header timeout',
    pattern: /\bclient_header_timeout\b/,
    platforms: ['nginx'],
  },
  {
    key: 'proxy_read_timeout',
    label: 'Proxy read timeout',
    pattern: /\bproxy_read_timeout\b/,
    platforms: ['nginx'],
  },
  { key: 'syncookies', label: 'SYN cookies', pattern: /tcp_syncookies|\bsyncookies\b/i, platforms: ['sysctl', 'firewall'] },
  {
    key: 'rate_limit',
    label: 'Rate limiting',
    pattern: /rate[_-]?limit|\blimit\s+sessions\b|\brate-limit\b/i,
    platforms: ['haproxy', 'firewall', 'generic'],
  },
  { key: 'maxconn', label: 'Connection cap (maxconn)', pattern: /\bmaxconn\b/, platforms: ['haproxy'] },
  { key: 'stick_table', label: 'Stick-table tracking', pattern: /\bstick-table\b/, platforms: ['haproxy'] },
  { key: 'connlimit', label: 'Connection limit (connlimit)', pattern: /\bconnlimit\b/, platforms: ['firewall'] },
  { key: 'hashlimit', label: 'Per-source rate limit (hashlimit)', pattern: /\bhashlimit\b/, platforms: ['firewall'] },
  { key: 'recent', label: 'Recent-match tracking (recent)', pattern: /\brecent\b/, platforms: ['firewall'] },
  { key: 'synproxy', label: 'SYN proxy (synproxy)', pattern: /\bsynproxy\b/, platforms: ['firewall'] },
  { key: 'waf', label: 'WAF enabled', pattern: /\b(waf|modsecurity|coraza|owasp)\b/i, platforms: ['generic'] },
  { key: 'scrub', label: 'Traffic scrubbing', pattern: /\bscrub(bing|ber)?\b/i, platforms: ['generic'] },
  { key: 'anycast', label: 'Anycast dispersion', pattern: /\banycast\b/i, platforms: ['generic'] },
  { key: 'blackhole', label: 'Blackholing (RTBH)', pattern: /\b(blackhole|rtbh)\b/i, platforms: ['generic'] },
  { key: 'flowspec', label: 'BGP FlowSpec', pattern: /\bflowspec\b/i, platforms: ['generic'] },
  { key: 'threshold', label: 'Rule thresholds', pattern: /\b(threshold|detection_filter)\b/, platforms: ['suricata'] },
  { key: 'cdn', label: 'CDN / edge protection', pattern: /\b(cdn|cloudfront|akamai|cloudflare)\b/i, platforms: ['generic'] },
];

function detectPlatform(content: string, fileName: string): string {
  const hay = `${fileName}\n${content}`.toLowerCase();
  if (hay.includes('limit_req') || hay.includes('server_name') || fileName.includes('nginx')) return 'nginx';
  if (hay.includes('frontend') && hay.includes('backend') || fileName.includes('haproxy')) return 'haproxy';
  if (hay.includes('%yaml') && (hay.includes('suricata') || fileName.includes('suricata'))) return 'suricata';
  if (fileName.includes('suricata') || hay.includes('suricata')) return 'suricata';
  if (fileName.includes('zeek') || fileName.includes('bro')) return 'zeek';
  if (hay.includes('iptables') || hay.includes('nft') || fileName.includes('iptables') || fileName.includes('nft')) {
    return 'firewall';
  }
  return 'generic';
}

/* ========================================================================== */
/* Engine                                                                     */
/* ========================================================================== */

export const antiDdosEngine: EngineModule = {
  name: ENGINE,
  title: 'Anti-DDoS Defense Engineering',
  description:
    'Defensive DDoS research, architecture review, offline traffic/PCAP analysis, detection design, safe ' +
    'detection-rule generation, rate-limit design, mitigation comparison, safe test planning and ' +
    'defense-performance analysis. Defensive and analysis only.',
  tools: [
    /* 1. anti_ddos_research ------------------------------------------------ */
    defineTool<
      { topic?: string; product?: string; layer?: DefenseLayer },
      Record<string, unknown>
    >({
      name: 'anti_ddos_research',
      title: 'Anti-DDoS research',
      engine: ENGINE,
      description:
        'Structured defensive research briefing over §4.1 categories (network, application, DNS/infra, detection) ' +
        'and §4.2 product intelligence. Persists relevant entries as defense_technology records.',
      capabilities: ['write_knowledge'],
      risk: 'safe',
      inputSchema: {
        topic: z.string().min(1).optional().describe('Filter technologies by keyword.'),
        product: z.string().min(1).optional().describe('Filter products by name/id/category.'),
        layer: LAYER_ENUM.optional().describe('Restrict technologies to a defence layer.'),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const seeded = seedDefenseCatalogue(ctx.knowledge);
        const technologies = searchDefenseTechnologies({ topic: input.topic, layer: input.layer });
        const products = searchDefenseProducts(input.product);

        for (const tech of technologies) {
          addEvidence(ctx, {
            claim: `Defence technology documented: ${tech.name} (${tech.layer}).`,
            prov: curatedProvenance('public-research', `Anti-DDoS technology ${tech.id}`),
            confidence: 'confirmed',
            data: { id: tech.id, layer: tech.layer },
          });
        }

        const byGroup = new Map<string, string[]>();
        for (const tech of technologies) {
          (byGroup.get(tech.group) ?? byGroup.set(tech.group, []).get(tech.group)!).push(tech.name);
        }

        const data = {
          technologyCount: technologies.length,
          technologies,
          productCount: products.length,
          products,
          productDisclaimer: PRODUCT_DISCLAIMER,
          seededRecords: seeded,
        };

        const summaryLines = [
          `Defensive research briefing — ${technologies.length} technology entries, ${products.length} product entries.`,
          seeded > 0 ? `Seeded ${seeded} defense_technology record(s) into the knowledge base.` : '',
          ...Object.entries(Object.fromEntries(byGroup)).map(
            ([group, names]) => `\n### ${group}\n${names.map((n) => `- ${n}`).join('\n')}`,
          ),
          products.length ? `\n### Products (public docs)\n${products.map((p) => `- ${p.name} — ${p.category}`).join('\n')}` : '',
          `\n_${PRODUCT_DISCLAIMER}_`,
        ];

        return finish({
          engine: ENGINE,
          tool: 'anti_ddos_research',
          startedAt: started,
          ctx,
          data,
          summary: summaryLines.filter(Boolean).join('\n'),
        });
      },
    }),

    /* 2. defense_architecture_analyze -------------------------------------- */
    defineTool<
      { path?: string; configFiles?: string[] },
      Record<string, unknown>
    >({
      name: 'defense_architecture_analyze',
      title: 'Defense architecture analyze',
      engine: ENGINE,
      description:
        'Read-only analysis of LOCAL defensive configuration (nginx, haproxy, suricata, zeek, iptables/nftables, ' +
        'WAF/CDN JSON). Reports protections PRESENT, protections MISSING, misconfigurations and concrete hardening ' +
        'recommendations based on defensive keywords.',
      capabilities: ['read_repo'],
      risk: 'safe',
      inputSchema: {
        path: z.string().min(1).optional().describe('Workspace-relative file or directory to scan.'),
        configFiles: z
          .array(z.string().min(1))
          .optional()
          .describe('Explicit list of workspace-relative configuration files.'),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        if (!input.path && (!input.configFiles || input.configFiles.length === 0)) {
          throw errors.invalidInput('Provide either "path" or "configFiles".');
        }

        const files = new Set<string>();
        if (input.configFiles) {
          for (const f of input.configFiles) files.add(resolveWorkspacePath(f, true));
        }
        if (input.path) {
          const resolved = resolveWorkspacePath(input.path, true);
          const stat = statSync(resolved);
          if (stat.isDirectory()) {
            for (const f of walkConfigFiles(resolved, 200)) files.add(f);
          } else {
            files.add(resolved);
          }
        }

        if (files.size === 0) throw errors.notFound('No configuration files found to analyze.');

        const present: Array<{ key: string; label: string; file: string; line: number }> = [];
        const platformVotes = new Map<string, number>();
        const scanned: string[] = [];
        const fileSizes: Record<string, number> = {};

        for (const file of files) {
          const artifact = readTextArtifact(file);
          scanned.push(file);
          fileSizes[file] = artifact.bytes;
          const platform = detectPlatform(artifact.content, basename(file));
          platformVotes.set(platform, (platformVotes.get(platform) ?? 0) + 1);

          for (const rule of PROTECTION_KEYWORDS) {
            const match = rule.pattern.exec(artifact.content);
            if (match && match.index >= 0) {
              const line = artifact.content.slice(0, match.index).split('\n').length;
              present.push({ key: rule.key, label: rule.label, file, line });
            }
          }
        }

        const primaryPlatform = [...platformVotes.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? 'generic';
        const presentKeys = new Set(present.map((p) => p.key));

        const expectedByPlatform: Record<string, string[]> = {
          nginx: ['limit_req', 'limit_conn', 'client_body_timeout', 'proxy_read_timeout'],
          haproxy: ['rate_limit', 'maxconn', 'stick_table'],
          suricata: ['threshold'],
          firewall: ['rate_limit', 'connlimit', 'syncookies'],
          zeek: [],
          generic: ['rate_limit', 'waf'],
        };
        const expected = expectedByPlatform[primaryPlatform] ?? [];
        const missing = expected.filter((k) => !presentKeys.has(k));

        const misconfigurations: string[] = [];
        if (primaryPlatform === 'nginx') {
          if (!presentKeys.has('limit_req')) misconfigurations.push('No limit_req found: request flooding is unthrottled.');
          if (!presentKeys.has('limit_conn')) misconfigurations.push('No limit_conn found: concurrent connections are uncapped.');
          if (!presentKeys.has('client_body_timeout')) misconfigurations.push('client_body_timeout not set: slow-request abuse possible.');
        }
        if (primaryPlatform === 'haproxy') {
          if (!presentKeys.has('maxconn')) misconfigurations.push('maxconn not set: server-side connection cap missing.');
          if (!presentKeys.has('stick_table')) misconfigurations.push('No stick-table: per-source tracking/rate limiting absent.');
        }
        if (primaryPlatform === 'suricata') {
          if (!presentKeys.has('threshold')) misconfigurations.push('No threshold/detection_filter: alert volume may be excessive.');
        }
        if (!presentKeys.has('syncookies')) {
          misconfigurations.push('No SYN-cookie configuration detected: enable tcp_syncookies for TCP state protection.');
        }

        const recommendations: string[] = [];
        if (missing.length) recommendations.push(`Add missing controls for ${primaryPlatform}: ${missing.join(', ')}.`);
        if (!presentKeys.has('cdn')) recommendations.push('Consider edge/CDN absorption to reduce origin exposure.');
        if (!presentKeys.has('anycast')) recommendations.push('Consider anycast dispersion for volumetric resilience.');
        if (!presentKeys.has('blackhole') && !presentKeys.has('flowspec')) {
          recommendations.push('Define an upstream mitigation path (RTBH and/or BGP FlowSpec) with a documented trigger policy.');
        }

        for (const p of present.slice(0, 40)) {
          addEvidence(ctx, {
            claim: `Protection present: ${p.label}.`,
            prov: localProvenance('config', p.file, 'read-only config scan'),
            confidence: 'observed',
            locator: { file: p.file, line: p.line },
          });
        }

        const data = {
          scannedFiles: scanned,
          fileSizes,
          primaryPlatform,
          protectionsPresent: present,
          protectionsMissing: missing.map((k) => ({ key: k, platform: primaryPlatform })),
          misconfigurations,
          recommendations,
          expectedControls: expected,
        };

        const summaryLines = [
          `Analyzed ${scanned.length} config file(s); detected primary platform: **${primaryPlatform}**.`,
          `Protections present (${present.length}): ${present.map((p) => p.label).join(', ') || 'none'}.`,
          `Protections missing: ${missing.join(', ') || 'none detected for this platform'}.`,
          misconfigurations.length
            ? `\nMisconfigurations:\n${misconfigurations.map((m) => `- ${m}`).join('\n')}`
            : '\nNo misconfigurations detected by the configured heuristics.',
          recommendations.length
            ? `\nRecommendations:\n${recommendations.map((r) => `- ${r}`).join('\n')}`
            : '',
        ];

        return finish({
          engine: ENGINE,
          tool: 'defense_architecture_analyze',
          startedAt: started,
          ctx,
          data,
          summary: summaryLines.filter(Boolean).join('\n'),
        });
      },
    }),

    /* 3. network_traffic_analyze ------------------------------------------- */
    defineTool<
      { pcapPath: string; topN?: number },
      Record<string, unknown>
    >({
      name: 'network_traffic_analyze',
      title: 'Network traffic analyze',
      engine: ENGINE,
      description:
        'Analyze a PCAP: uses tshark/tcpdump statistics when available, otherwise a pure-JS libpcap parser. ' +
        'Produces protocol hierarchy, top talkers/conversations, packet-size distribution and a defensive ' +
        'interpretation of whether the traffic is consistent with flood behaviour. Reads only; never sends traffic.',
      capabilities: ['read_pcap', 'network_read'],
      risk: 'safe',
      inputSchema: {
        pcapPath: z.string().min(1).describe('Workspace-relative path to a PCAP file.'),
        topN: z.number().int().min(1).max(50).optional().describe('Number of top entries (default 10).'),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const topN = input.topN ?? 10;
        const artifact = readBinaryArtifact(input.pcapPath);
        const digest = await sha256(artifact.buffer);

        let summary: PcapSummary;
        try {
          summary = parsePcap(artifact.buffer, { keepPackets: false, topN }).summary;
        } catch (err) {
          throw errors.invalidInput(`Could not parse PCAP: ${(err as Error).message}`, { path: artifact.path });
        }

        // Optional external tool for cross-checking / protocol hierarchy.
        const cfg = getConfig();
        let external: Record<string, unknown> | null = null;
        const usableTool = cfg.allowIsolatedExec && toolOnPathSync('tshark');
        if (usableTool) {
          try {
            const res = await runCommand('tshark', {
              args: ['-r', artifact.path, '-q', '-z', 'io,phs', '-z', 'conv,ip'],
              timeoutMs: 30_000,
              maxOutputBytes: 512 * 1024,
            });
            external = {
              tool: 'tshark',
              exitCode: res.exitCode,
              timedOut: res.timedOut,
              protocolHierarchy: parseTsharkProtocolHierarchy(res.stdout),
              raw: res.stdout.slice(0, 8000),
            };
          } catch (err) {
            ctx.evidence.warn(`tshark invocation failed, using pure-JS parser only: ${(err as Error).message}`);
          }
        }

        addEvidence(ctx, {
          claim: `Parsed ${summary.packetCount} packet(s) from ${basename(artifact.path)} (${digest}).`,
          prov: localProvenance('pcap', artifact.path, 'offline parse'),
          confidence: 'observed',
          locator: { file: artifact.path },
        });

        // Defensive interpretation.
        const tcpShare = (summary.protocols.TCP ?? 0) / Math.max(summary.packetCount, 1);
        const udpShare = (summary.protocols.UDP ?? 0) / Math.max(summary.packetCount, 1);
        const dominantProto = topEntries(new Map(Object.entries(summary.protocols)), 1)[0];
        const interpretation: string[] = [];
        if (summary.packetsPerSecond !== null && summary.packetsPerSecond > 5000) {
          interpretation.push(`High packet rate (${summary.packetsPerSecond} pps) — consistent with volumetric flood behaviour.`);
        }
        if (tcpShare > 0.6) interpretation.push('TCP-dominant traffic; check SYN/flag anomalies with pcap_analyze (focus syn_flood).');
        if (udpShare > 0.6) interpretation.push('UDP-dominant traffic; check port concentration and payload uniformity (focus udp_flood).');
        if (summary.topDstIps.length === 1 && summary.packetCount > 100) {
          interpretation.push('Traffic concentrated on a single destination — possible targeted flooding.');
        }
        if (interpretation.length === 0) interpretation.push('No obvious volumetric signature from summary statistics alone.');

        // Persist a pcap_evidence graph node.
        const nodeId = `pcap-evidence:${digest.replace('sha256:', '').slice(0, 16)}`;
        ctx.knowledge.upsertNode({
          id: nodeId,
          kind: 'pcap_evidence',
          label: basename(artifact.path),
          properties: {
            sha256: digest,
            packetCount: summary.packetCount,
            avgPacketSize: summary.avgPacketSize,
            packetsPerSecond: summary.packetsPerSecond,
            protocols: summary.protocols,
            topDstIps: summary.topDstIps,
          },
          provenance: [localProvenance('pcap', artifact.path)],
          confidence: 'observed',
        });

        const data = {
          path: artifact.path,
          sha256: digest,
          stats: summary,
          externalTool: external,
          defensiveInterpretation: interpretation,
          graphNodeId: nodeId,
        };

        const summaryLines = [
          `PCAP **${basename(artifact.path)}** — ${summary.packetCount} packets, avg size ${summary.avgPacketSize} B, ` +
            `format ${summary.format.endianness}/${summary.format.timestampResolution}, linkType ${summary.format.linkType}.`,
          `Duration ${summary.durationSeconds ?? 'n/a'} s; rate ${summary.packetsPerSecond ?? 'n/a'} pps.`,
          `Protocols: ${Object.entries(summary.protocols).map(([k, v]) => `${k}=${v}`).join(', ')}.`,
          `Top destination ports: ${summary.topDstPorts.map((p) => `${p.value}(${p.count})`).join(', ') || 'n/a'}.`,
          external ? `tshark protocol hierarchy entries: ${(external.protocolHierarchy as unknown[]).length}.` : 'tshark unavailable — pure-JS parser used.',
          `\nDefensive interpretation:\n${interpretation.map((i) => `- ${i}`).join('\n')}`,
        ];

        return finish({
          engine: ENGINE,
          tool: 'network_traffic_analyze',
          startedAt: started,
          ctx,
          data,
          summary: summaryLines.join('\n'),
          warnings: summary.parseWarnings,
        });
      },
    }),

    /* 4. pcap_analyze ------------------------------------------------------- */
    defineTool<
      { pcapPath: string; focus?: string; topN?: number },
      Record<string, unknown>
    >({
      name: 'pcap_analyze',
      title: 'PCAP analyze (detectors)',
      engine: ENGINE,
      description:
        'Deep multi-pass PCAP analysis with real detectors: SYN flood, UDP flood, HTTP flood, DNS amplification and ' +
        'beacon regularity. Returns per-detector measured values, threshold rationale, confidence, false-positive ' +
        'notes and mitigation advice. Offline analysis only; no traffic is generated.',
      capabilities: ['read_pcap'],
      risk: 'safe',
      inputSchema: {
        pcapPath: z.string().min(1).describe('Workspace-relative path to a PCAP file.'),
        focus: z
          .enum(['general', 'syn_flood', 'udp_flood', 'http_flood', 'dns_amplification', 'beacon'])
          .optional()
          .describe('Which detector to run (default general = all).'),
        topN: z.number().int().min(1).max(50).optional().describe('Top-N entries for supporting lists (default 10).'),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const focus = input.focus ?? 'general';
        const artifact = readBinaryArtifact(input.pcapPath);
        const digest = await sha256(artifact.buffer);

        let parsed;
        try {
          parsed = parsePcap(artifact.buffer, { keepPackets: true, topN: input.topN ?? 10 });
        } catch (err) {
          throw errors.invalidInput(`Could not parse PCAP: ${(err as Error).message}`, { path: artifact.path });
        }

        const verdicts = runDetectors(parsed.packets, focus);

        const evidence: EvidenceRef[] = [];
        for (const v of verdicts) {
          const ref = addEvidence(ctx, {
            claim: `Detector ${v.detector}: verdict=${v.verdict} (${JSON.stringify(v.measured)}).`,
            prov: localProvenance('pcap', artifact.path, 'offline detector'),
            confidence: v.confidence,
            locator: { file: artifact.path },
            data: v.measured,
          });
          evidence.push(ref);
          if (v.verdict === 'strong_signal' || v.verdict === 'weak_signal') {
            ctx.evidence.assert({
              statement: `The capture shows ${v.verdict.replace('_', ' ')} for ${v.detector}.`,
              status: 'researcher_interpretation',
              confidence: v.confidence,
              producedBy: 'pcap_analyze',
              supporting: [ref],
            });
          }
        }

        const nodeId = `pcap-evidence:${digest.replace('sha256:', '').slice(0, 16)}`;
        ctx.knowledge.upsertNode({
          id: nodeId,
          kind: 'pcap_evidence',
          label: basename(artifact.path),
          properties: {
            sha256: digest,
            focus,
            packetCount: parsed.summary.packetCount,
            verdicts: verdicts.map((v) => ({ detector: v.detector, verdict: v.verdict })),
          },
          provenance: [localProvenance('pcap', artifact.path)],
          confidence: 'observed',
        });

        const data = {
          path: artifact.path,
          sha256: digest,
          focus,
          summary: parsed.summary,
          verdicts,
          graphNodeId: nodeId,
        };

        const summaryLines = [
          `PCAP deep analysis (focus: ${focus}) — ${parsed.summary.packetCount} packets, ${digest}.`,
          ...verdicts.map(
            (v) =>
              `\n### ${v.detector}\nVerdict: **${v.verdict}** (confidence: ${v.confidence})\n` +
              `Measured: ${JSON.stringify(v.measured)}\n` +
              `Threshold rationale: ${v.thresholdsRationale}\n` +
              (v.falsePositiveNotes.length ? `False positives: ${v.falsePositiveNotes.join('; ')}\n` : '') +
              (v.mitigationAdvice.length ? `Mitigation: ${v.mitigationAdvice.join('; ')}` : ''),
          ),
        ];

        return finish({
          engine: ENGINE,
          tool: 'pcap_analyze',
          startedAt: started,
          ctx,
          data,
          summary: summaryLines.join('\n'),
          warnings: parsed.summary.parseWarnings,
        });
      },
    }),

    /* 5. ddos_detection_design --------------------------------------------- */
    defineTool<
      { targetProfile: string; constraints?: string[]; layer?: string },
      Record<string, unknown>
    >({
      name: 'ddos_detection_design',
      title: 'DDoS detection design',
      engine: ENGINE,
      description:
        'DESIGN (not attack) a DDoS detection system: sensor placement, metrics, baselines, threshold policy, ' +
        'alerting, escalation and false-positive controls. Optionally emitted as a detection_template record.',
      capabilities: ['write_knowledge'],
      risk: 'safe',
      inputSchema: {
        targetProfile: z.string().min(3).describe('Description of the system to protect.'),
        constraints: z.array(z.string().min(1)).optional().describe('Operational constraints to respect.'),
        layer: z.string().min(1).optional().describe('Primary protection layer of interest.'),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        seedDefenseCatalogue(ctx.knowledge);

        const design = {
          targetProfile: input.targetProfile,
          layer: input.layer ?? 'multi-layer',
          constraints: input.constraints ?? [],
          sensorPlacement: [
            'Edge/transit: flow export (NetFlow/IPFIX/sFlow) for volumetric detection.',
            'DMZ/SPAN: full-packet capture for protocol and payload-level detection.',
            'Application: access logs, WAF/bot telemetry and backend metrics.',
            'DNS: resolver/authoritative query telemetry with cache-hit visibility.',
          ],
          metrics: [
            'Packets/bytes per second per destination.',
            'Connection establishment rate and half-open count.',
            'Unique source-IP cardinality per destination.',
            'TCP flag distribution; UDP port concentration; payload-size uniformity.',
            'Application request rate per endpoint, method mix, UA/path cardinality.',
            'DNS query rate, cache-hit ratio, NXDOMAIN and large-response share.',
            'CPU, memory, socket/descriptor and conntrack utilisation.',
          ],
          baselines:
            'Build per-service baselines across time-of-day and weekly seasonality; exclude known attack windows; ' +
            'track headroom so detection precedes exhaustion.',
          thresholdPolicy: {
            style: 'Multi-signal, statistically-scored policy rather than a single static rate.',
            guidance: [
              'Combine rate deviation with cardinality, flag-mix and backend-latency signals.',
              'Express thresholds as deviations from baseline (policy), not fixed numbers.',
              'Use graduated responses: alert -> throttle -> block.',
            ],
          },
          alerting: ['Severity by detector confidence and blast radius.', 'Route to on-call with runbook links.'],
          escalation: [
            'Level 1: automated throttling / challenge.',
            'Level 2: upstream scrubbing / FlowSpec / RTBH (documented trigger).',
            'Level 3: manual incident command and provider engagement.',
          ],
          falsePositiveControls: [
            'Allow-list known scanners, monitors and batch clients.',
            'Track FP/FN outcomes and tune weekly.',
            'Prefer monitor-before-block for new rules.',
          ],
        };

        const record: KnowledgeRecord = {
          id: `detection-template:${(await sha256(input.targetProfile)).replace('sha256:', '').slice(0, 16)}`,
          category: 'detection_template',
          title: `Detection design — ${input.targetProfile.slice(0, 60)}`,
          identifiers: { layer: design.layer },
          affectedVersions: [],
          fixedVersions: [],
          klass: 'detection-design',
          rootCause: 'Defensive detection system specification.',
          attackSurface: design.layer,
          preconditions: [],
          publicExploitState: 'none',
          relatedMalwareFamilies: [],
          relatedMiraiVariants: [],
          relatedRecordIds: [],
          verification: 'statically_reviewed',
          confidence: 'inferred',
          license: 'operator-authored',
          provenance: [curatedProvenance('design', 'DDoS detection design document')],
          evidence: [],
          tags: ['detection-design', 'anti-ddos'],
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        };
        ctx.knowledge.upsertRecord(record);

        addEvidence(ctx, {
          claim: `Produced a detection design for: ${input.targetProfile}.`,
          prov: curatedProvenance('design', 'DDoS detection design'),
          confidence: 'inferred',
        });

        return finish({
          engine: ENGINE,
          tool: 'ddos_detection_design',
          startedAt: started,
          ctx,
          data: { design, templateRecordId: record.id },
          summary:
            `### DDoS detection design\nLayer: ${design.layer}. Constraints: ${design.constraints.join(', ') || 'none specified'}.\n\n` +
            `**Sensor placement**\n${design.sensorPlacement.map((s) => `- ${s}`).join('\n')}\n\n` +
            `**Metrics**\n${design.metrics.map((m) => `- ${m}`).join('\n')}\n\n` +
            `**Threshold policy**: ${design.thresholdPolicy.guidance.join(' ')}\n\n` +
            `Persisted detection_template record: ${record.id}.`,
        });
      },
    }),

    /* 6. detection_rule_generate ------------------------------------------- */
    defineTool<
      { format: 'suricata' | 'sigma' | 'yara' | 'zeek'; purpose: string; outputPath?: string; indicators?: string[] },
      Record<string, unknown>
    >({
      name: 'detection_rule_generate',
      title: 'Detection rule generate',
      engine: ENGINE,
      description:
        'Generate a SAFE DETECTION rule (suricata/sigma/yara/zeek notice) for a defensive purpose. Detection ' +
        'artefacts only — never attack artefacts. Text is structurally validated and may be written inside the ' +
        'workspace. Persisted with verification statically_reviewed.',
      capabilities: ['write_repo', 'write_knowledge'],
      risk: 'local_mutation',
      inputSchema: {
        format: z.enum(['suricata', 'sigma', 'yara', 'zeek']).describe('Rule format to generate.'),
        purpose: z.string().min(3).describe('Defensive detection purpose.'),
        outputPath: z.string().min(1).optional().describe('Optional workspace-relative path to write the rule.'),
        indicators: z.array(z.string().min(1)).optional().describe('Optional indicators (strings/paths) to reference.'),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const sid = (await sha256(`${input.format}:${input.purpose}`)).replace('sha256:', '').slice(0, 8);
        const numericSid = (Number.parseInt(sid.slice(0, 6), 16) % 9000000) + 1000000;
        const indicators = input.indicators ?? [];

        let rule = '';
        let category: KnowledgeRecord['category'] = 'network_detection_rule';

        if (input.format === 'suricata') {
          const contentMatches = indicators.map((i) => `content:"${i.replace(/"/g, '')}";`).join(' ');
          rule = [
            `# Suricata detection rule — purpose: ${input.purpose}`,
            `alert ip any any -> any any (`,
            `  msg:"${input.purpose.replace(/"/g, "'")}";`,
            contentMatches ? `  ${contentMatches}` : '  # add detection conditions (content/pcre/flow) here',
            `  threshold: type threshold, track by_src, count 100, seconds 10;`,
            `  classtype:attempted-dos; sid:${numericSid}; rev:1;)`,
          ].join('\n');
          category = 'network_detection_rule';
        } else if (input.format === 'sigma') {
          rule = [
            `title: ${input.purpose.replace(/"/g, "'")}`,
            'status: experimental',
            'description: Defensive detection for the stated purpose.',
            'logsource:',
            '  category: firewall',
            'detection:',
            '  selection:',
            ...(indicators.length
              ? indicators.map((i) => `    - "${i.replace(/"/g, '')}"`)
              : ['    event_action: "block"']),
            '  condition: selection | count() by src_ip > 100',
            'falsepositives:',
            '  - Legitimate high-volume clients',
            'level: medium',
          ].join('\n');
          category = 'sigma_rule';
        } else if (input.format === 'yara') {
          const ruleName = `mirai_defense_${sid.slice(0, 8)}`;
          rule = [
            `rule ${ruleName}`,
            '{',
            '  meta:',
            `    description = "${input.purpose.replace(/"/g, "'")}"`,
            '    author = "MIRAI Intelligence & Research (defensive)"',
            '  strings:',
            ...(indicators.length
              ? indicators.map((i, idx) => `    $s${idx + 1} = "${i.replace(/"/g, '')}" ascii`)
              : ['    $a = "detection-placeholder" ascii']),
            '  condition:',
            `    ${indicators.length > 1 ? 'any of them' : '$a'}`,
            '}',
          ].join('\n');
          category = 'yara_rule';
        } else {
          rule = [
            `# Zeek notice script — purpose: ${input.purpose}`,
            'module MIRAI_Defense;',
            'export {',
            '  redef enum Notice::Type += { Mirai_Defense_Alert };',
            '}',
            'event connection_state_remove(c: connection) {',
            '  # Defensive heuristic placeholder: correlate rate/cardinality before noticing.',
            '  NOTICE([$note=Mirai_Defense_Alert, $msg="Possible DDoS behaviour detected", $conn=c]);',
            '}',
          ].join('\n');
          category = 'network_detection_rule';
        }

        // Structural validation.
        const quotes = (rule.match(/"/g) ?? []).length;
        const braces = (rule.match(/[{}]/g) ?? []).length;
        const validation = {
          balancedQuotes: quotes % 2 === 0,
          balancedBraces: braces % 2 === 0,
          lineCount: rule.split('\n').length,
        };
        if (!validation.balancedQuotes) ctx.evidence.warn('Generated rule has unbalanced double quotes.');
        if (!validation.balancedBraces) ctx.evidence.warn('Generated rule has unbalanced braces.');

        let writtenPath: string | null = null;
        if (input.outputPath) {
          const target = resolveWorkspacePath(input.outputPath, false);
          mkdirSync(dirname(target), { recursive: true });
          writeFileSync(target, `${rule}\n`, 'utf8');
          writtenPath = target;
          addEvidence(ctx, {
            claim: `Wrote ${input.format} detection rule to ${target}.`,
            prov: localProvenance('rule-output', target),
            confidence: 'observed',
            locator: { file: target },
          });
        }

        const recordId = `rule:${input.format}:${sid}`;
        ctx.knowledge.upsertRecord(
          makeRuleRecord({
            id: recordId,
            category,
            title: `${input.format} rule — ${input.purpose.slice(0, 50)}`,
            purpose: input.purpose,
            format: input.format,
            tags: ['anti-ddos'],
          }),
        );

        return finish({
          engine: ENGINE,
          tool: 'detection_rule_generate',
          startedAt: started,
          ctx,
          data: { format: input.format, purpose: input.purpose, rule, validation, writtenPath, recordId },
          summary:
            `Generated a **${input.format}** detection rule (defensive, non-destructive).\n` +
            `Structural validation: ${JSON.stringify(validation)}.\n` +
            (writtenPath ? `Written to: ${writtenPath}.\n` : '') +
            `Persisted knowledge record: ${recordId}.\n\n\`\`\`\n${rule}\n\`\`\``,
        });
      },
    }),

    /* 7. rate_limit_design -------------------------------------------------- */
    defineTool<
      { scenario: string; dimensions?: string[] },
      Record<string, unknown>
    >({
      name: 'rate_limit_design',
      title: 'Rate limit design',
      engine: ENGINE,
      description:
        'Produce rate-limiting designs (token bucket, leaky bucket, sliding window, concurrency caps; ' +
        'per-IP/per-account/per-route) with algorithm rationale and POLICY-level parameter guidance, plus ' +
        'integration notes and an optional sample nginx limit_req/limit_conn configuration.',
      capabilities: [],
      risk: 'safe',
      inputSchema: {
        scenario: z.string().min(3).describe('Scenario/service to protect.'),
        dimensions: z.array(z.string().min(1)).optional().describe('Rate-limiting dimensions of interest.'),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        const dimensions = input.dimensions ?? ['per-ip', 'per-route', 'global'];

        const designs = [
          {
            algorithm: 'token_bucket',
            description: 'Allows short bursts up to a bucket size while enforcing a steady refill rate.',
            bestFor: 'General request limiting with tolerable bursts.',
            policyGuidance: 'Set refill = steady legitimate rate; bucket = acceptable burst; reject (429) on empty.',
          },
          {
            algorithm: 'leaky_bucket',
            description: 'Smooths output to a constant rate, buffering or dropping excess.',
            bestFor: 'Protecting strict downstream capacity.',
            policyGuidance: 'Set leak rate = downstream safe capacity; queue small or zero to avoid latency inflation.',
          },
          {
            algorithm: 'sliding_window',
            description: 'Counts requests over a rolling window for smoother enforcement than fixed windows.',
            bestFor: 'Fair per-account/per-key quotas.',
            policyGuidance: 'Choose window matching abuse timescale; store counters per key.',
          },
          {
            algorithm: 'concurrency_cap',
            description: 'Caps simultaneous in-flight requests/connections.',
            bestFor: 'Protecting workers, sockets and descriptors.',
            policyGuidance: 'Set cap above observed legitimate peak; combine with idle timeouts.',
          },
        ];

        const nginxSnippet = [
          '# Defensive sample configuration (intended for review, not auto-applied)',
          'limit_req_zone $binary_remote_addr zone=perip:10m rate=<RATE>r/s;',
          'limit_conn_zone $binary_remote_addr zone=conn_perip:10m;',
          'server {',
          '  location /api/ {',
          '    limit_req zone=perip burst=<BURST> nodelay;',
          '    limit_conn conn_perip <MAXCONN>;',
          '    client_body_timeout 10s;',
          '    proxy_read_timeout 30s;',
          '    proxy_pass http://backend;',
          '  }',
          '}',
        ].join('\n');

        const integrations: Record<string, string> = {
          nginx: 'Use limit_req/limit_conn with per-key zones; tune burst/nodelay per route.',
          haproxy: 'Use stick-tables with http_req_rate/conn_rate and per-tx rate-limit rules.',
          gateway: 'Enforce per-key/per-route budgets at the API gateway and propagate 429 with Retry-After.',
        };

        addEvidence(ctx, {
          claim: `Produced rate-limiting designs for scenario: ${input.scenario}.`,
          prov: curatedProvenance('design', 'Rate-limit design'),
          confidence: 'inferred',
        });

        return finish({
          engine: ENGINE,
          tool: 'rate_limit_design',
          startedAt: started,
          ctx,
          data: { scenario: input.scenario, dimensions, designs, integrations, nginxSnippet },
          summary:
            `### Rate-limit design — ${input.scenario}\nDimensions: ${dimensions.join(', ')}.\n\n` +
            designs.map((d) => `- **${d.algorithm}**: ${d.description} Best for: ${d.bestFor}. Policy: ${d.policyGuidance}`).join('\n') +
            `\n\n**Integrations**: ${Object.entries(integrations).map(([k, v]) => `${k} — ${v}`).join(' ')}\n\n` +
            `**Sample nginx (review before applying)**:\n\`\`\`nginx\n${nginxSnippet}\n\`\`\``,
        });
      },
    }),

    /* 8. mitigation_strategy_compare --------------------------------------- */
    defineTool<
      { strategies?: string[]; attackLayer?: string },
      Record<string, unknown>
    >({
      name: 'mitigation_strategy_compare',
      title: 'Mitigation strategy compare',
      engine: ENGINE,
      description:
        'Compare mitigation strategies (§4.1/§4.2) across coverage, latency, false-positive risk, cost/complexity, ' +
        'scalability and defensively-described bypass weaknesses. Includes §4.2 products from public documentation.',
      capabilities: [],
      risk: 'safe',
      inputSchema: {
        strategies: z.array(z.string().min(1)).optional().describe('Filter strategies by id/name keyword.'),
        attackLayer: z.string().min(1).optional().describe('Restrict to a defence layer.'),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        let strategies = MITIGATION_STRATEGIES;
        if (input.attackLayer) {
          strategies = strategies.filter((s) => s.layer === input.attackLayer);
        }
        if (input.strategies && input.strategies.length > 0) {
          const keys = input.strategies.map((s) => s.toLowerCase());
          strategies = strategies.filter((s) => keys.some((k) => s.id.includes(k) || s.name.toLowerCase().includes(k)));
        }
        if (strategies.length === 0) {
          throw errors.notFound('No mitigation strategies matched the request.');
        }

        const header = '| Strategy | Layer | Latency | FP risk | Cost | Complexity | Scalability |';
        const divider = '| --- | --- | --- | --- | --- | --- | --- |';
        const body = strategies.map(
          (s) =>
            `| ${s.name} | ${s.layer} | ${s.latencyImpact} | ${s.falsePositiveRisk} | ${s.deploymentCost} | ${s.complexity} | ${s.scalability} |`,
        );
        const markdown = [header, divider, ...body].join('\n');

        addEvidence(ctx, {
          claim: `Compared ${strategies.length} mitigation strategies and ${DEFENSE_PRODUCTS.length} products.`,
          prov: curatedProvenance('public-research', 'Mitigation matrix (§4.1/§4.2)'),
          confidence: 'confirmed',
        });

        return finish({
          engine: ENGINE,
          tool: 'mitigation_strategy_compare',
          startedAt: started,
          ctx,
          data: {
            strategies,
            products: DEFENSE_PRODUCTS,
            productDisclaimer: PRODUCT_DISCLAIMER,
            markdown,
          },
          summary:
            `### Mitigation strategy comparison\n\n${markdown}\n\n` +
            `### Products (public documentation only)\n` +
            DEFENSE_PRODUCTS.map(
              (p) => `- **${p.name}** — ${p.architecture} Detection: ${p.detectionApproach}`,
            ).join('\n') +
            `\n\n_${PRODUCT_DISCLAIMER}_`,
        });
      },
    }),

    /* 9. defense_test_plan -------------------------------------------------- */
    defineTool<
      { systemDescription: string; scope?: string[]; labToken?: string },
      Record<string, unknown>
    >({
      name: 'defense_test_plan',
      title: 'Defense test plan',
      engine: ENGINE,
      description:
        'Produce a SAFE §4.4 test plan: objectives, isolated-lab topology, allowed RATE-LIMITED localhost/isolated ' +
        'generators, measurements and explicit hard limits/abort criteria. If labToken is supplied it is validated ' +
        'via the platform lab-authorization gate; otherwise only the PLAN is produced. Never an unthrottled generator.',
      capabilities: [],
      risk: 'safe',
      inputSchema: {
        systemDescription: z.string().min(3).describe('The defensive system under test.'),
        scope: z.array(z.string().min(1)).optional().describe('Attack classes to measure against.'),
        labToken: z.string().min(1).optional().describe('Lab authorization token (MIRAI_LAB_TOKEN).'),
      },
      handler: async (input, ctx) => {
        const started = Date.now();

        let authorization: 'not_provided' | 'validated' = 'not_provided';
        if (input.labToken !== undefined) {
          requireLabAuthorization(input.labToken);
          authorization = 'validated';
        }

        const plan = {
          systemDescription: input.systemDescription,
          scope: input.scope ?? ['syn_flood', 'udp_flood', 'http_flood', 'dns_amplification'],
          objectives: [
            'Measure detection rate per attack class.',
            'Measure false-positive rate on benign traffic.',
            'Measure false-negative rate (missed attacks).',
            'Measure mitigation latency (time-to-mitigate).',
            'Measure throughput under mitigation and CPU/memory impact.',
          ],
          topology: [
            'Fully isolated lab network or localhost-only loopback.',
            'Generator, sensor and system-under-test on the isolated segment.',
            'No path to any public or third-party network.',
          ],
          allowedGenerators: [
            'Synthetic generators configured with STRICT rate and duration caps.',
            'Pre-recorded PCAP replay inside the isolated lab.',
            'Localhost/loopback bounded tests only.',
          ],
          prohibited: [
            'Unthrottled flood generators.',
            'Distributed load generators.',
            'Source-address spoofing.',
            'Reflection/amplification launchers.',
            'Any public-target stress tooling.',
          ],
          measurements: [
            'Detection rate = detected attacks / total attacks.',
            'FP rate = benign sessions flagged / total benign sessions.',
            'FN rate = 1 - detection rate.',
            'Mitigation latency in seconds from attack start to mitigation.',
            'Throughput (req/s, pps) under mitigation.',
            'CPU and memory usage of the SUT and sensors.',
          ],
          hardLimits: [
            'Traffic strictly bound to the isolated segment / loopback.',
            'Generator rate capped at a documented maximum.',
            'Total test duration bounded (for example <= 5 minutes per run).',
            'Automatic stop on SUT resource saturation or sensor loss.',
          ],
          abortCriteria: [
            'Any traffic attempting to leave the isolated segment.',
            'SUT or sensor exceeding defined resource thresholds.',
            'Unexpected impact on non-test systems.',
          ],
          authorization,
        };

        addEvidence(ctx, {
          claim: `Produced a SAFE defense test plan (authorization: ${authorization}).`,
          prov: curatedProvenance('design', 'Anti-DDoS test plan (§4.4)'),
          confidence: 'inferred',
          data: { authorization },
        });

        const authNote =
          authorization === 'validated'
            ? 'Lab authorization token validated. Even so, this tool only produces the PLAN.'
            : 'No lab token provided: this tool ONLY produces the plan. Active testing requires the configured ' +
              'lab authorization token (MIRAI_LAB_TOKEN) and must remain isolated, rate- and duration-bounded.';

        return finish({
          engine: ENGINE,
          tool: 'defense_test_plan',
          startedAt: started,
          ctx,
          data: { plan, authNote },
          summary:
            `### Safe anti-DDoS test plan\n${authNote}\n\n` +
            `**Objectives**\n${plan.objectives.map((o) => `- ${o}`).join('\n')}\n\n` +
            `**Topology**\n${plan.topology.map((t) => `- ${t}`).join('\n')}\n\n` +
            `**Allowed generators**\n${plan.allowedGenerators.map((g) => `- ${g}`).join('\n')}\n\n` +
            `**Prohibited**\n${plan.prohibited.map((p) => `- ${p}`).join('\n')}\n\n` +
            `**Hard limits**: ${plan.hardLimits.join('; ')}.\n` +
            `**Abort criteria**: ${plan.abortCriteria.join('; ')}.`,
        });
      },
    }),

    /* 10. defense_performance_analyze -------------------------------------- */
    defineTool<
      { metricsPath?: string; metrics?: Record<string, number>; baseline?: Record<string, number> },
      Record<string, unknown>
    >({
      name: 'defense_performance_analyze',
      title: 'Defense performance analyze',
      engine: ENGINE,
      description:
        'Analyze defensive performance measurements (detection rate, FP/FN, mitigation latency, throughput, ' +
        'CPU/memory): compare against baseline, flag regressions and produce recommendations. Reads a JSON/CSV ' +
        'workspace file when metricsPath is provided.',
      capabilities: ['read_repo'],
      risk: 'safe',
      inputSchema: {
        metricsPath: z.string().min(1).optional().describe('Workspace-relative JSON/CSV metrics file.'),
        metrics: z.record(z.number()).optional().describe('Inline metric values.'),
        baseline: z.record(z.number()).optional().describe('Inline baseline values for comparison.'),
      },
      handler: async (input, ctx) => {
        const started = Date.now();
        let metrics = input.metrics ?? {};
        const baseline = input.baseline ?? {};

        if (input.metricsPath) {
          const artifact = readTextArtifact(input.metricsPath);
          const parsed = parseMetricsArtifact(artifact.content, input.metricsPath);
          metrics = { ...parsed, ...metrics };
          addEvidence(ctx, {
            claim: `Loaded ${Object.keys(parsed).length} metric(s) from ${input.metricsPath}.`,
            prov: localProvenance('metrics', artifact.path),
            confidence: 'observed',
            locator: { file: artifact.path },
          });
        }

        if (Object.keys(metrics).length === 0) {
          throw errors.invalidInput('No metrics supplied. Provide "metrics", "baseline" or "metricsPath".');
        }

        // Higher-is-better vs lower-is-better metric semantics.
        const higherIsBetter = (key: string): boolean =>
          /(detection|throughput|caught|recall|quality)/i.test(key);
        const lowerIsBetter = (key: string): boolean =>
          /(latency|false|fp|fn|cpu|mem|memory|drop|error|jitter)/i.test(key);

        const comparisons = Object.entries(metrics).map(([key, value]) => {
          const base = baseline[key];
          const deltaPct = base !== undefined && base !== 0 ? ((value - base) / base) * 100 : null;
          let regression = false;
          if (base !== undefined && deltaPct !== null) {
            if (higherIsBetter(key) && deltaPct < -10) regression = true;
            if (lowerIsBetter(key) && deltaPct > 10) regression = true;
          }
          return {
            metric: key,
            value,
            baseline: base ?? null,
            deltaPct: deltaPct !== null ? round(deltaPct, 2) : null,
            direction: higherIsBetter(key) ? 'higher_is_better' : lowerIsBetter(key) ? 'lower_is_better' : 'neutral',
            regression,
          };
        });

        const regressions = comparisons.filter((c) => c.regression);
        const recommendations: string[] = [];
        if (regressions.length) {
          recommendations.push(`Investigate regressions: ${regressions.map((r) => r.metric).join(', ')}.`);
        }
        const fpMetric = Object.entries(metrics).find(([k]) => /fp|false.?pos/i.test(k));
        if (fpMetric && fpMetric[1] > 5) {
          recommendations.push('False-positive rate above 5%: review allow-lists and thresholds.');
        }
        const latencyMetric = Object.entries(metrics).find(([k]) => /latency/i.test(k));
        if (latencyMetric && latencyMetric[1] > 60) {
          recommendations.push('Mitigation latency above 60 s: shorten detection window and automate escalation.');
        }
        if (recommendations.length === 0) recommendations.push('No regressions detected; continue periodic measurement.');

        addEvidence(ctx, {
          claim: `Analyzed ${comparisons.length} metric(s); ${regressions.length} regression(s) flagged.`,
          prov: curatedProvenance('analysis', 'Defense performance comparison'),
          confidence: 'inferred',
          data: { regressions: regressions.map((r) => r.metric) },
        });

        const summaryLines = [
          `Analyzed ${comparisons.length} metric(s) against baseline (${Object.keys(baseline).length} baseline value(s)).`,
          regressions.length ? `Regressions (${regressions.length}): ${regressions.map((r) => r.metric).join(', ')}.` : 'No regressions flagged.',
          `\n${comparisons.map((c) => `- ${c.metric}: ${c.value} (baseline ${c.baseline ?? 'n/a'}, Δ ${c.deltaPct ?? 'n/a'}%, ${c.direction})${c.regression ? ' ⚠regression' : ''}`).join('\n')}`,
          `\n**Recommendations**\n${recommendations.map((r) => `- ${r}`).join('\n')}`,
        ];

        return finish({
          engine: ENGINE,
          tool: 'defense_performance_analyze',
          startedAt: started,
          ctx,
          data: { comparisons, regressions: regressions.map((r) => r.metric), recommendations },
          summary: summaryLines.join('\n'),
        });
      },
    }),
  ],
};

/* -------------------------------------------------------------------------- */
/* Metrics artifact parsing (JSON / simple CSV)                               */
/* -------------------------------------------------------------------------- */

function parseMetricsArtifact(content: string, path: string): Record<string, number> {
  const trimmed = content.trim();
  if (trimmed.startsWith('{')) {
    try {
      const obj = JSON.parse(trimmed) as Record<string, unknown>;
      const out: Record<string, number> = {};
      for (const [k, v] of Object.entries(obj)) {
        const n = typeof v === 'number' ? v : Number(v);
        if (Number.isFinite(n)) out[k] = n;
      }
      return out;
    } catch {
      /* fall through to CSV */
    }
  }

  // CSV: either "metric,value" rows or a header + single value row.
  const lines = trimmed.split(/\r?\n/).filter((l) => l.trim().length > 0);
  if (lines.length === 0) return {};

  const looksHeader = /metric|name/i.test(lines[0] ?? '') && /value|number|count/i.test(lines[0] ?? '');
  const out: Record<string, number> = {};

  if (looksHeader) {
    const header = (lines[0] ?? '').split(',').map((h) => h.trim().toLowerCase());
    const metricIdx = Math.max(header.findIndex((h) => /metric|name/.test(h)), 0);
    const valueIdx = Math.max(header.findIndex((h) => /value|number|count/.test(h)), 1);
    for (const line of lines.slice(1)) {
      const cols = line.split(',').map((c) => c.trim());
      const key = cols[metricIdx];
      const value = Number(cols[valueIdx]);
      if (key && Number.isFinite(value)) out[key] = value;
    }
    return out;
  }

  for (const line of lines) {
    const [key, value] = line.split(',').map((c) => c.trim());
    if (key && value !== undefined) {
      const n = Number(value);
      if (Number.isFinite(n)) out[key] = n;
    }
  }
  if (Object.keys(out).length === 0) {
    throw errors.invalidInput(`Could not parse metrics from "${path}" as JSON or CSV.`, { path });
  }
  return out;
}

/** Re-exported for documentation/tests. */
export { DEFENSE_PRODUCTS, MITIGATION_STRATEGIES, DEFENSE_TECHNOLOGIES } from './catalogue.js';
export { parsePcap } from './pcap.js';
