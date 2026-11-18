/**
 * Network Forensics engine (§6, §11).
 *
 * Read-only analysis of packet captures. All decoding is performed locally in
 * pure JS; encrypted traffic is never decrypted — only TLS metadata is read.
 * Findings are reported with provenance and confidence, and defensive notes
 * accompany any indicator that could otherwise be a false positive.
 */

import { createHash } from 'node:crypto';

import { z } from 'zod';

import { errors } from '../../core/errors.js';
import { discoverTools, runCommand, type ExecResult } from '../../shared/exec.js';
import { getKnowledgeBase } from '../../shared/knowledge-base.js';
import {
  addEvidence,
  curatedProvenance,
  defineTool,
  finish,
  localProvenance,
  readBinaryArtifact,
  zodCommon,
} from '../../tools/helpers.js';
import { getConfig } from '../../config/index.js';
import {
  flowKey,
  directionalKey,
  isPrivateIPv4,
  packetTime,
  parsePcap,
  type PcapPacket,
  type PcapParseResult,
} from './pcap.js';
import type { EngineModule } from '../../core/tool.js';
import type { ConfidenceLevel, Provenance } from '../../shared/types.js';

const ENGINE = 'network-forensics';

/* ------------------------------------------------------------------ */
/* Shared utilities                                                    */
/* ------------------------------------------------------------------ */

interface LoadedCapture {
  abs: string;
  buffer: Buffer;
  parsed: PcapParseResult;
  provenance: Provenance;
}

function loadCapture(pcapPath: string): LoadedCapture {
  const art = readBinaryArtifact(pcapPath);
  const parsed = parsePcap(art.buffer);
  return {
    abs: art.path,
    buffer: art.buffer,
    parsed,
    provenance: localProvenance('pcap', art.path, 'packet capture'),
  };
}

async function tryRun(command: string, args: string[], cwd?: string): Promise<ExecResult | undefined> {
  if (!getConfig().allowIsolatedExec) return undefined;
  try {
    return await runCommand(command, {
      args,
      ...(cwd ? { cwd } : {}),
      timeoutMs: 60_000,
      maxOutputBytes: 256 * 1024,
    });
  } catch {
    return undefined;
  }
}

function topEntries(map: Map<string, number>, n: number): { key: string; count: number }[] {
  return [...map.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([key, count]) => ({ key, count }));
}

function bump(map: Map<string, number>, key: string, by = 1): void {
  map.set(key, (map.get(key) ?? 0) + by);
}

function median(values: number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  if (sorted.length % 2 === 1) return sorted[mid] ?? 0;
  return ((sorted[mid - 1] ?? 0) + (sorted[mid] ?? 0)) / 2;
}

function mean(values: number[]): number {
  if (values.length === 0) return 0;
  return values.reduce((a, b) => a + b, 0) / values.length;
}

function stddev(values: number[]): number {
  if (values.length < 2) return 0;
  const m = mean(values);
  return Math.sqrt(values.reduce((a, b) => a + (b - m) ** 2, 0) / (values.length - 1));
}

function labelEntropy(label: string): number {
  if (label.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of label) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of counts.values()) {
    const p = c / label.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function payloadOf(pkt: PcapPacket): Buffer | undefined {
  return pkt.payload && pkt.payload.length > 0 ? pkt.payload : undefined;
}

/* ------------------------------------------------------------------ */
/* DNS parser                                                          */
/* ------------------------------------------------------------------ */

interface DnsAnswer {
  name: string;
  type: number;
  typeName: string;
  data: string;
}

interface DnsMessage {
  id: number;
  qr: boolean;
  aa: boolean;
  rd: boolean;
  ra: boolean;
  rcode: number;
  questions: { name: string; type: number; typeName: string }[];
  answers: DnsAnswer[];
}

const DNS_TYPE: Record<number, string> = {
  1: 'A',
  2: 'NS',
  5: 'CNAME',
  6: 'SOA',
  12: 'PTR',
  15: 'MX',
  16: 'TXT',
  28: 'AAAA',
  33: 'SRV',
  41: 'OPT',
  43: 'DS',
  46: 'RRSIG',
  65: 'HTTPS',
  255: 'ANY',
};

function readDnsName(buf: Buffer, start: number): { name: string; next: number } {
  const labels: string[] = [];
  let pos = start;
  let next = start;
  let jumped = false;
  let guard = 0;
  while (pos < buf.length && guard < 128) {
    guard += 1;
    const len = buf.readUInt8(pos);
    if (len === 0) {
      pos += 1;
      if (!jumped) next = pos;
      break;
    }
    if ((len & 0xc0) === 0xc0) {
      if (pos + 1 >= buf.length) break;
      const ptr = ((len & 0x3f) << 8) | buf.readUInt8(pos + 1);
      if (!jumped) next = pos + 2;
      jumped = true;
      if (ptr >= buf.length) break;
      pos = ptr;
      continue;
    }
    const end = pos + 1 + len;
    if (end > buf.length) break;
    labels.push(buf.toString('latin1', pos + 1, end));
    pos = end;
    if (!jumped) next = pos;
  }
  return { name: labels.join('.'), next: jumped ? next : pos };
}

function parseDnsWire(buf: Buffer): DnsMessage | undefined {
  if (buf.length < 12) return undefined;
  const id = buf.readUInt16BE(0);
  const flags = buf.readUInt16BE(2);
  const qdcount = buf.readUInt16BE(4);
  const ancount = buf.readUInt16BE(6);
  const qr = (flags & 0x8000) !== 0;
  const aa = (flags & 0x0400) !== 0;
  const rd = (flags & 0x0100) !== 0;
  const ra = (flags & 0x0080) !== 0;
  const rcode = flags & 0x000f;

  const questions: DnsMessage['questions'] = [];
  const answers: DnsAnswer[] = [];
  let pos = 12;

  for (let i = 0; i < qdcount && pos + 4 <= buf.length; i += 1) {
    const { name, next } = readDnsName(buf, pos);
    pos = next;
    if (pos + 4 > buf.length) break;
    const type = buf.readUInt16BE(pos);
    pos += 4;
    questions.push({ name, type, typeName: DNS_TYPE[type] ?? `TYPE${type}` });
  }

  for (let i = 0; i < ancount && pos + 10 <= buf.length; i += 1) {
    const { name, next } = readDnsName(buf, pos);
    pos = next;
    if (pos + 10 > buf.length) break;
    const type = buf.readUInt16BE(pos);
    const rdlength = buf.readUInt16BE(pos + 8);
    pos += 10;
    const rdataStart = pos;
    let data = '';
    if (type === 1 && rdlength === 4 && rdataStart + 4 <= buf.length) {
      data = `${buf.readUInt8(rdataStart)}.${buf.readUInt8(rdataStart + 1)}.${buf.readUInt8(rdataStart + 2)}.${buf.readUInt8(rdataStart + 3)}`;
    } else if (type === 28 && rdlength === 16 && rdataStart + 16 <= buf.length) {
      const groups: string[] = [];
      for (let g = 0; g < 8; g += 1) groups.push(buf.readUInt16BE(rdataStart + g * 2).toString(16));
      data = groups.join(':');
    } else if ((type === 5 || type === 2 || type === 12) && rdataStart + rdlength <= buf.length) {
      data = readDnsName(buf, rdataStart).name;
    }
    pos = rdataStart + rdlength;
    answers.push({ name, type, typeName: DNS_TYPE[type] ?? `TYPE${type}`, data });
  }

  return { id, qr, aa, rd, ra, rcode, questions, answers };
}

/* ------------------------------------------------------------------ */
/* TLS metadata parser                                                 */
/* ------------------------------------------------------------------ */

interface TlsClientHello {
  version: number;
  cipherSuites: number[];
  extensions: number[];
  curves: number[];
  pointFormats: number[];
  sni?: string;
  alpn: string[];
}

interface TlsCertInfo {
  subjectCn: string[];
  issuerCn: string[];
}

function parseClientHello(frag: Buffer): TlsClientHello | undefined {
  try {
    if (frag.length < 38) return undefined;
    let pos = 0;
    const version = frag.readUInt16BE(pos);
    pos += 2 + 32; // version + random
    const sessionLen = frag.readUInt8(pos);
    pos += 1 + sessionLen;
    if (pos + 2 > frag.length) return undefined;
    const csLen = frag.readUInt16BE(pos);
    pos += 2;
    const cipherSuites: number[] = [];
    for (let i = 0; i + 1 < csLen && pos + 2 <= frag.length; i += 2) {
      cipherSuites.push(frag.readUInt16BE(pos));
      pos += 2;
    }
    pos += csLen % 2 === 0 ? 0 : 0; // cipher suites are even-length
    if (pos + 1 > frag.length) return { version, cipherSuites, extensions: [], curves: [], pointFormats: [], alpn: [] };
    const compLen = frag.readUInt8(pos);
    pos += 1 + compLen;
    const result: TlsClientHello = { version, cipherSuites, extensions: [], curves: [], pointFormats: [], alpn: [] };
    if (pos + 2 > frag.length) return result;
    const extTotal = frag.readUInt16BE(pos);
    pos += 2;
    const extEnd = Math.min(pos + extTotal, frag.length);
    while (pos + 4 <= extEnd) {
      const extType = frag.readUInt16BE(pos);
      const extLen = frag.readUInt16BE(pos + 2);
      pos += 4;
      const extEndPos = Math.min(pos + extLen, frag.length);
      result.extensions.push(extType);
      if (extType === 0) {
        // server_name
        if (pos + 5 <= extEndPos) {
          const listLen = frag.readUInt16BE(pos);
          let s = pos + 2;
          const listEnd = Math.min(s + listLen, extEndPos);
          while (s + 3 <= listEnd) {
            const nameType = frag.readUInt8(s);
            const nameLen = frag.readUInt16BE(s + 1);
            s += 3;
            if (nameType === 0 && s + nameLen <= listEnd) {
              result.sni = frag.toString('latin1', s, s + nameLen);
              break;
            }
            s += nameLen;
          }
        }
      } else if (extType === 10) {
        // supported_groups
        if (pos + 2 <= extEndPos) {
          const listLen = frag.readUInt16BE(pos);
          let s = pos + 2;
          const listEnd = Math.min(s + listLen, extEndPos);
          while (s + 2 <= listEnd) {
            result.curves.push(frag.readUInt16BE(s));
            s += 2;
          }
        }
      } else if (extType === 11) {
        // ec_point_formats
        if (pos + 1 <= extEndPos) {
          const listLen = frag.readUInt8(pos);
          let s = pos + 1;
          const listEnd = Math.min(s + listLen, extEndPos);
          while (s < listEnd) {
            result.pointFormats.push(frag.readUInt8(s));
            s += 1;
          }
        }
      } else if (extType === 16) {
        // ALPN
        if (pos + 2 <= extEndPos) {
          const listLen = frag.readUInt16BE(pos);
          let s = pos + 2;
          const listEnd = Math.min(s + listLen, extEndPos);
          while (s + 1 <= listEnd) {
            const protoLen = frag.readUInt8(s);
            s += 1;
            if (s + protoLen > listEnd) break;
            result.alpn.push(frag.toString('latin1', s, s + protoLen));
            s += protoLen;
          }
        }
      }
      pos = extEndPos;
    }
    return result;
  } catch {
    return undefined;
  }
}

/** Parse just enough DER to recover common-name strings from a certificate. */
function parseDerCommonNames(der: Buffer, wanted: string): string[] {
  const out: string[] = [];
  // Very small TLV walk that looks for OID 2.5.4.3 (commonName) then the following string.
  for (let i = 0; i + 4 < der.length; i += 1) {
    // OID 2.5.4.3 = 06 03 55 04 03
    if (der.readUInt8(i) === 0x06 && der.readUInt8(i + 1) === 0x03 && der.readUInt8(i + 2) === 0x55 && der.readUInt8(i + 3) === 0x04 && der.readUInt8(i + 4) === 0x03) {
      // Skip the OID, then find the next string TLV (0x0c UTF8String, 0x13 PrintableString, 0x16 IA5String).
      let j = i + 5;
      while (j + 2 < der.length) {
        const tag = der.readUInt8(j);
        if (tag === 0x0c || tag === 0x13 || tag === 0x16) {
          const len = der.readUInt8(j + 1);
          if (j + 2 + len <= der.length) {
            out.push(der.toString('utf8', j + 2, j + 2 + len));
            if (out.length >= 32) return out;
          }
          break;
        }
        if (tag === 0x30 || tag === 0x31 || tag === 0x06) break;
        j += 1;
      }
    }
  }
  void wanted;
  return out;
}

/** Apply a tiny stateful TLS record reassembler per flow and yield records. */
function tlsRecords(payloads: Buffer[], concatenate = true): { contentType: number; version: number; fragment: Buffer }[] {
  const combined = concatenate ? Buffer.concat(payloads) : Buffer.concat([]);
  const records: { contentType: number; version: number; fragment: Buffer }[] = [];
  let pos = 0;
  let guard = 0;
  while (pos + 5 <= combined.length && guard < 10_000) {
    guard += 1;
    const contentType = combined.readUInt8(pos);
    const version = combined.readUInt16BE(pos + 1);
    const length = combined.readUInt16BE(pos + 3);
    if (pos + 5 + length > combined.length) break;
    records.push({ contentType, version, fragment: combined.subarray(pos + 5, pos + 5 + length) });
    pos += 5 + length;
  }
  return records;
}

/* ------------------------------------------------------------------ */
/* Flow accumulation                                                   */
/* ------------------------------------------------------------------ */

interface FlowAgg {
  key: string;
  src: string;
  dst: string;
  srcPort: number;
  dstPort: number;
  proto: string;
  packets: number;
  bytes: number;
  first: number;
  last: number;
  flags: Set<string>;
  payload: Buffer[];
  payloadBytes: number;
}

function buildFlows(packets: PcapPacket[], bidirectional = true): Map<string, FlowAgg> {
  const flows = new Map<string, FlowAgg>();
  for (const pkt of packets) {
    const key = bidirectional ? flowKey(pkt) : directionalKey(pkt);
    let flow = flows.get(key);
    if (!flow) {
      flow = {
        key,
        src: pkt.src ?? '?',
        dst: pkt.dst ?? '?',
        srcPort: pkt.srcPort ?? 0,
        dstPort: pkt.dstPort ?? 0,
        proto: pkt.protocol,
        packets: 0,
        bytes: 0,
        first: packetTime(pkt),
        last: packetTime(pkt),
        flags: new Set(),
        payload: [],
        payloadBytes: 0,
      };
      flows.set(key, flow);
    }
    flow.packets += 1;
    flow.bytes += pkt.origLen;
    const t = packetTime(pkt);
    if (t < flow.first) flow.first = t;
    if (t > flow.last) flow.last = t;
    if (pkt.tcpFlags) {
      if (pkt.tcpFlags.syn) flow.flags.add('SYN');
      if (pkt.tcpFlags.ack) flow.flags.add('ACK');
      if (pkt.tcpFlags.fin) flow.flags.add('FIN');
      if (pkt.tcpFlags.rst) flow.flags.add('RST');
      if (pkt.tcpFlags.psh) flow.flags.add('PSH');
      if (pkt.tcpFlags.urg) flow.flags.add('URG');
    }
    const payload = payloadOf(pkt);
    if (payload && flow.payloadBytes < 4 * 1024 * 1024) {
      flow.payload.push(payload);
      flow.payloadBytes += payload.length;
    }
  }
  return flows;
}

/* ------------------------------------------------------------------ */
/* Tool 1 — pcap_flow_analyze                                          */
/* ------------------------------------------------------------------ */

interface FlowAnalyzeResult {
  magic: string;
  linkType: number;
  parseErrors: string[];
  packetCount: number;
  byteTotal: number;
  protocolDist: { key: string; count: number }[];
  topSrcIps: { key: string; count: number }[];
  topDstIps: { key: string; count: number }[];
  topPorts: { key: string; count: number }[];
  topConversations: { key: string; count: number }[];
  tcpFlags: { key: string; count: number }[];
  avgPacketSize: number;
  medianPacketSize: number;
  packetsPerSecond: number;
  uniqueIps: number;
  tsharkProtocolHierarchy?: string;
}

const flowAnalyzeTool = defineTool<{ pcapPath: string; topN?: number }, FlowAnalyzeResult>({
  name: 'pcap_flow_analyze',
  title: 'PCAP flow statistics',
  engine: ENGINE,
  description:
    'Parse a packet capture and aggregate high-level flow statistics: packet/byte totals, protocol ' +
    'distribution, top source/destination IPs and ports, top conversations, TCP flag distribution, ' +
    'average/median packet size, packets-per-second and unique-IP cardinality. If tshark is available ' +
    'its protocol-hierarchy summary is included. Read-only.',
  capabilities: ['read_pcap'],
  risk: 'safe',
  inputSchema: { pcapPath: zodCommon.filePath, topN: z.number().int().min(1).max(100).optional() },
  handler: async (input, ctx) => {
    const started = Date.now();
    const topN = input.topN ?? 10;
    const { abs, parsed, provenance } = loadCapture(input.pcapPath);
    if (parsed.packets.length === 0 && parsed.magic === 'unknown') {
      throw errors.invalidInput(`${abs} is not a recognised PCAP/PCAPNG capture.`, { errors: parsed.errors });
    }

    const protocolDist = new Map<string, number>();
    const srcIps = new Map<string, number>();
    const dstIps = new Map<string, number>();
    const ports = new Map<string, number>();
    const conversations = new Map<string, number>();
    const tcpFlags = new Map<string, number>();
    const ips = new Set<string>();
    const sizes: number[] = [];
    let byteTotal = 0;
    let first = Infinity;
    let last = -Infinity;

    for (const pkt of parsed.packets) {
      bump(protocolDist, pkt.protocol);
      byteTotal += pkt.origLen;
      sizes.push(pkt.origLen);
      if (pkt.src) {
        bump(srcIps, pkt.src);
        ips.add(pkt.src);
      }
      if (pkt.dst) {
        bump(dstIps, pkt.dst);
        ips.add(pkt.dst);
      }
      if (pkt.dstPort !== undefined && pkt.dstPort > 0) bump(ports, String(pkt.dstPort));
      if (pkt.srcPort !== undefined && pkt.srcPort > 0) bump(ports, String(pkt.srcPort));
      const conv = `${pkt.src ?? '?'} -> ${pkt.dst ?? '?'}${pkt.dstPort ? ':' + pkt.dstPort : ''}`;
      bump(conversations, conv);
      if (pkt.tcpFlags) {
        if (pkt.tcpFlags.syn) bump(tcpFlags, 'SYN');
        if (pkt.tcpFlags.ack) bump(tcpFlags, 'ACK');
        if (pkt.tcpFlags.fin) bump(tcpFlags, 'FIN');
        if (pkt.tcpFlags.rst) bump(tcpFlags, 'RST');
        if (pkt.tcpFlags.psh) bump(tcpFlags, 'PSH');
        if (pkt.tcpFlags.urg) bump(tcpFlags, 'URG');
      }
      const t = packetTime(pkt);
      if (t > 0 && t < first) first = t;
      if (t > last) last = t;
    }

    const duration = Number.isFinite(first) && last > first ? last - first : 0;
    const pps = duration > 0 ? parsed.packets.length / duration : 0;

    let tsharkProtocolHierarchy: string | undefined;
    const available = await discoverTools(['tshark']);
    if (available['tshark'] === true) {
      const res = await tryRun('tshark', ['-r', abs, '-q', '-z', 'io,phs']);
      if (res) tsharkProtocolHierarchy = (res.stdout || res.stderr).trim().slice(0, 8192);
    }

    addEvidence(ctx, {
      claim: `Capture summarised: ${parsed.packets.length} packets, ${byteTotal} bytes, ${ips.size} unique IPs, ${duration.toFixed(3)}s span.`,
      prov: provenance,
      confidence: 'observed',
      data: { magic: parsed.magic, protocolDist: Object.fromEntries(protocolDist) },
    });
    for (const err of parsed.errors.slice(0, 5)) ctx.evidence.warn(`Parser note: ${err}`);

    const kb = getKnowledgeBase();
    const pcapDigest = createHash('sha256').update(abs).digest('hex').slice(0, 16);
    const nodeId = `pcap_evidence:${pcapDigest}`;
    kb.upsertNode({
      id: nodeId,
      kind: 'pcap_evidence',
      label: abs,
      properties: { packets: parsed.packets.length, bytes: byteTotal, uniqueIps: ips.size },
      provenance: [provenance],
      confidence: 'observed',
    });

    const summary =
      `## PCAP flow analysis — ${abs}\n` +
      `- Format: ${parsed.magic}; link type ${parsed.linkType}\n` +
      `- Packets: ${parsed.packets.length}; bytes: ${byteTotal}; unique IPs: ${ips.size}\n` +
      `- Avg packet size: ${mean(sizes).toFixed(1)} B; median: ${median(sizes).toFixed(1)} B\n` +
      `- Capture span: ${duration.toFixed(3)}s; ~${pps.toFixed(2)} packets/s\n` +
      `- Protocols: ${topEntries(protocolDist, topN).map((e) => `${e.key}:${e.count}`).join(', ')}\n` +
      `- Top sources: ${topEntries(srcIps, topN).map((e) => `${e.key}(${e.count})`).join(', ') || 'n/a'}\n` +
      `- Top destinations: ${topEntries(dstIps, topN).map((e) => `${e.key}(${e.count})`).join(', ') || 'n/a'}\n` +
      `- Top ports: ${topEntries(ports, topN).map((e) => `${e.key}(${e.count})`).join(', ') || 'n/a'}\n` +
      `- TCP flags: ${topEntries(tcpFlags, 8).map((e) => `${e.key}:${e.count}`).join(', ') || 'n/a'}` +
      (tsharkProtocolHierarchy ? `\n\n### tshark io,phs\n\`\`\`\n${tsharkProtocolHierarchy}\n\`\`\`` : '');

    return finish({
      engine: ENGINE,
      tool: 'pcap_flow_analyze',
      startedAt: started,
      ctx,
      summary,
      data: {
        magic: parsed.magic,
        linkType: parsed.linkType,
        parseErrors: parsed.errors,
        packetCount: parsed.packets.length,
        byteTotal,
        protocolDist: topEntries(protocolDist, topN),
        topSrcIps: topEntries(srcIps, topN),
        topDstIps: topEntries(dstIps, topN),
        topPorts: topEntries(ports, topN),
        topConversations: topEntries(conversations, topN),
        tcpFlags: topEntries(tcpFlags, 8),
        avgPacketSize: Number(mean(sizes).toFixed(2)),
        medianPacketSize: Number(median(sizes).toFixed(2)),
        packetsPerSecond: Number(pps.toFixed(3)),
        uniqueIps: ips.size,
        ...(tsharkProtocolHierarchy ? { tsharkProtocolHierarchy } : {}),
      },
    });
  },
});

/* ------------------------------------------------------------------ */
/* Tool 2 — pcap_dns_analyze                                           */
/* ------------------------------------------------------------------ */

interface DnsAnalyzeResult {
  dnsMessageCount: number;
  queryCount: number;
  responseCount: number;
  topQueryNames: { key: string; count: number }[];
  queryTypeDist: { key: string; count: number }[];
  nxdomainCount: number;
  nxdomainRatio: number;
  responseSizeDistribution: { key: string; count: number }[];
  tunnelingSignals: string[];
  findings: string[];
}

const dnsAnalyzeTool = defineTool<{ pcapPath: string; topN?: number }, DnsAnalyzeResult>({
  name: 'pcap_dns_analyze',
  title: 'DNS traffic analysis',
  engine: ENGINE,
  description:
    'Parse DNS over UDP/TCP in pure JS: transaction ids, flags (QR/AA/RD/RA/rcode), question names and ' +
    'types, and answer A/AAAA records. Computes per-name query counts, NXDOMAIN ratio, query-type ' +
    'distribution, response-size distribution (a reflection/amplification indicator) and detects ' +
    'DNS-tunnelling signals (long or high-entropy labels, high query rates). Read-only, with defensive notes.',
  capabilities: ['read_pcap'],
  risk: 'safe',
  inputSchema: { pcapPath: zodCommon.filePath, topN: z.number().int().min(1).max(100).optional() },
  handler: async (input, ctx) => {
    const started = Date.now();
    const topN = input.topN ?? 15;
    const { parsed, provenance } = loadCapture(input.pcapPath);

    const queryNames = new Map<string, number>();
    const queryTypes = new Map<string, number>();
    const responseSizes = new Map<string, number>();
    const querySizesById = new Map<number, number>();
    const tunnelingSignals: string[] = [];
    const longLabelNames = new Set<string>();
    const highEntropyNames = new Set<string>();
    let dnsMessageCount = 0;
    let queryCount = 0;
    let responseCount = 0;
    let nxdomainCount = 0;

    for (const pkt of parsed.packets) {
      const isDns =
        pkt.protocol === 'udp' && (pkt.srcPort === 53 || pkt.dstPort === 53);
      const isDnsTcp = pkt.protocol === 'tcp' && (pkt.srcPort === 53 || pkt.dstPort === 53);
      if (!isDns && !isDnsTcp) continue;
      const payload = payloadOf(pkt);
      if (!payload) continue;
      let wire = payload;
      if (isDnsTcp) {
        if (payload.length < 2) continue;
        const claimed = payload.readUInt16BE(0);
        wire = payload.subarray(2, Math.min(2 + claimed, payload.length));
      }
      const msg = parseDnsWire(wire);
      if (!msg) continue;
      dnsMessageCount += 1;
      if (msg.qr) {
        responseCount += 1;
        if (msg.rcode === 3) nxdomainCount += 1;
        const q = querySizesById.get(msg.id);
        const bucket = q !== undefined ? (wire.length > q * 4 ? 'large-response (>4x query)' : wire.length > q ? 'larger-than-query' : 'small-response') : 'unknown';
        bump(responseSizes, bucket);
      } else {
        queryCount += 1;
        querySizesById.set(msg.id, wire.length);
        for (const question of msg.questions) {
          bump(queryNames, question.name);
          bump(queryTypes, question.typeName);
          const labels = question.name.split('.');
          if (labels.some((l) => l.length > 30)) longLabelNames.add(question.name);
          if (labels.some((l) => l.length >= 12 && labelEntropy(l) > 3.5)) highEntropyNames.add(question.name);
        }
      }
    }

    if (longLabelNames.size > 0) {
      tunnelingSignals.push(`${longLabelNames.size} query name(s) contain labels longer than 30 characters (possible DNS tunnelling).`);
    }
    if (highEntropyNames.size > 0) {
      tunnelingSignals.push(`${highEntropyNames.size} query name(s) contain high-entropy labels (possible encoded payload).`);
    }
    const topNameEntry = topEntries(queryNames, 1)[0];
    if (topNameEntry && queryCount > 0 && topNameEntry.count / queryCount > 0.5 && queryCount >= 20) {
      tunnelingSignals.push(`A single name ("${topNameEntry.key}") accounts for >50% of ${queryCount} queries (possible beaconing/exfiltration to one authoritative name).`);
    }
    const nxdomainRatio = responseCount > 0 ? nxdomainCount / responseCount : 0;
    if (nxdomainRatio > 0.4 && responseCount >= 20) {
      tunnelingSignals.push(`High NXDOMAIN ratio (${(nxdomainRatio * 100).toFixed(1)}%) may indicate DGA or tunnelling.`);
    }
    if (queryTypes.has('TXT') && (queryTypes.get('TXT') ?? 0) > 10) {
      tunnelingSignals.push(`Elevated TXT queries (${queryTypes.get('TXT')}) — a common DNS-tunnelling channel.`);
    }

    const findings = [
      `${dnsMessageCount} DNS messages (${queryCount} queries / ${responseCount} responses).`,
      ...tunnelingSignals,
    ];

    addEvidence(ctx, {
      claim: `DNS analysed: ${queryCount} queries, ${responseCount} responses, NXDOMAIN ratio ${(nxdomainRatio * 100).toFixed(1)}%.`,
      prov: provenance,
      confidence: 'observed',
      data: { queryCount, responseCount, nxdomainCount },
    });
    for (const signal of tunnelingSignals) {
      addEvidence(ctx, {
        claim: signal,
        prov: provenance,
        confidence: 'hypothesis',
      });
    }
    if (parsed.errors.length) for (const err of parsed.errors.slice(0, 3)) ctx.evidence.warn(`Parser note: ${err}`);

    const summary =
      `## DNS analysis\n` +
      `- Messages: ${dnsMessageCount} (queries ${queryCount}, responses ${responseCount})\n` +
      `- NXDOMAIN: ${nxdomainCount} (${(nxdomainRatio * 100).toFixed(1)}% of responses)\n` +
      `- Query types: ${topEntries(queryTypes, topN).map((e) => `${e.key}:${e.count}`).join(', ') || 'n/a'}\n` +
      `- Top names: ${topEntries(queryNames, topN).map((e) => `${e.key}(${e.count})`).join(', ') || 'n/a'}\n` +
      `- Response-size buckets: ${topEntries(responseSizes, 5).map((e) => `${e.key}:${e.count}`).join(', ') || 'n/a'}\n\n` +
      `### Tunnelling signals\n${tunnelingSignals.length ? tunnelingSignals.map((s) => `- ${s}`).join('\n') : '- none detected'}\n\n` +
      `> Defensive note: these are heuristic indicators. Validate against baseline behaviour; legitimise ` +
      `large responses (e.g. DNSSEC) and CDNs before acting.`;

    return finish({
      engine: ENGINE,
      tool: 'pcap_dns_analyze',
      startedAt: started,
      ctx,
      summary,
      data: {
        dnsMessageCount,
        queryCount,
        responseCount,
        topQueryNames: topEntries(queryNames, topN),
        queryTypeDist: topEntries(queryTypes, topN),
        nxdomainCount,
        nxdomainRatio: Number(nxdomainRatio.toFixed(3)),
        responseSizeDistribution: topEntries(responseSizes, 5),
        tunnelingSignals,
        findings,
      },
    });
  },
});

/* ------------------------------------------------------------------ */
/* Tool 3 — pcap_http_analyze                                          */
/* ------------------------------------------------------------------ */

interface HttpAnalyzeResult {
  requestCount: number;
  methods: { key: string; count: number }[];
  hosts: { key: string; count: number }[];
  topPaths: { key: string; count: number }[];
  userAgents: { key: string; count: number }[];
  statusCodes: { key: string; count: number }[];
  requestsPerConnection: number;
  floodFlags: string[];
  tlsNote: string;
}

const REQUEST_LINE = /(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)\s+(\S+)\s+HTTP\/1\.[01]/g;
const STATUS_LINE = /^HTTP\/1\.[01]\s+(\d{3})/;

const httpAnalyzeTool = defineTool<{ pcapPath: string; topN?: number }, HttpAnalyzeResult>({
  name: 'pcap_http_analyze',
  title: 'HTTP traffic analysis',
  engine: ENGINE,
  description:
    'Reconstruct HTTP/1.x request lines and headers from unencrypted TCP payloads (best effort): ' +
    'methods, Host headers, paths, User-Agents and response status codes. Computes method distribution, ' +
    'path cardinality, User-Agent diversity, requests-per-connection and flags flood-like patterns. ' +
    'TLS-encrypted HTTP cannot be inspected and is explicitly noted. Read-only.',
  capabilities: ['read_pcap'],
  risk: 'safe',
  inputSchema: { pcapPath: zodCommon.filePath, topN: z.number().int().min(1).max(100).optional() },
  handler: async (input, ctx) => {
    const started = Date.now();
    const topN = input.topN ?? 15;
    const { parsed, provenance } = loadCapture(input.pcapPath);

    // Group client->server payloads per connection for request extraction.
    const connPayloads = new Map<string, Buffer[]>();
    const hosts = new Map<string, number>();
    const methods = new Map<string, number>();
    const paths = new Map<string, number>();
    const userAgents = new Map<string, number>();
    const statusCodes = new Map<string, number>();
    let requestCount = 0;

    for (const pkt of parsed.packets) {
      if (pkt.protocol !== 'tcp') continue;
      const payload = payloadOf(pkt);
      if (!payload) continue;
      const key = `${pkt.src ?? '?'}:${pkt.srcPort ?? 0}->${pkt.dst ?? '?'}:${pkt.dstPort ?? 0}`;
      const list = connPayloads.get(key) ?? [];
      if (list.reduce((a, b) => a + b.length, 0) < 2 * 1024 * 1024) list.push(payload);
      connPayloads.set(key, list);
    }

    for (const list of connPayloads.values()) {
      const data = Buffer.concat(list).toString('latin1');
      if (!/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT) /m.test(data) && !STATUS_LINE.test(data)) continue;

      REQUEST_LINE.lastIndex = 0;
      let match = REQUEST_LINE.exec(data);
      while (match) {
        requestCount += 1;
        if (match[1]) bump(methods, match[1]);
        if (match[2]) bump(paths, match[2].split('?')[0] ?? match[2]);
        match = REQUEST_LINE.exec(data);
      }
      const hostMatches = data.matchAll(/^Host:\s*(\S+)/gim);
      for (const h of hostMatches) if (h[1]) bump(hosts, h[1]);
      const uaMatches = data.matchAll(/^User-Agent:\s*(.+)$/gim);
      for (const ua of uaMatches) if (ua[1]) bump(userAgents, ua[1].trim().slice(0, 200));
      for (const line of data.split(/\r?\n/)) {
        const s = STATUS_LINE.exec(line);
        if (s && s[1]) bump(statusCodes, s[1]);
      }
    }

    const connectionCount = connPayloads.size;
    const requestsPerConnection = connectionCount > 0 ? requestCount / connectionCount : 0;
    const floodFlags: string[] = [];
    if (requestsPerConnection > 50 && requestCount >= 100) {
      floodFlags.push(`High requests-per-connection (${requestsPerConnection.toFixed(1)}) — possible request flooding or a crawler.`);
    }
    const topMethod = topEntries(methods, 1)[0];
    if (topMethod && topMethod.key === 'POST' && requestCount >= 100 && topMethod.count / requestCount > 0.9) {
      floodFlags.push('Overwhelmingly POST traffic — possible login/credential flood; verify against baselines.');
    }
    if (userAgents.size === 1 && requestCount >= 100) {
      floodFlags.push('A single User-Agent across many requests — possible automated tool traffic.');
    }

    const tlsNote =
      'Only cleartext HTTP/1.x is decoded. HTTP over TLS (HTTPS) is opaque here; use ' +
      'pcap_tls_metadata_analyze for TLS metadata. HTTP/2 and HTTP/3 are not reconstructed.';

    addEvidence(ctx, {
      claim: `HTTP analysed: ${requestCount} requests across ${connectionCount} connections; ${hosts.size} hosts, ${paths.size} unique paths.`,
      prov: provenance,
      confidence: 'observed',
      data: { methods: Object.fromEntries(methods), hosts: topEntries(hosts, 5) },
    });
    for (const flag of floodFlags) addEvidence(ctx, { claim: flag, prov: provenance, confidence: 'hypothesis' });

    const summary =
      `## HTTP analysis\n` +
      `- Requests: ${requestCount} across ${connectionCount} connections (${requestsPerConnection.toFixed(2)} req/conn)\n` +
      `- Methods: ${topEntries(methods, topN).map((e) => `${e.key}:${e.count}`).join(', ') || 'n/a'}\n` +
      `- Hosts: ${topEntries(hosts, topN).map((e) => `${e.key}(${e.count})`).join(', ') || 'n/a'}\n` +
      `- Top paths: ${topEntries(paths, topN).map((e) => `${e.key}(${e.count})`).join(', ') || 'n/a'}\n` +
      `- User-Agents: ${topEntries(userAgents, topN).map((e) => `${e.key}(${e.count})`).join(', ') || 'n/a'}\n` +
      `- Status codes: ${topEntries(statusCodes, topN).map((e) => `${e.key}:${e.count}`).join(', ') || 'n/a'}\n\n` +
      `### Flood-like flags\n${floodFlags.length ? floodFlags.map((f) => `- ${f}`).join('\n') : '- none detected'}\n\n` +
      `> ${tlsNote}`;

    return finish({
      engine: ENGINE,
      tool: 'pcap_http_analyze',
      startedAt: started,
      ctx,
      summary,
      data: {
        requestCount,
        methods: topEntries(methods, topN),
        hosts: topEntries(hosts, topN),
        topPaths: topEntries(paths, topN),
        userAgents: topEntries(userAgents, topN),
        statusCodes: topEntries(statusCodes, topN),
        requestsPerConnection: Number(requestsPerConnection.toFixed(3)),
        floodFlags,
        tlsNote,
      },
    });
  },
});

/* ------------------------------------------------------------------ */
/* Tool 4 — pcap_tls_metadata_analyze                                  */
/* ------------------------------------------------------------------ */

interface TlsAnalyzeResult {
  clientHelloCount: number;
  serverHelloCount: number;
  versions: { key: string; count: number }[];
  cipherSuites: { key: string; count: number }[];
  sni: { key: string; count: number }[];
  alpn: { key: string; count: number }[];
  ja3: { fingerprint: string; count: number; sample: string }[];
  certificates: TlsCertInfo[];
  limits: string;
}

const tlsVersionName = (v: number): string => {
  const map: Record<number, string> = { 0x0301: 'TLS1.0', 0x0302: 'TLS1.1', 0x0303: 'TLS1.2', 0x0304: 'TLS1.3' };
  return map[v] ?? `0x${v.toString(16)}`;
};

const tlsAnalyzeTool = defineTool<{ pcapPath: string }, TlsAnalyzeResult>({
  name: 'pcap_tls_metadata_analyze',
  title: 'TLS metadata / fingerprint analysis',
  engine: ENGINE,
  description:
    'Parse TLS ClientHello/ServerHello METADATA ONLY (no decryption is ever attempted): version, ' +
    'cipher suites, SNI, ALPN, supported groups, a JA3-style fingerprint (MD5 over version+ciphers+' +
    'extensions+curves+point-formats), and certificate subject/issuer common names when a ServerHello ' +
    'Certificate message is present (best-effort DER parsing). Read-only.',
  capabilities: ['read_pcap'],
  risk: 'safe',
  inputSchema: { pcapPath: zodCommon.filePath },
  handler: async (input, ctx) => {
    const started = Date.now();
    const { parsed, provenance } = loadCapture(input.pcapPath);

    // Collect directional streams touching TLS ports.
    const streams = new Map<string, { srcPort: number; dstPort: number; payloads: Buffer[] }>();
    for (const pkt of parsed.packets) {
      if (pkt.protocol !== 'tcp') continue;
      const port = pkt.dstPort ?? 0;
      const sport = pkt.srcPort ?? 0;
      if (![443, 8443, 8883, 993, 995, 465, 636, 990].includes(port) && ![443, 8443, 8883, 993, 995, 465, 636, 990].includes(sport)) {
        continue;
      }
      const payload = payloadOf(pkt);
      if (!payload) continue;
      const key = `${pkt.src ?? '?'}:${sport}->${pkt.dst ?? '?'}:${port}`;
      const entry = streams.get(key) ?? { srcPort: sport, dstPort: port, payloads: [] };
      if (entry.payloads.reduce((a, b) => a + b.length, 0) < 4 * 1024 * 1024) entry.payloads.push(payload);
      streams.set(key, entry);
    }

    const versions = new Map<string, number>();
    const cipherSuites = new Map<string, number>();
    const sniMap = new Map<string, number>();
    const alpnMap = new Map<string, number>();
    const ja3Map = new Map<string, { count: number; sample: string }>();
    const certificates: TlsCertInfo[] = [];
    let clientHelloCount = 0;
    let serverHelloCount = 0;

    for (const entry of streams.values()) {
      const records = tlsRecords(entry.payloads);
      for (const rec of records) {
        if (rec.contentType !== 22 || rec.fragment.length < 4) continue;
        const msgType = rec.fragment.readUInt8(0);
        const bodyLen = (rec.fragment.readUInt8(1) << 16) | (rec.fragment.readUInt8(2) << 8) | rec.fragment.readUInt8(3);
        const body = rec.fragment.subarray(4, Math.min(4 + bodyLen, rec.fragment.length));
        if (msgType === 1) {
          clientHelloCount += 1;
          const hello = parseClientHello(body);
          if (!hello) continue;
          bump(versions, tlsVersionName(hello.version));
          for (const cs of hello.cipherSuites) bump(cipherSuites, `0x${cs.toString(16)}`);
          if (hello.sni) bump(sniMap, hello.sni);
          for (const a of hello.alpn) bump(alpnMap, a);
          const ja3String = [
            hello.version,
            hello.cipherSuites.join('-'),
            hello.extensions.join('-'),
            hello.curves.join('-'),
            hello.pointFormats.join('-'),
          ].join(',');
          const fp = createHash('md5').update(ja3String).digest('hex');
          const existing = ja3Map.get(fp);
          ja3Map.set(fp, { count: (existing?.count ?? 0) + 1, sample: ja3String });
        } else if (msgType === 2) {
          serverHelloCount += 1;
        } else if (msgType === 11) {
          // TLS 1.2 certificate list
          let p = 0;
          if (body.length >= 3) {
            const total = (body.readUInt8(0) << 16) | (body.readUInt8(1) << 8) | body.readUInt8(2);
            p = 3;
            const end = Math.min(3 + total, body.length);
            while (p + 3 <= end) {
              const certLen = (body.readUInt8(p) << 16) | (body.readUInt8(p + 1) << 8) | body.readUInt8(p + 2);
              p += 3;
              if (p + certLen > end) break;
              const der = body.subarray(p, p + certLen);
              const cns = parseDerCommonNames(der, 'CN');
              if (cns.length) certificates.push({ subjectCn: cns.slice(0, 4), issuerCn: [] });
              p += certLen;
            }
          }
        }
      }
    }

    addEvidence(ctx, {
      claim: `TLS metadata parsed: ${clientHelloCount} ClientHello(s), ${serverHelloCount} ServerHello(s), ${ja3Map.size} unique JA3 fingerprint(s).`,
      prov: provenance,
      confidence: 'observed',
      data: { sni: topEntries(sniMap, 5), ja3: [...ja3Map.keys()] },
    });
    for (const [fp, info] of ja3Map) {
      addEvidence(ctx, {
        claim: `JA3 fingerprint ${fp} (seen ${info.count}x): ${info.sample}`,
        prov: provenance,
        confidence: 'observed',
      });
    }

    const limits =
      'TLS payloads are NEVER decrypted. Only ClientHello/ServerHello metadata and, where a cleartext ' +
      'certificate message is present (TLS 1.0-1.2), certificate common names are read. TLS 1.3 ' +
      'certificates are inside encrypted extensions and are therefore unavailable.';

    const summary =
      `## TLS metadata analysis\n` +
      `- ClientHellos: ${clientHelloCount}; ServerHellos: ${serverHelloCount}\n` +
      `- Versions: ${topEntries(versions, 8).map((e) => `${e.key}:${e.count}`).join(', ') || 'n/a'}\n` +
      `- SNI: ${topEntries(sniMap, 15).map((e) => `${e.key}(${e.count})`).join(', ') || 'n/a'}\n` +
      `- ALPN: ${topEntries(alpnMap, 10).map((e) => `${e.key}(${e.count})`).join(', ') || 'n/a'}\n` +
      `- Top cipher suites: ${topEntries(cipherSuites, 10).map((e) => `${e.key}:${e.count}`).join(', ') || 'n/a'}\n` +
      `- JA3 fingerprints: ${[...ja3Map.entries()].map(([fp, i]) => `${fp}(${i.count})`).join(', ') || 'n/a'}\n` +
      `- Certificates (CN): ${certificates.map((c) => c.subjectCn.join('/')).slice(0, 10).join(', ') || 'none parsed'}\n\n` +
      `> ${limits}`;

    return finish({
      engine: ENGINE,
      tool: 'pcap_tls_metadata_analyze',
      startedAt: started,
      ctx,
      summary,
      data: {
        clientHelloCount,
        serverHelloCount,
        versions: topEntries(versions, 8),
        cipherSuites: topEntries(cipherSuites, 10),
        sni: topEntries(sniMap, 15),
        alpn: topEntries(alpnMap, 10),
        ja3: [...ja3Map.entries()].map(([fingerprint, info]) => ({ fingerprint, count: info.count, sample: info.sample })),
        certificates,
        limits,
      },
    });
  },
});

/* ------------------------------------------------------------------ */
/* Tool 5 — c2_beacon_detect                                           */
/* ------------------------------------------------------------------ */

interface BeaconCandidate {
  dstIp: string;
  dstPort: number;
  packets: number;
  meanDelta: number;
  stddevDelta: number;
  cv: number;
  meanPayload: number;
  jitter: number;
  confidence: ConfidenceLevel;
  note: string;
}

interface BeaconDetectResult {
  candidates: BeaconCandidate[];
  timeline: { time: number; src: string; dst: string; dstPort: number; payloadLen: number }[];
  falsePositiveNotes: string[];
}

const beaconDetectTool = defineTool<{ pcapPath: string; minPackets?: number }, BeaconDetectResult>({
  name: 'c2_beacon_detect',
  title: 'Beacon / periodic-communication detection',
  engine: ENGINE,
  description:
    'Detect beacon-like periodic communication: group packets by destination IP and port, compute ' +
    'inter-arrival deltas, then flag conversations with a low coefficient of variation (regular timing), ' +
    'enough samples, and small consistent payload sizes. Also flags jitter-corrected patterns and ' +
    'DNS-based beaconing. Returns measured jitter, packet counts and confidence with false-positive notes.',
  capabilities: ['read_pcap'],
  risk: 'safe',
  inputSchema: { pcapPath: zodCommon.filePath, minPackets: z.number().int().min(2).max(10000).optional() },
  handler: async (input, ctx) => {
    const started = Date.now();
    const minPackets = input.minPackets ?? 8;
    const { abs, parsed, provenance } = loadCapture(input.pcapPath);

    const groups = new Map<string, { dstIp: string; dstPort: number; times: number[]; payloadLens: number[] }>();
    const timeline: BeaconDetectResult['timeline'] = [];
    let captureStart = Infinity;
    for (const pkt of parsed.packets) {
      const t = packetTime(pkt);
      if (t > 0 && t < captureStart) captureStart = t;
    }
    if (!Number.isFinite(captureStart)) captureStart = 0;

    for (const pkt of parsed.packets) {
      if (!pkt.dst || pkt.dstPort === undefined) continue;
      const key = `${pkt.dst}:${pkt.dstPort}:${pkt.protocol}`;
      const g = groups.get(key) ?? { dstIp: pkt.dst, dstPort: pkt.dstPort, times: [], payloadLens: [] };
      g.times.push(packetTime(pkt));
      g.payloadLens.push(pkt.payloadLen);
      groups.set(key, g);
      if (timeline.length < 500) {
        timeline.push({ time: Number((packetTime(pkt) - captureStart).toFixed(3)), src: pkt.src ?? '?', dst: pkt.dst, dstPort: pkt.dstPort, payloadLen: pkt.payloadLen });
      }
    }

    const candidates: BeaconCandidate[] = [];
    for (const g of groups.values()) {
      if (g.times.length < minPackets) continue;
      const sorted = [...g.times].sort((a, b) => a - b);
      const deltas: number[] = [];
      for (let i = 1; i < sorted.length; i += 1) {
        const d = (sorted[i] ?? 0) - (sorted[i - 1] ?? 0);
        if (d > 0) deltas.push(d);
      }
      if (deltas.length < minPackets - 1) continue;
      const m = mean(deltas);
      const sd = stddev(deltas);
      const cv = m > 0 ? sd / m : Infinity;
      const payloadMean = mean(g.payloadLens);
      const payloadSd = stddev(g.payloadLens);
      const consistentPayload = payloadMean <= 512 && payloadSd < Math.max(16, payloadMean * 0.3);
      const lowCv = cv < 0.3;
      const jitter = m > 0 ? sd : 0;

      // Jitter-corrected: many deltas near an integer multiple of the minimum delta.
      const minDelta = Math.min(...deltas);
      let harmonicHits = 0;
      if (minDelta > 0) {
        for (const d of deltas) {
          const ratio = d / minDelta;
          if (Math.abs(ratio - Math.round(ratio)) < 0.15 && Math.round(ratio) <= 8) harmonicHits += 1;
        }
      }
      const harmonic = deltas.length > 0 && harmonicHits / deltas.length > 0.6;

      const dnsBased = g.dstPort === 53;
      if ((lowCv && consistentPayload) || harmonic || (dnsBased && lowCv)) {
        const confidence: ConfidenceLevel = lowCv && consistentPayload && g.times.length >= minPackets * 2 ? 'inferred' : 'hypothesis';
        candidates.push({
          dstIp: g.dstIp,
          dstPort: g.dstPort,
          packets: g.times.length,
          meanDelta: Number(m.toFixed(4)),
          stddevDelta: Number(sd.toFixed(4)),
          cv: Number(cv.toFixed(4)),
          meanPayload: Number(payloadMean.toFixed(1)),
          jitter: Number(jitter.toFixed(4)),
          confidence,
          note: [
            lowCv ? 'low timing variance' : '',
            harmonic ? 'harmonic/multiples pattern (jitter-corrected)' : '',
            dnsBased ? 'DNS-based channel' : '',
            consistentPayload ? 'consistent small payloads' : '',
          ]
            .filter(Boolean)
            .join('; '),
        });
      }
    }
    candidates.sort((a, b) => a.cv - b.cv);

    const falsePositiveNotes = [
      'Periodic software updates, NTP, keep-alives, monitoring polls and proxies also produce regular timing.',
      'A low coefficient of variation alone is not proof of command-and-control; correlate with payload content, reputation and destination.',
      'Short captures (few samples) inflate variance; require more samples before chasing a candidate.',
    ];

    addEvidence(ctx, {
      claim: `Beacon detection over ${parsed.packets.length} packets: ${candidates.length} candidate(s) with regular timing.`,
      prov: provenance,
      confidence: 'hypothesis',
      data: { candidates: candidates.slice(0, 10) },
    });
    if (candidates.length > 0) {
      addEvidence(ctx, {
        claim: `Top beacon candidate: ${candidates[0]?.dstIp}:${candidates[0]?.dstPort} (CV ${candidates[0]?.cv}, ${candidates[0]?.packets} packets).`,
        prov: provenance,
        confidence: 'hypothesis',
      });
    }

    const kb = getKnowledgeBase();
    const pcapNode = `pcap_evidence:${createHash('sha256').update(abs).digest('hex').slice(0, 16)}`;
    kb.upsertNode({ id: pcapNode, kind: 'pcap_evidence', label: abs, properties: { packets: parsed.packets.length }, provenance: [provenance], confidence: 'observed' });
    for (const c of candidates.slice(0, 25)) {
      const indicatorId = `c2_indicator:beacon:${c.dstIp}:${c.dstPort}`;
      kb.upsertNode({
        id: indicatorId,
        kind: 'c2_indicator',
        label: `${c.dstIp}:${c.dstPort}`,
        properties: { cv: c.cv, packets: c.packets, meanDelta: c.meanDelta },
        provenance: [provenance],
        confidence: 'hypothesis',
      });
      kb.upsertEdge({ id: `${pcapNode}->communicates_with->${indicatorId}`, from: pcapNode, to: indicatorId, relation: 'communicates_with', provenance: [provenance], confidence: 'hypothesis', note: 'Beacon-like periodic communication.' });
    }

    const summary =
      `## Beacon detection (min packets: ${minPackets})\n` +
      `- Packets analysed: ${parsed.packets.length}; candidates: ${candidates.length}\n` +
      (candidates.length
        ? candidates
            .slice(0, 20)
            .map((c) => `  - ${c.dstIp}:${c.dstPort} — pkts ${c.packets}, mean Δ ${c.meanDelta}s, CV ${c.cv}, jitter ${c.jitter}s, payload~${c.meanPayload}B [${c.confidence}] ${c.note}`)
            .join('\n')
        : '  - none') +
      `\n\n### False-positive notes\n${falsePositiveNotes.map((n) => `- ${n}`).join('\n')}`;

    return finish({
      engine: ENGINE,
      tool: 'c2_beacon_detect',
      startedAt: started,
      ctx,
      warnings: ['Beacon detection is heuristic; validate candidates against baselines before acting.'],
      summary,
      data: { candidates, timeline, falsePositiveNotes },
    });
  },
});

/* ------------------------------------------------------------------ */
/* Tool 6 — ioc_extract                                                */
/* ------------------------------------------------------------------ */

interface IocResult {
  ipv4: string[];
  ipv4Filtered: number;
  privateIncluded: boolean;
  domains: string[];
  urls: string[];
  ja3: string[];
  hashes: string[];
  classification: { ipv4: string[]; domain: string[]; url: string[]; ja3: string[]; hash: string[] };
}

const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const URL_RE = /https?:\/\/[^\s"'<>)\]]+/gi;
const HASH_RE = /\b[a-f0-9]{64}\b|\b[a-f0-9]{32}\b/gi;
const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi;

const iocExtractTool = defineTool<{ pcapPath: string; includePrivate?: boolean }, IocResult>({
  name: 'ioc_extract',
  title: 'IOC extraction from capture',
  engine: ENGINE,
  description:
    'Extract indicators of compromise from a capture: IPv4 addresses (private/reserved filtered unless ' +
    'requested), domains (from DNS queries, TLS SNI and HTTP Host), URLs (from HTTP), JA3 fingerprints ' +
    'and hash-like strings. Results are deduplicated and classified for defensive ingestion.',
  capabilities: ['read_pcap'],
  risk: 'safe',
  inputSchema: { pcapPath: zodCommon.filePath, includePrivate: z.boolean().optional() },
  handler: async (input, ctx) => {
    const started = Date.now();
    const includePrivate = input.includePrivate ?? false;
    const { abs, parsed, provenance } = loadCapture(input.pcapPath);

    const ipv4 = new Set<string>();
    const domains = new Set<string>();
    const urls = new Set<string>();
    const ja3 = new Set<string>();
    const hashes = new Set<string>();
    let ipv4Filtered = 0;

    for (const pkt of parsed.packets) {
      for (const ip of [pkt.src, pkt.dst]) {
        if (!ip) continue;
        if (isPrivateIPv4(ip) && !includePrivate) {
          ipv4Filtered += 1;
          continue;
        }
        ipv4.add(ip);
      }
      const payload = payloadOf(pkt);
      if (!payload) continue;
      if (payload.length > 64 * 1024) continue; // skip very large blobs

      if (pkt.protocol === 'udp' && (pkt.srcPort === 53 || pkt.dstPort === 53)) {
        const msg = parseDnsWire(payload);
        if (msg && !msg.qr) for (const q of msg.questions) if (q.name) domains.add(q.name.toLowerCase());
      }
      if (pkt.protocol === 'tcp' && [443, 8443].includes(pkt.dstPort ?? 0)) {
        for (const rec of tlsRecords([payload])) {
          if (rec.contentType === 22 && rec.fragment.length > 4 && rec.fragment.readUInt8(0) === 1) {
            const hello = parseClientHello(rec.fragment.subarray(4));
            if (hello?.sni) domains.add(hello.sni.toLowerCase());
            if (hello) {
              const ja3String = [hello.version, hello.cipherSuites.join('-'), hello.extensions.join('-'), hello.curves.join('-'), hello.pointFormats.join('-')].join(',');
              ja3.add(createHash('md5').update(ja3String).digest('hex'));
            }
          }
        }
      }
      // ASCII scanning for host headers / URLs / hashes.
      const text = payload.toString('latin1');
      if (/^Host:/im.test(text) || /^GET |^POST |^HTTP\/1\./im.test(text)) {
        const hostMatch = text.matchAll(/^Host:\s*(\S+)/gim);
        for (const h of hostMatch) if (h[1] && !isPrivateIPv4(h[1])) domains.add(h[1].toLowerCase());
        for (const u of text.matchAll(URL_RE)) urls.add(u[0]);
      }
      if ([21, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 8080].includes(pkt.dstPort ?? 0) || payload.length > 64) {
        for (const h of text.matchAll(HASH_RE)) hashes.add(h[0].toLowerCase());
      }
    }

    // Derive bare domains from URLs.
    for (const url of urls) {
      try {
        const host = new URL(url).hostname.toLowerCase();
        if (!isPrivateIPv4(host)) domains.add(host);
      } catch {
        /* ignore malformed URL */
      }
    }

    // Cross-reference with the knowledge base for any known C2 indicators (§6).
    const kb = getKnowledgeBase();
    const known = kb.searchRecords({ categories: ['c2_protocol_spec'], limit: 100 });
    const correlatedKnown = new Set(known.flatMap((r) => r.tags));

    addEvidence(ctx, {
      claim: `IOCs extracted: ${ipv4.size} IPv4, ${domains.size} domains, ${urls.size} URLs, ${ja3.size} JA3, ${hashes.size} hashes (private filtered: ${ipv4Filtered}).`,
      prov: provenance,
      confidence: 'observed',
      locator: { file: abs },
      data: { ipv4: [...ipv4].slice(0, 50), domains: [...domains].slice(0, 50) },
    });

    const pcapNode = `pcap_evidence:${createHash('sha256').update(abs).digest('hex').slice(0, 16)}`;
    kb.upsertNode({ id: pcapNode, kind: 'pcap_evidence', label: abs, properties: { iocs: ipv4.size + domains.size }, provenance: [provenance], confidence: 'observed' });
    for (const ip of [...ipv4].slice(0, 50)) {
      const id = `c2_indicator:ip:${ip}`;
      kb.upsertNode({ id, kind: 'c2_indicator', label: ip, properties: { type: 'ipv4' }, provenance: [provenance], confidence: 'inferred' });
      kb.upsertEdge({ id: `${pcapNode}->references->${id}`, from: pcapNode, to: id, relation: 'references', provenance: [provenance], confidence: 'inferred' });
    }
    for (const d of [...domains].slice(0, 50)) {
      const id = `c2_indicator:domain:${d}`;
      kb.upsertNode({ id, kind: 'c2_indicator', label: d, properties: { type: 'domain' }, provenance: [provenance], confidence: 'inferred' });
      kb.upsertEdge({ id: `${pcapNode}->references->${id}`, from: pcapNode, to: id, relation: 'references', provenance: [provenance], confidence: 'inferred' });
    }

    const summary =
      `## IOC extraction — ${abs}\n` +
      `- IPv4: ${ipv4.size} (filtered private/reserved: ${ipv4Filtered}, includePrivate=${includePrivate})\n` +
      `  ${[...ipv4].slice(0, 30).join(', ') || 'none'}\n` +
      `- Domains: ${domains.size}\n  ${[...domains].slice(0, 30).join(', ') || 'none'}\n` +
      `- URLs: ${urls.size}\n  ${[...urls].slice(0, 15).join(', ') || 'none'}\n` +
      `- JA3: ${[...ja3].join(', ') || 'none'}\n` +
      `- Hashes: ${hashes.size} (${[...hashes].slice(0, 10).join(', ') || 'none'})\n` +
      `- Knowledge-base C2 tag references: ${correlatedKnown.size}\n\n` +
      `> IOCs are observations, not verdicts. Enrich with reputation/threat-intel before blocking.`;

    return finish({
      engine: ENGINE,
      tool: 'ioc_extract',
      startedAt: started,
      ctx,
      summary,
      data: {
        ipv4: [...ipv4],
        ipv4Filtered,
        privateIncluded: includePrivate,
        domains: [...domains],
        urls: [...urls],
        ja3: [...ja3],
        hashes: [...hashes],
        classification: { ipv4: [...ipv4], domain: [...domains], url: [...urls], ja3: [...ja3], hash: [...hashes] },
      },
    });
  },
});

/* ------------------------------------------------------------------ */
/* Tool 7 — network_timeline_reconstruct                               */
/* ------------------------------------------------------------------ */

interface TimelineEvent {
  time: number;
  kind: 'conversation_first_seen' | 'protocol_transition' | 'dns_lookup' | 'http_request' | 'tls_handshake' | 'beacon_event';
  detail: string;
  src?: string;
  dst?: string;
}

interface TimelineResult {
  events: TimelineEvent[];
  durationSeconds: number;
  truncated: boolean;
}

const timelineTool = defineTool<{ pcapPath: string; focusIp?: string; maxEvents?: number }, TimelineResult>({
  name: 'network_timeline_reconstruct',
  title: 'Network timeline reconstruction',
  engine: ENGINE,
  description:
    'Build a chronological timeline from a capture: first-seen per conversation, protocol transitions, ' +
    'DNS lookups, HTTP requests, TLS handshakes and beacon events. Optionally focus on a single IP. ' +
    'Returns ordered events with relative timestamps and a markdown timeline. Read-only.',
  capabilities: ['read_pcap'],
  risk: 'safe',
  inputSchema: {
    pcapPath: zodCommon.filePath,
    focusIp: z.string().optional().describe('Only include events involving this IP.'),
    maxEvents: z.number().int().min(1).max(10000).optional(),
  },
  handler: async (input, ctx) => {
    const started = Date.now();
    const maxEvents = input.maxEvents ?? 2000;
    const { parsed, provenance } = loadCapture(input.pcapPath);

    let captureStart = Infinity;
    for (const pkt of parsed.packets) {
      const t = packetTime(pkt);
      if (t > 0 && t < captureStart) captureStart = t;
    }
    if (!Number.isFinite(captureStart)) captureStart = 0;

    const focus = input.focusIp;
    const involves = (pkt: PcapPacket): boolean => !focus || pkt.src === focus || pkt.dst === focus;

    const events: TimelineEvent[] = [];
    const seenConv = new Set<string>();
    const seenProto = new Set<string>();

    for (const pkt of parsed.packets) {
      if (!involves(pkt)) continue;
      const rel = Number((packetTime(pkt) - captureStart).toFixed(3));
      const conv = flowKey(pkt);
      if (!seenConv.has(conv)) {
        seenConv.add(conv);
        events.push({ time: rel, kind: 'conversation_first_seen', detail: `${pkt.protocol} ${pkt.src}:${pkt.srcPort} -> ${pkt.dst}:${pkt.dstPort}`, ...(pkt.src ? { src: pkt.src } : {}), ...(pkt.dst ? { dst: pkt.dst } : {}) });
      }
      const protoKey = `${pkt.dst ?? '?'}:${pkt.dstPort ?? 0}:${pkt.protocol}`;
      if (!seenProto.has(protoKey)) {
        seenProto.add(protoKey);
        events.push({ time: rel, kind: 'protocol_transition', detail: `${pkt.protocol} to ${pkt.dst}:${pkt.dstPort}`, ...(pkt.dst ? { dst: pkt.dst } : {}) });
      }

      const payload = payloadOf(pkt);
      if (!payload) continue;
      if (pkt.protocol === 'udp' && (pkt.srcPort === 53 || pkt.dstPort === 53)) {
        const msg = parseDnsWire(payload);
        if (msg && !msg.qr) {
          for (const q of msg.questions) {
            events.push({ time: rel, kind: 'dns_lookup', detail: `DNS ${q.typeName} ${q.name}`, ...(pkt.src ? { src: pkt.src } : {}), ...(pkt.dst ? { dst: pkt.dst } : {}) });
          }
        }
      }
      if (pkt.protocol === 'tcp' && [443, 8443].includes(pkt.dstPort ?? 0)) {
        for (const rec of tlsRecords([payload])) {
          if (rec.contentType === 22 && rec.fragment.length > 4 && rec.fragment.readUInt8(0) === 1) {
            const hello = parseClientHello(rec.fragment.subarray(4));
            events.push({ time: rel, kind: 'tls_handshake', detail: `TLS ClientHello ${hello?.sni ?? '(no SNI)'}`, ...(pkt.src ? { src: pkt.src } : {}), ...(pkt.dst ? { dst: pkt.dst } : {}) });
          }
        }
      }
      if (pkt.protocol === 'tcp' && [80, 8080, 8000].includes(pkt.dstPort ?? 0)) {
        const line = payload.toString('latin1').split(/\r?\n/)[0] ?? '';
        const m = REQUEST_LINE.exec(line);
        REQUEST_LINE.lastIndex = 0;
        if (m) events.push({ time: rel, kind: 'http_request', detail: `${m[1]} ${m[2]}`, ...(pkt.src ? { src: pkt.src } : {}), ...(pkt.dst ? { dst: pkt.dst } : {}) });
      }
      if (events.length > maxEvents * 3) break;
    }

    events.sort((a, b) => a.time - b.time);
    const truncated = events.length > maxEvents;
    const limited = events.slice(0, maxEvents);
    const durationSeconds = limited.length > 0 ? limited[limited.length - 1]?.time ?? 0 : 0;

    addEvidence(ctx, {
      claim: `Timeline reconstructed: ${limited.length} event(s) over ${durationSeconds}s${focus ? ` (focus ${focus})` : ''}.`,
      prov: provenance,
      confidence: 'observed',
      data: { events: limited.length },
    });

    const summary =
      `## Network timeline${focus ? ` (focus ${focus})` : ''}\n` +
      `- Events: ${limited.length}${truncated ? ` (truncated from ${events.length})` : ''}; span ${durationSeconds}s\n\n` +
      `| t (s) | event | detail |\n|------:|-------|--------|\n` +
      limited
        .slice(0, 200)
        .map((e) => `| ${e.time} | ${e.kind} | ${e.detail} |`)
        .join('\n');

    return finish({
      engine: ENGINE,
      tool: 'network_timeline_reconstruct',
      startedAt: started,
      ctx,
      summary,
      data: { events: limited, durationSeconds, truncated },
    });
  },
});

/* ------------------------------------------------------------------ */
/* Tool 8 — protocol_fingerprint                                       */
/* ------------------------------------------------------------------ */

interface ProtocolInventoryEntry {
  protocol: string;
  packets: number;
  evidence: string;
  confidence: ConfidenceLevel;
}

interface ProtocolFingerprintResult {
  protocols: ProtocolInventoryEntry[];
  externalProtocolLogs?: { tool: string; output: string };
  heuristicNote: string;
}

const protocolFingerprintTool = defineTool<{ pcapPath: string }, ProtocolFingerprintResult>({
  name: 'protocol_fingerprint',
  title: 'Protocol / service fingerprinting',
  engine: ENGINE,
  description:
    'Fingerprint the protocols and services present in a capture by port and payload heuristics: HTTP, ' +
    'DNS, TLS, DHCP, SSDP, mDNS, NTP, Telnet, SNMP, MQTT and CoAP. If Suricata or Zeek are available ' +
    'they are run read-only over the capture for protocol logs; otherwise pure-JS heuristics are used.',
  capabilities: ['read_pcap'],
  risk: 'safe',
  inputSchema: { pcapPath: zodCommon.filePath },
  handler: async (input, ctx) => {
    const started = Date.now();
    const { abs, parsed, provenance } = loadCapture(input.pcapPath);

    const inventory = new Map<string, ProtocolInventoryEntry>();
    const mark = (protocol: string, ev: string, confidence: ConfidenceLevel): void => {
      const existing = inventory.get(protocol);
      if (existing) {
        existing.packets += 1;
      } else {
        inventory.set(protocol, { protocol, packets: 1, evidence: ev, confidence });
      }
    };

    for (const pkt of parsed.packets) {
      const dp = pkt.dstPort ?? 0;
      const sp = pkt.srcPort ?? 0;
      const payload = payloadOf(pkt);
      if ([80, 8080, 8000].includes(dp) || [80, 8080, 8000].includes(sp)) mark('HTTP', 'tcp port', 'inferred');
      if (dp === 53 || sp === 53) mark('DNS', 'udp/tcp port 53', 'inferred');
      if ([443, 8443].includes(dp) || [443, 8443].includes(sp)) mark('TLS', 'tcp port', 'inferred');
      if (dp === 67 || dp === 68 || sp === 67 || sp === 68) mark('DHCP', 'udp port 67/68', 'inferred');
      if (dp === 1900 || sp === 1900) mark('SSDP', 'udp port 1900', 'inferred');
      if (dp === 5353 || sp === 5353) mark('mDNS', 'udp port 5353', 'inferred');
      if (dp === 123 || sp === 123) mark('NTP', 'udp port 123', 'inferred');
      if (dp === 23 || sp === 23) mark('Telnet', 'tcp port 23', 'inferred');
      if (dp === 161 || sp === 161 || dp === 162) mark('SNMP', 'udp port 161/162', 'inferred');
      if (dp === 1883 || sp === 1883) mark('MQTT', 'tcp port 1883', 'inferred');
      if (dp === 5683 || sp === 5683) mark('CoAP', 'udp port 5683', 'inferred');
      if (dp === 22 || sp === 22) mark('SSH', 'tcp port 22', 'inferred');

      if (payload) {
        const head = payload.subarray(0, 8).toString('latin1');
        if (/^(GET|POST|PUT|HEAD|DELETE|OPTIONS) /m.test(head)) mark('HTTP', 'request line in payload', 'observed');
        if (payload.length >= 3 && payload.readUInt8(0) === 0x16 && payload.readUInt8(1) === 0x03) mark('TLS', 'TLS record header', 'observed');
        if (/^\$INIT/.test(head) || /^SUBSCRIBE|^CONNECT|^PUBLISH/m.test(payload.subarray(0, 16).toString('latin1'))) mark('MQTT', 'MQTT control packet', 'observed');
        if (/^\{\s*"/.test(payload.subarray(0, 4).toString('latin1'))) mark('JSON/API', 'JSON payload heuristic', 'hypothesis');
      }
    }

    let externalProtocolLogs: { tool: string; output: string } | undefined;
    const available = await discoverTools(['suricata', 'zeek']);
    if (available['suricata'] === true) {
      const res = await tryRun('suricata', ['-r', abs, '-l', '.', '--runmode', 'single']);
      if (res) externalProtocolLogs = { tool: 'suricata', output: (res.stdout || res.stderr).trim().slice(0, 8192) };
    } else if (available['zeek'] === true) {
      const res = await tryRun('zeek', ['-r', abs, 'protocols.bare']);
      if (res) externalProtocolLogs = { tool: 'zeek', output: (res.stdout || res.stderr).trim().slice(0, 8192) };
    }

    const protocols = [...inventory.values()].sort((a, b) => b.packets - a.packets);
    addEvidence(ctx, {
      claim: `Protocol fingerprint: ${protocols.map((p) => p.protocol).join(', ') || 'none identified'}.`,
      prov: provenance,
      confidence: 'inferred',
      data: { protocols: protocols.map((p) => ({ protocol: p.protocol, packets: p.packets })) },
    });

    const heuristicNote =
      'Heuristics rely on well-known ports and shallow payload signatures; encrypted or non-standard ' +
      'ports reduce confidence. Install Suricata or Zeek for authoritative protocol logs.';

    const summary =
      `## Protocol fingerprint\n` +
      protocols.map((p) => `- ${p.protocol}: ${p.packets} packet(s) — ${p.evidence} [${p.confidence}]`).join('\n') +
      (externalProtocolLogs ? `\n\n### ${externalProtocolLogs.tool} output\n\`\`\`\n${externalProtocolLogs.output}\n\`\`\`` : '') +
      `\n\n> ${heuristicNote}`;

    return finish({
      engine: ENGINE,
      tool: 'protocol_fingerprint',
      startedAt: started,
      ctx,
      summary,
      data: { protocols, ...(externalProtocolLogs ? { externalProtocolLogs } : {}), heuristicNote },
    });
  },
});

/* ------------------------------------------------------------------ */
/* Tool 9 — flow_summarize                                             */
/* ------------------------------------------------------------------ */

interface FlowSummaryRow {
  src: string;
  dst: string;
  srcPort: number;
  dstPort: number;
  proto: string;
  start: number;
  end: number;
  duration: number;
  packets: number;
  bytes: number;
  avgPps: number;
  flags: string[];
}

interface FlowSummarizeResult {
  flowCount: number;
  flows: FlowSummaryRow[];
  topFlows: FlowSummaryRow[];
  minBytes: number;
}

const flowSummarizeTool = defineTool<{ pcapPath: string; minBytes?: number }, FlowSummarizeResult>({
  name: 'flow_summarize',
  title: 'Per-flow summary',
  engine: ENGINE,
  description:
    'Produce a per-flow summary table (5-tuple, start/end, duration, packets, bytes, average pps and ' +
    'flags seen) and the aggregate top flows. Read-only. A CSV export is not required.',
  capabilities: ['read_pcap'],
  risk: 'safe',
  inputSchema: { pcapPath: zodCommon.filePath, minBytes: z.number().int().min(0).optional() },
  handler: async (input, ctx) => {
    const started = Date.now();
    const minBytes = input.minBytes ?? 0;
    const { parsed, provenance } = loadCapture(input.pcapPath);

    let captureStart = Infinity;
    for (const pkt of parsed.packets) {
      const t = packetTime(pkt);
      if (t > 0 && t < captureStart) captureStart = t;
    }
    if (!Number.isFinite(captureStart)) captureStart = 0;

    const flows = buildFlows(parsed.packets, true);
    const rows: FlowSummaryRow[] = [];
    for (const flow of flows.values()) {
      if (flow.bytes < minBytes) continue;
      const duration = Math.max(0, flow.last - flow.first);
      rows.push({
        src: flow.src,
        dst: flow.dst,
        srcPort: flow.srcPort,
        dstPort: flow.dstPort,
        proto: flow.proto,
        start: Number((flow.first - captureStart).toFixed(3)),
        end: Number((flow.last - captureStart).toFixed(3)),
        duration: Number(duration.toFixed(3)),
        packets: flow.packets,
        bytes: flow.bytes,
        avgPps: duration > 0 ? Number((flow.packets / duration).toFixed(3)) : 0,
        flags: [...flow.flags].sort(),
      });
    }
    rows.sort((a, b) => b.bytes - a.bytes);
    const topFlows = rows.slice(0, 20);

    addEvidence(ctx, {
      claim: `Flow summary: ${rows.length} flows (minBytes ${minBytes}); top flow ${topFlows[0] ? `${topFlows[0].src}->${topFlows[0].dst} (${topFlows[0].bytes}B)` : 'n/a'}.`,
      prov: provenance,
      confidence: 'observed',
    });

    const summary =
      `## Flow summary (${rows.length} flows)\n\n` +
      `| src | dst | proto | start | dur(s) | pkts | bytes | pps | flags |\n` +
      `|-----|-----|-------|------:|-------:|-----:|------:|----:|-------|\n` +
      topFlows
        .map((f) => `| ${f.src}:${f.srcPort} | ${f.dst}:${f.dstPort} | ${f.proto} | ${f.start} | ${f.duration} | ${f.packets} | ${f.bytes} | ${f.avgPps} | ${f.flags.join('')} |`)
        .join('\n');

    return finish({
      engine: ENGINE,
      tool: 'flow_summarize',
      startedAt: started,
      ctx,
      summary,
      data: { flowCount: rows.length, flows: rows, topFlows, minBytes },
    });
  },
});

/* ------------------------------------------------------------------ */
/* Engine export                                                       */
/* ------------------------------------------------------------------ */

export const networkForensicsEngine: EngineModule = {
  name: ENGINE,
  title: 'Network Forensics',
  description:
    'Read-only packet-capture analysis: flow statistics, DNS, HTTP, TLS metadata, beacon detection, ' +
    'IOC extraction, timeline reconstruction, protocol fingerprinting and per-flow summaries. Encrypted ' +
    'traffic is never decrypted; only TLS metadata is inspected.',
  tools: [
    flowAnalyzeTool,
    dnsAnalyzeTool,
    httpAnalyzeTool,
    tlsAnalyzeTool,
    beaconDetectTool,
    iocExtractTool,
    timelineTool,
    protocolFingerprintTool,
    flowSummarizeTool,
  ],
};
