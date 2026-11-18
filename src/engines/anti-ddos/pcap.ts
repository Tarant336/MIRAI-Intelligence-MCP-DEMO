/**
 * Pure-JS classic libpcap reader and decoder (§4.1 / §4.3).
 *
 * This is the offline fallback used when tshark/tcpdump are unavailable. It
 * parses the classic libpcap global header and per-packet records and decodes
 * Ethernet (including VLAN/QinQ) -> IPv4/IPv6 -> TCP/UDP, plus lightweight
 * DNS and HTTP inspection. It NEVER generates traffic; it only reads captures.
 *
 * Reference: https://wiki.wireshark.org/Development/LibpcapFileFormat
 */

export interface DnsInfo {
  isResponse: boolean;
  rcode: number;
  questionCount: number;
  answerCount: number;
  qtype?: number;
  qname?: string;
}

export interface HttpInfo {
  method: string;
  path: string;
  host?: string;
  userAgent?: string;
}

export interface TcpFlags {
  syn: boolean;
  ack: boolean;
  rst: boolean;
  fin: boolean;
  psh: boolean;
  urg: boolean;
  headerLen: number;
}

export type PacketProtocol = 'TCP' | 'UDP' | 'ICMP' | 'GRE' | 'OTHER';

export interface DecodedPacket {
  index: number;
  ts: number;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  protocol: PacketProtocol;
  ipVersion: 4 | 6;
  frameLength: number;
  ipLength: number;
  payloadLength: number;
  tcp?: TcpFlags;
  dns?: DnsInfo;
  http?: HttpInfo;
}

export interface PcapFormat {
  magic: string;
  endianness: 'little' | 'big';
  timestampResolution: 'microsecond' | 'nanosecond';
  linkType: number;
  version: string;
}

export interface PcapSummary {
  format: PcapFormat;
  packetCount: number;
  capturedBytes: number;
  originalBytes: number;
  malformedRecords: number;
  durationSeconds: number | null;
  packetsPerSecond: number | null;
  avgPacketSize: number;
  protocols: Record<string, number>;
  ipVersions: Record<string, number>;
  topSrcIps: Array<{ value: string; count: number }>;
  topDstIps: Array<{ value: string; count: number }>;
  topDstPorts: Array<{ value: string; count: number }>;
  packetSizeDistribution: Array<{ bucket: string; count: number }>;
  parseWarnings: string[];
}

export interface ParseOptions {
  /** Hard cap on records decoded (guards against very large files). */
  maxPackets?: number;
  /** Whether to retain decoded packets (needed by the deep analyser). */
  keepPackets?: boolean;
  /** Number of entries in each top-N list. */
  topN?: number;
}

export interface ParseResult {
  summary: PcapSummary;
  packets: DecodedPacket[];
}

const PCAP_MAGIC_MICRO_LE = 0xa1b2c3d4;
const PCAP_MAGIC_BIG = 0xd4c3b2a1;
const PCAP_MAGIC_NANO_LE = 0xa1b23c4d;
const PCAP_MAGIC_NANO_BIG = 0x4d3cb2a1;

const LINKTYPE_ETHERNET = 1;
const LINKTYPE_RAW_IP = 101;
const LINKTYPE_LINUX_SLL = 113;
const LINKTYPE_LINUX_SLL2 = 276;

function ipv4ToString(dv: DataView, off: number): string {
  return `${dv.getUint8(off)}.${dv.getUint8(off + 1)}.${dv.getUint8(off + 2)}.${dv.getUint8(off + 3)}`;
}

function ipv6ToString(dv: DataView, off: number): string {
  const groups: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    groups.push(dv.getUint16(off + i).toString(16));
  }
  return groups.join(':');
}

function decodeDns(buf: Buffer, payloadOffset: number, payloadEnd: number): DnsInfo | undefined {
  const available = payloadEnd - payloadOffset;
  if (available < 12) return undefined;
  const flags = buf.readUInt16BE(payloadOffset + 2);
  const info: DnsInfo = {
    isResponse: (flags & 0x8000) !== 0,
    rcode: flags & 0x000f,
    questionCount: buf.readUInt16BE(payloadOffset + 4),
    answerCount: buf.readUInt16BE(payloadOffset + 6),
  };
  // Parse the first question name (label sequence) when present.
  let cursor = payloadOffset + 12;
  const labels: string[] = [];
  let guard = 0;
  while (cursor < payloadEnd && guard < 128) {
    const len = buf.readUInt8(cursor);
    if (len === 0) {
      cursor += 1;
      break;
    }
    if ((len & 0xc0) === 0xc0) {
      cursor += 2;
      break;
    }
    cursor += 1;
    if (cursor + len > payloadEnd) break;
    labels.push(buf.subarray(cursor, cursor + len).toString('latin1'));
    cursor += len;
    guard += 1;
  }
  if (labels.length > 0) info.qname = labels.join('.');
  if (cursor + 2 <= payloadEnd) info.qtype = buf.readUInt16BE(cursor);
  return info;
}

function decodeHttp(payload: Buffer, payloadOffset: number, payloadEnd: number): HttpInfo | undefined {
  const len = Math.min(payloadEnd - payloadOffset, 1024);
  if (len <= 0) return undefined;
  const text = payload.subarray(payloadOffset, payloadOffset + len).toString('latin1');
  const requestLine = /^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE)\s+(\S+)\s+HTTP\/\d\.\d/m.exec(text);
  if (!requestLine) return undefined;
  const info: HttpInfo = { method: requestLine[1] ?? 'GET', path: requestLine[2] ?? '/' };
  const host = /^Host:\s*([^\r\n]+)/im.exec(text);
  if (host?.[1]) info.host = host[1].trim();
  const ua = /^User-Agent:\s*([^\r\n]+)/im.exec(text);
  if (ua?.[1]) info.userAgent = ua[1].trim();
  return info;
}

function decodeTransport(
  dv: DataView,
  buf: Buffer,
  start: number,
  end: number,
  protocol: number,
  packet: DecodedPacket,
): void {
  if (protocol === 6 && start + 20 <= end) {
    packet.protocol = 'TCP';
    packet.srcPort = dv.getUint16(start);
    packet.dstPort = dv.getUint16(start + 2);
    const flagsByte = dv.getUint8(start + 13);
    const headerLen = Math.max((dv.getUint8(start + 12) >> 4) * 4, 20);
    packet.tcp = {
      syn: (flagsByte & 0x02) !== 0,
      ack: (flagsByte & 0x10) !== 0,
      rst: (flagsByte & 0x04) !== 0,
      fin: (flagsByte & 0x01) !== 0,
      psh: (flagsByte & 0x08) !== 0,
      urg: (flagsByte & 0x20) !== 0,
      headerLen,
    };
    const payloadStart = start + headerLen;
    packet.payloadLength = Math.max(end - payloadStart, 0);
    const httpCandidate =
      [80, 8080, 8000, 8888, 3000, 5000].includes(packet.srcPort) ||
      [80, 8080, 8000, 8888, 3000, 5000].includes(packet.dstPort);
    if (httpCandidate && payloadStart < end) {
      const http = decodeHttp(buf, payloadStart, end);
      if (http) packet.http = http;
    }
  } else if (protocol === 17 && start + 8 <= end) {
    packet.protocol = 'UDP';
    packet.srcPort = dv.getUint16(start);
    packet.dstPort = dv.getUint16(start + 2);
    const udpLen = dv.getUint16(start + 4);
    const payloadStart = start + 8;
    const payloadEnd = Math.min(start + Math.max(udpLen, 8), end);
    packet.payloadLength = Math.max(payloadEnd - payloadStart, 0);
    if (packet.srcPort === 53 || packet.dstPort === 53) {
      const dns = decodeDns(buf, payloadStart, payloadEnd);
      if (dns) packet.dns = dns;
    }
  } else if (protocol === 1) {
    packet.protocol = 'ICMP';
  } else if (protocol === 47) {
    packet.protocol = 'GRE';
  } else {
    packet.protocol = 'OTHER';
  }
}

function decodeIpv4(
  dv: DataView,
  buf: Buffer,
  start: number,
  end: number,
  packet: DecodedPacket,
): void {
  const versionIhl = dv.getUint8(start);
  const ihl = (versionIhl & 0x0f) * 4;
  const ipLength = dv.getUint16(start + 2);
  const protocol = dv.getUint8(start + 9);
  packet.ipVersion = 4;
  packet.ipLength = ipLength;
  packet.srcIp = ipv4ToString(dv, start + 12);
  packet.dstIp = ipv4ToString(dv, start + 16);

  const fragField = dv.getUint16(start + 6);
  const moreFragments = (fragField & 0x2000) !== 0;
  const fragmentOffset = fragField & 0x1fff;
  const ipEnd = Math.min(start + Math.max(ipLength, ihl), end);

  if (fragmentOffset !== 0 || moreFragments) {
    // Fragmented datagrams are counted but transport parsing is skipped.
    packet.protocol = 'OTHER';
    packet.payloadLength = Math.max(ipEnd - (start + ihl), 0);
    return;
  }

  if (start + ihl <= end) {
    decodeTransport(dv, buf, start + ihl, ipEnd, protocol, packet);
  }
}

function decodeIpv6(
  dv: DataView,
  buf: Buffer,
  start: number,
  end: number,
  packet: DecodedPacket,
): void {
  packet.ipVersion = 6;
  const payloadLength = dv.getUint16(start + 4);
  let nextHeader = dv.getUint8(start + 6);
  packet.ipLength = 40 + payloadLength;
  packet.srcIp = ipv6ToString(dv, start + 8);
  packet.dstIp = ipv6ToString(dv, start + 24);

  let cursor = start + 40;
  const ipEnd = Math.min(start + 40 + payloadLength, end);
  let hops = 0;
  // Walk the common extension headers to reach the transport header.
  while (hops < 4 && [0, 43, 60, 51, 50].includes(nextHeader) && cursor + 8 <= ipEnd) {
    const extLen = dv.getUint8(cursor + 1);
    const len = nextHeader === 51 || nextHeader === 50 ? (extLen + 2) * 4 : (extLen + 1) * 8;
    nextHeader = dv.getUint8(cursor);
    cursor += len;
    hops += 1;
  }
  if (cursor <= ipEnd) {
    decodeTransport(dv, buf, cursor, ipEnd, nextHeader, packet);
  } else {
    packet.protocol = 'OTHER';
  }
}

function decodeLinkLayer(
  dv: DataView,
  buf: Buffer,
  linkType: number,
  start: number,
  end: number,
  warnings: string[],
  packet: DecodedPacket,
): void {
  let etherType = 0;
  let ipStart = start;

  if (linkType === LINKTYPE_ETHERNET) {
    if (start + 14 > end) {
      packet.protocol = 'OTHER';
      return;
    }
    etherType = dv.getUint16(start + 12);
    ipStart = start + 14;
    // VLAN (0x8100) and QinQ (0x88a8).
    let guard = 0;
    while ((etherType === 0x8100 || etherType === 0x88a8) && guard < 2 && ipStart + 4 <= end) {
      etherType = dv.getUint16(ipStart + 2);
      ipStart += 4;
      guard += 1;
    }
  } else if (linkType === LINKTYPE_LINUX_SLL) {
    if (start + 16 > end) {
      packet.protocol = 'OTHER';
      return;
    }
    etherType = dv.getUint16(start + 14);
    ipStart = start + 16;
  } else if (linkType === LINKTYPE_LINUX_SLL2) {
    if (start + 20 > end) {
      packet.protocol = 'OTHER';
      return;
    }
    etherType = dv.getUint16(start);
    ipStart = start + 20;
  } else if (linkType === LINKTYPE_RAW_IP) {
    const version = dv.getUint8(start) >> 4;
    etherType = version === 6 ? 0x86dd : 0x0800;
  } else {
    if (!warnings.includes(`unsupported link type ${linkType}`)) {
      warnings.push(`unsupported link type ${linkType}`);
    }
    packet.protocol = 'OTHER';
    return;
  }

  if (ipStart > end) {
    packet.protocol = 'OTHER';
    return;
  }

  const version = dv.getUint8(ipStart) >> 4;
  if (etherType === 0x0800 || (linkType === LINKTYPE_RAW_IP && version === 4)) {
    if (ipStart + 20 <= end) decodeIpv4(dv, buf, ipStart, end, packet);
    else packet.protocol = 'OTHER';
  } else if (etherType === 0x86dd || (linkType === LINKTYPE_RAW_IP && version === 6)) {
    if (ipStart + 40 <= end) decodeIpv6(dv, buf, ipStart, end, packet);
    else packet.protocol = 'OTHER';
  } else if (etherType === 0x0806) {
    packet.protocol = 'OTHER';
    packet.srcIp = 'ARP';
    packet.dstIp = 'ARP';
  } else {
    packet.protocol = 'OTHER';
  }
}

function topN(counts: Map<string, number>, n: number): Array<{ value: string; count: number }> {
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([value, count]) => ({ value, count }));
}

function bucketFor(size: number): string {
  if (size <= 64) return '0-64';
  if (size <= 128) return '65-128';
  if (size <= 256) return '129-256';
  if (size <= 512) return '257-512';
  if (size <= 1024) return '513-1024';
  if (size <= 1500) return '1025-1500';
  return '>1500';
}

/** Parse a classic libpcap capture into a summary plus (optionally) packets. */
export function parsePcap(buffer: Buffer, options: ParseOptions = {}): ParseResult {
  const maxPackets = options.maxPackets ?? 500_000;
  const keepPackets = options.keepPackets ?? true;
  const topCount = options.topN ?? 10;

  const warnings: string[] = [];
  if (buffer.length < 24) {
    throw new Error('Capture is smaller than the libpcap global header (24 bytes).');
  }

  const dv = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  const magicLE = dv.getUint32(0, true);

  let endianness: 'little' | 'big';
  let timestampResolution: 'microsecond' | 'nanosecond';
  let magicHex: string;
  if (magicLE === PCAP_MAGIC_MICRO_LE) {
    endianness = 'little';
    timestampResolution = 'microsecond';
    magicHex = 'd4c3b2a1';
  } else if (magicLE === PCAP_MAGIC_BIG) {
    endianness = 'big';
    timestampResolution = 'microsecond';
    magicHex = 'a1b2c3d4';
  } else if (magicLE === PCAP_MAGIC_NANO_LE) {
    endianness = 'little';
    timestampResolution = 'nanosecond';
    magicHex = '4d3cb2a1';
  } else if (magicLE === PCAP_MAGIC_NANO_BIG) {
    endianness = 'big';
    timestampResolution = 'nanosecond';
    magicHex = 'a1b23c4d';
  } else {
    throw new Error(`Unrecognised libpcap magic 0x${magicLE.toString(16)}.`);
  }

  const le = endianness === 'little';
  const versionMajor = dv.getUint16(4, le);
  const versionMinor = dv.getUint16(6, le);
  const linkType = dv.getUint32(20, le);

  const format: PcapFormat = {
    magic: magicHex,
    endianness,
    timestampResolution,
    linkType,
    version: `${versionMajor}.${versionMinor}`,
  };

  const packets: DecodedPacket[] = [];
  const protocolCounts = new Map<string, number>();
  const ipVersionCounts = new Map<string, number>();
  const srcIpCounts = new Map<string, number>();
  const dstIpCounts = new Map<string, number>();
  const dstPortCounts = new Map<string, number>();
  const sizeBuckets = new Map<string, number>();

  let offset = 24;
  let index = 0;
  let capturedBytes = 0;
  let originalBytes = 0;
  let malformed = 0;
  let firstTs: number | null = null;
  let lastTs: number | null = null;

  const fracDivisor = timestampResolution === 'nanosecond' ? 1e9 : 1e6;

  while (offset + 16 <= buffer.length && index < maxPackets) {
    const tsSec = dv.getUint32(offset, le);
    const tsFrac = dv.getUint32(offset + 4, le);
    const inclLen = dv.getUint32(offset + 8, le);
    const origLen = dv.getUint32(offset + 12, le);

    if (inclLen > buffer.length - offset - 16 || inclLen > 0x40000000) {
      malformed += 1;
      break;
    }

    const dataStart = offset + 16;
    const dataEnd = dataStart + inclLen;
    const ts = tsSec + tsFrac / fracDivisor;

    const packet: DecodedPacket = {
      index,
      ts,
      srcIp: '?',
      dstIp: '?',
      srcPort: 0,
      dstPort: 0,
      protocol: 'OTHER',
      ipVersion: 4,
      frameLength: inclLen,
      ipLength: 0,
      payloadLength: 0,
    };
    try {
      decodeLinkLayer(dv, buffer, linkType, dataStart, dataEnd, warnings, packet);
    } catch {
      packet.protocol = 'OTHER';
    }

    capturedBytes += inclLen;
    originalBytes += origLen;
    protocolCounts.set(packet.protocol, (protocolCounts.get(packet.protocol) ?? 0) + 1);
    ipVersionCounts.set(`IPv${packet.ipVersion}`, (ipVersionCounts.get(`IPv${packet.ipVersion}`) ?? 0) + 1);
    if (packet.srcIp && packet.srcIp !== '?') srcIpCounts.set(packet.srcIp, (srcIpCounts.get(packet.srcIp) ?? 0) + 1);
    if (packet.dstIp && packet.dstIp !== '?') dstIpCounts.set(packet.dstIp, (dstIpCounts.get(packet.dstIp) ?? 0) + 1);
    if (packet.dstPort > 0) dstPortCounts.set(String(packet.dstPort), (dstPortCounts.get(String(packet.dstPort)) ?? 0) + 1);
    const bucket = bucketFor(inclLen);
    sizeBuckets.set(bucket, (sizeBuckets.get(bucket) ?? 0) + 1);

    if (firstTs === null || ts < firstTs) firstTs = ts;
    if (lastTs === null || ts > lastTs) lastTs = ts;

    if (keepPackets) packets.push(packet);

    offset = dataEnd;
    index += 1;
  }

  if (index >= maxPackets && offset + 16 <= buffer.length) {
    warnings.push(`stopped after ${maxPackets} packets (maxPackets cap)`);
  }

  const durationSeconds = firstTs !== null && lastTs !== null ? Math.max(lastTs - firstTs, 0) : null;
  const packetsPerSecond =
    durationSeconds && durationSeconds > 0 ? Number((index / durationSeconds).toFixed(3)) : null;

  const summary: PcapSummary = {
    format,
    packetCount: index,
    capturedBytes,
    originalBytes,
    malformedRecords: malformed,
    durationSeconds: durationSeconds !== null ? Number(durationSeconds.toFixed(6)) : null,
    packetsPerSecond,
    avgPacketSize: index > 0 ? Number((capturedBytes / index).toFixed(2)) : 0,
    protocols: Object.fromEntries(protocolCounts),
    ipVersions: Object.fromEntries(ipVersionCounts),
    topSrcIps: topN(srcIpCounts, topCount),
    topDstIps: topN(dstIpCounts, topCount),
    topDstPorts: topN(dstPortCounts, topCount),
    packetSizeDistribution: [...sizeBuckets.entries()]
      .map(([bucket, count]) => ({ bucket, count }))
      .sort((a, b) => a.bucket.localeCompare(b.bucket)),
    parseWarnings: warnings,
  };

  return { summary, packets };
}

/** Parse a tshark `-z io,phs` protocol-hierarchy block into name/frames pairs. */
export function parseTsharkProtocolHierarchy(stdout: string): Array<{ protocol: string; frames: number }> {
  const out: Array<{ protocol: string; frames: number }> = [];
  for (const rawLine of stdout.split(/\r?\n/)) {
    const m = /^\s*([A-Za-z0-9_.\-/]+)\s+frames:\s*(\d+)\s+bytes:\s*(\d+)/.exec(rawLine);
    if (m && m[1] && m[2]) out.push({ protocol: m[1], frames: Number(m[2]) });
  }
  return out;
}
