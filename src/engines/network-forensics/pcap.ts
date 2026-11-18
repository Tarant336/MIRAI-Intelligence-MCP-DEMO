/**
 * Dependency-free PCAP / PCAPNG parser (§6).
 *
 * This is a REUSABLE, pure-JS, read-only parser. It is deliberately defensive:
 * malformed input must NEVER throw — every anomaly is collected into the
 * returned `errors[]` array and parsing continues where possible.
 *
 * Supported:
 *   - libpcap magic 0xa1b2c3d4 (microsecond, LE/BE)
 *   - libpcap magic 0xa1b23c4d (nanosecond, LE/BE)
 *   - pcapng Section Header Block (0x0a0d0d0a) with IDB/EPB/SPB blocks
 *   - Ethernet (link type 1) with 802.1Q VLAN (0x8100 / 0x88a8)
 *   - raw IP link types (101 / 12 / 228)
 *   - IPv4 (honours IHL, skips options), TCP and UDP, ICMP classification
 */

export interface PcapTcpFlags {
  syn: boolean;
  ack: boolean;
  fin: boolean;
  rst: boolean;
  psh: boolean;
  urg: boolean;
}

export interface PcapPacket {
  index: number;
  tsSec: number;
  tsUsec: number;
  origLen: number;
  capLen: number;
  linkType: number;
  src?: string;
  dst?: string;
  srcPort?: number;
  dstPort?: number;
  protocol: 'tcp' | 'udp' | 'icmp' | 'other' | 'unknown';
  tcpFlags?: PcapTcpFlags;
  vlan?: number;
  payloadLen: number;
  /** Transport-layer payload as a zero-copy view into the capture buffer. */
  payload?: Buffer;
}

export interface PcapParseResult {
  linkType: number;
  magic: string;
  packets: PcapPacket[];
  errors: string[];
}

const DEFAULT_MAX_PACKETS = 500_000;

function readU8(buf: Buffer, off: number): number {
  return off >= 0 && off < buf.length ? buf.readUInt8(off) : 0;
}

function readU16(buf: Buffer, off: number, le: boolean): number {
  if (off < 0 || off + 2 > buf.length) return 0;
  return le ? buf.readUInt16LE(off) : buf.readUInt16BE(off);
}

function readU32(buf: Buffer, off: number, le: boolean): number {
  if (off < 0 || off + 4 > buf.length) return 0;
  return le ? buf.readUInt32LE(off) : buf.readUInt32BE(off);
}

function ipv4ToString(buf: Buffer, off: number): string {
  return `${readU8(buf, off)}.${readU8(buf, off + 1)}.${readU8(buf, off + 2)}.${readU8(buf, off + 3)}`;
}

/** Serialize an IPv4 address (4 bytes) as a dotted string. */
export function serializeIpv4(bytes: ArrayLike<number>): string {
  return `${bytes[0] ?? 0}.${bytes[1] ?? 0}.${bytes[2] ?? 0}.${bytes[3] ?? 0}`;
}

function decodeTcp(data: Buffer, off: number, end: number, pkt: PcapPacket): void {
  pkt.protocol = 'tcp';
  if (off + 20 > data.length) {
    pkt.payloadLen = 0;
    return;
  }
  pkt.srcPort = readU16(data, off, false);
  pkt.dstPort = readU16(data, off + 2, false);
  const b12 = readU8(data, off + 12);
  const b13 = readU8(data, off + 13);
  const flags = ((b12 & 0x01) << 8) | b13;
  pkt.tcpFlags = {
    fin: (flags & 0x01) !== 0,
    syn: (flags & 0x02) !== 0,
    rst: (flags & 0x04) !== 0,
    psh: (flags & 0x08) !== 0,
    ack: (flags & 0x10) !== 0,
    urg: (flags & 0x20) !== 0,
  };
  const dataOffset = ((b12 >> 4) & 0x0f) * 4;
  const headerLen = dataOffset >= 20 ? dataOffset : 20;
  pkt.payloadLen = Math.max(0, end - (off + headerLen));
  if (pkt.payloadLen > 0 && off + headerLen < data.length) {
    pkt.payload = data.subarray(off + headerLen, end);
  }
}

function decodeUdp(data: Buffer, off: number, end: number, pkt: PcapPacket): void {
  pkt.protocol = 'udp';
  if (off + 8 > data.length) {
    pkt.payloadLen = 0;
    return;
  }
  pkt.srcPort = readU16(data, off, false);
  pkt.dstPort = readU16(data, off + 2, false);
  const udpLen = readU16(data, off + 4, false);
  const end2 = udpLen >= 8 && off + udpLen <= end ? off + udpLen : end;
  pkt.payloadLen = Math.max(0, end2 - (off + 8));
  if (pkt.payloadLen > 0 && off + 8 < data.length) {
    pkt.payload = data.subarray(off + 8, end2);
  }
}

function decodeIPv4(data: Buffer, l3off: number, pkt: PcapPacket): void {
  if (l3off + 20 > data.length) {
    pkt.protocol = 'unknown';
    return;
  }
  const vihl = readU8(data, l3off);
  if ((vihl >> 4) !== 4) {
    pkt.protocol = 'other';
    return;
  }
  const ihl = (vihl & 0x0f) * 4;
  if (ihl < 20 || l3off + ihl > data.length) {
    pkt.protocol = 'other';
    return;
  }
  const totalLen = readU16(data, l3off + 2, false);
  const proto = readU8(data, l3off + 9);
  pkt.src = ipv4ToString(data, l3off + 12);
  pkt.dst = ipv4ToString(data, l3off + 16);

  const l4off = l3off + ihl;
  let ipEnd = data.length;
  if (totalLen >= ihl && l3off + totalLen <= data.length) {
    ipEnd = l3off + totalLen;
  }
  if (proto === 6) decodeTcp(data, l4off, ipEnd, pkt);
  else if (proto === 17) decodeUdp(data, l4off, ipEnd, pkt);
  else if (proto === 1) {
    pkt.protocol = 'icmp';
    pkt.payloadLen = Math.max(0, ipEnd - l4off);
  } else pkt.protocol = 'other';
}

function decodeEthernet(data: Buffer, pkt: PcapPacket): void {
  if (data.length < 14) {
    pkt.protocol = 'unknown';
    return;
  }
  let etherType = readU16(data, 12, false);
  let l3off = 14;
  if (etherType === 0x8100 || etherType === 0x88a8) {
    if (data.length >= 18) {
      const tci = readU16(data, 14, false);
      pkt.vlan = tci & 0x0fff;
      etherType = readU16(data, 16, false);
      l3off = 18;
    }
  }
  if (etherType === 0x0800) decodeIPv4(data, l3off, pkt);
  else if (etherType === 0x86dd) pkt.protocol = 'other'; // IPv6 not decoded further
  else pkt.protocol = 'other';
}

function decodeLink(
  data: Buffer,
  linkType: number,
  index: number,
  tsSec: number,
  tsUsec: number,
  capLen: number,
  origLen: number,
  errors: string[],
): PcapPacket {
  const pkt: PcapPacket = {
    index,
    tsSec,
    tsUsec,
    capLen,
    origLen,
    linkType,
    protocol: 'unknown',
    payloadLen: 0,
  };
  try {
    if (linkType === 1) decodeEthernet(data, pkt);
    else if (linkType === 101 || linkType === 12 || linkType === 228) {
      if ((readU8(data, 0) >> 4) === 4) decodeIPv4(data, 0, pkt);
      else pkt.protocol = 'other';
    } else pkt.protocol = 'other';
  } catch (err) {
    errors.push(`packet ${index}: ${(err as Error).message}`);
    pkt.protocol = 'unknown';
  }
  return pkt;
}

function parseLibpcap(
  buf: Buffer,
  maxPackets: number,
  errors: string[],
): PcapParseResult | undefined {
  if (buf.length < 24) {
    errors.push('libpcap: file shorter than the 24-byte global header');
    return undefined;
  }
  const magicLE = buf.readUInt32LE(0);
  let little: boolean;
  let nanosecond = false;
  let magic: string;
  if (magicLE === 0xa1b2c3d4) {
    little = true;
    magic = '0xa1b2c3d4 (libpcap, little-endian, microsecond)';
  } else if (magicLE === 0xd4c3b2a1) {
    little = false;
    magic = '0xa1b2c3d4 (libpcap, big-endian, microsecond)';
  } else if (magicLE === 0xa1b23c4d) {
    little = true;
    nanosecond = true;
    magic = '0xa1b23c4d (libpcap, little-endian, nanosecond)';
  } else if (magicLE === 0x4d3cb2a1) {
    little = false;
    nanosecond = true;
    magic = '0xa1b23c4d (libpcap, big-endian, nanosecond)';
  } else {
    return undefined;
  }

  const linkType = readU32(buf, 20, little);
  const packets: PcapPacket[] = [];
  let off = 24;
  while (off + 16 <= buf.length && packets.length < maxPackets) {
    const tsSec = readU32(buf, off, little);
    const tsFrac = readU32(buf, off + 4, little);
    const capLen = readU32(buf, off + 8, little);
    const origLen = readU32(buf, off + 12, little);
    off += 16;
    if (capLen > buf.length - off) {
      errors.push(`libpcap: packet ${packets.length} caplen ${capLen} exceeds remaining ${buf.length - off} bytes (truncated)`);
      break;
    }
    const data = buf.subarray(off, off + capLen);
    off += capLen;
    const tsUsec = nanosecond ? Math.floor(tsFrac / 1000) : tsFrac;
    packets.push(decodeLink(data, linkType, packets.length, tsSec, tsUsec, capLen, origLen, errors));
  }
  return { linkType, magic, packets, errors };
}

function parseNg(
  buf: Buffer,
  maxPackets: number,
  errors: string[],
): PcapParseResult | undefined {
  if (buf.length < 12 || buf.readUInt32LE(0) !== 0x0a0d0d0a) return undefined;

  const packets: PcapPacket[] = [];
  let linkType = 1; // default Ethernet
  const magic = '0x0a0d0d0a (pcapng)';
  let off = 0;
  let guard = 0;
  while (off + 12 <= buf.length && packets.length < maxPackets && guard < 5_000_000) {
    guard += 1;
    const blockType = buf.readUInt32LE(off);
    const blockLen = buf.readUInt32LE(off + 4);
    if (blockLen < 12 || off + blockLen > buf.length || blockLen % 4 !== 0) {
      errors.push(`pcapng: block at offset ${off} has invalid length ${blockLen}`);
      break;
    }
    const body = buf.subarray(off + 8, off + blockLen - 4);

    if (blockType === 0x00000001) {
      // Interface Description Block
      if (body.length >= 8) linkType = body.readUInt16LE(0);
    } else if (blockType === 0x00000006) {
      // Enhanced Packet Block
      if (body.length >= 20) {
        const tsHigh = body.readUInt32LE(4);
        const tsLow = body.readUInt32LE(8);
        const capLen = body.readUInt32LE(12);
        const origLen = body.readUInt32LE(16);
        const avail = body.length - 20;
        const n = Math.min(capLen, avail);
        if (capLen > avail) {
          errors.push(`pcapng: packet ${packets.length} caplen ${capLen} exceeds available ${avail} bytes (truncated)`);
        }
        const data = body.subarray(20, 20 + n);
        const ticks = tsHigh * 4294967296 + tsLow;
        const tsSec = Math.floor(ticks / 1_000_000);
        const tsUsec = ticks % 1_000_000;
        packets.push(decodeLink(data, linkType, packets.length, tsSec, tsUsec, n, origLen, errors));
      } else {
        errors.push(`pcapng: EPB at offset ${off} is too small`);
      }
    } else if (blockType === 0x00000003) {
      // Simple Packet Block
      if (body.length >= 4) {
        const origLen = body.readUInt32LE(0);
        const data = body.subarray(4);
        packets.push(decodeLink(data, linkType, packets.length, 0, 0, data.length, origLen, errors));
      }
    }
    off += blockLen;
  }
  return { linkType, magic, packets, errors };
}

/**
 * Parse a PCAP or PCAPNG buffer. Never throws: anomalies are reported in
 * `errors` and the best-effort packet list is returned.
 */
export function parsePcap(buffer: Buffer, maxPackets = DEFAULT_MAX_PACKETS): PcapParseResult {
  const errors: string[] = [];
  try {
    if (buffer.length === 0) {
      return { linkType: 0, magic: 'unknown', packets: [], errors: ['empty capture'] };
    }
    const ng = parseNg(buffer, maxPackets, errors);
    if (ng) return ng;
    const lib = parseLibpcap(buffer, maxPackets, errors);
    if (lib) return lib;
    return {
      linkType: 0,
      magic: 'unknown',
      packets: [],
      errors: [...errors, 'unrecognized capture format (not libpcap or pcapng)'],
    };
  } catch (err) {
    return {
      linkType: 0,
      magic: 'unknown',
      packets: [],
      errors: [...errors, `fatal parser error: ${(err as Error).message}`],
    };
  }
}

/** Whether an IPv4 address is private, loopback, link-local, multicast or reserved. */
export function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split('.').map((p) => Number.parseInt(p, 10));
  const a = parts[0];
  const b = parts[1];
  if (a === undefined || b === undefined || Number.isNaN(a) || Number.isNaN(b)) return true;
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 0) return true;
  if (a >= 224) return true;
  return false;
}

/** Direction-normalized 5-tuple key for a packet (lower endpoint first). */
export function flowKey(pkt: PcapPacket): string {
  const a = `${pkt.src ?? '?'}:${pkt.srcPort ?? 0}`;
  const b = `${pkt.dst ?? '?'}:${pkt.dstPort ?? 0}`;
  const [x, y] = a <= b ? [a, b] : [b, a];
  return `${pkt.protocol}|${x}|${y}`;
}

/** Directional 5-tuple key (keeps source/destination orientation). */
export function directionalKey(pkt: PcapPacket): string {
  return `${pkt.protocol}|${pkt.src ?? '?'}:${pkt.srcPort ?? 0}->${pkt.dst ?? '?'}:${pkt.dstPort ?? 0}`;
}

/** Absolute capture timestamp in seconds (float). */
export function packetTime(pkt: PcapPacket): number {
  return pkt.tsSec + pkt.tsUsec / 1_000_000;
}
