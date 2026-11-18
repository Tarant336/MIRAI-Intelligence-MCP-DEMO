/**
 * Regression tests for c2_protocol_analyze (P2.1).
 *
 * The tool used to be a stub: given a capture it only recorded that the file
 * existed and delegated everything to network-forensics. These tests lock down
 * the real offline parser: documented Mirai bot-login framing, uint16
 * length-prefix message framing, the exact `cnc/attack.go` attack-command
 * layout, per-field offsets/byte-order, message types, command identifiers and
 * honest "unsupported" reporting.
 *
 * All fixtures are built by hand here with explicit ground truth; the parser
 * connects to no live C2 and builds no client or server.
 */

import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

import { buildRegistry } from '../src/index.js';
import {
  MIRAI_ATTACK_VECTORS,
  analyzeMessageStream,
  decodeMiraiAttackCommand,
  type C2MessageField,
} from '../src/engines/malware-intelligence/protocol.js';
import { createLogger } from '../src/core/logger.js';
import { EvidenceCollector } from '../src/shared/evidence.js';
import { getKnowledgeBase } from '../src/shared/knowledge-base.js';
import type { ToolContext } from '../src/core/tool.js';

const registry = buildRegistry();

function makeCtx(tool: string): ToolContext {
  return {
    logger: createLogger({ test: true, tool }),
    knowledge: getKnowledgeBase(),
    evidence: new EvidenceCollector(),
  };
}

async function invoke(name: string, input: Record<string, unknown>) {
  const entry = registry.get(name);
  if (!entry) throw new Error(`Tool ${name} not registered`);
  return entry.def.handler(input, makeCtx(name));
}

/* --- ground-truth C2 payloads --------------------------------------------- */

const BOT_ID = 'c2bot1'; // 6 printable bytes
const LOGIN = Buffer.concat([Buffer.from([0x00, 0x00, 0x00, BOT_ID.length]), Buffer.from(BOT_ID, 'latin1')]);
const KEEP_ALIVE = Buffer.from([0x00, 0x00]); // uint16 BE length = 0
const PING_PAYLOAD = Buffer.from('PING', 'latin1');
const PING = Buffer.concat([Buffer.from([0x00, PING_PAYLOAD.length]), PING_PAYLOAD]);

/** Documented `cnc/attack.go Build()` layout, built field-by-field. */
function buildAttackPayload(): Buffer {
  return Buffer.concat([
    Buffer.from([0x00, 0x00, 0x00, 0x3c]), // duration = 60
    Buffer.from([0x03]), // type = 3 (syn)
    Buffer.from([0x01]), // targetCount = 1
    Buffer.from([203, 0, 113, 10, 32]), // target ip 203.0.113.10 / netmask 32
    Buffer.from([0x01]), // flagCount = 1
    Buffer.from([0x01, 0x04]), // flag key 0x01, len 4
    Buffer.from('1000', 'latin1'),
  ]);
}
const ATTACK_PAYLOAD = buildAttackPayload();
const ATTACK = Buffer.concat([Buffer.from([0x00, ATTACK_PAYLOAD.length]), ATTACK_PAYLOAD]);

const SERVER_REPLY_PAYLOAD = Buffer.from('PONG\r\n', 'latin1');
const SERVER_REPLY = Buffer.concat([Buffer.from([0x00, SERVER_REPLY_PAYLOAD.length]), SERVER_REPLY_PAYLOAD]);

function field(fields: C2MessageField[], name: string): C2MessageField | undefined {
  return fields.find((f) => f.name === name);
}

/* --- hand-built libpcap fixture ------------------------------------------- */

const FIX_DIR = join('test-artifacts', '_c2_fixtures');
const CLIENT_IP = '10.0.0.5';
const SERVER_IP = '10.0.0.9';
const CLIENT_PORT = 40222;
const SERVER_PORT = 48101;

function ipBytes(ip: string): number[] {
  return ip.split('.').map((p) => Number.parseInt(p, 10));
}

function tcpFrame(opts: {
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  seq: number;
  ack: number;
  flags: { syn?: boolean; ack?: boolean; psh?: boolean; fin?: boolean };
  payload?: Buffer;
}): Buffer {
  const payload = opts.payload ?? Buffer.alloc(0);
  const eth = Buffer.alloc(14);
  Buffer.from([0x02, 0, 0, 0, 0, 0x02]).copy(eth, 0);
  Buffer.from([0x02, 0, 0, 0, 0, 0x01]).copy(eth, 6);
  eth.writeUInt16BE(0x0800, 12);

  const ip = Buffer.alloc(20);
  ip.writeUInt8(0x45, 0);
  ip.writeUInt16BE(20 + 20 + payload.length, 2);
  ip.writeUInt16BE(0x1234, 4);
  ip.writeUInt16BE(0x4000, 6);
  ip.writeUInt8(64, 8);
  ip.writeUInt8(6, 9); // TCP
  Buffer.from(ipBytes(opts.srcIp)).copy(ip, 12);
  Buffer.from(ipBytes(opts.dstIp)).copy(ip, 16);

  const tcp = Buffer.alloc(20);
  tcp.writeUInt16BE(opts.srcPort, 0);
  tcp.writeUInt16BE(opts.dstPort, 2);
  tcp.writeUInt32BE(opts.seq >>> 0, 4);
  tcp.writeUInt32BE(opts.ack >>> 0, 8);
  tcp.writeUInt8(0x50, 12); // data offset = 5 (20-byte header)
  let fl = 0;
  if (opts.flags.fin) fl |= 0x01;
  if (opts.flags.syn) fl |= 0x02;
  if (opts.flags.psh) fl |= 0x08;
  if (opts.flags.ack) fl |= 0x10;
  tcp.writeUInt8(fl, 13);
  tcp.writeUInt16BE(65535, 14);
  return Buffer.concat([eth, ip, tcp, payload]);
}

function writePcap(frames: Buffer[]): Buffer {
  const parts: Buffer[] = [];
  const gh = Buffer.alloc(24);
  gh.writeUInt32LE(0xa1b2c3d4, 0); // little-endian, microsecond
  gh.writeUInt16LE(2, 4);
  gh.writeUInt16LE(4, 6);
  gh.writeUInt32LE(65535, 16);
  gh.writeUInt32LE(1, 20); // Ethernet
  parts.push(gh);
  let t = 1_700_000_000;
  for (const f of frames) {
    const ph = Buffer.alloc(16);
    ph.writeUInt32LE(t, 0);
    ph.writeUInt32LE(0, 4);
    ph.writeUInt32LE(f.length, 8);
    ph.writeUInt32LE(f.length, 12);
    parts.push(ph, f);
    t += 1;
  }
  return Buffer.concat(parts);
}

function buildC2Capture(): Buffer {
  const c2sPayload = Buffer.concat([LOGIN, KEEP_ALIVE, PING, ATTACK]);
  return writePcap([
    tcpFrame({ srcIp: CLIENT_IP, dstIp: SERVER_IP, srcPort: CLIENT_PORT, dstPort: SERVER_PORT, seq: 1000, ack: 0, flags: { syn: true } }),
    tcpFrame({ srcIp: SERVER_IP, dstIp: CLIENT_IP, srcPort: SERVER_PORT, dstPort: CLIENT_PORT, seq: 5000, ack: 1001, flags: { syn: true, ack: true } }),
    tcpFrame({ srcIp: CLIENT_IP, dstIp: SERVER_IP, srcPort: CLIENT_PORT, dstPort: SERVER_PORT, seq: 1001, ack: 5001, flags: { ack: true } }),
    tcpFrame({ srcIp: CLIENT_IP, dstIp: SERVER_IP, srcPort: CLIENT_PORT, dstPort: SERVER_PORT, seq: 1001, ack: 5001, flags: { psh: true, ack: true }, payload: c2sPayload }),
    tcpFrame({ srcIp: SERVER_IP, dstIp: CLIENT_IP, srcPort: SERVER_PORT, dstPort: CLIENT_PORT, seq: 5001, ack: 1001 + c2sPayload.length, flags: { psh: true, ack: true }, payload: SERVER_REPLY }),
  ]);
}

function writeFixture(name: string, buf: Buffer): string {
  mkdirSync(FIX_DIR, { recursive: true });
  const p = join(FIX_DIR, name);
  writeFileSync(p, buf);
  return p;
}

afterAll(() => {
  rmSync(FIX_DIR, { recursive: true, force: true });
});

/* --- unit tests: analyzeMessageStream -------------------------------------- */

describe('analyzeMessageStream (unit)', () => {
  it('recognises the documented Mirai bot-login handshake and frames the rest', () => {
    const stream = Buffer.concat([LOGIN, KEEP_ALIVE, PING, ATTACK]);
    const a = analyzeMessageStream(stream, 'client-to-server');

    expect(a.framing.kind).toBe('mirai-bot-login');
    expect(a.framing.confidence).toBe('observed');
    expect(a.messages).toHaveLength(4);

    const login = a.messages[0]!;
    expect(login.messageType).toBe('login');
    expect(login.totalLength).toBe(4 + BOT_ID.length);
    expect(field(login.fields, 'bot_login_marker')?.value).toBe('00 00 00');
    expect(field(login.fields, 'id_length')?.value).toBe(BOT_ID.length);
    expect(field(login.fields, 'bot_id')?.value).toBe(BOT_ID);

    const keepAlive = a.messages[1]!;
    expect(keepAlive.payloadLength).toBe(0);
    expect(keepAlive.confidence).toBe('observed');

    const ping = a.messages[2]!;
    expect(ping.messageType).toBe('command');
    expect(ping.commandIdentifier).toBe('PING');

    const attack = a.messages[3]!;
    expect(attack.messageType).toBe('attack');
    expect(attack.confidence).toBe('hypothesis');
  });

  it('frames a keep-alive + command stream purely by the uint16 BE length prefix', () => {
    // Two keep-alives first, so the opening bytes are NOT a valid login signature.
    const stream = Buffer.concat([KEEP_ALIVE, KEEP_ALIVE, PING]);
    const a = analyzeMessageStream(stream, 'client-to-server');
    expect(a.framing.kind).toBe('length-prefixed');
    expect(a.framing.prefixSize).toBe(2);
    expect(a.framing.byteOrder).toBe('big');
    expect(a.messages).toHaveLength(3);
    expect(a.messages[0]!.byteOrder).toBe('big');
    expect(field(a.messages[0]!.fields, 'length_prefix')?.value).toBe(0);
    expect(a.messages[2]!.commandIdentifier).toBe('PING');
  });

  it('does NOT misread a run of zero bytes as a bot-login handshake', () => {
    const a = analyzeMessageStream(Buffer.alloc(8), 'client-to-server');
    expect(a.framing.kind).not.toBe('mirai-bot-login');
  });

  it('never throws and reports honestly on empty / opaque input', () => {
    expect(() => analyzeMessageStream(Buffer.alloc(0), 'server-to-client')).not.toThrow();
    expect(() => analyzeMessageStream(Buffer.from([0xff, 0xfe, 0xfd]), 'server-to-client')).not.toThrow();

    const empty = analyzeMessageStream(Buffer.alloc(0), 'server-to-client');
    expect(empty.messages).toHaveLength(0);
    expect(empty.framing.kind).toBe('unknown');

    const opaque = analyzeMessageStream(Buffer.from([0xff, 0xfe, 0xfd]), 'server-to-client');
    expect(opaque.unsupported.length).toBeGreaterThan(0);
  });
});

/* --- unit tests: decodeMiraiAttackCommand ---------------------------------- */

describe('decodeMiraiAttackCommand (unit)', () => {
  it('decodes the documented layout exactly, with offsets and byte order', () => {
    const fields = decodeMiraiAttackCommand(ATTACK_PAYLOAD, 100);
    expect(fields).not.toBeNull();
    const f = fields!;

    const duration = field(f, 'duration_seconds')!;
    expect(duration.value).toBe(60);
    expect(duration.offset).toBe(100);
    expect(duration.byteOrder).toBe('big');

    const type = field(f, 'attack_type')!;
    expect(type.value).toBe(`3 (${MIRAI_ATTACK_VECTORS[3]})`);
    expect(type.offset).toBe(104);

    expect(field(f, 'target_count')?.value).toBe(1);
    expect(field(f, 'target[0].ip')?.value).toBe('203.0.113.10');
    expect(field(f, 'target[0].netmask')?.value).toBe(32);
    expect(field(f, 'flag_count')?.value).toBe(1);
    expect(field(f, 'flag[0]')?.value).toBe('1:1000');
  });

  it('returns null instead of force-interpreting a non-matching payload', () => {
    expect(decodeMiraiAttackCommand(Buffer.from('hello'), 0)).toBeNull();
    expect(decodeMiraiAttackCommand(Buffer.concat([ATTACK_PAYLOAD, Buffer.from([0xff])]), 0)).toBeNull();
  });
});

/* --- tool-level regression: c2_protocol_analyze over a capture ------------- */

interface StreamReport {
  flowKey: string;
  from: string;
  to: string;
  orientation: 'syn' | 'assumed';
  analysis: {
    direction: string;
    byteLength: number;
    framing: { kind: string; prefixSize: number; byteOrder: string; confidence: string; evidence: string };
    messages: {
      messageType: string;
      commandIdentifier: string | null;
      payloadLength: number;
      fields: C2MessageField[];
    }[];
    unsupported: string[];
  };
}
interface C2Data {
  source: string;
  pcapNote: string | null;
  streams: StreamReport[];
  commandIdentifiers: string[];
  pcapErrors: string[];
}

describe('c2_protocol_analyze capture parsing (P2.1)', () => {
  it('reassembles the TCP stream, frames messages and reports fields + confidence', async () => {
    const pcapPath = writeFixture('c2-session.pcap', buildC2Capture());
    const res = await invoke('c2_protocol_analyze', { pcapPath });
    expect(res.ok).toBe(true);
    const data = res.data as C2Data;

    expect(data.source).toBe('capture');
    expect(data.pcapErrors).toEqual([]);
    expect(data.pcapNote).toContain('packet(s)');
    expect(data.streams.length).toBeGreaterThanOrEqual(2);

    const client = data.streams.find((s) => s.from.startsWith(CLIENT_IP));
    expect(client, 'client-to-server stream should be reported').toBeDefined();
    expect(client!.analysis.direction).toBe('client-to-server');
    expect(client!.orientation).toBe('syn'); // orientation came from the SYN handshake
    expect(client!.analysis.framing.kind).toBe('mirai-bot-login');
    expect(client!.analysis.messages).toHaveLength(4);

    const [, , ping, attack] = client!.analysis.messages;
    expect(ping!.commandIdentifier).toBe('PING');
    expect(attack!.messageType).toBe('attack');
    expect(field(attack!.fields, 'duration_seconds')?.value).toBe(60);
    expect(field(attack!.fields, 'attack_type')?.value).toBe('3 (syn)');
    expect(field(attack!.fields, 'target[0].ip')?.value).toBe('203.0.113.10');

    expect(data.commandIdentifiers).toContain('PING');

    const server = data.streams.find((s) => s.analysis.direction === 'server-to-client');
    expect(server, 'server-to-client stream should be reported').toBeDefined();
    expect(server!.analysis.framing.kind).toBe('length-prefixed');
    expect(server!.analysis.messages[0]!.commandIdentifier).toBe('PONG');

    // Honest reporting: encrypted / reassembly limits must be stated.
    expect(client!.analysis.unsupported.join(' ')).toContain('encryption');
  });

  it('emits observed evidence for the login handshake and hypothesis for the attack layout', async () => {
    const pcapPath = writeFixture('c2-session-evidence.pcap', buildC2Capture());
    const res = await invoke('c2_protocol_analyze', { pcapPath });
    const evidence = res.evidence as { claim: string; confidence: string }[];
    expect(evidence.some((e) => e.claim.includes('bot-login handshake') && e.confidence === 'observed')).toBe(true);
    expect(evidence.some((e) => e.claim.includes('attack-command layout') && e.confidence === 'hypothesis')).toBe(true);
  });

  it('degrades gracefully on a non-PCAP file and never claims a capture was parsed', async () => {
    const bogus = writeFixture('not-a-capture.bin', Buffer.from('this is not a capture'));
    const res = await invoke('c2_protocol_analyze', { pcapPath: bogus });
    expect(res.ok).toBe(true);
    const data = res.data as C2Data;
    expect(data.source).toBe('capture');
    expect(data.pcapNote).toContain('not a recognised');
    expect(data.streams).toHaveLength(0);
  });

  it('rejects a capture path outside the workspace (path confinement preserved)', async () => {
    await expect(invoke('c2_protocol_analyze', { pcapPath: '../escape.pcap' })).rejects.toThrow();
  });
});
