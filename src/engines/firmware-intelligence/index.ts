/**
 * Firmware Intelligence engine (§5, §11).
 *
 * Static, read-only analysis of firmware images and their extracted
 * filesystems. NOTHING here executes untrusted firmware: extraction produces
 * artifacts only, emulation is planned (never launched), and every finding is
 * reported with explicit provenance and confidence (§5, §10, §B1/§C2).
 */

import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { basename, join, relative } from 'node:path';
import { gunzipSync } from 'node:zlib';

import { z } from 'zod';

import { getConfig } from '../../config/index.js';
import { errors } from '../../core/errors.js';
import { discoverTools, runCommand, type ExecResult } from '../../shared/exec.js';
import { getKnowledgeBase } from '../../shared/knowledge-base.js';
import { resolveWorkspacePath } from '../../shared/security.js';
import {
  addEvidence,
  curatedProvenance,
  defineTool,
  finish,
  localProvenance,
  readBinaryArtifact,
  sha256,
  zodCommon,
} from '../../tools/helpers.js';
import {
  carveStreams,
  classifyStrings,
  detectContainerFormat,
  entropyMap,
  extractStrings,
  highEntropyRegions,
  matchComponents,
  parseCpioNewc,
  parseCpioNewcArchive,
  parseElf,
  parseTar,
  scanEmbeddedSignatures,
  shannonEntropy,
  type CarvedStream,
  type CveHint,
  type ElfReport,
  type FormatHit,
  type StringHit,
} from './analysis.js';
import type { EngineModule } from '../../core/tool.js';
import type {
  KnowledgeCategory,
  KnowledgeRecord,
  VerificationState,
} from '../../shared/knowledge-base.js';
import type { ConfidenceLevel, Provenance } from '../../shared/types.js';

const ENGINE = 'firmware-intelligence';
const ANALYSIS_WINDOW = 64 * 1024 * 1024; // cap for O(n) string/entropy passes

/* ------------------------------------------------------------------ */
/* Local helper utilities                                              */
/* ------------------------------------------------------------------ */

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

function bounded(buf: Buffer): Buffer {
  return buf.length > ANALYSIS_WINDOW ? buf.subarray(0, ANALYSIS_WINDOW) : buf;
}

function nowIso(): string {
  return new Date().toISOString();
}

function walkFiles(root: string, maxFiles = 5000): { rel: string; abs: string; size: number }[] {
  const out: { rel: string; abs: string; size: number }[] = [];
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
      const abs = join(dir, entry.name);
      if (entry.isDirectory()) stack.push(abs);
      else if (entry.isFile()) {
        try {
          out.push({ rel: relative(root, abs).replace(/\\/g, '/'), abs, size: statSync(abs).size });
        } catch {
          /* ignore */
        }
      }
    }
  }
  return out;
}

interface ComponentRecordInput {
  id: string;
  title: string;
  product: string;
  vendor?: string;
  version?: string;
  klass?: string;
  cves: CveHint[];
  provenance: Provenance[];
  confidence: ConfidenceLevel;
  verification: VerificationState;
  tags: string[];
  identifiers?: Record<string, string>;
}

function buildComponentRecord(input: ComponentRecordInput): KnowledgeRecord {
  const ts = nowIso();
  const category: KnowledgeCategory = 'firmware_component';
  return {
    id: input.id,
    category,
    title: input.title,
    identifiers: input.identifiers ?? {},
    ...(input.vendor ? { vendor: input.vendor } : {}),
    product: input.product,
    affectedVersions: input.version ? [input.version] : [],
    fixedVersions: input.cves.map((c) => c.fixed),
    ...(input.klass ? { klass: input.klass } : {}),
    preconditions: [],
    publicExploitState: 'unknown',
    relatedMalwareFamilies: [],
    relatedMiraiVariants: [],
    relatedRecordIds: [],
    verification: input.verification,
    confidence: input.confidence,
    provenance: input.provenance,
    evidence: [],
    tags: input.tags,
    createdAt: ts,
    updatedAt: ts,
  };
}

/* ------------------------------------------------------------------ */
/* Tool 1 — firmware_analyze                                           */
/* ------------------------------------------------------------------ */

interface FirmwareAnalyzeResult {
  path: string;
  sha256: string;
  sizeBytes: number;
  truncated: boolean;
  container?: FormatHit;
  embeddedSignatures: FormatHit[];
  overallEntropy: number;
  highEntropyRegions: { offset: number; size: number; entropy: number }[];
  entropySample: { offset: number; entropy: number }[];
  stringCount: number;
  classified: ReturnType<typeof classifyStrings>;
  serviceHints: string[];
  externalToolFindings: { tool: string; output: string }[];
}

const analyzeTool = defineTool<{ filePath: string; maxBytes?: number }, FirmwareAnalyzeResult>({
  name: 'firmware_analyze',
  title: 'Firmware image analysis',
  engine: ENGINE,
  description:
    'Statically analyse a firmware image: detect the container format by magic (SquashFS, JFFS2, ' +
    'UBIFS, CramFS, ext, TRX, U-Boot, DLOB, CHK, ELF, gzip/xz/bzip2/zstd, tar, cpio), scan common ' +
    'offsets for embedded signatures, extract printable strings and classify kernel/vendor/service/' +
    'credential/URL/CVE hints, and compute SHA-256 plus an entropy map that highlights compressed or ' +
    'encrypted regions. Read-only: the image is never executed.',
  capabilities: ['read_firmware'],
  risk: 'safe',
  inputSchema: { filePath: zodCommon.filePath, maxBytes: zodCommon.maxBytes },
  handler: async (input, ctx) => {
    const started = Date.now();
    const art = readBinaryArtifact(input.filePath, input.maxBytes);
    const buf = art.buffer;
    const analysisBuf = bounded(buf);

    const container = detectContainerFormat(buf);
    const embeddedSignatures = scanEmbeddedSignatures(analysisBuf);
    const strings = extractStrings(analysisBuf, 5, 40000);
    const classified = classifyStrings(strings);
    const overallEntropy = Number(shannonEntropy(analysisBuf).toFixed(4));
    const highRegions = highEntropyRegions(analysisBuf, 7.5, 256).slice(0, 64);
    const entropySample = entropyMap(analysisBuf, Math.max(4096, Math.ceil(analysisBuf.length / 64))).slice(0, 64);
    const digest = await sha256(buf);

    // Optional external corroboration (read-only tools only).
    const externalToolFindings: { tool: string; output: string }[] = [];
    const available = await discoverTools(['binwalk', 'file', 'strings']);
    if (available['file'] === true) {
      const r = await tryRun('file', [art.path]);
      if (r) externalToolFindings.push({ tool: 'file', output: (r.stdout || r.stderr).trim().slice(0, 4096) });
    }
    if (available['strings'] === true) {
      const r = await tryRun('strings', ['-n', '5', art.path]);
      if (r) {
        const lines = r.stdout.split(/\r?\n/).filter((l) => l.length >= 5);
        externalToolFindings.push({ tool: 'strings', output: `count=${lines.length}; sample:\n${lines.slice(0, 40).join('\n')}` });
      }
    }
    if (available['binwalk'] === true) {
      const r = await tryRun('binwalk', [art.path]);
      if (r) externalToolFindings.push({ tool: 'binwalk', output: (r.stdout || r.stderr).trim().slice(0, 8192) });
    }

    const serviceHints = [...new Set([...classified.services, ...(classified.busyboxVersions.length ? ['busybox'] : [])])];

    addEvidence(ctx, {
      claim: `Firmware image analysed: ${basename(art.path)} (${art.bytes} bytes, sha256 ${digest}).`,
      prov: localProvenance('firmware', art.path, 'static firmware analysis'),
      confidence: 'observed',
      locator: { file: art.path },
      data: { container: container?.format ?? null, overallEntropy, embedded: embeddedSignatures.length },
    });
    if (container) {
      addEvidence(ctx, {
        claim: `Container format detected: ${container.description} at offset 0x${container.offset.toString(16)}.`,
        prov: localProvenance('firmware', art.path, 'magic signature'),
        confidence: 'observed',
      });
    }
    for (const region of highRegions.slice(0, 10)) {
      addEvidence(ctx, {
        claim: `High-entropy region at 0x${region.offset.toString(16)} (~${region.size} bytes, entropy ${region.entropy}) — likely compressed or encrypted.`,
        prov: localProvenance('firmware', art.path, 'entropy scan'),
        confidence: 'inferred',
      });
    }
    if (art.truncated) ctx.evidence.warn(`Analysis limited to the first ${input.maxBytes} bytes of ${art.bytes}.`);

    // Persist a knowledge record for this firmware artifact.
    const recordId = `firmware:${digest.slice(7, 19)}`;
    const kb = getKnowledgeBase();
    kb.upsertRecord(
      buildComponentRecord({
        id: recordId,
        title: `Firmware image ${basename(art.path)}`,
        product: container?.format ?? 'unknown',
        version: container?.format,
        klass: 'firmware-image',
        cves: [],
        provenance: [localProvenance('firmware', art.path)],
        confidence: 'observed',
        verification: 'statically_reviewed',
        tags: ['firmware', container?.format ?? 'unknown'],
        identifiers: { sha256: digest.replace(/^sha256:/, '') },
      }),
    );
    const nodeId = `firmware_version:${digest.slice(7, 19)}`;
    kb.upsertNode({
      id: nodeId,
      kind: 'firmware_version',
      label: basename(art.path),
      properties: { sha256: digest, size: art.bytes, container: container?.format ?? 'unknown' },
      provenance: [localProvenance('firmware', art.path)],
      confidence: 'observed',
    });

    const summary =
      `## Firmware analysis — ${basename(art.path)}\n` +
      `- Size: ${art.bytes} bytes | sha256: ${digest}\n` +
      `- Container: ${container ? `${container.description} @ 0x${container.offset.toString(16)}` : 'unrecognised'}\n` +
      `- Embedded signatures: ${embeddedSignatures.length}; strings: ${strings.length}; overall entropy: ${overallEntropy}/8\n` +
      `- High-entropy regions (possible compression/encryption): ${highRegions.length}\n` +
      `- Services hinted: ${serviceHints.join(', ') || 'none'}\n` +
      `- Kernel versions: ${classified.kernelVersions.join(', ') || 'none'} | Distros: ${classified.distributions.join(', ') || 'none'}\n` +
      `- Credential-like strings: ${classified.credentialCandidates.length}; URLs: ${classified.urls.length}; CVE refs: ${classified.cveReferences.length}\n` +
      (externalToolFindings.length ? `- External tools used: ${externalToolFindings.map((f) => f.tool).join(', ')}\n` : '') +
      `\n> Static analysis only — no code from this image was executed.`;

    return finish({
      engine: ENGINE,
      tool: 'firmware_analyze',
      startedAt: started,
      ctx,
      summary,
      data: {
        path: art.path,
        sha256: digest,
        sizeBytes: art.bytes,
        truncated: art.truncated,
        ...(container ? { container } : {}),
        embeddedSignatures,
        overallEntropy,
        highEntropyRegions: highRegions,
        entropySample,
        stringCount: strings.length,
        classified,
        serviceHints,
        externalToolFindings,
      } satisfies FirmwareAnalyzeResult,
    });
  },
});

/* ------------------------------------------------------------------ */
/* Tool 2 — firmware_extract                                           */
/* ------------------------------------------------------------------ */

interface ExtractManifestEntry {
  name: string;
  path: string;
  size: number;
  sha256: string;
}

interface FirmwareExtractResult {
  mode: 'binwalk' | 'builtin';
  outputDir: string;
  members: ExtractManifestEntry[];
  streamCount: number;
  note: string;
}

const STREAM_EXT: Record<CarvedStream['type'], string> = {
  gzip: 'gz',
  xz: 'xz',
  bzip2: 'bz2',
  zstd: 'zst',
};

const extractTool = defineTool<{ filePath: string; outputDir?: string }, FirmwareExtractResult>({
  name: 'firmware_extract',
  title: 'Firmware extraction (isolated, static)',
  engine: ENGINE,
  description:
    'Extract members from a firmware image into a workspace directory. When binwalk is available it ' +
    'is run with --extract inside the workspace; otherwise a pure-JS best-effort carve is used that ' +
    'splits embedded gzip/xz/bzip2/zstd streams by magic and parses cpio "newc" archives. All output ' +
    'stays inside the workspace. Extracted content is NEVER executed.',
  capabilities: ['read_firmware', 'run_isolated'],
  risk: 'isolated_exec',
  inputSchema: { filePath: zodCommon.filePath, outputDir: z.string().optional().describe('Output directory (workspace-relative). Defaults to extraction-out/<name>.') },
  handler: async (input, ctx) => {
    const started = Date.now();
    const art = readBinaryArtifact(input.filePath);
    const outRel = input.outputDir ?? join('extraction-out', `${basename(art.path)}.extracted`);
    const outAbs = resolveWorkspacePath(outRel);
    mkdirSync(outAbs, { recursive: true });

    const warnings: string[] = [];
    let mode: 'binwalk' | 'builtin' = 'builtin';
    let streamCount = 0;

    const available = await discoverTools(['binwalk']);
    if (available['binwalk'] === true) {
      mode = 'binwalk';
      const res = await tryRun('binwalk', ['--extract', '--directory', outAbs, art.path]);
      if (!res) {
        warnings.push('binwalk invocation failed; nothing extracted.');
      } else if (res.exitCode !== 0 && res.stderr) {
        warnings.push(`binwalk exited ${res.exitCode}: ${res.stderr.trim().slice(0, 300)}`);
      }
    } else {
      // ---- Pure-JS carving ------------------------------------------------
      const container = detectContainerFormat(art.buffer);
      // Archive containers (cpio/tar) at the start of the image.
      const writeMember = (dir: string, name: string, data: Buffer): void => {
        const safe = name.replace(/\\/g, '/').split('/').filter((p) => p !== '' && p !== '.' && p !== '..');
        if (safe.length === 0) return;
        const target = join(dir, ...safe);
        mkdirSync(join(target, '..'), { recursive: true });
        writeFileSync(target, data);
      };

      let cpioScanFrom = 0;
      if (container && container.format.startsWith('cpio')) {
        const parsed = parseCpioNewcArchive(art.buffer, 0);
        for (const m of parsed.members) writeMember(join(outAbs, 'cpio'), m.name, m.data);
        // Resume the embedded scan strictly after the leading archive.
        cpioScanFrom = parsed.end > 0 ? parsed.end : art.buffer.length;
      } else if (container && container.format === 'tar') {
        const members = parseTar(art.buffer);
        for (const m of members) writeMember(join(outAbs, 'tar'), m.name, m.data);
      }

      // Embedded compression streams.
      const streams = carveStreams(art.buffer);
      streamCount = streams.length;
      streams.forEach((stream, i) => {
        const ext = STREAM_EXT[stream.type];
        const fileName = `carve-${String(i).padStart(3, '0')}-0x${stream.offset.toString(16)}.${ext}`;
        writeFileSync(join(outAbs, fileName), stream.data);
        if (stream.type === 'gzip') {
          try {
            const decompressed = gunzipSync(stream.data, { maxOutputLength: getConfig().maxArtifactBytes });
            writeFileSync(join(outAbs, `${fileName}.decompressed`), decompressed);
          } catch {
            /* carving keeps the raw bytes; decompression is optional best effort */
          }
        }
      });

      // Additional cpio archives embedded anywhere in the image. Each archive is
      // parsed sequentially and the scan resumes *after* it, so a `070701` byte
      // sequence inside a member payload is never mistaken for a new archive.
      const cpioMagic = Buffer.from('070701', 'latin1');
      let searchFrom = cpioScanFrom;
      let cpioCount = 0;
      while (cpioCount < 20) {
        const idx = art.buffer.indexOf(cpioMagic, searchFrom);
        if (idx < 0) break;
        const parsed = parseCpioNewcArchive(art.buffer, idx);
        if (parsed.members.length > 0) {
          const dir = join(outAbs, `cpio-embedded-${cpioCount}-0x${idx.toString(16)}`);
          for (const m of parsed.members) writeMember(dir, m.name, m.data);
          cpioCount += 1;
        }
        searchFrom = parsed.end > idx ? parsed.end : idx + cpioMagic.length;
      }
    }

    // ---- Manifest ---------------------------------------------------------
    const members: ExtractManifestEntry[] = [];
    for (const file of walkFiles(outAbs, 5000)) {
      let digest = '';
      try {
        digest = await sha256(readFileSync(file.abs));
      } catch {
        digest = 'sha256:unreadable';
      }
      members.push({ name: file.rel, path: file.abs, size: file.size, sha256: digest });
    }

    addEvidence(ctx, {
      claim: `Firmware extracted into ${outAbs} using ${mode}; ${members.length} member file(s) produced.`,
      prov: localProvenance('firmware', art.path, `extraction (${mode})`),
      confidence: 'observed',
      locator: { file: outAbs },
      data: { members: members.length, streams: streamCount },
    });
    ctx.evidence.warn('Extracted content is inert data; do NOT execute it outside an isolated emulator.');

    const note =
      'Extraction is a static, non-executing operation. Treat every extracted binary as untrusted; ' +
      'only run it inside a network-isolated emulator (see emulation_plan).';

    return finish({
      engine: ENGINE,
      tool: 'firmware_extract',
      startedAt: started,
      ctx,
      warnings,
      summary:
        `## Firmware extraction (${mode})\n` +
        `- Output: ${outAbs}\n` +
        `- Members written: ${members.length} (streams carved: ${streamCount})\n` +
        (members.length ? `- Extracted: ${members.slice(0, 20).map((m) => m.name).join(', ')}${members.length > 20 ? ' …' : ''}\n` : '') +
        `\n> ${note}`,
      data: { mode, outputDir: outAbs, members, streamCount, note },
    });
  },
});

/* ------------------------------------------------------------------ */
/* Tool 3 — firmware_filesystem_analyze                                */
/* ------------------------------------------------------------------ */

interface VfsFile {
  path: string;
  size: number;
  read: (maxBytes?: number) => Buffer;
}
type Vfs = Map<string, VfsFile>;

function vfsFromDir(root: string, maxFiles = 50000): { vfs: Vfs; warnings: string[] } {
  const vfs: Vfs = new Map();
  const warnings: string[] = [];
  const stack: string[] = [root];
  let count = 0;
  while (stack.length > 0 && count < maxFiles) {
    const dir = stack.pop();
    if (!dir) break;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const abs = join(dir, entry.name);
      if (entry.isDirectory()) stack.push(abs);
      else if (entry.isFile()) {
        let size = 0;
        try {
          size = statSync(abs).size;
        } catch {
          /* ignore */
        }
        const rel = `/${relative(root, abs).replace(/\\/g, '/')}`;
        vfs.set(rel, {
          path: rel,
          size,
          read: (maxBytes?: number) => {
            try {
              const data = readFileSync(abs);
              return maxBytes ? data.subarray(0, maxBytes) : data;
            } catch {
              return Buffer.alloc(0);
            }
          },
        });
        count += 1;
      }
    }
  }
  if (count >= maxFiles) warnings.push(`File listing truncated at ${maxFiles} entries.`);
  return { vfs, warnings };
}

function vfsFromArchive(buf: Buffer, container: string): { vfs: Vfs; warnings: string[] } {
  const vfs: Vfs = new Map();
  const members = container === 'tar' ? parseTar(buf) : parseCpioNewc(buf);
  for (const m of members) {
    if (m.name.endsWith('/')) continue;
    const path = `/${m.name}`;
    vfs.set(path, { path, size: m.size, read: () => m.data });
  }
  return { vfs, warnings: [] };
}

function readVfsText(vfs: Vfs, path: string, maxBytes = 256 * 1024): string | undefined {
  const file = vfs.get(path);
  if (!file) return undefined;
  return file.read(maxBytes).toString('utf8');
}

interface FilesystemProfile {
  input: string;
  sourceKind: 'directory' | 'archive';
  fileCount: number;
  initSystem: string[];
  inittabPresent: boolean;
  initScripts: string[];
  rcScripts: string[];
  services: { name: string; evidence: string }[];
  configFiles: string[];
  users: { name: string; uid: string; shell: string; passwordField: string }[];
  shadowPresent: boolean;
  hostKeys: string[];
  telnetIndicators: string[];
  httpServerConfigs: string[];
  hardcodedCredentials: { file: string; snippet: string }[];
  sysctlFiles: string[];
  hardeningGaps: string[];
}

function analyzeFilesystem(vfs: Vfs, input: string, sourceKind: 'directory' | 'archive'): FilesystemProfile {
  const keys = [...vfs.keys()];
  const initSystem: string[] = [];
  const initScripts = keys.filter((k) => /^\/etc\/init\.d\/[^/]+$/.test(k)).map((k) => basename(k));
  const rcScripts = keys.filter((k) => /^\/etc\/(rcS\.d|rc\.d|rc[0-9]\.d|rc[0-9])\/[^/]+$/.test(k) || /^\/etc\/rc\.d\/[^/]+$/.test(k));
  const inittabPresent = keys.includes('/etc/inittab');

  if (keys.includes('/sbin/init') || keys.includes('/bin/busybox')) initSystem.push('BusyBox init');
  if (inittabPresent) initSystem.push('inittab (BusyBox/SysV)');
  if (keys.includes('/sbin/procd') || keys.includes('/etc/rc.common')) initSystem.push('OpenWrt procd');
  if (keys.some((k) => /^\/lib\/systemd\/systemd$/.test(k) || /^\/usr\/lib\/systemd\/systemd$/.test(k)) || keys.includes('/etc/systemd'))
    initSystem.push('systemd');
  if (initScripts.length > 0 && initSystem.length === 0) initSystem.push('SysV-style init.d');
  if (initSystem.length === 0) initSystem.push('undetermined');

  const configFiles = keys.filter((k) => /^\/etc\/.*\.(conf|cfg|ini)$/.test(k) || /^\/etc\/config\/[^/]+$/.test(k));

  const services: { name: string; evidence: string }[] = [];
  for (const s of initScripts) services.push({ name: s, evidence: '/etc/init.d' });
  for (const k of keys) {
    const m = /^\/etc\/config\/([^/]+)$/.exec(k);
    if (m && m[1]) services.push({ name: m[1], evidence: '/etc/config (UCI)' });
  }

  // ---- Credentials ------------------------------------------------------
  const users: FilesystemProfile['users'] = [];
  let shadowPresent = false;
  const passwd = readVfsText(vfs, '/etc/passwd');
  if (passwd !== undefined) {
    for (const line of passwd.split(/\r?\n/)) {
      const parts = line.split(':');
      if (parts.length >= 7) {
        users.push({ name: parts[0] ?? '', passwordField: parts[1] ?? '', uid: parts[2] ?? '', shell: parts[6] ?? '' });
      }
    }
  }
  shadowPresent = keys.includes('/etc/shadow');

  const hostKeys = keys.filter((k) => /^\/etc\/dropbear\/.*key/i.test(k) || /^\/etc\/ssh\/ssh_host_.*key/.test(k));

  const telnetIndicators: string[] = [];
  for (const k of keys) {
    if (/telnetd?$/i.test(basename(k)) || k === '/etc/init.d/telnetd') telnetIndicators.push(k);
  }
  const inetd = readVfsText(vfs, '/etc/inetd.conf');
  if (inetd && /telnet\s+stream\s+tcp/i.test(inetd)) telnetIndicators.push('/etc/inetd.conf: telnet service enabled');

  const httpServerConfigs = keys.filter((k) =>
    [/^\/etc\/httpd\.conf$/, /^\/etc\/lighttpd\.conf$/, /^\/etc\/boa\.conf$/, /^\/etc\/goahead\.conf$/, /^\/etc\/nginx\.conf$/].some((re) =>
      re.test(k),
    ),
  );

  const hardcodedCredentials: { file: string; snippet: string }[] = [];
  for (const k of [...configFiles, '/etc/passwd']) {
    const text = readVfsText(vfs, k);
    if (!text) continue;
    for (const line of text.split(/\r?\n/)) {
      if (/(?:password|passwd|psk|passphrase|secret|key)\s*[:=]\s*\S+/i.test(line) && !/^\s*#/.test(line)) {
        hardcodedCredentials.push({ file: k, snippet: line.trim().slice(0, 160) });
        if (hardcodedCredentials.length >= 100) break;
      }
    }
  }

  const sysctlFiles = keys.filter((k) => k === '/etc/sysctl.conf' || k.startsWith('/proc/sys/') || k.startsWith('/etc/sysctl.d/'));

  // ---- Hardening gaps ---------------------------------------------------
  const gaps: string[] = [];
  if (!shadowPresent && passwd !== undefined) gaps.push('No /etc/shadow: password hashes may be world-readable in /etc/passwd.');
  if (users.some((u) => u.name === 'root' && u.passwordField !== 'x' && u.passwordField !== '*' && u.passwordField !== '!' && u.passwordField !== ''))
    gaps.push('Root account in /etc/passwd has a non-shadowed password field.');
  if (telnetIndicators.length > 0) gaps.push('Telnet (cleartext) service indicators found — replace with SSH.');
  if (httpServerConfigs.length > 0) gaps.push('Embedded HTTP server config present — verify authentication and firmware-update protections.');
  if (hardcodedCredentials.length > 0) gaps.push('Hardcoded credential-like values found in configuration files.');
  if (hostKeys.length === 0 && (keys.includes('/etc/dropbear') || keys.includes('/etc/ssh')))
    gaps.push('SSH host keys are not pre-generated in this image.');

  return {
    input,
    sourceKind,
    fileCount: keys.length,
    initSystem,
    inittabPresent,
    initScripts,
    rcScripts,
    services,
    configFiles,
    users,
    shadowPresent,
    hostKeys,
    telnetIndicators,
    httpServerConfigs,
    hardcodedCredentials,
    sysctlFiles,
    hardeningGaps: gaps,
  };
}

const filesystemTool = defineTool<{ path: string }, FilesystemProfile>({
  name: 'firmware_filesystem_analyze',
  title: 'Extracted filesystem analysis',
  engine: ENGINE,
  description:
    'Inspect an already-extracted firmware filesystem directory or a cpio/tar archive: identify the ' +
    'init system (BusyBox, systemd, OpenWrt procd, SysV), enumerate init/rc scripts and services, ' +
    'inspect default credential files (/etc/passwd, /etc/shadow), SSH/dropbear host keys, telnet and ' +
    'HTTP configuration, flag hardcoded credentials in config files, and summarise hardening gaps. ' +
    'Read-only.',
  capabilities: ['read_firmware'],
  risk: 'safe',
  inputSchema: { path: z.string().min(1).describe('Workspace path to an extracted directory or a cpio/tar archive.') },
  handler: async (input, ctx) => {
    const started = Date.now();
    const abs = resolveWorkspacePath(input.path, true);
    const stat = statSync(abs);

    let vfs: Vfs;
    let warnings: string[] = [];
    let sourceKind: 'directory' | 'archive';
    if (stat.isDirectory()) {
      sourceKind = 'directory';
      const built = vfsFromDir(abs);
      vfs = built.vfs;
      warnings = built.warnings;
    } else {
      sourceKind = 'archive';
      const art = readBinaryArtifact(input.path);
      const container = detectContainerFormat(art.buffer);
      if (!container || (!container.format.startsWith('cpio') && container.format !== 'tar')) {
        throw errors.invalidInput(
          `Archive at ${input.path} is not a recognisable cpio/tar and is not a directory.`,
          { detected: container?.format ?? 'unknown' },
        );
      }
      const built = vfsFromArchive(art.buffer, container.format);
      vfs = built.vfs;
      warnings = built.warnings;
    }

    if (vfs.size === 0) throw errors.notFound(`Any filesystem entries under "${input.path}"`);

    const profile = analyzeFilesystem(vfs, abs, sourceKind);

    addEvidence(ctx, {
      claim: `Filesystem analysed (${sourceKind}): ${profile.fileCount} entries; init system: ${profile.initSystem.join(', ')}.`,
      prov: localProvenance('firmware', abs, 'filesystem analysis'),
      confidence: 'observed',
      locator: { file: abs },
      data: { initSystem: profile.initSystem, services: profile.services.length },
    });
    for (const cred of profile.hardcodedCredentials.slice(0, 10)) {
      addEvidence(ctx, {
        claim: `Credential-like value in ${cred.file}: ${cred.snippet}`,
        prov: localProvenance('firmware', abs, 'config scan'),
        confidence: 'inferred',
      });
    }
    if (profile.shadowPresent) {
      addEvidence(ctx, {
        claim: 'Password hashes are stored in /etc/shadow (not world-readable in /etc/passwd).',
        prov: localProvenance('firmware', abs, 'credential file check'),
        confidence: 'observed',
      });
    }

    const kb = getKnowledgeBase();
    const nodeId = `firmware_component:fs:${createHash('sha256').update(abs).digest('hex').slice(0, 16)}`;
    kb.upsertNode({
      id: nodeId,
      kind: 'firmware_version',
      label: basename(abs),
      properties: { fileCount: profile.fileCount, initSystem: profile.initSystem.join(',') },
      provenance: [localProvenance('firmware', abs)],
      confidence: 'observed',
    });

    const summary =
      `## Extracted filesystem — ${basename(abs)} (${sourceKind})\n` +
      `- Entries: ${profile.fileCount}\n` +
      `- Init system: ${profile.initSystem.join(', ')}\n` +
      `- Init scripts: ${profile.initScripts.length}; rc scripts: ${profile.rcScripts.length}\n` +
      `- Services: ${profile.services.map((s) => s.name).slice(0, 20).join(', ') || 'none'}\n` +
      `- Config files: ${profile.configFiles.length}; users: ${profile.users.length}; /etc/shadow: ${profile.shadowPresent ? 'yes' : 'no'}\n` +
      `- Host keys: ${profile.hostKeys.length}; telnet indicators: ${profile.telnetIndicators.length}; HTTP configs: ${profile.httpServerConfigs.length}\n` +
      `- Hardcoded credential-like values: ${profile.hardcodedCredentials.length}\n\n` +
      `### Hardening gaps\n${profile.hardeningGaps.length ? profile.hardeningGaps.map((g) => `- ${g}`).join('\n') : '- none detected'}`;

    return finish({ engine: ENGINE, tool: 'firmware_filesystem_analyze', startedAt: started, ctx, warnings, summary, data: profile });
  },
});

/* ------------------------------------------------------------------ */
/* Tool 4 — elf_analyze                                                */
/* ------------------------------------------------------------------ */

interface ElfAnalyzeResult {
  path: string;
  sha256: string;
  report: ElfReport;
}

const elfTool = defineTool<{ filePath: string; maxStrings?: number }, ElfAnalyzeResult>({
  name: 'elf_analyze',
  title: 'ELF binary analysis',
  engine: ENGINE,
  description:
    'Parse an ELF binary in pure JS: header (class, endianness, OSABI, type, machine, entry), section ' +
    'and program headers with resolved names, the interpreter, DT_NEEDED dependencies, and ' +
    'checksec-style flags (NX, PIE, RELRO, stack canary, FORTIFY, stripped). Detects uClibc/glibc/musl ' +
    'hints and UPX/packer indicators. Read-only; the binary is never executed.',
  capabilities: ['read_binary'],
  risk: 'safe',
  inputSchema: { filePath: zodCommon.filePath, maxStrings: z.number().int().min(1).max(200000).optional() },
  handler: async (input, ctx) => {
    const started = Date.now();
    const art = readBinaryArtifact(input.filePath);
    const report = parseElf(art.buffer);
    if (!report.isElf) {
      throw errors.invalidInput(`${art.path} is not an ELF binary.`, { warnings: report.warnings });
    }
    const digest = await sha256(art.buffer);

    addEvidence(ctx, {
      claim: `ELF analysed: ${report.machineName} ${report.elfClass}-bit ${report.typeName}, entry 0x${report.entry.toString(16)}.`,
      prov: localProvenance('binary', art.path, 'ELF parse'),
      confidence: 'observed',
      locator: { file: art.path },
      data: { checksec: report.checksec, needed: report.needed },
    });
    addEvidence(ctx, {
      claim: `Checksec: NX=${report.checksec.nx}, PIE=${report.checksec.pie}, RELRO=${report.checksec.relro}, canary=${report.checksec.canary}, FORTIFY=${report.checksec.fortify}, stripped=${report.checksec.stripped}.`,
      prov: localProvenance('binary', art.path, 'checksec heuristics'),
      confidence: 'inferred',
    });
    for (const hint of report.packerHints) {
      addEvidence(ctx, {
        claim: `Packer indicator: ${hint}.`,
        prov: localProvenance('binary', art.path, 'packer heuristic'),
        confidence: 'inferred',
      });
    }

    const summary =
      `## ELF analysis — ${basename(art.path)}\n` +
      `- ${report.machineName}, ${report.elfClass}-bit, ${report.endian}-endian, ${report.typeName}, OSABI ${report.osabi}\n` +
      `- Entry 0x${report.entry.toString(16)} | sections ${report.sections.length} | segments ${report.programHeaders.length}\n` +
      `- Interpreter: ${report.interpreter ?? 'none'}\n` +
      `- Dependencies: ${report.needed.join(', ') || 'none parsed'}\n` +
      `- Libc hints: ${report.libcHints.join(', ') || 'none'}\n` +
      `- Checksec: NX=${report.checksec.nx} PIE=${report.checksec.pie} RELRO=${report.checksec.relro} canary=${report.checksec.canary} fortify=${report.checksec.fortify} stripped=${report.checksec.stripped}\n` +
      `- Packer hints: ${report.packerHints.join(', ') || 'none'}\n` +
      `- sha256: ${digest}`;

    return finish({
      engine: ENGINE,
      tool: 'elf_analyze',
      startedAt: started,
      ctx,
      warnings: report.warnings,
      summary,
      data: { path: art.path, sha256: digest, report },
    });
  },
});

/* ------------------------------------------------------------------ */
/* Tool 5 — firmware_component_scan                                    */
/* ------------------------------------------------------------------ */

interface ComponentFinding {
  component: string;
  version?: string;
  cves: { id: string; fixed: string; note: string; ref: string; confidence: ConfidenceLevel }[];
}

interface ComponentScanResult {
  path: string;
  sourceKind: 'file' | 'directory';
  stringsScanned: number;
  findings: ComponentFinding[];
  caveat: string;
}

function collectStringHits(abs: string, isDir: boolean): { hits: StringHit[]; scanned: number } {
  const hits: StringHit[] = [];
  if (isDir) {
    let scanned = 0;
    for (const file of walkFiles(abs, 4000)) {
      if (file.size > 8 * 1024 * 1024) continue; // skip very large blobs
      try {
        const data = readFileSync(file.abs).subarray(0, 4 * 1024 * 1024);
        scanned += data.length;
        for (const h of extractStrings(data, 5, 20000)) hits.push({ value: h.value, offset: h.offset });
      } catch {
        /* ignore unreadable files */
      }
    }
    return { hits, scanned };
  }
  const art = readBinaryArtifact(abs);
  const window = bounded(art.buffer);
  return { hits: extractStrings(window, 5, 60000), scanned: window.length };
}

const componentScanTool = defineTool<{ path: string; components?: string[] }, ComponentScanResult>({
  name: 'firmware_component_scan',
  title: 'Vulnerable component scan',
  engine: ENGINE,
  description:
    'Scan a firmware image or extracted directory for known components and their versions (busybox, ' +
    'dropbear, openssl, openssh, libupnp, miniupnpd, lighttpd, boa, goahead, dnsmasq, wpa_supplicant, ' +
    'hostapd, samba, avahi, glibc/uClibc/musl) and cross-reference a curated table of widely-documented ' +
    'version→CVE hints. Version-string matches are INDICATIVE only, not proof of exploitability.',
  capabilities: ['read_firmware'],
  risk: 'safe',
  inputSchema: {
    path: z.string().min(1).describe('Workspace path to a firmware image or extracted directory.'),
    components: z.array(z.string()).optional().describe('Restrict to these component names.'),
  },
  handler: async (input, ctx) => {
    const started = Date.now();
    const abs = resolveWorkspacePath(input.path, true);
    const stat = statSync(abs);
    const isDir = stat.isDirectory();
    const { hits, scanned } = collectStringHits(abs, isDir);

    const matches = matchComponents(hits, input.components);
    const findings: ComponentFinding[] = matches.map((m) => ({
      component: m.component,
      ...(m.version ? { version: m.version } : {}),
      cves: m.cves.map((c) => ({ ...c, confidence: 'inferred' as ConfidenceLevel })),
    }));

    const prov = localProvenance('firmware', abs, isDir ? 'directory string scan' : 'image string scan');
    addEvidence(ctx, {
      claim: `Scanned ${scanned} bytes of strings; matched ${findings.length} known component(s).`,
      prov,
      confidence: 'observed',
      locator: { file: abs },
      data: { components: findings.map((f) => `${f.component}${f.version ? '@' + f.version : ''}`) },
    });
    for (const f of findings) {
      addEvidence(ctx, {
        claim: `Component ${f.component}${f.version ? ` version ${f.version}` : ''} detected; ${f.cves.length} candidate CVE hint(s).`,
        prov,
        confidence: 'inferred',
      });
    }

    // Persist records + graph nodes/edges.
    const kb = getKnowledgeBase();
    for (const f of findings) {
      const key = createHash('sha256').update(`${f.component}@${f.version ?? 'unknown'}`).digest('hex').slice(0, 12);
      kb.upsertRecord(
        buildComponentRecord({
          id: `firmware_component:${f.component}:${f.version ?? 'unknown'}`,
          title: `${f.component}${f.version ? ` ${f.version}` : ''} in firmware`,
          product: f.component,
          version: f.version,
          klass: 'embedded-component',
          cves: f.cves,
          provenance: [prov, curatedProvenance('curated-cve-hints', 'widely documented CVEs')],
          confidence: 'inferred',
          verification: 'unverified',
          tags: ['firmware', 'component', f.component],
        }),
      );
      const componentNode = `firmware_component:${key}`;
      kb.upsertNode({
        id: componentNode,
        kind: 'firmware_version',
        label: `${f.component}${f.version ? ` ${f.version}` : ''}`,
        properties: { component: f.component, version: f.version ?? 'unknown' },
        provenance: [prov],
        confidence: 'inferred',
      });
      for (const cve of f.cves) {
        const cveNode = `cve:${cve.id}`;
        kb.upsertNode({
          id: cveNode,
          kind: 'cve',
          label: cve.id,
          properties: { fixedVersion: cve.fixed, note: cve.note, ref: cve.ref },
          provenance: [curatedProvenance('curated-cve-hints', cve.ref)],
          confidence: 'inferred',
        });
        kb.upsertEdge({
          id: `${componentNode}->has_vulnerability->${cveNode}`,
          from: componentNode,
          to: cveNode,
          relation: 'has_vulnerability',
          provenance: [prov, curatedProvenance('curated-cve-hints', cve.ref)],
          confidence: 'hypothesis',
          note: 'Version-string match; applicability requires verification.',
        });
      }
    }

    const caveat =
      'CAVEATS (§B1/§C2): components are identified from embedded version strings, which can be ' +
      'backported, patched or spoofed. A listed CVE indicates a version-range match only and is NOT ' +
      'proof of exploitability — confirm the actual build, patches and configuration before acting.';

    const summary =
      `## Component scan — ${basename(abs)} (${isDir ? 'directory' : 'image'})\n` +
      `- Bytes of strings scanned: ${scanned}\n` +
      `- Matched components: ${findings.length}\n` +
      findings
        .map((f) => `  - ${f.component}${f.version ? ` @ ${f.version}` : ' (version unknown)'}: ${f.cves.map((c) => c.id).join(', ') || 'no curated CVE hints'}`)
        .join('\n') +
      `\n\n> ${caveat}`;

    return finish({ engine: ENGINE, tool: 'firmware_component_scan', startedAt: started, ctx, summary, data: { path: abs, sourceKind: isDir ? 'directory' : 'file', stringsScanned: scanned, findings, caveat } });
  },
});

/* ------------------------------------------------------------------ */
/* Tool 6 — emulation_plan                                             */
/* ------------------------------------------------------------------ */

interface EmulationPlan {
  detectedArch: string;
  emulator: string;
  qemuTemplate: string;
  firmwareFrameworks: { name: string; purpose: string; steps: string[] }[];
  networkIsolation: string[];
  snapshotStrategy: string[];
  resourceCaps: string[];
  safetyChecklist: string[];
  rationale: string;
}

const ARCH_TO_QEMU: Record<string, { system: string; user: string }> = {
  ARM: { system: 'qemu-system-arm', user: 'qemu-arm-static' },
  'AArch64 (ARM64)': { system: 'qemu-system-aarch64', user: 'qemu-aarch64-static' },
  MIPS: { system: 'qemu-system-mips', user: 'qemu-mips-static' },
  'MIPS (little-endian, MIPSEL)': { system: 'qemu-system-mipsel', user: 'qemu-mipsel-static' },
  PowerPC: { system: 'qemu-system-ppc', user: 'qemu-ppc-static' },
  'PowerPC64': { system: 'qemu-system-ppc64', user: 'qemu-ppc64-static' },
  'x86-64': { system: 'qemu-system-x86_64', user: 'qemu-x86_64-static' },
  'x86 (i386)': { system: 'qemu-system-i386', user: 'qemu-i386-static' },
};

const emulationTool = defineTool<{ filePath?: string; arch?: string; goal?: string }, EmulationPlan>({
  name: 'emulation_plan',
  title: 'Isolated emulation plan',
  engine: ENGINE,
  description:
    'Produce a SAFE, isolated emulation PLAN for a firmware image: exact QEMU invocation templates ' +
    '(qemu-system-* and qemu-user-static), FirmAE/FAT/EMBA workflow steps, network-isolation settings ' +
    '(user-mode networking, no host bridging by default), snapshot/rollback strategy, resource caps and ' +
    'a safety checklist. This tool NEVER launches an emulator; it only returns a plan and rationale.',
  capabilities: ['read_firmware'],
  risk: 'safe',
  inputSchema: {
    filePath: z.string().optional().describe('Optional firmware image to infer the architecture from.'),
    arch: z.string().optional().describe('Explicit architecture, e.g. arm, mipsel, aarch64.'),
    goal: z.string().optional().describe('Analysis goal, e.g. "observe default services" or "trace nvram".'),
  },
  handler: async (input, ctx) => {
    const started = Date.now();
    let detectedArch = input.arch ?? 'unknown';
    if (detectedArch === 'unknown' && input.filePath) {
      try {
        const art = readBinaryArtifact(input.filePath, 2 * 1024 * 1024);
        const container = detectContainerFormat(art.buffer);
        if (container && container.format === 'elf') {
          const report = parseElf(art.buffer);
          detectedArch = report.machineName;
        } else if (container) {
          detectedArch = `unknown (container: ${container.format})`;
        }
      } catch {
        /* keep unknown */
      }
    }
    const normalized = Object.keys(ARCH_TO_QEMU).find(
      (k) => detectedArch.toLowerCase().includes(k.toLowerCase()) || (input.arch ? k.toLowerCase().includes(input.arch.toLowerCase()) : false),
    );
    const qemu = normalized ? ARCH_TO_QEMU[normalized] : undefined;
    const systemBin = qemu?.system ?? 'qemu-system-<arch>';
    const userBin = qemu?.user ?? 'qemu-<arch>-static';

    const qemuTemplate =
      `# Full-system emulation (run ONLY inside an isolated, network-segmented host/VM)\n` +
      `${systemBin} \\\n` +
      `  -M <machine-or-virt> -kernel <vmlinux> \\\n` +
      `  -drive file=<rootfs.ext4>,format=raw,if=virtio \\\n` +
      `  -append "console=ttyS0 root=/dev/vda rw" \\\n` +
      `  -nographic -m 256 -smp 1 \\\n` +
      `  -netdev user,id=n0,restrict=on -device <nic-model>,netdev=n0 \\\n` +
      `  -snapshot\n` +
      `# Per-binary user-mode emulation (chrooted into the extracted rootfs):\n` +
      `sudo chroot <rootfs> ${userBin} -L <rootfs> /bin/<target>`;

    const firmwareFrameworks = [
      {
        name: 'FirmAE',
        purpose: 'Automated firmware emulation with service detection.',
        steps: [
          'Run inside a dedicated VM/container with no host network bridging.',
          `./run.sh -a <arch> <firmware.bin> (targets: ${detectedArch})`,
          'Use its network-isolated mode; review every auto-injected service.',
          'Capture serial console output for the emulation report.',
        ],
      },
      {
        name: 'FAT (Firmware Analysis Toolkit)',
        purpose: 'QEMU-based emulation derived from FIRMADYNE.',
        steps: [
          './fat.py <firmware.bin>',
          'Map high ports 1:1 to the guest; never expose to the LAN.',
          'Inspect the generated run.sh QEMU command before executing.',
        ],
      },
      {
        name: 'EMBA',
        purpose: 'End-to-end firmware analysis pipeline.',
        steps: [
          'sudo ./emba -f <firmware.bin> -l <log-dir>',
          'Prefer the static-analysis modules; enable emulation only in a sandbox.',
        ],
      },
    ];

    const networkIsolation = [
      'Use QEMU user-mode networking (`-netdev user,restrict=on`) — no host bridging, no TAP by default.',
      'Alternatively use QEMU `-net none` for fully offline emulation.',
      'Place the emulator on a dedicated host-only network inside the lab; block egress to the internet.',
      'Never map guest services to the host LAN; if a port forward is needed, bind to 127.0.0.1 only.',
      'Log and rate-limit any outbound traffic from the guest for behavioural observation.',
    ];

    const snapshotStrategy = [
      'Boot with QEMU `-snapshot` so the disk image is never modified.',
      'Take a QEMU monitor snapshot after boot (`savevm clean`) before interacting.',
      'Keep an immutable copy of the rootfs; re-flash between experiments.',
      'Record the exact image hash in the emulation report for reproducibility.',
    ];

    const resourceCaps = [
      'Cap guest RAM (`-m 256`) and CPU (`-smp 1`) to limit runaway firmware.',
      'Wrap the emulator in a cgroup/timeout (e.g. `timeout 600`) and kill on completion.',
      'Limit disk growth with a sparse/copy-on-write overlay.',
      'Capture console output to a bounded file to avoid log exhaustion.',
    ];

    const safetyChecklist = [
      'The firmware is UNTRUSTED: assume it may contain backdoors, exploits and destructive payloads.',
      'Emulate ONLY in an isolated VM/container with no access to production networks or data.',
      'Never mount host directories into the guest read-write.',
      'Review extracted scripts before letting init run; prefer single-binary emulation where possible.',
      'Confirm the QEMU command line matches this plan before execution.',
      'This tool did NOT launch any emulator — execution is a separate, explicit operator action.',
    ];

    addEvidence(ctx, {
      claim: `Isolated emulation plan generated for architecture "${detectedArch}" (no emulator launched).`,
      prov: (input.filePath ? localProvenance('firmware', input.filePath, 'emulation planning') : curatedProvenance('emulation-playbook')),
      confidence: 'inferred',
      data: { detectedArch, emulator: userBin },
    });

    const kb = getKnowledgeBase();
    const recordId = `research_paper:emulation-plan:${createHash('sha256').update(`${detectedArch}:${input.goal ?? ''}`).digest('hex').slice(0, 12)}`;
    kb.upsertRecord(
      buildComponentRecord({
        id: recordId,
        title: `Isolated emulation plan (${detectedArch})`,
        product: 'emulation-plan',
        version: detectedArch,
        klass: 'emulation-plan',
        cves: [],
        provenance: [curatedProvenance('emulation-playbook', input.goal ?? 'general')],
        confidence: 'inferred',
        verification: 'statically_reviewed',
        tags: ['firmware', 'emulation', 'plan'],
      }),
    );

    const summary =
      `## Emulation plan (ISOLATED) — arch: ${detectedArch}\n` +
      `### QEMU template\n\`\`\`sh\n${qemuTemplate}\n\`\`\`\n` +
      `### Network isolation\n${networkIsolation.map((s) => `- ${s}`).join('\n')}\n` +
      `### Snapshot strategy\n${snapshotStrategy.map((s) => `- ${s}`).join('\n')}\n` +
      `### Resource caps\n${resourceCaps.map((s) => `- ${s}`).join('\n')}\n` +
      `### Safety checklist\n${safetyChecklist.map((s) => `- ${s}`).join('\n')}\n\n` +
      `> No emulator was launched. Execution is a separate, explicit operator action inside an isolated environment.`;

    return finish({
      engine: ENGINE,
      tool: 'emulation_plan',
      startedAt: started,
      ctx,
      summary,
      data: {
        detectedArch,
        emulator: normalized ? systemBin : 'qemu-system-<arch>',
        qemuTemplate,
        firmwareFrameworks,
        networkIsolation,
        snapshotStrategy,
        resourceCaps,
        safetyChecklist,
        rationale:
          'Untrusted firmware must never be executed on the analysis host. This plan constrains ' +
          'emulation to an isolated, network-restricted sandbox with rollback and resource caps, and ' +
          'keeps execution a deliberate operator decision (§5, §10).',
      },
    });
  },
});

/* ------------------------------------------------------------------ */
/* Tool 7 — firmware_patch_diff                                        */
/* ------------------------------------------------------------------ */

interface PatchDiffResult {
  before: { path: string; sha256: string; size: number; entropy: number };
  after: { path: string; sha256: string; size: number; entropy: number };
  sizeDelta: number;
  entropyDelta: number;
  identical: boolean;
  newStrings: string[];
  removedStrings: string[];
  componentDeltas: { component: string; before?: string; after?: string; change: 'added' | 'removed' | 'changed' }[];
}

const patchDiffTool = defineTool<{ beforePath: string; afterPath: string }, PatchDiffResult>({
  name: 'firmware_patch_diff',
  title: 'Firmware patch diff',
  engine: ENGINE,
  description:
    'Compare two firmware versions to support patch analysis: SHA-256 and size of both, entropy ' +
    'comparison, the set-difference of extracted strings (added/removed), and component version ' +
    'differences detected in both images. Read-only.',
  capabilities: ['read_firmware'],
  risk: 'safe',
  inputSchema: { beforePath: zodCommon.filePath, afterPath: z.string().min(1).describe('Path to the newer firmware image (workspace-relative).') },
  handler: async (input, ctx) => {
    const started = Date.now();
    const before = readBinaryArtifact(input.beforePath);
    const after = readBinaryArtifact(input.afterPath);
    const beforeHash = await sha256(before.buffer);
    const afterHash = await sha256(after.buffer);

    const beforeStrings = new Set(extractStrings(bounded(before.buffer), 5, 40000).map((s) => s.value));
    const afterStrings = new Set(extractStrings(bounded(after.buffer), 5, 40000).map((s) => s.value));
    const newStrings: string[] = [];
    for (const s of afterStrings) if (!beforeStrings.has(s)) newStrings.push(s);
    const removedStrings: string[] = [];
    for (const s of beforeStrings) if (!afterStrings.has(s)) removedStrings.push(s);

    const beforeComponents = matchComponents(extractStrings(bounded(before.buffer), 5, 40000));
    const afterComponents = matchComponents(extractStrings(bounded(after.buffer), 5, 40000));
    const componentNames = new Set([...beforeComponents.map((c) => c.component), ...afterComponents.map((c) => c.component)]);
    const componentDeltas: PatchDiffResult['componentDeltas'] = [];
    for (const name of componentNames) {
      const b = beforeComponents.find((c) => c.component === name)?.version;
      const a = afterComponents.find((c) => c.component === name)?.version;
      if (b === a) continue;
      componentDeltas.push({
        component: name,
        ...(b ? { before: b } : {}),
        ...(a ? { after: a } : {}),
        change: !b ? 'added' : !a ? 'removed' : 'changed',
      });
    }

    const beforeEntropy = Number(shannonEntropy(bounded(before.buffer)).toFixed(4));
    const afterEntropy = Number(shannonEntropy(bounded(after.buffer)).toFixed(4));
    const identical = beforeHash === afterHash;

    addEvidence(ctx, {
      claim: `Patch diff: before ${beforeHash} (${before.bytes}B) vs after ${afterHash} (${after.bytes}B); identical=${identical}.`,
      prov: localProvenance('firmware', `${before.path} vs ${after.path}`, 'patch diff'),
      confidence: 'observed',
      data: { sizeDelta: after.bytes - before.bytes, newStrings: newStrings.length, removedStrings: removedStrings.length },
    });
    for (const d of componentDeltas) {
      addEvidence(ctx, {
        claim: `Component ${d.component} ${d.change}${d.before ? ` (before ${d.before})` : ''}${d.after ? ` (after ${d.after})` : ''}.`,
        prov: localProvenance('firmware', `${before.path} vs ${after.path}`, 'component delta'),
        confidence: 'inferred',
      });
    }

    const summary =
      `## Firmware patch diff\n` +
      `- Before: ${beforeHash} (${before.bytes} B, entropy ${beforeEntropy})\n` +
      `- After:  ${afterHash} (${after.bytes} B, entropy ${afterEntropy})\n` +
      `- Size delta: ${after.bytes - before.bytes} B; entropy delta: ${(afterEntropy - beforeEntropy).toFixed(4)}\n` +
      `- Identical: ${identical}\n` +
      `- New strings: ${newStrings.length}; removed strings: ${removedStrings.length}\n` +
      `- Component deltas: ${componentDeltas.length}\n` +
      componentDeltas.map((d) => `  - ${d.component}: ${d.before ?? '∅'} → ${d.after ?? '∅'} (${d.change})`).join('\n');

    return finish({
      engine: ENGINE,
      tool: 'firmware_patch_diff',
      startedAt: started,
      ctx,
      summary,
      data: {
        before: { path: before.path, sha256: beforeHash, size: before.bytes, entropy: beforeEntropy },
        after: { path: after.path, sha256: afterHash, size: after.bytes, entropy: afterEntropy },
        sizeDelta: after.bytes - before.bytes,
        entropyDelta: Number((afterEntropy - beforeEntropy).toFixed(4)),
        identical,
        newStrings: newStrings.slice(0, 500),
        removedStrings: removedStrings.slice(0, 500),
        componentDeltas,
      },
    });
  },
});

/* ------------------------------------------------------------------ */
/* Tool 8 — firmware_integrity_check                                   */
/* ------------------------------------------------------------------ */

interface IntegrityResult {
  path: string;
  sizeBytes: number;
  sha256: string;
  md5: string;
  expected: { sha256?: string; md5?: string; size?: number };
  matches: { sha256: boolean | null; md5: boolean | null; size: boolean | null };
  trailingSignatureBlocks: { offset: number; kind: string; note: string }[];
  note: string;
}

const integrityTool = defineTool<
  { filePath: string; expectedSha256?: string; expectedMd5?: string; expectedSize?: number },
  IntegrityResult
>({
  name: 'firmware_integrity_check',
  title: 'Firmware integrity check',
  engine: ENGINE,
  description:
    'Compute SHA-256 and MD5 digests and size of a firmware image, verify them against expected ' +
    'values with match/mismatch reporting, and note the presence of signature-like trailing blocks ' +
    '(e.g. U-Boot FIT / RSA payloads). Presence of a signature block is reported but is NOT claimed ' +
    'as verification without the corresponding keys.',
  capabilities: ['read_firmware'],
  risk: 'safe',
  inputSchema: {
    filePath: zodCommon.filePath,
    expectedSha256: z.string().optional(),
    expectedMd5: z.string().optional(),
    expectedSize: z.number().int().min(0).optional(),
  },
  handler: async (input, ctx) => {
    const started = Date.now();
    const art = readBinaryArtifact(input.filePath);
    const buf = art.buffer;
    const digest = await sha256(buf);
    const md5 = `md5:${createHash('md5').update(buf).digest('hex')}`;

    const norm = (s: string): string => s.trim().toLowerCase().replace(/^(sha256|md5):/, '');
    const matches = {
      sha256: input.expectedSha256 ? norm(digest) === norm(input.expectedSha256) : null,
      md5: input.expectedMd5 ? norm(md5) === norm(input.expectedMd5) : null,
      size: input.expectedSize !== undefined ? art.bytes === input.expectedSize : null,
    };

    // Signature-like trailing blocks (best effort, no key material used).
    const trailingSignatureBlocks: IntegrityResult['trailingSignatureBlocks'] = [];
    const fitMagic = Buffer.from([0xd0, 0x0d, 0xfe, 0xed]);
    let searchFrom = Math.max(0, buf.length - 1024 * 1024);
    let fitIdx = buf.indexOf(fitMagic, searchFrom);
    while (fitIdx >= 0 && trailingSignatureBlocks.length < 8) {
      trailingSignatureBlocks.push({
        offset: fitIdx,
        kind: 'FDT/FIT',
        note: 'Flattened device tree / U-Boot FIT signature container present.',
      });
      fitIdx = buf.indexOf(fitMagic, fitIdx + 4);
    }
    if (/RSA|PKCS#7|CMS|BEGIN CERTIFICATE/.test(buf.subarray(Math.max(0, buf.length - 65536)).toString('latin1'))) {
      trailingSignatureBlocks.push({
        offset: Math.max(0, buf.length - 65536),
        kind: 'RSA/PKCS#7',
        note: 'Signature-like text found near the end of the image.',
      });
    }

    addEvidence(ctx, {
      claim: `Integrity digest computed: ${digest} (md5 ${md5}, ${art.bytes} bytes).`,
      prov: localProvenance('firmware', art.path, 'integrity hashing'),
      confidence: 'observed',
      locator: { file: art.path },
    });
    if (matches.sha256 !== null || matches.md5 !== null || matches.size !== null) {
      const ok = matches.sha256 !== false && matches.md5 !== false && matches.size !== false;
      addEvidence(ctx, {
        claim: `Expected-value comparison ${ok ? 'PASSED' : 'FAILED'} (sha256=${matches.sha256}, md5=${matches.md5}, size=${matches.size}).`,
        prov: localProvenance('firmware', art.path, 'expected value comparison'),
        confidence: 'observed',
      });
    }

    const summary =
      `## Firmware integrity — ${basename(art.path)}\n` +
      `- Size: ${art.bytes} bytes\n` +
      `- sha256: ${digest}\n` +
      `- md5:    ${md5}\n` +
      `- Expected comparisons: sha256=${matches.sha256 ?? 'n/a'} md5=${matches.md5 ?? 'n/a'} size=${matches.size ?? 'n/a'}\n` +
      `- Signature-like blocks: ${trailingSignatureBlocks.length ? trailingSignatureBlocks.map((b) => `${b.kind}@0x${b.offset.toString(16)}`).join(', ') : 'none detected'}\n\n` +
      `> Signature block presence is reported only; cryptographic verification requires the vendor key and is not asserted here.`;

    return finish({
      engine: ENGINE,
      tool: 'firmware_integrity_check',
      startedAt: started,
      ctx,
      summary,
      data: {
        path: art.path,
        sizeBytes: art.bytes,
        sha256: digest,
        md5,
        expected: {
          ...(input.expectedSha256 ? { sha256: input.expectedSha256 } : {}),
          ...(input.expectedMd5 ? { md5: input.expectedMd5 } : {}),
          ...(input.expectedSize !== undefined ? { size: input.expectedSize } : {}),
        },
        matches,
        trailingSignatureBlocks,
        note: 'No key material was used; signature verification is out of scope for this static check.',
      },
    });
  },
});

/* ------------------------------------------------------------------ */
/* Engine export                                                       */
/* ------------------------------------------------------------------ */

export const firmwareIntelligenceEngine: EngineModule = {
  name: ENGINE,
  title: 'Firmware Intelligence',
  description:
    'Static, read-only firmware analysis: container/format detection, string and entropy profiling, ' +
    'safe extraction, extracted-filesystem inspection, ELF parsing, known-component/CVE hints, isolated ' +
    'emulation planning, patch diffing and integrity verification. Untrusted firmware is never executed.',
  tools: [
    analyzeTool,
    extractTool,
    filesystemTool,
    elfTool,
    componentScanTool,
    emulationTool,
    patchDiffTool,
    integrityTool,
  ],
};
