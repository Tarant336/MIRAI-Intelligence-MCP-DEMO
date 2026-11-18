/**
 * Pure-JS firmware analysis primitives (§5).
 *
 * No external binaries are required and nothing here ever executes the
 * artefact under analysis. Everything is static, read-only parsing so that
 * untrusted firmware can be inspected safely outside of an emulator.
 */

/* ------------------------------------------------------------------ */
/* Magic signatures                                                    */
/* ------------------------------------------------------------------ */

export interface Signature {
  name: string;
  description: string;
  bytes: number[];
  /** When set, the signature is only meaningful at this exact offset. */
  onlyOffset?: number;
}

export const COMMON_OFFSETS = [0x0, 0x100, 0x400, 0x1000, 0x10000, 0x200000];

export const SIGNATURES: Signature[] = [
  { name: 'squashfs-le', description: 'SquashFS filesystem (little-endian, hsqs)', bytes: [0x68, 0x73, 0x71, 0x73] },
  { name: 'squashfs-be', description: 'SquashFS filesystem (big-endian, sqsh)', bytes: [0x73, 0x71, 0x73, 0x68] },
  { name: 'jffs2', description: 'JFFS2 filesystem node magic', bytes: [0x85, 0x19] },
  { name: 'ubifs', description: 'UBIFS node magic', bytes: [0x31, 0x18, 0x10, 0x06] },
  { name: 'ubi', description: 'UBI erase-counter header (UBI#)', bytes: [0x55, 0x42, 0x49, 0x23] },
  { name: 'cramfs', description: 'CramFS filesystem magic', bytes: [0x45, 0x3d, 0xcd, 0x28] },
  { name: 'ext', description: 'ext2/3/4 superblock magic', bytes: [0x53, 0xef], onlyOffset: 0x438 },
  { name: 'trx', description: 'TRX firmware header (HDR0)', bytes: [0x48, 0x44, 0x52, 0x30] },
  { name: 'uimage', description: 'U-Boot legacy uImage magic', bytes: [0x27, 0x05, 0x19, 0x56] },
  { name: 'dlob', description: 'DLOB firmware container', bytes: [0x44, 0x4c, 0x4f, 0x42] },
  { name: 'chk', description: 'CHK firmware container', bytes: [0x43, 0x48, 0x4b] },
  { name: 'elf', description: 'ELF executable / object', bytes: [0x7f, 0x45, 0x4c, 0x46] },
  { name: 'gzip', description: 'gzip compressed stream', bytes: [0x1f, 0x8b] },
  { name: 'xz', description: 'XZ compressed stream', bytes: [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00] },
  { name: 'bzip2', description: 'bzip2 compressed stream', bytes: [0x42, 0x5a, 0x68] },
  { name: 'zstd', description: 'Zstandard compressed stream', bytes: [0x28, 0xb5, 0x2f, 0xfd] },
  { name: 'lzma', description: 'LZMA-alone compressed stream', bytes: [0x5d, 0x00, 0x00] },
  { name: 'tar', description: 'tar archive (POSIX ustar)', bytes: [0x75, 0x73, 0x74, 0x61, 0x72], onlyOffset: 0x101 },
  { name: 'cpio-newc', description: 'cpio "newc" archive', bytes: [0x30, 0x37, 0x30, 0x37, 0x30, 0x31] },
  { name: 'cpio-newc', description: 'cpio "newc" archive', bytes: [0x30, 0x37, 0x30, 0x37, 0x30, 0x32] },
  { name: 'fit', description: 'Flattened device tree / U-Boot FIT', bytes: [0xd0, 0x0d, 0xfe, 0xed] },
];

function matchesAt(buf: Buffer, offset: number, bytes: number[]): boolean {
  if (offset < 0 || offset + bytes.length > buf.length) return false;
  for (let i = 0; i < bytes.length; i += 1) {
    if (buf.readUInt8(offset + i) !== bytes[i]) return false;
  }
  return true;
}

export interface FormatHit {
  format: string;
  description: string;
  offset: number;
}

/** Detect the primary container format by checking signatures at offset 0. */
export function detectContainerFormat(buf: Buffer): FormatHit | undefined {
  for (const sig of SIGNATURES) {
    if (sig.onlyOffset !== undefined && sig.onlyOffset !== 0) continue;
    if (matchesAt(buf, 0, sig.bytes)) {
      return { format: sig.name, description: sig.description, offset: 0 };
    }
  }
  // ext filesystems place their magic deep inside the superblock.
  if (matchesAt(buf, 0x438, [0x53, 0xef])) {
    return { format: 'ext', description: 'ext2/3/4 filesystem image', offset: 0x438 };
  }
  if (matchesAt(buf, 0x101, [0x75, 0x73, 0x74, 0x61, 0x72])) {
    return { format: 'tar', description: 'tar archive (POSIX ustar)', offset: 0x101 };
  }
  return undefined;
}

/** Scan the common offsets for embedded signatures. */
export function scanEmbeddedSignatures(buf: Buffer): FormatHit[] {
  const hits: FormatHit[] = [];
  for (const offset of COMMON_OFFSETS) {
    for (const sig of SIGNATURES) {
      if (sig.onlyOffset !== undefined && sig.onlyOffset !== offset) continue;
      if (offset === 0 && sig.onlyOffset !== undefined) continue;
      if (matchesAt(buf, offset, sig.bytes)) {
        hits.push({ format: sig.name, description: sig.description, offset });
      }
    }
  }
  return hits;
}

/* ------------------------------------------------------------------ */
/* Entropy                                                             */
/* ------------------------------------------------------------------ */

/** Shannon entropy (bits/byte) of a buffer, range 0..8. */
export function shannonEntropy(buf: Buffer): number {
  if (buf.length === 0) return 0;
  const counts = new Array<number>(256).fill(0);
  for (let i = 0; i < buf.length; i += 1) counts[buf.readUInt8(i)] = (counts[buf.readUInt8(i)] ?? 0) + 1;
  let entropy = 0;
  const len = buf.length;
  for (const c of counts) {
    if (c > 0) {
      const p = c / len;
      entropy -= p * Math.log2(p);
    }
  }
  return entropy;
}

export interface EntropyBlock {
  offset: number;
  size: number;
  entropy: number;
}

/** Compute entropy over fixed-size blocks. */
export function entropyMap(buf: Buffer, blockSize = 256): EntropyBlock[] {
  const blocks: EntropyBlock[] = [];
  for (let offset = 0; offset < buf.length; offset += blockSize) {
    const slice = buf.subarray(offset, Math.min(offset + blockSize, buf.length));
    blocks.push({ offset, size: slice.length, entropy: Number(shannonEntropy(slice).toFixed(3)) });
  }
  return blocks;
}

/** Merge contiguous high-entropy blocks into regions (compression/encryption). */
export function highEntropyRegions(buf: Buffer, threshold = 7.5, blockSize = 256): EntropyBlock[] {
  const regions: EntropyBlock[] = [];
  let current: EntropyBlock | undefined;
  for (let offset = 0; offset < buf.length; offset += blockSize) {
    const slice = buf.subarray(offset, Math.min(offset + blockSize, buf.length));
    const entropy = shannonEntropy(slice);
    if (entropy >= threshold) {
      if (current) {
        current.size += slice.length;
      } else {
        current = { offset, size: slice.length, entropy: Number(entropy.toFixed(3)) };
      }
    } else if (current) {
      regions.push({ ...current, entropy: Number(current.entropy.toFixed(3)) });
      current = undefined;
    }
  }
  if (current) regions.push({ ...current, entropy: Number(current.entropy.toFixed(3)) });
  return regions;
}

/* ------------------------------------------------------------------ */
/* Strings and classification                                          */
/* ------------------------------------------------------------------ */

export interface StringHit {
  value: string;
  offset: number;
}

/** Extract printable ASCII strings (length >= minLen) with their offsets. */
export function extractStrings(buf: Buffer, minLen = 5, maxStrings = 20000): StringHit[] {
  const hits: StringHit[] = [];
  let start = -1;
  for (let i = 0; i < buf.length; i += 1) {
    const b = buf.readUInt8(i);
    const printable = b >= 0x20 && b <= 0x7e;
    if (printable) {
      if (start < 0) start = i;
    } else {
      if (start >= 0) {
        const len = i - start;
        if (len >= minLen) {
          hits.push({ value: buf.toString('latin1', start, i), offset: start });
          if (hits.length >= maxStrings) return hits;
        }
        start = -1;
      }
    }
  }
  if (start >= 0 && buf.length - start >= minLen && hits.length < maxStrings) {
    hits.push({ value: buf.toString('latin1', start, buf.length), offset: start });
  }
  return hits;
}

export interface ClassifiedStrings {
  kernelVersions: string[];
  versionBanners: string[];
  busyboxVersions: string[];
  distributions: string[];
  services: string[];
  credentialCandidates: string[];
  urls: string[];
  cveReferences: string[];
}

const SERVICE_KEYWORDS = [
  'httpd',
  'telnetd',
  'dropbear',
  'upnp',
  'boa',
  'goahead',
  'lighttpd',
  'dnsmasq',
  'sshd',
  'ftpd',
  'tftp',
  'snmpd',
  'mqtt',
];

/** Classify extracted strings into security-relevant buckets. */
export function classifyStrings(hits: StringHit[]): ClassifiedStrings {
  const out: ClassifiedStrings = {
    kernelVersions: [],
    versionBanners: [],
    busyboxVersions: [],
    distributions: [],
    services: [],
    credentialCandidates: [],
    urls: [],
    cveReferences: [],
  };
  const seen = new Set<string>();
  const push = (list: string[], value: string): void => {
    const key = value.trim();
    if (!key || seen.has(key)) return;
    seen.add(key);
    list.push(key);
  };
  for (const { value } of hits) {
    const kernel = /Linux version (\d+\.\d+(?:\.\d+)?[^\s"']*)/i.exec(value);
    if (kernel && kernel[1]) push(out.kernelVersions, kernel[1]);
    const busybox = /BusyBox\s+v?([0-9][0-9A-Za-z._-]*)/i.exec(value);
    if (busybox && busybox[1]) push(out.busyboxVersions, busybox[1]);
    if (/buildroot/i.test(value)) push(out.distributions, 'Buildroot');
    if (/openwrt/i.test(value)) push(out.distributions, 'OpenWrt');
    if (/\blede\b/i.test(value)) push(out.distributions, 'LEDE');
    if (/(?:version|v)\s*[=:]?\s*\d+\.\d+(?:\.\d+)?/i.test(value) && out.versionBanners.length < 200) {
      push(out.versionBanners, value.slice(0, 120));
    }
    const lower = value.toLowerCase();
    for (const kw of SERVICE_KEYWORDS) {
      if (lower.includes(kw)) {
        push(out.services, kw);
        break;
      }
    }
    if (/(?:password|passwd|pwd|passphrase|secret|token|api[_-]?key)\s*[:=]\s*\S+/i.test(value)) {
      if (out.credentialCandidates.length < 200) push(out.credentialCandidates, value.slice(0, 160));
    }
    const url = /https?:\/\/[^\s"'<>)]+/i.exec(value);
    if (url && url[0]) push(out.urls, url[0]);
    const cve = /CVE-\d{4}-\d{4,7}/gi.exec(value);
    if (cve && cve[0]) push(out.cveReferences, cve[0].toUpperCase());
  }
  return out;
}

/* ------------------------------------------------------------------ */
/* ELF parsing                                                         */
/* ------------------------------------------------------------------ */

export interface ElfSection {
  name: string;
  type: number;
  typeName: string;
  addr: number;
  offset: number;
  size: number;
}

export interface ElfProgramHeader {
  type: number;
  typeName: string;
  flags: number;
  offset: number;
  vaddr: number;
  filesz: number;
  memsz: number;
}

export interface ElfCheckSec {
  nx: boolean;
  pie: boolean;
  relro: 'none' | 'partial' | 'full';
  canary: boolean;
  fortify: boolean;
  stripped: boolean;
}

export interface ElfReport {
  isElf: boolean;
  elfClass: '32' | '64' | 'unknown';
  endian: 'little' | 'big' | 'unknown';
  osabi: string;
  type: number;
  typeName: string;
  machine: number;
  machineName: string;
  entry: number;
  phoff: number;
  phentsize: number;
  phnum: number;
  shoff: number;
  shentsize: number;
  shnum: number;
  shstrndx: number;
  sections: ElfSection[];
  programHeaders: ElfProgramHeader[];
  interpreter?: string;
  needed: string[];
  checksec: ElfCheckSec;
  libcHints: string[];
  packerHints: string[];
  notes: string[];
  warnings: string[];
}

const MACHINE_TABLE: Record<number, string> = {
  2: 'SPARC',
  3: 'x86 (i386)',
  8: 'MIPS',
  10: 'MIPS (little-endian, MIPSEL)',
  20: 'PowerPC',
  21: 'PowerPC64',
  40: 'ARM',
  42: 'SuperH (SH)',
  43: 'SPARCv9',
  50: 'IA-64 (Itanium)',
  62: 'x86-64',
  183: 'AArch64 (ARM64)',
  243: 'RISC-V',
};

const OSABI_TABLE: Record<number, string> = {
  0: 'System V',
  1: 'HP-UX',
  2: 'NetBSD',
  3: 'Linux',
  6: 'Solaris',
  9: 'FreeBSD',
  12: 'OpenBSD',
  97: 'ARM',
  255: 'Standalone',
};

const SECTION_TYPE_TABLE: Record<number, string> = {
  0: 'NULL',
  1: 'PROGBITS',
  2: 'SYMTAB',
  3: 'STRTAB',
  4: 'RELA',
  5: 'HASH',
  6: 'DYNAMIC',
  7: 'NOTE',
  8: 'NOBITS',
  9: 'REL',
  14: 'INIT_ARRAY',
  15: 'FINI_ARRAY',
};

const PH_TYPE_TABLE: Record<number, string> = {
  1: 'PT_LOAD',
  2: 'PT_DYNAMIC',
  3: 'PT_INTERP',
  4: 'PT_NOTE',
  5: 'PT_SHLIB',
  6: 'PT_PHDR',
  7: 'PT_TLS',
  0x6474e550: 'PT_GNU_EH_FRAME',
  0x6474e551: 'PT_GNU_STACK',
  0x6474e552: 'PT_GNU_RELRO',
};

const ELF_TYPE_TABLE: Record<number, string> = {
  0: 'ET_NONE',
  1: 'ET_REL',
  2: 'ET_EXEC',
  3: 'ET_DYN',
  4: 'ET_CORE',
};

function emptyElfReport(warnings: string[]): ElfReport {
  return {
    isElf: false,
    elfClass: 'unknown',
    endian: 'unknown',
    osabi: 'unknown',
    type: 0,
    typeName: 'ET_NONE',
    machine: 0,
    machineName: 'unknown',
    entry: 0,
    phoff: 0,
    phentsize: 0,
    phnum: 0,
    shoff: 0,
    shentsize: 0,
    shnum: 0,
    shstrndx: 0,
    sections: [],
    programHeaders: [],
    needed: [],
    checksec: { nx: false, pie: false, relro: 'none', canary: false, fortify: false, stripped: true },
    libcHints: [],
    packerHints: [],
    notes: [],
    warnings,
  };
}

function readCString(buf: Buffer, off: number, max = 512): string {
  if (off < 0 || off >= buf.length) return '';
  let end = off;
  const limit = Math.min(buf.length, off + max);
  while (end < limit && buf.readUInt8(end) !== 0) end += 1;
  return buf.toString('latin1', off, end);
}

/** Parse ELF metadata, section/program headers and compute checksec-style flags. */
export function parseElf(buf: Buffer): ElfReport {
  const warnings: string[] = [];
  try {
    if (buf.length < 20 || !matchesAt(buf, 0, [0x7f, 0x45, 0x4c, 0x46])) {
      return emptyElfReport(['Not an ELF file (bad magic).']);
    }
    const clsByte = buf.readUInt8(4);
    const dataByte = buf.readUInt8(5);
    const elfClass: ElfReport['elfClass'] = clsByte === 1 ? '32' : clsByte === 2 ? '64' : 'unknown';
    const endian: ElfReport['endian'] = dataByte === 1 ? 'little' : dataByte === 2 ? 'big' : 'unknown';
    if (elfClass === 'unknown' || endian === 'unknown') {
      return emptyElfReport(['Unsupported ELF class or endianness.']);
    }
    const le = endian === 'little';
    const osabi = OSABI_TABLE[buf.readUInt8(7)] ?? `unknown(${buf.readUInt8(7)})`;

    const is64 = elfClass === '64';
    const u16 = (o: number): number => (o + 2 <= buf.length ? (le ? buf.readUInt16LE(o) : buf.readUInt16BE(o)) : 0);
    const u32 = (o: number): number => (o + 4 <= buf.length ? (le ? buf.readUInt32LE(o) : buf.readUInt32BE(o)) : 0);
    const u64 = (o: number): number => {
      if (o + 8 > buf.length) return 0;
      return Number(le ? buf.readBigUInt64LE(o) : buf.readBigUInt64BE(o));
    };
    const addrAt = (o: number): number => (is64 ? u64(o) : u32(o));

    const type = u16(16);
    const machine = u16(18);
    const entry = addrAt(24);
    const phoff = is64 ? u64(32) : u32(28);
    const shoff = is64 ? u64(40) : u32(32);
    const phentsize = u16(is64 ? 54 : 42);
    const phnum = u16(is64 ? 56 : 44);
    const shentsize = u16(is64 ? 58 : 46);
    const shnum = u16(is64 ? 60 : 48);
    const shstrndx = u16(is64 ? 62 : 50);

    // ---- Section headers -------------------------------------------------
    const sections: ElfSection[] = [];
    if (shoff > 0 && shentsize >= (is64 ? 64 : 40)) {
      for (let i = 0; i < shnum; i += 1) {
        const base = shoff + i * shentsize;
        if (base + shentsize > buf.length) {
          warnings.push(`section header ${i} is out of bounds`);
          break;
        }
        let nameOff: number;
        let stype: number;
        let addr: number;
        let offset: number;
        let size: number;
        if (is64) {
          nameOff = u32(base);
          stype = u32(base + 4);
          addr = u64(base + 16);
          offset = u64(base + 24);
          size = u64(base + 32);
        } else {
          nameOff = u32(base);
          stype = u32(base + 4);
          addr = u32(base + 12);
          offset = u32(base + 16);
          size = u32(base + 20);
        }
        sections.push({
          name: '',
          type: stype,
          typeName: SECTION_TYPE_TABLE[stype] ?? `0x${stype.toString(16)}`,
          addr,
          offset,
          size,
        });
        void nameOff;
      }
      // Resolve names via the section header string table.
      const strtab = sections[shstrndx];
      if (strtab && strtab.offset > 0 && strtab.offset < buf.length) {
        for (let i = 0; i < sections.length; i += 1) {
          const base = shoff + i * shentsize;
          const nameOff = u32(base);
          const name = readCString(buf, strtab.offset + nameOff, 128);
          const s = sections[i];
          if (s && name) s.name = name;
        }
      } else if (shstrndx !== 0) {
        warnings.push('shstrtab not resolvable; section names unavailable');
      }
    } else if (shnum > 0) {
      warnings.push('section headers missing or malformed');
    }

    // ---- Program headers -------------------------------------------------
    const programHeaders: ElfProgramHeader[] = [];
    if (phoff > 0 && phentsize >= (is64 ? 56 : 32)) {
      for (let i = 0; i < phnum; i += 1) {
        const base = phoff + i * phentsize;
        if (base + phentsize > buf.length) {
          warnings.push(`program header ${i} is out of bounds`);
          break;
        }
        let ptype: number;
        let flags: number;
        let offset: number;
        let vaddr: number;
        let filesz: number;
        let memsz: number;
        if (is64) {
          ptype = u32(base);
          flags = u32(base + 4);
          offset = u64(base + 8);
          vaddr = u64(base + 16);
          filesz = u64(base + 32);
          memsz = u64(base + 40);
        } else {
          ptype = u32(base);
          offset = u32(base + 4);
          vaddr = u32(base + 8);
          filesz = u32(base + 16);
          memsz = u32(base + 20);
          flags = u32(base + 24);
        }
        programHeaders.push({
          type: ptype,
          typeName: PH_TYPE_TABLE[ptype] ?? `0x${ptype.toString(16)}`,
          flags,
          offset,
          vaddr,
          filesz,
          memsz,
        });
      }
    }

    // ---- Interpreter + dynamic dependencies ------------------------------
    const mapVaddrToOffset = (vaddr: number): number => {
      for (const ph of programHeaders) {
        if (ph.type === 1 && vaddr >= ph.vaddr && vaddr < ph.vaddr + ph.filesz) {
          return ph.offset + (vaddr - ph.vaddr);
        }
      }
      return -1;
    };

    let interpreter: string | undefined;
    const interp = programHeaders.find((ph) => ph.type === 3);
    if (interp && interp.offset < buf.length) {
      const s = readCString(buf, interp.offset, 256);
      if (s) interpreter = s;
    }

    const needed: string[] = [];
    const dyn = programHeaders.find((ph) => ph.type === 2);
    let bindNow = false;
    if (dyn && dyn.offset < buf.length) {
      const entrySize = is64 ? 16 : 8;
      let strtabVaddr = -1;
      const rawNeeded: number[] = [];
      for (let off = dyn.offset; off + entrySize <= Math.min(buf.length, dyn.offset + dyn.filesz); off += entrySize) {
        const tag = is64 ? u64(off) : u32(off);
        const val = is64 ? u64(off + 8) : u32(off + 4);
        if (tag === 0) break; // DT_NULL
        if (tag === 5) strtabVaddr = val; // DT_STRTAB
        if (tag === 24) bindNow = true; // DT_BIND_NOW
        if (tag === 30 && (val & 0x8) !== 0) bindNow = true; // DT_FLAGS DF_BIND_NOW
        if (tag === 0x6ffffffb && (val & 0x1) !== 0) bindNow = true; // DT_FLAGS_1 DF_1_NOW
        if (tag === 1) rawNeeded.push(val); // DT_NEEDED
      }
      if (strtabVaddr >= 0) {
        const strOff = mapVaddrToOffset(strtabVaddr);
        if (strOff >= 0) {
          for (const rel of rawNeeded) {
            const name = readCString(buf, strOff + rel, 256);
            if (name) needed.push(name);
          }
        } else {
          warnings.push('DT_STRTAB not mappable; DT_NEEDED names unavailable');
        }
      } else if (rawNeeded.length > 0) {
        warnings.push('DT_STRTAB absent; DT_NEEDED names unavailable');
      }
    }

    // ---- Security hints from strings / sections --------------------------
    const strings = extractStrings(buf, 4, 40000);
    const joined = strings.map((s) => s.value).join('\n');
    const libcHints: string[] = [];
    if (/uClibc/i.test(joined)) libcHints.push('uClibc');
    if (/musl|ld-musl/i.test(joined)) libcHints.push('musl');
    if (/glibc|GNU C Library|GLIBC_/i.test(joined)) libcHints.push('glibc');
    for (const dep of needed) {
      if (/musl/i.test(dep)) libcHints.push('musl');
      else if (/uclibc/i.test(dep)) libcHints.push('uClibc');
      else if (/libc\.so/i.test(dep) && !libcHints.includes('glibc') && !libcHints.includes('uClibc') && !libcHints.includes('musl')) {
        libcHints.push('libc (unspecified)');
      }
    }

    const packerHints: string[] = [];
    if (sections.some((s) => /^UPX[0-9]?$/i.test(s.name))) packerHints.push('UPX (UPX section names present)');
    if (/UPX!/.test(joined)) packerHints.push('UPX (UPX! marker)');
    if (/This file is packed/i.test(joined)) packerHints.push('generic packer message');
    if (/\$Info:/.test(joined)) packerHints.push('UPX $Info header');

    const hasSymtab = sections.some((s) => s.name === '.symtab');
    const hasGnuStack = programHeaders.some((ph) => ph.type === 0x6474e551);
    const gnuStack = programHeaders.find((ph) => ph.type === 0x6474e551);
    const nx = hasGnuStack ? (gnuStack !== undefined && (gnuStack.flags & 0x1) === 0) : false;
    if (!hasGnuStack) warnings.push('no PT_GNU_STACK: NX status could not be determined');

    const relroHeader = programHeaders.some((ph) => ph.type === 0x6474e552);
    const relro: ElfCheckSec['relro'] = relroHeader ? (bindNow ? 'full' : 'partial') : 'none';

    const canary = /__stack_chk_fail|__stack_chk_guard|__stack_chk_fail_local/.test(joined);
    const fortify = /__\w+_chk\b|_chk@/.test(joined);

    return {
      isElf: true,
      elfClass,
      endian,
      osabi,
      type,
      typeName: ELF_TYPE_TABLE[type] ?? `0x${type.toString(16)}`,
      machine,
      machineName: MACHINE_TABLE[machine] ?? `unknown(${machine})`,
      entry,
      phoff,
      phentsize,
      phnum,
      shoff,
      shentsize,
      shnum,
      shstrndx,
      sections,
      programHeaders,
      ...(interpreter ? { interpreter } : {}),
      needed,
      checksec: {
        nx,
        pie: type === 3,
        relro,
        canary,
        fortify,
        stripped: !hasSymtab,
      },
      libcHints,
      packerHints,
      notes: [],
      warnings,
    };
  } catch (err) {
    return emptyElfReport([`ELF parse failed: ${(err as Error).message}`]);
  }
}

/* ------------------------------------------------------------------ */
/* Archive carving (cpio newc, tar)                                    */
/* ------------------------------------------------------------------ */

export interface ArchiveMember {
  name: string;
  size: number;
  data: Buffer;
}

function sanitizeMemberName(name: string): string {
  // Split on separators and drop empty / "." / ".." segments. We must NOT do a
  // blanket `.replace(/\.\//g, '')` first: on `../../etc/evil` it rewrites the
  // first `./` and leaves `..etc/evil`, which then slips past the `..` filter.
  const parts = name
    .replace(/\\/g, '/')
    .split('/')
    .filter((p) => p !== '' && p !== '.' && p !== '..');
  return parts.join('/') || 'unnamed';
}

export interface CpioParseResult {
  members: ArchiveMember[];
  /** Offset immediately past the parsed archive (start of the next byte). */
  end: number;
  /** True when a `TRAILER!!!` record terminated the archive cleanly. */
  complete: boolean;
}

/**
 * Parse a cpio "newc"/"crc" archive sequentially starting at `start`.
 *
 * Parsing follows the format strictly — header, filename, 4-byte-aligned data,
 * then the trailing `TRAILER!!!` record — and stops at the first structural
 * violation. It never treats a `070701` byte sequence that occurs inside a
 * member payload as the start of a new archive, which is what previously
 * produced duplicated members.
 */
export function parseCpioNewcArchive(
  buf: Buffer,
  start = 0,
  maxMembers = 5000,
  maxBytes = 128 * 1024 * 1024,
): CpioParseResult {
  const members: ArchiveMember[] = [];
  let off = start;
  let consumed = 0;
  let complete = false;
  const hex = (s: string): number => Number.parseInt(s, 16);
  while (off >= 0 && off + 110 <= buf.length && members.length < maxMembers) {
    const magic = buf.toString('latin1', off, off + 6);
    if (magic !== '070701' && magic !== '070702') break;
    const field = (n: number): number => hex(buf.toString('latin1', off + 6 + n * 8, off + 6 + n * 8 + 8));
    const filesize = field(6);
    const namesize = field(11);
    if (!Number.isInteger(filesize) || !Number.isInteger(namesize) || filesize < 0 || namesize <= 0) break;
    const nameStart = off + 110;
    if (nameStart + namesize > buf.length) break;
    const rawName = buf.toString('latin1', nameStart, nameStart + namesize).replace(/\0+$/, '');
    // Header + name is padded to a 4-byte boundary; data follows, padded too.
    const dataStart = nameStart + (((namesize + 110 + 3) & ~3) - 110);
    const dataEnd = dataStart + filesize;
    off = dataEnd + ((4 - (filesize % 4)) % 4);
    if (rawName === 'TRAILER!!!') {
      complete = true;
      break;
    }
    if (dataEnd > buf.length) {
      members.push({ name: sanitizeMemberName(rawName), size: filesize, data: buf.subarray(dataStart, buf.length) });
      break;
    }
    if (consumed + filesize <= maxBytes) {
      members.push({ name: sanitizeMemberName(rawName), size: filesize, data: buf.subarray(dataStart, dataEnd) });
      consumed += filesize;
    } else {
      members.push({ name: sanitizeMemberName(rawName), size: filesize, data: Buffer.alloc(0) });
    }
  }
  return { members, end: off, complete };
}

/** Parse a cpio "newc"/"crc" archive into members (best effort, always safe). */
export function parseCpioNewc(buf: Buffer, maxMembers = 5000, maxBytes = 128 * 1024 * 1024): ArchiveMember[] {
  return parseCpioNewcArchive(buf, 0, maxMembers, maxBytes).members;
}

/** Parse a POSIX/ustar tar archive into members (best effort). */
export function parseTar(buf: Buffer, maxMembers = 5000, maxBytes = 128 * 1024 * 1024): ArchiveMember[] {
  const members: ArchiveMember[] = [];
  let off = 0;
  let consumed = 0;
  let pendingLongName: string | undefined;
  while (off + 512 <= buf.length && members.length < maxMembers) {
    const nameField = buf.toString('latin1', off, off + 100).replace(/\0.*$/, '');
    if (nameField === '') break; // zero block terminates the archive
    const sizeField = buf.toString('latin1', off + 124, off + 136).replace(/\0.*$/, '').trim();
    const size = Number.parseInt(sizeField, 8) || 0;
    const typeFlag = buf.toString('latin1', off + 156, off + 157);
    const prefix = buf.toString('latin1', off + 345, off + 500).replace(/\0.*$/, '');
    let name = prefix ? `${prefix}/${nameField}` : nameField;
    const dataStart = off + 512;
    const dataEnd = dataStart + size;
    if (typeFlag === 'L') {
      pendingLongName = buf.toString('latin1', dataStart, Math.min(dataEnd, buf.length)).replace(/\0+$/, '');
    } else if (typeFlag === '0' || typeFlag === '' || typeFlag === '\0') {
      if (pendingLongName) name = pendingLongName;
      pendingLongName = undefined;
      const end = dataEnd <= buf.length ? dataEnd : buf.length;
      if (consumed + size <= maxBytes) {
        members.push({ name: sanitizeMemberName(name), size, data: buf.subarray(dataStart, end) });
        consumed += size;
      } else {
        members.push({ name: sanitizeMemberName(name), size, data: Buffer.alloc(0) });
      }
    } else {
      pendingLongName = undefined;
    }
    // Zero-length members (directories, empty files) land exactly on dataStart,
    // so the no-progress guard must compare against the header offset: an
    // archive whose first entry is a directory (`./`) still advances one block.
    const nextOff = dataStart + (((size + 511) & ~511));
    if (nextOff <= off) break;
    off = nextOff;
  }
  return members;
}

export interface CarvedStream {
  type: 'gzip' | 'xz' | 'bzip2' | 'zstd';
  offset: number;
  data: Buffer;
}

const STREAM_MAGICS: { type: CarvedStream['type']; bytes: number[] }[] = [
  { type: 'gzip', bytes: [0x1f, 0x8b] },
  { type: 'xz', bytes: [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00] },
  { type: 'bzip2', bytes: [0x42, 0x5a, 0x68] },
  { type: 'zstd', bytes: [0x28, 0xb5, 0x2f, 0xfd] },
];

function findAll(buf: Buffer, pattern: number[], from: number): number {
  const needle = Buffer.from(pattern);
  return buf.indexOf(needle, from);
}

/** Carve embedded compression streams by magic, bounded to the next stream. */
export function carveStreams(buf: Buffer, scanLimit = 64 * 1024 * 1024): CarvedStream[] {
  const limit = Math.min(buf.length, scanLimit);
  const hits: { type: CarvedStream['type']; offset: number }[] = [];
  for (const { type, bytes } of STREAM_MAGICS) {
    let idx = findAll(buf, bytes, 0);
    while (idx >= 0 && idx < limit) {
      hits.push({ type, offset: idx });
      idx = findAll(buf, bytes, idx + 1);
    }
  }
  hits.sort((a, b) => a.offset - b.offset);
  const streams: CarvedStream[] = [];
  for (let i = 0; i < hits.length; i += 1) {
    const hit = hits[i];
    if (!hit) continue;
    const next = hits[i + 1];
    const end = next ? next.offset : Math.min(buf.length, limit);
    if (end <= hit.offset) continue;
    streams.push({ type: hit.type, offset: hit.offset, data: buf.subarray(hit.offset, end) });
  }
  return streams;
}

/* ------------------------------------------------------------------ */
/* Curated component / CVE table                                       */
/* ------------------------------------------------------------------ */

export interface CveHint {
  id: string;
  fixed: string;
  note: string;
  ref: string;
}

export interface ComponentSpec {
  component: string;
  banner: RegExp;
  cves: CveHint[];
}

/**
 * Curated table of widely-documented components and their version→CVE hints.
 * Version-string matches are INDICATIVE only, never proof of exploitability
 * (§B1/§C2): an embedded banner can be backported, patched or spoofed.
 */
export const COMPONENT_TABLE: ComponentSpec[] = [
  {
    component: 'busybox',
    banner: /BusyBox\s+v?([0-9][0-9A-Za-z._-]*)/i,
    cves: [
      { id: 'CVE-2017-16544', fixed: '1.27.2', note: 'ash tab-completion escape injection via filenames', ref: 'https://nvd.nist.gov/vuln/detail/CVE-2017-16544' },
      { id: 'CVE-2018-1000500', fixed: '1.28.3', note: 'wget does not validate TLS certificates', ref: 'https://nvd.nist.gov/vuln/detail/CVE-2018-1000500' },
    ],
  },
  {
    component: 'dropbear',
    banner: /dropbear(?:_sshd)?[^0-9]*([0-9]{4}\.[0-9]{2})/i,
    cves: [
      { id: 'CVE-2016-7406', fixed: '2016.73', note: 'format string in SSH authentication handling', ref: 'https://nvd.nist.gov/vuln/detail/CVE-2016-7406' },
      { id: 'CVE-2018-15599', fixed: '2018.76', note: 'user enumeration via timing in recv_msg_userauth_request', ref: 'https://nvd.nist.gov/vuln/detail/CVE-2018-15599' },
    ],
  },
  {
    component: 'openssl',
    banner: /OpenSSL\s+([0-9][0-9A-Za-z._-]*)/i,
    cves: [
      { id: 'CVE-2014-0160', fixed: '1.0.1g', note: 'Heartbleed TLS heartbeat information disclosure', ref: 'https://nvd.nist.gov/vuln/detail/CVE-2014-0160' },
      { id: 'CVE-2014-0224', fixed: '1.0.1h', note: 'CCS injection man-in-the-middle', ref: 'https://nvd.nist.gov/vuln/detail/CVE-2014-0224' },
      { id: 'CVE-2016-2107', fixed: '1.0.2h', note: 'padding oracle in AES-NI CBC MAC check', ref: 'https://nvd.nist.gov/vuln/detail/CVE-2016-2107' },
      { id: 'CVE-2022-0778', fixed: '3.0.2', note: 'infinite loop in BN_mod_sqrt (DoS)', ref: 'https://nvd.nist.gov/vuln/detail/CVE-2022-0778' },
    ],
  },
  {
    component: 'openssh',
    banner: /OpenSSH[_\s]+([0-9][0-9A-Za-z._p-]*)/i,
    cves: [
      { id: 'CVE-2018-15473', fixed: '7.7', note: 'username enumeration via authentication timing', ref: 'https://nvd.nist.gov/vuln/detail/CVE-2018-15473' },
      { id: 'CVE-2024-6387', fixed: '9.8', note: 'regreSSHion race condition in signal handler (RCE)', ref: 'https://nvd.nist.gov/vuln/detail/CVE-2024-6387' },
    ],
  },
  {
    component: 'libupnp',
    banner: /libupnp[/ ][^0-9]*([0-9][0-9A-Za-z._-]*)/i,
    cves: [
      { id: 'CVE-2016-8863', fixed: '1.6.21', note: 'heap buffer overflow in the SOAP/HTTP handling', ref: 'https://nvd.nist.gov/vuln/detail/CVE-2016-8863' },
    ],
  },
  {
    component: 'miniupnpd',
    banner: /miniupnpd[/ ]?([0-9][0-9A-Za-z._-]*)/i,
    cves: [
      { id: 'CVE-2019-12147', fixed: '2.1.20191027', note: 'buffer overflow in the SSDP/HTTP parser', ref: 'https://nvd.nist.gov/vuln/detail/CVE-2019-12147' },
    ],
  },
  {
    component: 'lighttpd',
    banner: /lighttpd[/ ]([0-9][0-9A-Za-z._-]*)/i,
    cves: [
      { id: 'CVE-2022-37797', fixed: '1.4.66', note: 'use-after-free in mod_wstunnel (DoS)', ref: 'https://nvd.nist.gov/vuln/detail/CVE-2022-37797' },
    ],
  },
  {
    component: 'boa',
    banner: /Boa[/ ]([0-9][0-9A-Za-z._-]*)/,
    cves: [
      { id: 'CVE-2017-9833', fixed: '0.94.14', note: 'directory traversal in request handling', ref: 'https://nvd.nist.gov/vuln/detail/CVE-2017-9833' },
    ],
  },
  {
    component: 'goahead',
    banner: /GoAhead[/-]([0-9][0-9A-Za-z._-]*)/i,
    cves: [
      { id: 'CVE-2017-17562', fixed: '3.6.5', note: 'LD_PRELOAD injection via CGI environment', ref: 'https://nvd.nist.gov/vuln/detail/CVE-2017-17562' },
      { id: 'CVE-2019-5096', fixed: '3.6.5', note: 'heap overflow in multipart form parsing', ref: 'https://nvd.nist.gov/vuln/detail/CVE-2019-5096' },
    ],
  },
  {
    component: 'dnsmasq',
    banner: /dnsmasq[/-]([0-9][0-9A-Za-z._-]*)/i,
    cves: [
      { id: 'CVE-2017-14491', fixed: '2.78', note: 'heap overflow in DNS response generation (DNSpooq predecessor)', ref: 'https://nvd.nist.gov/vuln/detail/CVE-2017-14491' },
      { id: 'CVE-2020-25681', fixed: '2.83', note: 'DNSpooq: heap overflow in DNSSEC validation', ref: 'https://nvd.nist.gov/vuln/detail/CVE-2020-25681' },
    ],
  },
  {
    component: 'wpa_supplicant',
    banner: /wpa_supplicant[/-]?([0-9][0-9A-Za-z._-]*)/i,
    cves: [
      { id: 'CVE-2017-13077', fixed: '2.7', note: 'KRACK: reinstallation of pairwise key in 4-way handshake', ref: 'https://nvd.nist.gov/vuln/detail/CVE-2017-13077' },
      { id: 'CVE-2019-9494', fixed: '2.8', note: 'EAP-pwd side-channel / invalid curve attack', ref: 'https://nvd.nist.gov/vuln/detail/CVE-2019-9494' },
    ],
  },
  {
    component: 'hostapd',
    banner: /hostapd[/-]?([0-9][0-9A-Za-z._-]*)/i,
    cves: [
      { id: 'CVE-2017-13077', fixed: '2.7', note: 'KRACK: reinstallation of pairwise key in 4-way handshake', ref: 'https://nvd.nist.gov/vuln/detail/CVE-2017-13077' },
    ],
  },
  {
    component: 'samba',
    banner: /Samba[/ ]([0-9][0-9A-Za-z._-]*)/,
    cves: [
      { id: 'CVE-2017-7494', fixed: '4.6.4', note: 'SambaCry: remote code execution via shared library loading', ref: 'https://nvd.nist.gov/vuln/detail/CVE-2017-7494' },
    ],
  },
  {
    component: 'avahi',
    banner: /avahi[/-]([0-9][0-9A-Za-z._-]*)/i,
    cves: [
      { id: 'CVE-2017-6519', fixed: '0.6.32', note: 'avahi-daemon denial of service via crafted packet', ref: 'https://nvd.nist.gov/vuln/detail/CVE-2017-6519' },
    ],
  },
  {
    component: 'glibc',
    banner: /GNU C Library[^\n]*?(?:version\s+|release\s+)?([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i,
    cves: [
      { id: 'CVE-2015-7547', fixed: '2.23', note: 'getaddrinfo stack buffer overflow', ref: 'https://nvd.nist.gov/vuln/detail/CVE-2015-7547' },
      { id: 'CVE-2023-4911', fixed: '2.38', note: 'Looney Tunables: ld.so GLIBC_TUNABLES buffer overflow', ref: 'https://nvd.nist.gov/vuln/detail/CVE-2023-4911' },
    ],
  },
  {
    component: 'uclibc',
    banner: /uClibc[- ]?([0-9][0-9A-Za-z._-]*)/i,
    cves: [
      { id: 'CVE-2017-9722', fixed: '1.0.27', note: 'stack-based buffer overflow in getaddrinfo (verify applicability)', ref: 'https://nvd.nist.gov/vuln/detail/CVE-2017-9722' },
    ],
  },
  {
    component: 'musl',
    banner: /musl[- ]?libc[- ]?([0-9][0-9A-Za-z._-]*)/i,
    cves: [
      { id: 'CVE-2020-28928', fixed: '1.2.1', note: 'wcsnrtombs buffer overflow (DoS)', ref: 'https://nvd.nist.gov/vuln/detail/CVE-2020-28928' },
    ],
  },
];

export interface ComponentMatch {
  component: string;
  version?: string;
  cves: CveHint[];
}

/** Match known components + versions from a string list. */
export function matchComponents(
  entries: StringHit[],
  filter?: string[],
): ComponentMatch[] {
  const wanted = filter && filter.length > 0 ? new Set(filter.map((c) => c.toLowerCase())) : undefined;
  const matches = new Map<string, ComponentMatch>();
  for (const spec of COMPONENT_TABLE) {
    if (wanted && !wanted.has(spec.component.toLowerCase())) continue;
    for (const hit of entries) {
      const m = spec.banner.exec(hit.value);
      if (m) {
        const version = m[1];
        const existing = matches.get(spec.component);
        if (!existing || (!existing.version && version)) {
          matches.set(spec.component, {
            component: spec.component,
            ...(version ? { version } : {}),
            cves: spec.cves,
          });
        }
        break;
      }
    }
  }
  return [...matches.values()];
}
