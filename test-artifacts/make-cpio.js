// Build a cpio "newc-crc" archive in the exact layout the MIRAI parser expects:
//   0-6:     magic "070701" (6 ASCII chars)
//   6-110:   13 fields x 8 octal chars (only field 6=size and field 11=namesize are read)
//   110-210: name padded to 100 bytes
//   then:    file data, padded to a 4-byte boundary
import fs from 'node:fs';

const files = [
  { name: 'bin/init', data: '#!/bin/sh\necho hello\n' },
  { name: 'bin/sh', data: '#!/bin/sh\necho sh\n' },
  { name: 'bin/cat', data: '#!/bin/sh\necho cat\n' },
  { name: 'etc/os-release', data: 'vinux 5.10.0\nbusybox 1.30.1\nsquashfs 4.0\n' },
  { name: 'etc/passwd', data: 'root::0:0:root:/root:/bin/sh\n' },
];

function field8(n) {
  const num = typeof n === 'number' ? n : parseInt(n, 8);
  return Buffer.from(num.toString(8).padStart(8, '0'), 'ascii');
}

function ocat10(n) {
  const num = typeof n === 'number' ? n : parseInt(n, 8);
  return Buffer.from(num.toString(8).padStart(10, '0'), 'ascii');
}

const out = [];
for (const f of files) {
  const data = Buffer.from(f.data);
  const namesize = f.name.length;
  const alignedHeader = 110 + namesize; // header + name, rounded to 4 bytes
  const alignedData = ((data.length + 3) & ~3);
  out.push(Buffer.from('070701', 'ascii'));                    // magic
  out.push(Buffer.alloc(48));                                   // mode..gid  (fields 0-5)
  out.push(ocat10(data.length));                                // field 6 = size
  out.push(Buffer.alloc(40));                                   // mtime..devmajor (fields 7-11)
  out.push(field8(namesize));                                   // field 11 per parser = namesize
  out.push(Buffer.alloc(8));                                    // field 12
  out.push(Buffer.from(f.name.padEnd(100, '\0'), 'latin1'));    // name (100 bytes)
  out.push(Buffer.alloc(alignedHeader - 110 - namesize));       // header+name pad
  out.push(data);                                               // data
  out.push(Buffer.alloc(alignedData - alignedHeader + 110 + namesize - data.length)); // data pad
}
out.push(Buffer.from('TRAILER!!!\0\0\0'));

fs.writeFileSync('sample_firmware_fs.cpio', Buffer.concat(out));
console.log('Wrote cpio with', files.length, 'entries, size', out.reduce((a, b) => a + b.length, 0));
