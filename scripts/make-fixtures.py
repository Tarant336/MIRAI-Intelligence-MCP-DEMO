"""Generate well-formed test archives for firmware_extract validation.

Creates:
  test-artifacts/valid-fs.cpio  - cpio "newc" with 3 known members
  test-artifacts/valid-fs.tar   - ustar tar with the same 3 members

Ground truth (member -> sha256 is printed at generation time):
  etc/passwd        = b"root:x:0:0:root:/root:/bin/sh\n"
  etc/init.d/rcS    = b"#!/bin/sh\\nmount -t proc none /proc\\n"
  bin/hello         = b"\\x7fELF" + b"\\x00" * 60
"""

import hashlib
import io
import os
import tarfile

OUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "test-artifacts")

MEMBERS = [
    ("etc/passwd", b"root:x:0:0:root:/root:/bin/sh\n", 0o100644),
    ("etc/init.d/rcS", b"#!/bin/sh\nmount -t proc none /proc\n", 0o100755),
    ("bin/hello", b"\x7fELF" + b"\x00" * 60, 0o100755),
]


def pad4(n: int) -> int:
    return (4 - (n % 4)) % 4


def newc_entry(name: str, data: bytes, mode: int, ino: int) -> bytes:
    name_bytes = name.encode() + b"\x00"
    fields = [
        ino,            # ino
        mode,           # mode
        0,              # uid
        0,              # gid
        1,              # nlink
        0x5F000000,     # mtime
        len(data),      # filesize
        0,              # devmajor
        0,              # devminor
        0,              # rdevmajor
        0,              # rdevminor
        len(name_bytes),  # namesize
        0,              # check
    ]
    header = b"070701" + b"".join(f"{f:08x}".encode() for f in fields)
    assert len(header) == 110, len(header)
    out = header + name_bytes
    out += b"\x00" * pad4(len(out))
    out += data
    out += b"\x00" * pad4(len(data))
    return out


def write_cpio(path: str) -> None:
    buf = io.BytesIO()
    for i, (name, data, mode) in enumerate(MEMBERS, start=1):
        buf.write(newc_entry(name, data, mode, i))
    buf.write(newc_entry("TRAILER!!!", b"", 0, 0))
    with open(path, "wb") as f:
        f.write(buf.getvalue())


def write_tar(path: str) -> None:
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as tar:
        for name, data, mode in MEMBERS:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = mode & 0o777
            info.mtime = 0
            tar.addfile(info, io.BytesIO(data))


if __name__ == "__main__":
    cpio_path = os.path.join(OUT_DIR, "valid-fs.cpio")
    tar_path = os.path.join(OUT_DIR, "valid-fs.tar")
    write_cpio(cpio_path)
    write_tar(tar_path)
    print("GROUND TRUTH")
    for name, data, _ in MEMBERS:
        print(f"  {name:20s} size={len(data):3d} sha256={hashlib.sha256(data).hexdigest()}")
    print(f"cpio: {cpio_path} bytes={os.path.getsize(cpio_path)}")
    print(f"tar : {tar_path} bytes={os.path.getsize(tar_path)}")