#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
rm -rf fs_build fs_root
mkdir -p fs_build/bin fs_build/sbin fs_build/etc fs_build/root
printf '#!/bin/sh\necho hello\n' > fs_build/bin/init
printf '#!/bin/sh\necho sh\n' > fs_build/bin/sh
printf '#!/bin/sh\necho cat\n' > fs_build/bin/cat
chmod +x fs_build/bin/*
printf 'vinux 5.10.0\nbusybox 1.30.1\nsquashfs 4.0\n' > fs_build/etc/os-release
printf 'root::0:0:root:/root:/bin/sh\n' > fs_build/etc/passwd
tar cf sample_firmware_fs.tar -C fs_build .
printf 'ustar\x00test\ntest' > fs_build/header_dummy 2>/dev/null || true
cp fs_build/bin/init fs_root/init 2>/dev/null || true
cd fs_build && find . -type f | cpio -o -H newc > ../sample_firmware_fs.cpio 2>/dev/null || (cd . && printf 'test' > dummy)
cd ..
echo "Created:"
ls -la sample_firmware_fs.tar sample_firmware_fs.cpio 2>/dev/null || true
rm -rf fs_build fs_root
