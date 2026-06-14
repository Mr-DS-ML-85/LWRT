#!/bin/sh
# Assemble the LWRT root filesystem around the single multicall binary and
# emit a gzipped cpio initramfs the kernel can embed (CONFIG_INITRAMFS_SOURCE)
# or load. Everything userspace is one ~0.6 MB static binary plus symlinks.
set -eu

HERE=$(cd "$(dirname "$0")/.." && pwd)
TARGET="${LWRT_TARGET:-mipsel-unknown-linux-musl}"
BIN="$HERE/target/$TARGET/release/lwrt"
OUT="${1:-$HERE/build/rootfs}"
CPIO="$HERE/build/lwrt-initramfs.cpio.gz"

[ -f "$BIN" ] || { echo "build the binary first: scripts/build.sh" >&2; exit 1; }

rm -rf "$OUT"
mkdir -p "$OUT"/sbin "$OUT"/bin "$OUT"/etc/lwrt "$OUT"/proc "$OUT"/sys \
         "$OUT"/dev "$OUT"/tmp "$OUT"/run "$OUT"/var/ipkg/installed

install -m 0755 "$BIN" "$OUT/sbin/lwrt"
cp "$HERE/rootfs/etc/lwrt/config" "$OUT/etc/lwrt/config"

# PID 1 and the busybox-style applet symlinks. /init is the kernel's default
# rdinit path; basename "init" makes the multicall binary run the init applet.
ln -sf /sbin/lwrt "$OUT/init"
ln -sf /sbin/lwrt "$OUT/sbin/init"
for a in ifup dhcp dns fw wg httpd ipkg ntp log ubus mtd sysupgrade; do
    ln -sf /sbin/lwrt "$OUT/bin/$a"
done

# A couple of device nodes for the very first instant before devtmpfs mounts.
[ -e "$OUT/dev/console" ] || mknod -m 600 "$OUT/dev/console" c 5 1 2>/dev/null || true
[ -e "$OUT/dev/null" ]    || mknod -m 666 "$OUT/dev/null"    c 1 3 2>/dev/null || true

mkdir -p "$(dirname "$CPIO")"
( cd "$OUT" && find . | cpio -o -H newc 2>/dev/null | gzip -9 ) > "$CPIO"

echo "rootfs:    $OUT"
echo "initramfs: $CPIO ($(wc -c < "$CPIO") bytes)"
echo
echo "Point the kernel at it with:"
echo "  CONFIG_INITRAMFS_SOURCE=\"$OUT\""
echo "or boot the .cpio.gz as an external initramfs."
