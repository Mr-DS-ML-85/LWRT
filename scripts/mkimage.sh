#!/bin/sh
# Bake LWRT into the MIPS XIP kernel and emit a bootable execute-in-place image.
#
# Pipeline:
#   1. cross-build the LWRT multicall binary (scripts/build.sh)
#   2. stage the root filesystem            (scripts/mkrootfs.sh -> build/rootfs)
#   3. hand that rootfs to the XIP kernel as its CONFIG_INITRAMFS_SOURCE and
#      build the flash image                (kernel: make WORK=... image)
#
# The kernel tree stays generic: we pass the rootfs through $LWRT_ROOTFS, which
# its scripts/build-userspace.sh turns into a gen_init_cpio list.
#
# Override the XIP kernel tree:  LWRT_KERNEL=/path/to/mips-xip-kernel
# Override the kernel work dir:  LWRT_KWORK=/path/to/build   (reuses a built tree)
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

# 1. Locate the XIP kernel tree.
KERNEL="${LWRT_KERNEL:-}"
if [ -z "$KERNEL" ]; then
    for c in \
        "$HOME/mips-xip-kernel" \
        "$ROOT/../mips-xip-kernel" \
        "$ROOT/mips-xip-kernel"; do
        [ -f "$c/Makefile" ] && [ -d "$c/patches" ] && KERNEL=$(cd "$c" && pwd) && break
    done
fi
[ -n "$KERNEL" ] || { echo "ERROR: set LWRT_KERNEL to your mips-xip-kernel tree" >&2; exit 1; }

# 2. Pick the kernel work/build dir. Prefer an already-populated tree (with a
#    compiled vmlinux) so rebuilds are incremental; else use the kernel default.
KWORK="${LWRT_KWORK:-}"
if [ -z "$KWORK" ]; then
    for c in \
        "$ROOT/mips-xip-kernel/build" \
        "$KERNEL/build"; do
        [ -f "$c/linux-6.12.34/vmlinux" ] && KWORK="$c" && break
    done
    [ -n "$KWORK" ] || KWORK="$KERNEL/build"
fi

ROOTFS="$ROOT/build/rootfs"

echo "==> 1/3 building LWRT binary"
"$ROOT/scripts/build.sh"

echo "==> 2/3 staging rootfs"
"$ROOT/scripts/mkrootfs.sh" "$ROOTFS" >/dev/null
echo "rootfs: $ROOTFS"

# LWRT needs a richer kernel than the bare XIP boot-test config (procfs,
# devtmpfs, tmpfs, INET, bridge/VLAN, nftables/NAT). Default to the LWRT
# defconfig; override with LWRT_DEFCONFIG.
DEFCONFIG="${LWRT_DEFCONFIG:-lwrt_qemu_malta_defconfig}"

echo "==> 3/3 building XIP image"
echo "kernel:    $KERNEL"
echo "work:      $KWORK"
echo "defconfig: $DEFCONFIG"
LWRT_ROOTFS="$ROOTFS" DEFCONFIG="$DEFCONFIG" make -C "$KERNEL" WORK="$KWORK" image

OUT="$KWORK/out"
echo
echo "XIP image: $OUT/xip-bios.bin"
echo "boot it:   $KERNEL/scripts/run-qemu.sh $OUT/xip-bios.bin"
