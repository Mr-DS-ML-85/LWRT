#!/bin/sh
# Portable cross-build for LWRT. Locates the musl toolchain, wires the linker
# and STAGING_DIR via environment (so .cargo/config.toml stays machine-neutral),
# regenerates the libunwind shim, then builds the release binary.
#
# Override the toolchain location:   LWRT_TOOLCHAIN=/path/to/toolchain-... build.sh
# Override the OpenWrt tree:         LWRT_OPENWRT=/path/to/openwrt           build.sh
# Override the target triple:        LWRT_TARGET=mipsel-unknown-linux-musl   build.sh
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

TARGET="${LWRT_TARGET:-mipsel-unknown-linux-musl}"

# 1. Find the OpenWrt staging_dir (musl toolchain + sysroot).
OPENWRT="${LWRT_OPENWRT:-}"
if [ -z "$OPENWRT" ]; then
    for c in \
        "$HOME/openwrt" \
        "$HOME/Desktop/tools/mips-xip-kernel/openwrt" \
        "/opt/openwrt"; do
        [ -d "$c/staging_dir" ] && OPENWRT="$c" && break
    done
fi
[ -n "$OPENWRT" ] || { echo "ERROR: set LWRT_OPENWRT to your OpenWrt tree (with staging_dir)" >&2; exit 1; }

export STAGING_DIR="$OPENWRT/staging_dir"

# 2. Find the musl gcc wrapper.
TC="${LWRT_TOOLCHAIN:-}"
if [ -z "$TC" ]; then
    TC=$(find "$STAGING_DIR" -maxdepth 1 -type d -name 'toolchain-mipsel_24kc_*musl*' | head -n1)
fi
[ -n "$TC" ] || { echo "ERROR: set LWRT_TOOLCHAIN to your toolchain-mipsel_24kc_*musl dir" >&2; exit 1; }
GCC=$(find "$TC/bin" -name '*-linux-musl-gcc' | head -n1)
[ -x "$GCC" ] || { echo "ERROR: musl gcc not found under $TC/bin" >&2; exit 1; }

export CARGO_TARGET_MIPSEL_UNKNOWN_LINUX_MUSL_LINKER="$GCC"

# 3. Regenerate the libunwind shim (copy of libgcc_eh.a) if missing.
mkdir -p "$ROOT/vendor"
if [ ! -f "$ROOT/vendor/libunwind.a" ]; then
    EH=$(find "$TC" -name 'libgcc_eh.a' | head -n1)
    [ -n "$EH" ] || { echo "ERROR: libgcc_eh.a not found in toolchain" >&2; exit 1; }
    cp "$EH" "$ROOT/vendor/libunwind.a"
    echo "vendor/libunwind.a <- $EH"
fi

echo "toolchain: $GCC"
echo "staging:   $STAGING_DIR"
echo "target:    $TARGET"
echo

exec cargo +nightly build --release --target "$TARGET" "$@"
