#!/bin/sh
# mkrepo.sh — build an LWRT package feed: turn a tree of package sources into
# `.ipk` archives plus a signed-by-digest `Packages` index, ready to publish on
# GitHub Pages / Releases and consume with `ipkg update && ipkg install`.
#
# Layout of a package source (one dir per package under the feed root):
#
#   feed/
#     hello/
#       control          # opkg-style metadata (Package:, Version:, ...)
#       root/            # files to install, laid out relative to /
#         usr/bin/hello
#         etc/hello.conf
#
# Each `.ipk` is an UNCOMPRESSED POSIX ustar archive whose FIRST member is
# `./control` and whose remaining members are `./<path>` (extracted relative to
# / by the `ipkg` applet). The `Packages` index lists every package with its
# Filename, Size and SHA256sum — the same fields `ipkg install` verifies. There
# is no gzip and no ar wrapper: LWRT links no compression library on purpose.
#
#   scripts/mkrepo.sh [FEED_DIR] [OUT_DIR]
#     FEED_DIR  source tree of packages   (default: ./feed)
#     OUT_DIR   where .ipk + Packages land (default: ./dist)
#
# Override the package architecture string with LWRT_ARCH (default mipsel_24kc).
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
FEED="${1:-$ROOT/feed}"
OUT="${2:-$ROOT/dist}"
ARCH="${LWRT_ARCH:-mipsel_24kc}"

[ -d "$FEED" ] || { echo "mkrepo: no feed dir: $FEED" >&2; exit 1; }

# sha256 helper: prefer sha256sum, fall back to shasum / openssl.
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d' ' -f1
    else
        openssl dgst -sha256 "$1" | awk '{print $NF}'
    fi
}

# Read a single `Key:` value out of an opkg control file.
control_field() {
    # $1 = control file, $2 = key
    sed -n "s/^$2:[[:space:]]*//p" "$1" | head -n1
}

rm -rf "$OUT"
mkdir -p "$OUT"
INDEX="$OUT/Packages"
: > "$INDEX"

count=0
for pkgdir in "$FEED"/*/; do
    [ -d "$pkgdir" ] || continue
    name=$(basename "$pkgdir")
    ctrl="$pkgdir/control"
    [ -f "$ctrl" ] || { echo "mkrepo: $name: missing control" >&2; exit 1; }

    pkg=$(control_field "$ctrl" Package)
    ver=$(control_field "$ctrl" Version)
    [ -n "$pkg" ] || { echo "mkrepo: $name: control has no Package:" >&2; exit 1; }
    [ -n "$ver" ] || ver="0"

    ipk="${pkg}_${ver}_${ARCH}.ipk"
    out_ipk="$OUT/$ipk"

    # 1. control member first (ustar, uncompressed). `./control` is what the
    #    ipkg extractor captures as metadata instead of writing to disk.
    ( cd "$pkgdir" && tar --format=ustar --numeric-owner --owner=0 --group=0 \
        -cf "$out_ipk" ./control )

    # 2. append the payload, named relative to / (e.g. ./usr/bin/hello).
    if [ -d "$pkgdir/root" ]; then
        ( cd "$pkgdir/root" && tar --format=ustar --numeric-owner --owner=0 \
            --group=0 -rf "$out_ipk" . )
    fi

    size=$(wc -c < "$out_ipk" | tr -d ' ')
    sha=$(sha256_of "$out_ipk")

    # 3. index stanza: emit the control verbatim, then the fetch/verify fields.
    {
        cat "$ctrl"
        # ensure the stanza ends cleanly before our appended fields
        printf '\n'
        printf 'Filename: %s\n' "$ipk"
        printf 'Size: %s\n' "$size"
        printf 'SHA256sum: %s\n' "$sha"
        printf '\n'
    } >> "$INDEX"

    echo "packed $ipk  ($size bytes, sha256 ${sha%????????????????????????????????????????????????????????})"
    count=$((count + 1))
done

[ "$count" -gt 0 ] || { echo "mkrepo: feed had no packages" >&2; exit 1; }

# A digest of the index itself, so a client can pin/verify the feed root.
idx_sha=$(sha256_of "$INDEX")
echo "$idx_sha  Packages" > "$OUT/Packages.sha256"

echo
echo "feed ready: $OUT"
echo "  $count package(s), index $(wc -c < "$INDEX" | tr -d ' ') bytes"
echo "  Packages.sha256: $idx_sha"
echo
echo "Publish: commit $OUT/ to a gh-pages branch (or attach to a Release) and"
echo "point [ipkg] repo= at its raw URL. Then on the device:"
echo "  ipkg update && ipkg list && ipkg install <name>"
