# LWRT packaging — the `.ipk` format and hosting a feed on GitHub

LWRT ships its own tiny package manager, `ipkg`, instead of opkg. The on-wire
formats are deliberately a strict, trivially-parseable subset of opkg's so the
client needs **no** ar / gzip / tar / TLS libraries — none are linked into the
static musl binary. This document is the end-to-end contract: the archive
format, the index format, how integrity is anchored, and how to publish a feed
straight from a GitHub repository.

---

## 1. The `.ipk` archive

An LWRT package is an **uncompressed POSIX `ustar` archive** named
`<pkg>_<version>_<arch>.ipk`. There is no outer `ar` wrapper and no gzip layer
(stock opkg `.ipk`s are `ar(control.tar.gz, data.tar.gz, debian-binary)` — LWRT
does not use that).

Rules the extractor (`src/ipkg.rs::extract_ustar`) enforces:

1. **The first member is `./control`** — the package metadata. It is read into
   memory and stored at `/var/ipkg/installed/<name>.control`; it is *never*
   written under `/`.
2. **Every other member is extracted relative to `/`.** A member named
   `./usr/bin/hello` installs to `/usr/bin/hello`. Leading `./` and `/` are
   stripped and any `..` component is dropped, so an archive cannot escape the
   root (`sanitize()` guarantees this — see the `sanitize_refuses_escapes`
   test).
3. Directory members (`ustar` typeflag `5`) are `mkdir -p`'d; regular files
   (typeflag `0` or NUL) are written, creating parent dirs as needed. Symlinks
   and device nodes are ignored for now.
4. The list of installed paths is recorded at
   `/var/ipkg/installed/<name>.list` so `ipkg remove` can delete exactly what
   was installed (it never removes `./control`).

### The `control` file

opkg-style `Key: value` lines, one stanza:

```
Package: hello
Version: 1.0
Architecture: mipsel_24kc
Maintainer: Irfan Mahir
Section: utils
Description: Minimal example LWRT package — prints a greeting.
```

Only `Package` is strictly required by the tooling; `Version`/`Architecture`
are conventional and feed into the `.ipk` filename.

---

## 2. The `Packages` index

A feed is a flat directory of `.ipk` files plus one `Packages` index: blank-
line-separated stanzas, one per package. `ipkg update` downloads it to
`/var/ipkg/Packages`; `ipkg list` prints it; `ipkg install <name>` looks the
name up in it.

```
Package: hello
Version: 1.0
Architecture: mipsel_24kc
Maintainer: Irfan Mahir
Section: utils
Description: Minimal example LWRT package — prints a greeting.
Filename: hello_1.0_mipsel_24kc.ipk
Size: 10240
SHA256sum: 5283b2b98955dfab04c2f2b4a0da8045b6ff17e2e6151486c77f04d7a123bcc9
```

The three fields the client verifies against:

| Field       | Meaning                                              |
|-------------|------------------------------------------------------|
| `Filename`  | path of the `.ipk` relative to the feed root URL     |
| `Size`      | exact byte length of the `.ipk`                      |
| `SHA256sum` | SHA-256 of the `.ipk` bytes (hex)                    |

---

## 3. Integrity model (read this before trusting a feed)

LWRT links no TLS, so packages are fetched over plain **HTTP/1.0**. Integrity
is therefore anchored in the *index*, not the transport:

- `ipkg install` **refuses** to install a package that is not in the index, and
  **refuses** any index entry that lacks a `SHA256sum`. It never guesses a URL.
- It checks `Size` first (cheap), then recomputes SHA-256 over the downloaded
  blob and compares it to `SHA256sum` (constant-work, case-insensitive). A
  mismatch aborts before anything is unpacked.
- This means **the index is the trust root.** Whoever controls the `Packages`
  file controls what gets installed. Today the index itself is fetched over
  HTTP, so a network attacker who can rewrite it can substitute packages.

`mkrepo.sh` also emits `Packages.sha256` (the digest of the index). A future
hardening step is an `ed25519`-signed index (a dedicated crypto module) so the
device can verify the feed root offline; the per-package SHA-256 chaining is
already in place to make that a single signature over the whole feed. Until
then, treat a feed as exactly as trustworthy as the channel you fetch the index
over — prefer serving it over a TLS-terminating proxy or pinning
`Packages.sha256` out of band.

---

## 4. Building a feed: `scripts/mkrepo.sh`

Lay out one directory per package under a feed root:

```
feed/
  hello/
    control            # the metadata stanza
    root/              # files to install, laid out relative to /
      usr/bin/hello
      etc/hello.conf
```

Then:

```sh
scripts/mkrepo.sh             # feed/ -> dist/
# or
scripts/mkrepo.sh path/to/feed path/to/out
LWRT_ARCH=mipsel_24kc scripts/mkrepo.sh   # override arch in filenames
```

It produces, in `dist/`:

- one `<pkg>_<ver>_<arch>.ipk` per package (control member first, payload
  relative to `/`),
- a `Packages` index with `Filename` / `Size` / `SHA256sum` filled in,
- `Packages.sha256`, the digest of the index.

The script needs only `tar` (ustar format) and one of
`sha256sum` / `shasum` / `openssl` — all present on a normal build host.

---

## 5. Hosting the feed on GitHub

Two equally-static options; pick by how big the feed is.

### Option A — GitHub Pages (good default)

1. Build the feed: `scripts/mkrepo.sh`.
2. Commit `dist/` to a `gh-pages` branch (or a `docs/feed/` dir on `main`) and
   enable Pages for that branch/dir.
3. Your feed root URL is then e.g.
   `https://<user>.github.io/<repo>/` (whatever directory holds `Packages`).
4. Point the device at it in `/etc/lwrt/config`:

   ```ini
   [ipkg]
   repo = http://<user>.github.io/<repo>
   ```

   > Note: `ipkg` speaks **HTTP only**. GitHub Pages is HTTPS-only and will
   > 301-redirect `http://` → `https://`, which the minimal client does not
   > follow. For a real device, front the Pages site with an HTTP-capable
   > mirror/proxy, or use Option B with an HTTP origin. The integrity model
   > above is what keeps plain-HTTP fetches safe-by-digest.

### Option B — GitHub Releases (good for large/binary feeds)

1. Build the feed.
2. `gh release create v1 dist/*.ipk dist/Packages dist/Packages.sha256`
3. The release assets get stable
   `https://github.com/<user>/<repo>/releases/download/v1/<file>` URLs.
4. Set `repo =` to that `…/download/v1` base (again, via an HTTP-capable mirror
   for on-device use).

### A note on architecture

The example arch string is `mipsel_24kc` (matches the build target). Keep one
feed per arch, or namespace the `Filename`s; the client does not itself filter
by `Architecture`, it installs whatever the index points it at.

---

## 6. End-to-end smoke test (on the build host)

```sh
scripts/mkrepo.sh
python3 -m http.server 8000 --directory dist &   # serve the feed over HTTP
# then, against a device or a test root with the lwrt binary:
ipkg update                    # pulls http://host:8000/Packages
ipkg list
ipkg install hello             # size + SHA-256 verified, then unpacked to /
ipkg remove hello              # deletes exactly the recorded file list
```

The unit tests in `src/ipkg.rs` cover the index parser
(`find_entry_pulls_the_right_stanza`) and the path-escape guard
(`sanitize_refuses_escapes`).
