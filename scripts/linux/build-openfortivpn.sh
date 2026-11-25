#!/usr/bin/env bash
# Build openfortivpn 1.24.1 with the vpnt patches, outside the package, so CI
# and local checks exercise the same client that packaging/arch/PKGBUILD ships.
#
# usage: scripts/linux/build-openfortivpn.sh <work-dir> [<source-tarball>]
#
# Prints the path of the prepared source tree on the last line; the client is
# <tree>/openfortivpn. Without <source-tarball> it downloads the pinned release.
# Exits non-zero when the digest, a patch or the build fails.
set -euo pipefail

version=1.24.1
digest=c40d33acd97b89c2e943bfd839c19b69e5a7a5997052e2fc9a595602745c0465
url="https://github.com/adrienverge/openfortivpn/archive/refs/tags/v$version.tar.gz"

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "usage: $0 <work-dir> [<source-tarball>]" >&2
  exit 2
fi

repo=$(cd -- "$(dirname -- "$0")/../.." && pwd)
work=$1
mkdir -p -- "$work"
work=$(cd -- "$work" && pwd)
tarball=${2:-$work/openfortivpn-$version.tar.gz}

if [ ! -f "$tarball" ]; then
  curl -fsSL --retry 3 -o "$tarball" "$url"
fi
echo "$digest  $tarball" | sha256sum -c - >&2

tree=$work/openfortivpn-$version
rm -rf -- "$tree"
tar -xzf "$tarball" -C "$work"

# Same order as packaging/arch/PKGBUILD: the five patches shared with macOS,
# then the Linux ones. Linux patches that a branch does not carry yet are
# skipped, so this script works before and after they land.
patches=(
  scripts/macos/patches/openfortivpn-no-routes.patch
  scripts/macos/patches/openfortivpn-bound-transport.patch
  scripts/macos/patches/openfortivpn-ppp-supervisor.patch
  scripts/macos/patches/openfortivpn-split-routes.patch
  scripts/macos/patches/openfortivpn-split-dns.patch
  packaging/linux/patches/openfortivpn-require-pin.patch
  packaging/linux/patches/openfortivpn-defer-password.patch
  packaging/linux/patches/openfortivpn-local-cidr.patch
)
cd -- "$tree"
for patch_file in "${patches[@]}"; do
  case $patch_file in
    packaging/linux/*) [ -f "$repo/$patch_file" ] || { echo "skip $patch_file (absent)" >&2; continue; } ;;
  esac
  echo "patch $patch_file" >&2
  patch -s -t -p1 --forward --no-backup-if-mismatch -i "$repo/$patch_file"
done
leftovers=$(find . \( -name '*.rej' -o -name '*.orig' \) -print)
if [ -n "$leftovers" ]; then
  printf 'unexpected patch artifacts:\n%s\n' "$leftovers" >&2
  exit 1
fi

sh ./autogen.sh >&2
./configure --prefix=/usr --with-pppd=/usr/sbin/pppd --with-resolvconf=DISABLED \
  --with-systemdsystemunitdir=no --enable-legacy-pppd >&2
make -j"$(nproc)" >&2
test -x "$tree/openfortivpn"
echo "$tree"
