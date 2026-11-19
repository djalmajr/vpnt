#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
repo=$(git -C "$script_dir" rev-parse --show-toplevel)

if [[ -n $(git -C "$repo" status --porcelain) ]]; then
    printf '%s\n' 'Working tree has local changes. The source archive uses HEAD.' >&2
fi

version=$(git -C "$repo" show HEAD:Cargo.toml | awk -F '"' '
    /^\[package\]$/ { package = 1; next }
    /^\[/ { package = 0 }
    package && /^version[[:space:]]*=/ { print $2 }
')
recipe_version=$(awk -F= '$1 == "pkgver" { print $2 }' "$script_dir/PKGBUILD")
if [[ -z $version || $version != "$recipe_version" ]]; then
    printf 'Version mismatch: HEAD Cargo.toml=%s, PKGBUILD=%s\n' "$version" "$recipe_version" >&2
    exit 1
fi

for asset in packaging/linux/vpnt.desktop packaging/linux/vpnt.svg; do
    if ! git -C "$repo" cat-file -e "HEAD:$asset"; then
        printf 'Required package asset is missing from HEAD: %s\n' "$asset" >&2
        exit 1
    fi
done

cd -- "$script_dir"
archive="vpnt-$version.tar.gz"
temporary=$(mktemp -- "vpnt-$version.XXXXXX.tar.gz")
trap 'rm -f -- "$temporary"' EXIT
git -C "$repo" archive --format=tar.gz --prefix="vpnt-$version/" --output="$script_dir/$temporary" HEAD
mv -f -- "$temporary" "$archive"
trap - EXIT

makepkg -f -d --noconfirm
