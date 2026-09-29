#!/bin/bash
set -x

elf="$1"
rootdir="$2"
ldd "$elf" | sed 's/\(\s*\).*=>\s*/\1/g' | awk '{print $1}' | (while read line; do
    target="$rootdir/$line"
    mkdir -p "$(dirname "$target")"
    cp "$line" "$target"
done)

mkdir -p "$rootdir"
cp "$elf" "$rootdir/executable"
