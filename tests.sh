#!/bin/bash
set -xe

cargo build
for cfile in tests/fixtures/*.c; do
	dir=$(dirname "$cfile")
	base=$(basename "$cfile" .c)
	gcc -O3 -o "$dir/${base}.out" "$dir/${base}.c"
done

# for assembly files, the assumption is that they run without dynamic linker
for cfile in tests/fixtures/*.S; do
	dir=$(dirname "$cfile")
	base=$(basename "$cfile" .S)
	gcc -nostdlib -nostartfiles -static -Wl,--no-dynamic-linker,--fatal-warnings -o "$dir/${base}.out" "$dir/${base}.S"
done

umask 0077
python3 -m unittest discover -s tests/ "$@"
