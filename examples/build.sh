#!/bin/sh
# Builds the sample binaries used in the documentation into examples/build/.
set -e
cd "$(dirname "$0")"
mkdir -p build
gcc -O0 -o build/crackme crackme.c
# Windows sample: needs MinGW (Debian: apt install gcc-mingw-w64-x86-64). Stripped on purpose.
if command -v x86_64-w64-mingw32-gcc >/dev/null; then
    x86_64-w64-mingw32-gcc -O1 -s -o build/invoicer.exe invoicer.c
else
    echo "x86_64-w64-mingw32-gcc not found; skipping invoicer.exe" >&2
fi
python3 make_firmware.py build/firmware.bin
ls -l build
