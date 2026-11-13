#!/bin/sh
# Copyright 2026 Rafał Jackiewicz
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

# Builds the Styx sample (an executable plus its dynamically linked library) for Linux and,
# when MinGW is installed, for Windows. Output: examples/build/styx/{linux,windows}/
set -e
cd "$(dirname "$0")"
OUT=../build/styx
mkdir -p "$OUT/linux" "$OUT/windows"
CFLAGS="-O1 -Wall -Wextra -fvisibility=hidden"

gcc $CFLAGS -fPIC -shared -s -o "$OUT/linux/libobol.so" original/obol.c
gcc $CFLAGS -s -o "$OUT/linux/ferryman" original/ferryman.c -L"$OUT/linux" -lobol -Wl,-rpath,'$ORIGIN'

if command -v x86_64-w64-mingw32-gcc >/dev/null; then
    x86_64-w64-mingw32-gcc $CFLAGS -shared -s -o "$OUT/windows/obol.dll" original/obol.c
    x86_64-w64-mingw32-gcc $CFLAGS -s -o "$OUT/windows/ferryman.exe" original/ferryman.c \
        -L"$OUT/windows" -lobol
else
    echo "x86_64-w64-mingw32-gcc not found; skipping the Windows build" >&2
fi
ls -l "$OUT/linux" "$OUT/windows"
