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
./styx/build.sh
