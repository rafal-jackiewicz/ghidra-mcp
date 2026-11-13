#!/usr/bin/env python3
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

"""Sample 3: a 64-byte raw ARM Cortex-M image (vector table + one tiny handler).
Raw firmware has no headers, so Ghidra must be told the processor and load address."""
import struct, sys
vectors = struct.pack("<8I", 0x20001000, 0x08000021, 0x08000021, 0x08000021, 0, 0, 0, 0)
handler = bytes.fromhex("00207047") * 8  # movs r0,#0 ; bx lr
open(sys.argv[1] if len(sys.argv) > 1 else "firmware.bin", "wb").write(vectors + handler)
