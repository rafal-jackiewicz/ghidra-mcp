#!/usr/bin/env python3
"""Sample 3: a 64-byte raw ARM Cortex-M image (vector table + one tiny handler).
Raw firmware has no headers, so Ghidra must be told the processor and load address."""
import struct, sys
vectors = struct.pack("<8I", 0x20001000, 0x08000021, 0x08000021, 0x08000021, 0, 0, 0, 0)
handler = bytes.fromhex("00207047") * 8  # movs r0,#0 ; bx lr
open(sys.argv[1] if len(sys.argv) > 1 else "firmware.bin", "wb").write(vectors + handler)
