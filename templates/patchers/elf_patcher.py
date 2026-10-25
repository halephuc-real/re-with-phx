#!/usr/bin/env python3
"""Patch an ELF file by file offset, virtual address, or byte pattern.

Dependency-free. Always writes a separate output file unless --in-place is
explicitly requested.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import struct
import sys
from pathlib import Path


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_hex_bytes(value: str) -> bytes:
    compact = re.sub(r"[\s,]", "", value)
    if len(compact) % 2 != 0:
        raise ValueError("hex byte string must contain an even number of digits")
    return bytes.fromhex(compact)


def parse_pattern(value: str) -> tuple[list[int], list[bool]]:
    tokens = re.split(r"[\s,]+", value.strip())
    values: list[int] = []
    mask: list[bool] = []
    for token in tokens:
        if token in {"?", "??", "**"}:
            values.append(0)
            mask.append(False)
            continue
        if len(token) != 2:
            raise ValueError(f"invalid pattern token: {token!r}")
        values.append(int(token, 16))
        mask.append(True)
    if not values:
        raise ValueError("empty pattern")
    return values, mask


def find_pattern(data: bytes, values: list[int], mask: list[bool]) -> list[int]:
    hits: list[int] = []
    size = len(values)
    for offset in range(0, len(data) - size + 1):
        if all(not mask[i] or data[offset + i] == values[i] for i in range(size)):
            hits.append(offset)
    return hits


class ELF:
    def __init__(self, data: bytes) -> None:
        self.data = data
        if data[:4] != b"\x7fELF":
            raise ValueError("not an ELF file")
        self.is_64 = data[4] == 2
        self.endian = "<" if data[5] == 1 else ">"
        if self.is_64:
            self.phoff = struct.unpack_from(self.endian + "Q", data, 32)[0]
            self.phentsize = struct.unpack_from(self.endian + "H", data, 54)[0]
            self.phnum = struct.unpack_from(self.endian + "H", data, 56)[0]
        else:
            self.phoff = struct.unpack_from(self.endian + "I", data, 28)[0]
            self.phentsize = struct.unpack_from(self.endian + "H", data, 42)[0]
            self.phnum = struct.unpack_from(self.endian + "H", data, 44)[0]
        self.segments: list[dict[str, int]] = []
        for index in range(self.phnum):
            offset = self.phoff + index * self.phentsize
            if self.is_64:
                p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from(
                    self.endian + "IIQQQQQQ", data, offset
                )
            else:
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack_from(
                    self.endian + "IIIIIIII", data, offset
                )
            self.segments.append(
                {
                    "type": p_type,
                    "flags": p_flags,
                    "offset": p_offset,
                    "vaddr": p_vaddr,
                    "filesz": p_filesz,
                    "memsz": p_memsz,
                    "align": p_align,
                }
            )

    def vaddr_to_offset(self, vaddr: int) -> int:
        loads = [segment for segment in self.segments if segment["type"] == 1]
        for segment in loads:
            start = segment["vaddr"]
            if start <= vaddr < start + segment["filesz"]:
                return segment["offset"] + (vaddr - start)
        for segment in self.segments:
            start = segment["vaddr"]
            if start <= vaddr < start + segment["filesz"]:
                return segment["offset"] + (vaddr - start)
        raise ValueError(f"virtual address 0x{vaddr:X} does not map to file data")

    def describe(self, offset: int) -> str:
        for segment in self.segments:
            start = segment["offset"]
            if start <= offset < start + segment["filesz"]:
                vaddr = segment["vaddr"] + (offset - start)
                return f"segment_type=0x{segment['type']:X} vaddr=0x{vaddr:X}"
        return "offset outside segment data"


def apply_patch(
    data: bytearray,
    offset: int,
    patch: bytes,
    expected: bytes | None,
) -> None:
    end = offset + len(patch)
    if end > len(data):
        raise ValueError("patch extends past end of file")
    if expected is not None:
        actual = bytes(data[offset:end])
        if actual != expected:
            raise ValueError(
                f"expected bytes do not match at 0x{offset:X}: "
                f"actual={actual.hex(' ')} expected={expected.hex(' ')}"
            )
    data[offset:end] = patch


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", type=Path)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--offset", type=lambda value: int(value, 0))
    mode.add_argument("--vaddr", type=lambda value: int(value, 0))
    mode.add_argument("--pattern")
    parser.add_argument("--bytes", dest="patch", required=True)
    parser.add_argument("--expected")
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--in-place", action="store_true")
    args = parser.parse_args()

    original = args.target.read_bytes()
    elf = ELF(original)
    data = bytearray(original)
    patch = parse_hex_bytes(args.patch)
    expected = parse_hex_bytes(args.expected) if args.expected else None

    if args.pattern:
        values, mask = parse_pattern(args.pattern)
        hits = find_pattern(original, values, mask)
        if not hits:
            raise SystemExit("pattern not found")
        if len(hits) > 1:
            joined = ", ".join(f"0x{hit:X}" for hit in hits[:20])
            raise SystemExit(f"pattern matched {len(hits)} locations: {joined}")
        offset = hits[0]
    elif args.vaddr is not None:
        offset = elf.vaddr_to_offset(args.vaddr)
    else:
        offset = args.offset

    apply_patch(data, offset, patch, expected)

    if args.in_place:
        output = args.target
    else:
        output = args.output or args.target.with_name(args.target.stem + ".patched" + args.target.suffix)
    output.write_bytes(data)

    print(f"target:  {args.target}")
    print(f"output:  {output}")
    print(f"offset:  0x{offset:X} ({elf.describe(offset)})")
    print(f"patch:   {patch.hex(' ')}")
    print(f"sha256:  {sha256(original)} -> {sha256(bytes(data))}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
