#!/usr/bin/env python3
"""Patch a PE file by RVA or byte pattern.

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


class PE:
    def __init__(self, data: bytes) -> None:
        self.data = data
        if data[:2] != b"MZ":
            raise ValueError("not a PE file: missing MZ header")
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe_offset : pe_offset + 4] != b"PE\0\0":
            raise ValueError("not a PE file: missing PE signature")
        coff = pe_offset + 4
        self.number_of_sections = struct.unpack_from("<H", data, coff + 2)[0]
        self.size_of_optional_header = struct.unpack_from("<H", data, coff + 16)[0]
        self.optional_header = coff + 20
        magic = struct.unpack_from("<H", data, self.optional_header)[0]
        if magic == 0x10B:
            self.is_64 = False
            self.image_base = struct.unpack_from("<I", data, self.optional_header + 28)[0]
        elif magic == 0x20B:
            self.is_64 = True
            self.image_base = struct.unpack_from("<Q", data, self.optional_header + 24)[0]
        else:
            raise ValueError(f"unsupported optional header magic: 0x{magic:X}")
        self.size_of_headers = struct.unpack_from("<I", data, self.optional_header + 60)[0]
        self.section_table = self.optional_header + self.size_of_optional_header
        self.sections: list[dict[str, int]] = []
        for index in range(self.number_of_sections):
            offset = self.section_table + index * 40
            name = data[offset : offset + 8].rstrip(b"\0").decode("ascii", "replace")
            virtual_size = struct.unpack_from("<I", data, offset + 8)[0]
            virtual_address = struct.unpack_from("<I", data, offset + 12)[0]
            size_of_raw_data = struct.unpack_from("<I", data, offset + 16)[0]
            pointer_to_raw_data = struct.unpack_from("<I", data, offset + 20)[0]
            self.sections.append(
                {
                    "name": name,
                    "virtual_size": virtual_size,
                    "virtual_address": virtual_address,
                    "size_of_raw_data": size_of_raw_data,
                    "pointer_to_raw_data": pointer_to_raw_data,
                }
            )

    def rva_to_offset(self, rva: int) -> int:
        if rva < self.size_of_headers:
            return rva
        for section in self.sections:
            span = max(section["virtual_size"], section["size_of_raw_data"])
            start = section["virtual_address"]
            if start <= rva < start + span:
                delta = rva - start
                if delta >= section["size_of_raw_data"]:
                    raise ValueError(
                        f"RVA 0x{rva:X} is in virtual-only space of section "
                        f"{section['name']!r}"
                    )
                return section["pointer_to_raw_data"] + delta
        raise ValueError(f"RVA 0x{rva:X} does not map to any section")

    def describe(self, offset: int) -> str:
        for section in self.sections:
            start = section["pointer_to_raw_data"]
            size = section["size_of_raw_data"]
            if start <= offset < start + size:
                rva = section["virtual_address"] + (offset - start)
                return f"section={section['name']} rva=0x{rva:X} va=0x{self.image_base + rva:X}"
        return "offset outside section data"


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
    mode.add_argument("--rva", type=lambda value: int(value, 0))
    mode.add_argument("--offset", type=lambda value: int(value, 0))
    mode.add_argument("--pattern")
    parser.add_argument("--bytes", dest="patch", required=True)
    parser.add_argument("--expected")
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--in-place", action="store_true")
    args = parser.parse_args()

    original = args.target.read_bytes()
    pe = PE(original)
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
    elif args.rva is not None:
        offset = pe.rva_to_offset(args.rva)
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
    print(f"offset:  0x{offset:X} ({pe.describe(offset)})")
    print(f"patch:   {patch.hex(' ')}")
    print(f"sha256:  {sha256(original)} -> {sha256(bytes(data))}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
