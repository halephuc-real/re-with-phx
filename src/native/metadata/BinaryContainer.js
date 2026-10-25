/** Distinguish corrupt recognized binaries from containers outside parser coverage. */
export class BinaryFormatFailure extends Error {
    kind;
    constructor(kind, message) {
        super(message);
        this.kind = kind;
        this.name = "BinaryFormatFailure";
    }
}
/** Resource boundary exceeded while decoding metadata or native container structure. */
export class BinaryResourceFailure extends Error {
    boundary;
    maximum_bytes;
    constructor(boundary, maximum_bytes, message) {
        super(message);
        this.boundary = boundary;
        this.maximum_bytes = maximum_bytes;
        this.name = "BinaryResourceFailure";
    }
}
/** Reader that checks every structural range before decoding numeric fields. */
export class BinaryReader {
    bytes;
    little;
    constructor(bytes, little) {
        this.bytes = bytes;
        this.little = little;
    }
    range(offset, size, label) {
        if (!Number.isSafeInteger(offset) ||
            !Number.isSafeInteger(size) ||
            offset < 0 ||
            size < 0 ||
            offset > this.bytes.length ||
            size > this.bytes.length - offset)
            throw new BinaryFormatFailure("malformed", `${label} range is truncated or outside the file`);
        return this.bytes.subarray(offset, offset + size);
    }
    u16(offset) {
        const value = this.range(offset, 2, "16-bit field");
        return this.little ? value.readUInt16LE() : value.readUInt16BE();
    }
    u32(offset) {
        const value = this.range(offset, 4, "32-bit field");
        return this.little ? value.readUInt32LE() : value.readUInt32BE();
    }
    word(offset, bits) {
        if (bits === 32)
            return BigInt(this.u32(offset));
        const value = this.range(offset, 8, "64-bit field");
        return this.little ? value.readBigUInt64LE() : value.readBigUInt64BE();
    }
    fileRange(offset, size, label) {
        if (offset > BigInt(this.bytes.length) ||
            size > BigInt(this.bytes.length) - offset)
            throw new BinaryFormatFailure("malformed", `${label} range is outside the file`);
        const result = { address: 0n, offset: Number(offset), size: Number(size) };
        this.range(result.offset, result.size, label);
        return result;
    }
    table(offset, count, width, label) {
        const size = BigInt(count) * BigInt(width);
        if (size > 16n * 1024n * 1024n)
            throw new BinaryResourceFailure("structure", 16 * 1024 * 1024, `${label} exceeds the 16 MiB structural decoding budget`);
        return this.fileRange(offset, size, label).offset;
    }
}
/** Admit a declared file span, or mark it unbacked when it leaves the file. */
export const declaredFileRange = (fileBytes, offset, size) => {
    if (offset < 0n ||
        size < 0n ||
        offset > BigInt(Number.MAX_SAFE_INTEGER) ||
        size > BigInt(Number.MAX_SAFE_INTEGER) ||
        offset > BigInt(fileBytes) ||
        size > BigInt(fileBytes) - offset)
        return { offset: 0, size: 0, file_backed: false };
    return {
        offset: Number(offset),
        size: Number(size),
        file_backed: size > 0n,
    };
};
/** Map a virtual span without losing precision or selecting an ambiguous alias. */
export const mappedFileOffset = (mappings, address, size, zeroFills = []) => {
    let found;
    for (const mapping of mappings) {
        const delta = address - mapping.address;
        if (delta < 0n ||
            delta > BigInt(mapping.size) ||
            BigInt(size) > BigInt(mapping.size) - delta)
            continue;
        const offset = mapping.offset + Number(delta);
        if (found !== undefined && found !== offset)
            throw new BinaryFormatFailure("malformed", "Virtual address has ambiguous file mappings");
        found = offset;
    }
    if (found === undefined)
        throw new BinaryFormatFailure("malformed", "Virtual address or string range is not file mapped");
    for (const zeroFill of zeroFills) {
        if (spansOverlap(address, BigInt(size), zeroFill.address, zeroFill.size))
            throw new BinaryFormatFailure("malformed", "Virtual address has ambiguous file and zero-fill mappings");
    }
    const end = address + BigInt(size);
    for (const mapping of mappings) {
        const start = address > mapping.address ? address : mapping.address;
        const mappingEnd = mapping.address + BigInt(mapping.size);
        const overlapEnd = end < mappingEnd ? end : mappingEnd;
        if (start >= overlapEnd)
            continue;
        if (BigInt(found) + start - address !==
            BigInt(mapping.offset) + start - mapping.address)
            throw new BinaryFormatFailure("malformed", "Virtual address has ambiguous file mappings");
    }
    return found;
};
/** Recognize a wholly zero-filled span while refusing even partial file aliases. */
export const isZeroFilledSpan = (mappings, zeroFills, address, size) => {
    const bytes = BigInt(size);
    if (!zeroFills.some((mapping) => address >= mapping.address &&
        address + bytes <= mapping.address + mapping.size))
        return false;
    for (const mapping of mappings) {
        if (spansOverlap(address, bytes, mapping.address, BigInt(mapping.size)))
            throw new BinaryFormatFailure("malformed", "Virtual address has ambiguous file and zero-fill mappings");
    }
    return true;
};
const spansOverlap = (address, size, otherAddress, otherSize) => size > 0n &&
    otherSize > 0n &&
    address < otherAddress + otherSize &&
    otherAddress < address + size;
