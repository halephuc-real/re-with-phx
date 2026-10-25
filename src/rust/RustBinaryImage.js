import { BinaryFormatFailure, BinaryResourceFailure, } from "../native/metadata/BinaryContainer.js";
import { readBinaryContainer } from "../native/metadata/readBinaryContainer.js";
import { readAuditableSection, RustAuditableFormatFailure, RustAuditableResourceFailure, } from "./RustAuditableReader.js";
const RUSTC_PREFIX = Buffer.from("/rustc/");
const HASH_BYTES = 40;
/** One toolchain normally leaves one hash; a small cap bounds retained output. */
const MAX_RUSTC_HASHES = 64;
/** Read dependency metadata from container sections without executing the image. */
export const readRustBinaryImage = (bytes) => {
    const container = readContainer(bytes);
    const dependency = dependencySection(container.format, container.sections);
    return {
        format: container.format,
        architecture: container.architecture,
        bits: container.bits,
        byte_order: container.byte_order,
        auditable_metadata: dependency === null
            ? null
            : readDependency(bytes, container.format, dependency),
        rustc_commit: rustcCommit(bytes, container.sections),
    };
};
const readContainer = (bytes) => {
    try {
        return readBinaryContainer(bytes);
    }
    catch (cause) {
        if (cause instanceof BinaryFormatFailure)
            throw new RustAuditableFormatFailure(cause.kind, cause.message, {
                cause,
            });
        if (cause instanceof BinaryResourceFailure)
            throw new RustAuditableResourceFailure({
                resource: "memory",
                reported_limits: { maximum_bytes: cause.maximum_bytes },
            }, cause.message, {
                cause,
            });
        throw cause;
    }
};
const dependencySection = (format, sections) => {
    const expected = format === "macho" ? "__DATA,.dep-v0" : ".dep-v0";
    const matches = sections.filter((section) => section.name === expected);
    if (matches.length > 1)
        throw new RustAuditableFormatFailure("malformed", "Image contains more than one dependency section");
    const section = matches[0];
    if (section === undefined)
        return null;
    if (section.compressed)
        throw new RustAuditableFormatFailure("unsupported", "Compressed dependency sections are unsupported");
    if (!section.file_backed)
        throw new RustAuditableFormatFailure("malformed", "Dependency section is not file-backed");
    return section;
};
const readDependency = (bytes, format, section) => readAuditableSection(format === "macho" ? "__DATA,.dep-v0" : ".dep-v0", section.offset, bytes.subarray(section.offset, section.offset + section.size));
const rustcCommit = (bytes, sections) => {
    const hashes = [];
    const seen = new Set();
    // Overlapping declared sections are scanned once, so total work stays
    // bounded by the file size however many sections reference a range.
    for (const range of mergedReadOnlyRanges(sections))
        collectHashes(bytes, range, seen, hashes);
    return hashes.length === 0 ? null : { evidence_kind: "inferred", hashes };
};
const mergedReadOnlyRanges = (sections) => {
    const ranges = sections
        .filter((section) => section.read_only && section.size > 0)
        .map((section) => ({
        offset: section.offset,
        end: section.offset + section.size,
    }))
        .sort((left, right) => left.offset - right.offset);
    const merged = [];
    for (const range of ranges) {
        const last = merged.at(-1);
        if (last !== undefined && range.offset <= last.end)
            last.end = Math.max(last.end, range.end);
        else
            merged.push({ ...range });
    }
    return merged;
};
const collectHashes = (bytes, range, seen, hashes) => {
    const region = bytes.subarray(range.offset, range.end);
    let cursor = 0;
    while (cursor < region.length) {
        const at = region.indexOf(RUSTC_PREFIX, cursor);
        if (at < 0)
            return;
        const start = at + RUSTC_PREFIX.length;
        const hash = hashAt(region, start);
        if (hash !== null && !seen.has(hash)) {
            if (seen.size >= MAX_RUSTC_HASHES)
                throw new RustAuditableResourceFailure({
                    resource: "capacity",
                    reported_limits: { maximum_rustc_hashes: MAX_RUSTC_HASHES },
                }, `Read-only data contains more than ${MAX_RUSTC_HASHES} distinct rustc commit paths.`);
            seen.add(hash);
            hashes.push({ hash, file_offset: range.offset + at });
        }
        cursor = at + 1;
    }
};
const hashAt = (region, start) => {
    const end = start + HASH_BYTES;
    if (end >= region.length || region[end] !== 0x2f)
        return null;
    for (let index = start; index < end; index += 1) {
        const byte = region[index] ?? 0;
        const hex = (byte >= 0x30 && byte <= 0x39) || (byte >= 0x61 && byte <= 0x66);
        if (!hex)
            return null;
    }
    return region.toString("latin1", start, end);
};
