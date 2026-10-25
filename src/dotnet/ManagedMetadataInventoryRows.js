import { managedDecodeBudget } from "./ManagedDecodeBudget.js";
import { memberDeclaringTypeRowLookup } from "./ManagedMemberOwnership.js";
import { metadataRowOffset, } from "./ManagedMetadataLayout.js";
import { metadataRowCursor, metadataCodedToken, metadataCodedTokenInvalidReason, metadataToken, readMetadataBlob, readMetadataGuid, readMetadataString, } from "./ManagedMetadataHeaps.js";
import { managedFailure, readManagedValue } from "./ManagedReaderFailure.js";
const HAS_CUSTOM_ATTRIBUTE_TABLES = [
    6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44,
    43,
];
const CUSTOM_ATTRIBUTE_TYPE_TABLES = [undefined, undefined, 6, 10];
const publicKeyIdentity = (bytes, kind, layout) => ({
    kind: bytes.length === 0 ? "none" : kind,
    byte_length: bytes.length,
    sha256: bytes.length === 0
        ? null
        : managedDecodeBudget(layout).digest(bytes, "sha256"),
    token: bytes.length === 0
        ? null
        : kind === "public-key"
            ? Buffer.from(managedDecodeBudget(layout).digest(bytes, "sha1"), "hex")
                .subarray(-8)
                .reverse()
                .toString("hex")
            : bytes.length === 8
                ? bytes.toString("hex")
                : null,
});
export const readModule = (bytes, layout, heapExtent) => {
    const table = layout.table(0);
    if (table === undefined || table.rowCount === 0)
        return null;
    const cursor = metadataRowCursor(bytes, layout, 0, 1);
    const generation = cursor.readUInt16();
    const name = readMetadataString(bytes, layout, cursor.readIndex(layout.stringIndexSize), heapExtent);
    const mvid = readMetadataGuid(bytes, layout, cursor.readIndex(layout.guidIndexSize));
    const encId = readMetadataGuid(bytes, layout, cursor.readIndex(layout.guidIndexSize));
    const encBaseId = readMetadataGuid(bytes, layout, cursor.readIndex(layout.guidIndexSize));
    return {
        name,
        generation,
        mvid,
        enc_id: encId,
        enc_base_id: encBaseId,
        token: metadataToken(0, 1),
        row_offset: table.offset,
    };
};
export const readAssembly = (bytes, layout, heapExtent) => {
    const table = layout.table(32);
    if (table === undefined || table.rowCount === 0)
        return null;
    const cursor = metadataRowCursor(bytes, layout, 32, 1);
    const hashAlgorithm = cursor.readUInt32();
    const version = [
        cursor.readUInt16(),
        cursor.readUInt16(),
        cursor.readUInt16(),
        cursor.readUInt16(),
    ].join(".");
    const flags = cursor.readUInt32();
    const key = readMetadataBlob(bytes, layout, cursor.readIndex(layout.blobIndexSize), heapExtent);
    const name = readMetadataString(bytes, layout, cursor.readIndex(layout.stringIndexSize), heapExtent);
    const culture = readMetadataString(bytes, layout, cursor.readIndex(layout.stringIndexSize), heapExtent);
    return {
        name,
        version,
        culture: culture.length === 0 ? null : culture,
        flags,
        hash_algorithm: hashAlgorithm,
        public_key: publicKeyIdentity(key, (flags & 1) === 0 ? "public-key-token" : "public-key", layout),
        token: metadataToken(32, 1),
        row_offset: table.offset,
    };
};
/** One owner for the shared AssemblyRef prefix and column indexes. */
const assemblyReferenceHeader = (bytes, layout, row) => {
    const cursor = metadataRowCursor(bytes, layout, 35, row);
    const version = [
        cursor.readUInt16(),
        cursor.readUInt16(),
        cursor.readUInt16(),
        cursor.readUInt16(),
    ].join(".");
    return {
        cursor,
        version,
        flags: cursor.readUInt32(),
        keyIndex: cursor.readIndex(layout.blobIndexSize),
        nameIndex: cursor.readIndex(layout.stringIndexSize),
    };
};
/** Name/token facts do not require decoding or hashing unrelated key/hash payloads. */
export const readAssemblyReferenceName = (bytes, layout, row, heapExtent) => {
    const { nameIndex } = assemblyReferenceHeader(bytes, layout, row);
    return {
        name: readMetadataString(bytes, layout, nameIndex, heapExtent),
        token: metadataToken(35, row),
        row_offset: metadataRowOffset(layout, 35, row),
    };
};
export const readAssemblyReference = (bytes, layout, row, heapExtent) => {
    const { cursor, version, flags, keyIndex, nameIndex } = assemblyReferenceHeader(bytes, layout, row);
    const keyOrToken = readMetadataBlob(bytes, layout, keyIndex, heapExtent);
    const name = readMetadataString(bytes, layout, nameIndex, heapExtent);
    const culture = readMetadataString(bytes, layout, cursor.readIndex(layout.stringIndexSize), heapExtent);
    const hashValue = readMetadataBlob(bytes, layout, cursor.readIndex(layout.blobIndexSize), heapExtent);
    return {
        name,
        version,
        culture: culture.length === 0 ? null : culture,
        flags,
        public_key_or_token: publicKeyIdentity(keyOrToken, (flags & 1) === 0 ? "public-key-token" : "public-key", layout),
        hash_value_sha256: hashValue.length === 0
            ? null
            : managedDecodeBudget(layout).digest(hashValue, "sha256"),
        hash_value_length: hashValue.length,
        token: metadataToken(35, row),
        row_offset: metadataRowOffset(layout, 35, row),
    };
};
const readTypeName = ({ bytes, layout, table, row, heapExtent, }) => {
    const descriptor = layout.table(table);
    if (descriptor === undefined || row < 1 || row > descriptor.rowCount)
        return null;
    const cursor = metadataRowCursor(bytes, layout, table, row);
    if (table === 1)
        cursor.readIndex(layout.codedIndexSize("ResolutionScope"));
    else
        cursor.readUInt32();
    const name = readMetadataString(bytes, layout, cursor.readIndex(layout.stringIndexSize), heapExtent);
    const namespace = readMetadataString(bytes, layout, cursor.readIndex(layout.stringIndexSize), heapExtent);
    return namespace.length === 0 ? name : `${namespace}.${name}`;
};
const declaringTypeForMethod = (bytes, layout, methodRow, heapExtent, memberLists) => {
    const owner = memberDeclaringTypeRowLookup(bytes, layout, 6, memberLists)(methodRow);
    if (owner === 0)
        return null;
    return readTypeName({ bytes, layout, table: 2, row: owner, heapExtent });
};
const attributeTypeName = (bytes, layout, rawType, heapExtent, memberLists) => {
    const tag = rawType & 7;
    const row = Math.floor(rawType / 8);
    if (row === 0)
        return null;
    if (tag === 2)
        return declaringTypeForMethod(bytes, layout, row, heapExtent, memberLists);
    if (tag !== 3)
        return null;
    const memberRefs = layout.table(10);
    if (memberRefs === undefined || row > memberRefs.rowCount)
        return null;
    const cursor = metadataRowCursor(bytes, layout, 10, row);
    const parent = cursor.readIndex(layout.codedIndexSize("MemberRefParent"));
    const parentTag = parent & 7;
    const parentRow = Math.floor(parent / 8);
    if (parentTag === 0)
        return readTypeName({
            bytes,
            layout,
            table: 2,
            row: parentRow,
            heapExtent,
        });
    if (parentTag === 1)
        return readTypeName({
            bytes,
            layout,
            table: 1,
            row: parentRow,
            heapExtent,
        });
    if (parentTag === 3)
        return declaringTypeForMethod(bytes, layout, parentRow, heapExtent, memberLists);
    return null;
};
const decodeCompressedLength = (blob, offset) => {
    const first = blob[offset];
    if (first === undefined)
        return undefined;
    if ((first & 0x80) === 0)
        return { length: first, prefix: 1 };
    if ((first & 0xc0) === 0x80 && blob[offset + 1] !== undefined)
        return {
            length: ((first & 0x3f) << 8) | (blob[offset + 1] ?? 0),
            prefix: 2,
        };
    if ((first & 0xe0) === 0xc0 &&
        blob[offset + 1] !== undefined &&
        blob[offset + 2] !== undefined &&
        blob[offset + 3] !== undefined)
        return {
            length: (first & 0x1f) * 16777216 +
                (blob[offset + 1] ?? 0) * 65536 +
                (blob[offset + 2] ?? 0) * 0x0100 +
                (blob[offset + 3] ?? 0),
            prefix: 4,
        };
    return undefined;
};
const decodeFixedString = (blob, layout) => {
    if (blob.length < 3 || blob.readUInt16LE(0) !== 1 || blob[2] === 0xff)
        return null;
    const length = decodeCompressedLength(blob, 2);
    if (length === undefined)
        return null;
    const start = 2 + length.prefix;
    if (start > blob.length - length.length)
        return null;
    managedDecodeBudget(layout).reserveString(length.length, layout.blob.offset);
    try {
        return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(blob.subarray(start, start + length.length));
    }
    catch (cause) {
        // Invalid UTF-8 blobs decode as null.
        void cause;
        return null;
    }
};
export const readCustomAttribute = (bytes, layout, row, heapExtent, issues, memberLists) => {
    const cursor = metadataRowCursor(bytes, layout, 12, row);
    const parentRaw = cursor.readIndex(layout.codedIndexSize("HasCustomAttribute"));
    const typeOffset = cursor.offset;
    const typeRaw = cursor.readIndex(layout.codedIndexSize("CustomAttributeType"));
    const value = readMetadataBlob(bytes, layout, cursor.readIndex(layout.blobIndexSize), heapExtent);
    const parent = metadataCodedToken(parentRaw, 5, HAS_CUSTOM_ATTRIBUTE_TABLES, layout.rowCounts);
    if (parent === null) {
        const parentReason = metadataCodedTokenInvalidReason(parentRaw, 5, HAS_CUSTOM_ATTRIBUTE_TABLES, layout.rowCounts);
        throw managedFailure("invalid-row", `metadata.CustomAttribute:${metadataToken(12, row)}`, `CustomAttribute parent coded index 0x${parentRaw.toString(16)} is invalid${parentReason === null ? " because the required parent is null" : `: ${parentReason}`}`, cursor.start);
    }
    const constructor = metadataCodedToken(typeRaw, 3, CUSTOM_ATTRIBUTE_TYPE_TABLES, layout.rowCounts);
    if (constructor === null) {
        const typeReason = metadataCodedTokenInvalidReason(typeRaw, 3, CUSTOM_ATTRIBUTE_TYPE_TABLES, layout.rowCounts);
        issues.push({
            code: "invalid-row",
            scope: `metadata.CustomAttribute:${metadataToken(12, row)}`,
            offset: typeOffset,
            detail: typeReason === null
                ? "CustomAttribute constructor coded index 0x0 is null, but Type must reference a MethodDef or MemberRef row"
                : `CustomAttribute constructor coded index 0x${typeRaw.toString(16)} is invalid: ${typeReason}`,
        });
    }
    let typeName = null;
    if (constructor !== null)
        typeName =
            readManagedValue(() => attributeTypeName(bytes, layout, typeRaw, heapExtent, memberLists), issues) ?? null;
    return {
        parent_token: parent,
        constructor_token: constructor,
        type_name: typeName,
        value_length: value.length,
        value_sha256: managedDecodeBudget(layout).digest(value, "sha256"),
        decoded_fixed_string: typeName === "System.Runtime.Versioning.TargetFrameworkAttribute"
            ? decodeFixedString(value, layout)
            : null,
        token: metadataToken(12, row),
        row_offset: cursor.start,
    };
};
export const readResource = ({ bytes, layout, row, directory, issues, }) => {
    const cursor = metadataRowCursor(bytes, layout, 40, row);
    const declaredOffset = cursor.readUInt32();
    const flags = cursor.readUInt32();
    const name = readMetadataString(bytes, layout, cursor.readIndex(layout.stringIndexSize), Math.max(layout.strings.size, layout.blob.size));
    const implementationOffset = cursor.offset;
    const implementationRaw = cursor.readIndex(layout.codedIndexSize("Implementation"));
    const implementationToken = metadataCodedToken(implementationRaw, 2, [38, 35, 39], layout.rowCounts);
    const implementationReason = metadataCodedTokenInvalidReason(implementationRaw, 2, [38, 35, 39], layout.rowCounts);
    if (implementationReason !== null)
        issues.push({
            code: "invalid-row",
            scope: `metadata.ManifestResource:${metadataToken(40, row)}`,
            offset: implementationOffset,
            detail: `ManifestResource implementation coded index 0x${implementationRaw.toString(16)} is invalid: ${implementationReason}`,
        });
    let dataLength = null;
    let dataSha256 = null;
    if (implementationRaw === 0) {
        if (directory === null || declaredOffset > directory.size - 4) {
            issues.push({
                code: "invalid-resource",
                scope: `metadata.ManifestResource:${metadataToken(40, row)}`,
                offset: directory?.offset ?? null,
                detail: "Embedded resource offset leaves the CLI resources directory",
            });
        }
        else {
            const start = directory.offset + declaredOffset;
            dataLength = bytes.readUInt32LE(start);
            if (dataLength > directory.size - declaredOffset - 4) {
                issues.push({
                    code: "invalid-resource",
                    scope: `metadata.ManifestResource:${metadataToken(40, row)}`,
                    offset: start,
                    detail: "Embedded resource length leaves the CLI resources directory",
                });
            }
            else {
                dataSha256 = managedDecodeBudget(layout).digest(bytes.subarray(start + 4, start + 4 + dataLength), "sha256");
            }
        }
    }
    return {
        name,
        flags,
        visibility: (flags & 7) === 1 ? "public" : (flags & 7) === 2 ? "private" : "unknown",
        implementation_token: implementationToken,
        embedded: implementationRaw === 0,
        declared_offset: declaredOffset,
        data_length: dataLength,
        data_sha256: dataSha256,
        token: metadataToken(40, row),
        row_offset: cursor.start,
    };
};
