import { Il2cppBinaryFormatFailure } from "./Il2cppBinaryFormat.js";
import { openImageSteps, readPointer, readSlot, isExecutable, } from "./Il2cppBinaryImage.js";
import { findModules, findCodeRegistration, findMetadataRegistration, } from "./Il2cppBinaryRegistration.js";
import { createTypeNamer } from "./Il2cppBinaryTypes.js";
/**
 * Link metadata methods to native code addresses without executing the image.
 * A method token's row id selects its module's methodPointers slot.
 */
export function* linkIl2cppBinarySteps(bytes, metadata, facts, architecture, options = {}) {
    const version = metadata.metadata_version;
    yield;
    const image = yield* openImageSteps(bytes, architecture);
    const modules = yield* findModules(image, metadata);
    const registration_ = yield* findCodeRegistration(image, modules);
    const methodImage = new Int32Array(metadata.methods.length).fill(-1);
    for (const [index, entry] of metadata.images.entries())
        for (let offset = 0; offset < entry.type_count; offset++) {
            const type = metadata.types[entry.type_start + offset];
            if (offset % LINK_BATCH === 0)
                yield;
            for (let method = 0; method < type.method_count; method++) {
                if (method % LINK_BATCH === 0)
                    yield;
                methodImage[type.method_start + method] = index;
            }
        }
    yield;
    const methodAddress = (index) => {
        const owner = methodImage[index];
        // No image range holds this method, so no module slot describes it.
        if (owner === -1)
            return "unknown";
        const module = modules[owner];
        const token = facts.methodTokens[index];
        const row = token & 0xffffff;
        if (token >>> 24 !== 0x06 || row === 0 || row > module.method_pointer_count)
            throw new Il2cppBinaryFormatFailure("invalid-method-token", `method ${index} token 0x${token.toString(16)} is outside module ${metadata.images[owner].name}'s ${module.method_pointer_count} method pointers`);
        const address = readSlot(image, module.method_pointers + BigInt((row - 1) * 8));
        if (address === null || address === undefined)
            throw new Il2cppBinaryFormatFailure("invalid-method-pointer", `module ${metadata.images[owner].name} method pointer ${row - 1} is not file mapped`);
        if (address === "unknown")
            return "unknown";
        if (address === 0n)
            return "no-body";
        if (!isExecutable(image, address))
            throw new Il2cppBinaryFormatFailure("invalid-method-pointer", `method ${index} points outside unambiguous executable file data at 0x${address.toString(16)}`);
        return address;
    };
    const method_addresses = [];
    for (let index = 0; index < metadata.methods.length; index++) {
        if (index % LINK_BATCH === 0)
            yield;
        const code = methodAddress(index);
        if (typeof code === "bigint" && code < image.imageBase)
            throw new Il2cppBinaryFormatFailure("invalid-method-pointer", "method address precedes the link image base");
        const row = typeof code === "bigint"
            ? {
                state: "code",
                address: `0x${code.toString(16)}`,
                rva: `0x${(code - image.imageBase).toString(16)}`,
            }
            : { state: code, address: null, rva: null };
        options.onRow?.(row);
        method_addresses.push(row);
    }
    const registration = yield* findMetadataRegistration(image, metadata.types.length);
    const typeName = createTypeNamer(image, metadata, facts, version, options.beforeText);
    function* reference(type) {
        if (type === -1)
            return { type, name: null };
        if (type < 0 || type >= registration.count)
            throw new Il2cppBinaryFormatFailure("invalid-type", `type index ${type} is outside the ${registration.count} binary types`);
        // 27.0/27.1 and 27.2 share header version 27 but place byref differently.
        if (version === 27)
            return { type, name: null };
        const address = readPointer(image, registration.types + BigInt(type * 8)) ?? 0n;
        if (address === 0n)
            throw new Il2cppBinaryFormatFailure("invalid-type", `type ${type} has no Il2CppType record`);
        return { type, name: yield* typeName(address, 0) };
    }
    function* column(types) {
        const rows = [];
        for (let index = 0; index < types.length; index++) {
            if (index % LINK_BATCH === 0)
                yield;
            const row = yield* reference(types[index]);
            options.onRow?.(row);
            rows.push(row);
        }
        return rows;
    }
    const return_types = yield* column(facts.returnTypes);
    const field_types = yield* column(facts.fieldTypes);
    const parameter_types = yield* column(facts.parameterTypes);
    return {
        format: image.container.format,
        architecture: image.container.architecture,
        image_base: image.imageBase,
        code_gen_modules_field: registration_.field,
        code_gen_modules_array: registration_.array,
        code_gen_modules: modules,
        method_addresses,
        types_field: registration.field,
        types_count: registration.count,
        return_types,
        field_types,
        parameter_types,
    };
}
/** Rows between cooperative yields while linking. */
const LINK_BATCH = 256;
/** Synchronous linking for byte-level callers. */
export const linkIl2cppBinary = (bytes, metadata, facts, architecture) => {
    const steps = linkIl2cppBinarySteps(bytes, metadata, facts, architecture);
    for (;;) {
        const step = steps.next();
        if (step.done)
            return step.value;
    }
};
