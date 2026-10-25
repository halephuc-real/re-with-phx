import { issue } from "./AppleDispatchDecodeFacts.js";
/**
 * Parse an `@property` attribute string such as `T@"NSString",C,N,V_name`.
 * Each comma-separated token is one attribute; `T` is the type encoding.
 */
export const parsePropertyAttributes = (name, attributes) => decodePropertyAttributes(name, attributes).property;
/**
 * Decode one attribute string. A quoted class name that never closes leaves
 * the string incomplete: later attributes may be inside the unfinished type,
 * so a missing `N` or `R` does not establish the Objective-C defaults.
 */
const decodePropertyAttributes = (name, attributes) => {
    const { tokens, complete } = attributes.length === 0
        ? { tokens: [], complete: true }
        : splitAttributes(attributes);
    const typeAttributes = tokens.filter((token) => token[0] === "T");
    const typeAttribute = typeAttributes.length === 1 ? typeAttributes[0] : undefined;
    const typeEncoding = typeAttribute !== undefined && typeAttribute.length > 1
        ? typeAttribute.slice(1)
        : null;
    const value = (code) => tokens.find((token) => token[0] === code)?.slice(1) ?? null;
    const defaultsEstablished = typeEncoding !== null && complete;
    const property = {
        name,
        type_encoding: typeEncoding,
        attributes: tokens.map((token) => ({
            name: token.slice(0, 1),
            value: token.slice(1),
        })),
        atomicity: tokens.includes("N")
            ? "nonatomic"
            : defaultsEstablished
                ? "atomic"
                : null,
        is_readonly: tokens.includes("R")
            ? true
            : defaultsEstablished
                ? false
                : null,
        getter: value("G"),
        setter: value("S"),
    };
    return { property, complete };
};
/**
 * Split on commas that are outside a quoted class name in the type encoding,
 * and report whether every quote closed.
 */
const splitAttributes = (attributes) => {
    const tokens = [];
    let current = "";
    let quoted = false;
    for (const character of attributes) {
        if (character === '"')
            quoted = !quoted;
        if (character === "," && !quoted) {
            tokens.push(current);
            current = "";
        }
        else
            current += character;
    }
    tokens.push(current);
    return {
        tokens: tokens.filter((token) => token.length > 0),
        complete: !quoted,
    };
};
/**
 * Decode `property_list_t { entsize_and_flags, count, property_t[] }`. Each
 * entry is decoded on its own, so one malformed entry is reported without
 * discarding the properties decoded before or after it.
 */
export const readObjcPropertyList = (read, list, admit, onTruncated) => {
    const properties = [];
    const issues = [];
    if (list === 0n)
        return { properties, issues };
    const entrySize = read.u32(list) & ~3;
    const count = read.u32(list + 4n);
    if (entrySize !== 16)
        throw new TypeError(`Unsupported Objective-C property entry size ${entrySize}`);
    for (let index = 0; index < count; index++) {
        if (!admit()) {
            onTruncated?.();
            break;
        }
        const entry = list + 8n + BigInt(index * entrySize);
        const location = `0x${entry.toString(16)}`;
        try {
            const name = read.string(read.pointer(entry));
            if (name.length === 0)
                throw new TypeError("the property name is empty");
            const decoded = decodePropertyAttributes(name, read.string(read.pointer(entry + 8n)));
            properties.push(decoded.property);
            if (!decoded.complete)
                issues.push({
                    code: "property_attributes_incomplete",
                    message: `property ${name} has an unterminated quoted class name in its type attribute, so atomicity and unestablished read-only state are unknown`,
                    location,
                });
        }
        catch (cause) {
            issues.push({
                code: "property_decode_failed",
                message: `property ${String(index)} could not be decoded: ${cause instanceof Error ? cause.message : String(cause)}`,
                location,
            });
        }
    }
    return { properties, issues };
};
/** Decode a property list, recording a failure for `owner` instead of throwing. */
export const readObjcPropertiesOf = (read, list, context) => {
    try {
        const { properties, issues } = readObjcPropertyList(read, list, context.admit, context.onTruncated);
        for (const item of issues)
            context.issues.push(issue("objc_properties_categories", item.code, `${context.owner}: ${item.message}`, item.location));
        return properties;
    }
    catch (cause) {
        context.issues.push(issue("objc_properties_categories", "property_decode_failed", `${context.owner}: ${cause instanceof Error ? cause.message : String(cause)}`, context.location));
        return [];
    }
};
