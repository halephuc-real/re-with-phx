export class XmlPlistTextDecodeError extends TypeError {
    reason;
    declaredEncoding;
    constructor(reason, message, declaredEncoding, options) {
        super(message, options);
        this.reason = reason;
        this.declaredEncoding = declaredEncoding;
        this.name = "XmlPlistTextDecodeError";
    }
}
/** Decode BOM-aware XML plist text and verify any declaration against its bytes. */
export const decodeXmlPlistText = (bytes) => {
    const encoding = bytes[0] === 0xff && bytes[1] === 0xfe
        ? "utf-16le"
        : bytes[0] === 0xfe && bytes[1] === 0xff
            ? "utf-16be"
            : "utf-8";
    let text;
    try {
        text = new TextDecoder(encoding, { fatal: true }).decode(bytes);
    }
    catch (cause) {
        throw new XmlPlistTextDecodeError("invalid-bytes", "XML text bytes are invalid for the detected encoding", undefined, { cause });
    }
    const declaration = /^<\?xml\s[^?]*\bencoding\s*=\s*["']([^"']+)["']/u.exec(text)?.[1];
    const declared = declaration?.toLowerCase();
    if (declared !== undefined &&
        !["utf-8", "utf-16", "utf-16le", "utf-16be"].includes(declared))
        throw new XmlPlistTextDecodeError("unsupported-encoding", `Unsupported XML encoding declaration: ${declaration}. Supported encodings are UTF-8 and BOM-marked UTF-16 in either byte order.`, declaration);
    if (declared !== undefined &&
        declared !== encoding &&
        !(encoding !== "utf-8" && declared === "utf-16"))
        throw new XmlPlistTextDecodeError("encoding-mismatch", "XML encoding declaration disagrees with its bytes", declaration);
    return text;
};
