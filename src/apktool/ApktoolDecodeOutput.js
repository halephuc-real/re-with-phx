import { parseXmlDocument } from "../domain/xmlDocument.js";
import { ok, err } from "../domain/result.js";
import { isMap, isScalar, parseDocument, } from "yaml";
const metaInfoTag = {
    tag: "tag:yaml.org,2002:brut.androlib.meta.MetaInfo",
    collection: "map",
    resolve: (map) => map,
};
/**
 * Read values from Apktool's tagged metadata document. YAML's core schema
 * distinguishes null from quoted strings; numeric values use their source
 * range so version codes retain the spelling Apktool emitted.
 */
export const parseApktoolYml = (yml) => {
    const document = parseDocument(yml, {
        schema: "core",
        customTags: [metaInfoTag],
        strict: true,
        uniqueKeys: true,
    });
    if (document.errors.length > 0)
        throw new TypeError(`apktool.yml is not valid Apktool metadata: ${document.errors[0]?.message ?? "YAML parse error"}`);
    if (!isMap(document.contents))
        throw new TypeError("apktool.yml root must be an Apktool metadata mapping");
    return {
        versionName: yamlScalar(document, ["versionInfo", "versionName"], yml),
        versionCode: yamlScalar(document, ["versionInfo", "versionCode"], yml),
        minSdkVersion: yamlScalar(document, ["sdkInfo", "minSdkVersion"], yml),
        targetSdkVersion: yamlScalar(document, ["sdkInfo", "targetSdkVersion"], yml),
    };
};
/** Read the package attribute from the decoded Android manifest root. */
export const parseManifestPackage = (manifest) => {
    const parsed = parseXmlDocument(manifest, {
        doctype: "allow",
        lineEndings: "preserve",
    });
    if (!parsed.ok)
        throw new TypeError(`AndroidManifest.xml is not well-formed XML: ${parsed.error.message}`, { cause: parsed.error });
    const root = parsed.value.documentElement;
    if (root === null || root.nodeName !== "manifest")
        throw new TypeError("AndroidManifest.xml root must be <manifest>");
    return root.getAttribute("package") || null;
};
/** A whole-document failure does not establish an omitted-entry count. */
export class ApktoolStringsDocumentError extends Error {
    reason;
    _tag = "ApktoolStringsDocumentError";
    constructor(reason, message, options) {
        super(message, options);
        this.reason = reason;
    }
}
/**
 * Project direct `<string>` children from decoded resources XML. DOM parsing
 * identifies elements and attributes; text values are sliced from the input
 * at parser-reported locations so entity spelling and whitespace are kept.
 * Markup-bearing string values are omitted and counted as partial evidence.
 */
export const parseDecodedStrings = (stringsXml) => {
    const parsed = parseXmlDocument(stringsXml, {
        doctype: "allow",
        lineEndings: "preserve",
    });
    if (!parsed.ok)
        return err(new ApktoolStringsDocumentError("malformed", parsed.error.message, {
            cause: parsed.error,
        }));
    const root = parsed.value.documentElement;
    if (root === null || root.nodeName !== "resources")
        return err(new ApktoolStringsDocumentError("wrong_root", "String resource document root must be <resources>"));
    const entries = [];
    let unparsedCount = 0;
    const offsets = sourceLineOffsets(stringsXml);
    for (const child of childNodes(root)) {
        if (child.nodeType !== 1)
            continue;
        const element = child;
        if (element.nodeName !== "string")
            continue;
        const name = element.getAttribute("name");
        if (name === null || name.length === 0) {
            unparsedCount += 1;
            continue;
        }
        const content = childNodes(element);
        if (content.some((node) => node.nodeType !== 3 && node.nodeType !== 8)) {
            unparsedCount += 1;
            continue;
        }
        if (content.every((node) => node.nodeType === 8)) {
            entries.push({ name, value: "" });
            continue;
        }
        const value = content
            .filter((node) => node.nodeType === 3)
            .map((node) => {
            const start = sourceOffset(node, offsets);
            if (start === undefined)
                return null;
            // A literal '<' cannot appear in well-formed XML text. Ending here
            // also excludes comments after the document element from this value.
            const end = stringsXml.indexOf("<", start);
            if (end < start)
                return null;
            return stringsXml.slice(start, end);
        });
        if (value.some((part) => part === null)) {
            unparsedCount += 1;
            continue;
        }
        entries.push({ name, value: value.join("") });
    }
    return ok({ entries, unparsedCount });
};
const yamlScalar = (document, path, source) => {
    const node = document.getIn(path, true);
    if (!isScalar(node) || node.value === null)
        return null;
    if (typeof node.value === "string")
        return node.value;
    const range = node.range;
    return range === null || range === undefined
        ? String(node.value)
        : source.slice(range[0], range[1]);
};
const childNodes = (node) => {
    const children = [];
    for (let child = node.firstChild; child !== null; child = child.nextSibling)
        children.push(child);
    return children;
};
const sourceLineOffsets = (source) => {
    const offsets = [0];
    for (const match of source.matchAll(/\r\n?|\n/gu)) {
        const index = match.index;
        offsets.push(index + match[0].length);
    }
    return offsets;
};
const sourceOffset = (node, lineOffsets) => {
    const line = node.lineNumber;
    const column = node.columnNumber;
    if (line === undefined || column === undefined)
        return undefined;
    const lineStart = lineOffsets[line - 1];
    return lineStart === undefined ? undefined : lineStart + column - 1;
};
