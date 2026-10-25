import { open, readdir } from "node:fs/promises";
import { join } from "node:path";
import { parseXmlDocument } from "../domain/xmlDocument.js";
import { decodeXmlPlistText } from "../domain/propertyListXmlText.js";
import { ConfigurationError } from "../domain/configurationErrors.js";
import { OwnedFileHandle } from "../filesystem/OwnedFileHandle.js";
import { readBoundedFileBytes } from "../process/BoundedFileBytes.js";
// Language definitions are small XML files; refuse anything implausibly large.
const MAX_LDEFS_BYTES = 4 * 1024 * 1024;
// Processor modules ship under Processors; installed extensions may add more.
const LANGUAGE_ROOTS = ["Ghidra/Processors", "Ghidra/Extensions"];
/** Language definition handles whose close is unconfirmed but retryable. */
const pendingLanguageFileCleanup = new Set();
/**
 * Cleanup of one or more language definition handles is unconfirmed. Any
 * read failure that preceded it is kept as the primary failure.
 */
export class GhidraLanguageCatalogCleanupError extends Error {
    paths;
    causes;
    readFailure;
    constructor(paths, causes, readFailure) {
        super(`Language definition cleanup is unconfirmed: ${paths.join(", ")}`, readFailure === undefined ? undefined : { cause: readFailure });
        this.paths = paths;
        this.causes = causes;
        this.readFailure = readFailure;
    }
}
/** Close one owner; retain it only while a later close can still succeed. */
const closeLanguageFile = async (file) => {
    try {
        await file.owner.close();
        pendingLanguageFileCleanup.delete(file);
        return undefined;
    }
    catch (cause) {
        // Descriptor invalidation does not prove that this owner confirmed close.
        // Keep even sticky failures in the lifecycle scope so later reads surface
        // the unresolved cleanup instead of silently abandoning ownership.
        pendingLanguageFileCleanup.add(file);
        return cause;
    }
};
/** Retry every retained owner before reporting the failures together. */
const retryLanguageFileCleanup = async () => {
    const failed = [];
    for (const file of pendingLanguageFileCleanup) {
        const cause = await closeLanguageFile(file);
        if (cause !== undefined)
            failed.push({ path: file.path, cause });
    }
    if (failed.length > 0)
        throw new GhidraLanguageCatalogCleanupError(failed.map(({ path }) => path), failed.map(({ cause }) => cause));
};
/** Parse the `<language>` elements of one `.ldefs` document. */
export const parseGhidraLanguageDefinitions = (text) => {
    const definitions = [];
    const parsed = parseXmlDocument(text, {
        doctype: "allow",
        lineEndings: "normalize",
    });
    if (!parsed.ok)
        throw parsed.error;
    const document = parsed.value;
    const root = document.documentElement;
    if (root?.tagName !== "language_definitions")
        throw new SyntaxError("Expected Ghidra language_definitions XML root");
    for (const language of Array.from(root.getElementsByTagName("language"))) {
        if (language.parentNode !== root)
            continue;
        const id = language.getAttribute("id");
        if (id === null)
            continue;
        const compilerSpecIds = [];
        for (const compiler of Array.from(language.getElementsByTagName("compiler"))) {
            if (compiler.parentNode !== language)
                continue;
            const compilerId = compiler.getAttribute("id");
            if (compilerId !== null)
                compilerSpecIds.push(compilerId);
        }
        definitions.push({ id, compilerSpecIds });
    }
    return definitions;
};
const languageDirectories = async (installDir) => {
    const directories = [];
    for (const root of LANGUAGE_ROOTS) {
        let modules;
        try {
            modules = await readdir(join(installDir, root));
        }
        catch {
            continue;
        }
        for (const module of modules.sort())
            directories.push(join(installDir, root, module, "data", "languages"));
    }
    return directories;
};
/** Read at most the catalog limit; undefined marks an oversized file. */
const readLanguageDefinitionFile = async (path) => {
    await retryLanguageFileCleanup();
    const file = { path, owner: new OwnedFileHandle(await open(path, "r")) };
    let read;
    try {
        read = {
            ok: true,
            bytes: await readBoundedFileBytes(file.owner.handle, MAX_LDEFS_BYTES),
        };
    }
    catch (cause) {
        read = { ok: false, cause };
    }
    const cleanup = await closeLanguageFile(file);
    if (cleanup !== undefined)
        throw new GhidraLanguageCatalogCleanupError([path], [cleanup], read.ok ? undefined : read.cause);
    if (!read.ok)
        throw read.cause;
    return read.bytes;
};
/** Read every language definition shipped by one Ghidra installation. */
export const readGhidraLanguageCatalog = async (installDir) => {
    // Surface retained cleanup even when this catalog has no definitions to read.
    await retryLanguageFileCleanup();
    const definitions = [];
    for (const directory of await languageDirectories(installDir)) {
        let entries;
        try {
            entries = await readdir(directory);
        }
        catch {
            continue;
        }
        for (const entry of entries.sort()) {
            if (!entry.endsWith(".ldefs"))
                continue;
            const bytes = await readLanguageDefinitionFile(join(directory, entry));
            if (bytes === undefined)
                continue;
            // The XML byte owner validates encoding and declaration before syntax
            // parsing; a literal U+FFFD cannot diagnose invalid source bytes.
            definitions.push(...parseGhidraLanguageDefinitions(decodeXmlPlistText(bytes)));
        }
    }
    return definitions;
};
/**
 * Check a configured import language against the installation before launch,
 * so an unknown ID fails as configuration instead of as a failed import.
 */
export const admitGhidraLanguageOverride = (override, catalog, providerVersion) => {
    const language = catalog.find((value) => value.id === override.languageId);
    if (language === undefined)
        return new ConfigurationError("Invalid PhxRE environment configuration", {
            settings: [
                {
                    setting: "PHXRE_GHIDRA_LANGUAGE_ID",
                    constraint: `is not a language defined by Ghidra ${providerVersion}`,
                },
            ],
        });
    if (override.compilerSpecId !== undefined &&
        !language.compilerSpecIds.includes(override.compilerSpecId))
        return new ConfigurationError("Invalid PhxRE environment configuration", {
            settings: [
                {
                    setting: "PHXRE_GHIDRA_COMPILER_SPEC_ID",
                    constraint: `must be one of the selected language's compiler specs: ${language.compilerSpecIds.join(", ")}`,
                },
            ],
        });
    return null;
};
