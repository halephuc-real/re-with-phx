import { AsarArtifactReader } from "../AsarArtifactReader.js";
import { DirectoryArtifactReader } from "../DirectoryArtifactReader.js";
import { GodotPckArtifactReader } from "../GodotPckArtifactReader.js";
import { MachOSliceArtifactReader } from "../MachOSliceArtifactReader.js";
import { NativeDmgArtifactReader } from "../NativeDmgArtifactReader.js";
import { PyInstallerArtifactReader } from "../PyInstallerArtifactReader.js";
import { ZipArtifactReader } from "../ZipArtifactReader.js";
import { isZipPackageFormat, ZIP_NON_ENTRY_LIMITATION, } from "../../domain/zipPackageFormat.js";
export const createReader = (path, format, environment, rootSource) => {
    if (isZipPackageFormat(format))
        return new ZipArtifactReader(path, format, undefined, rootSource);
    switch (format) {
        case "directory":
            return new DirectoryArtifactReader(path);
        case "asar":
            return new AsarArtifactReader(path);
        case "pyinstaller":
            return new PyInstallerArtifactReader(path, rootSource);
        case "godot-pck":
            return new GodotPckArtifactReader(path, rootSource);
        case "mach-o-universal":
            return process.platform === "darwin"
                ? new MachOSliceArtifactReader(path, environment, undefined, rootSource)
                : undefined;
        case "dmg":
            if (process.platform !== "darwin")
                return undefined;
            return new NativeDmgArtifactReader(path, environment);
        default:
            return undefined;
    }
};
/** Decide traversal scope and availability once, independently of diagnostic wording. */
export const inventoryCoverage = (format, reader, traversal) => {
    if (reader !== undefined)
        return {
            coverage: { scope: "container-entries", status: traversal.status },
            limitations: [
                ...(isZipPackageFormat(reader.format)
                    ? [ZIP_NON_ENTRY_LIMITATION]
                    : []),
                ...(reader.format === "godot-pck"
                    ? [
                        "PCK inventory establishes packaged bytes and metadata; scenes, binary resources, GDScript bytecode and runtime signal behavior were not decoded.",
                    ]
                    : []),
                ...traversal.limitations,
            ],
        };
    // dmg and pkg reach here only after classifyRootFormat matched their bytes.
    if (format === "dmg" || format === "pkg")
        return {
            coverage: { scope: "container-entries", status: "unknown" },
            limitations: [
                `${format.toUpperCase()} root hash is observed; child inventory requires a native macOS adapter.`,
            ],
        };
    if (format === "mach-o-universal")
        return {
            coverage: { scope: "container-entries", status: "unknown" },
            limitations: [
                "Universal Mach-O slices require the native macOS lipo adapter.",
            ],
        };
    if (isZipPackageFormat(format) ||
        format === "directory" ||
        format === "asar" ||
        format === "godot-pck")
        return {
            coverage: { scope: "container-entries", status: "unknown" },
            limitations: [`${format} child inventory reader is unavailable.`],
        };
    return {
        coverage: { scope: "root", status: "complete" },
        limitations: ["Artifact has no child container entries."],
    };
};
