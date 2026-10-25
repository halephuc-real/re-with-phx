import { lstat, readlink, realpath } from "node:fs/promises";
import { isAbsolute, join, relative, sep } from "node:path";
import { AnalysisInputError } from "../../domain/analysisErrorCore.js";
import { resolveTreePath } from "../../domain/apple/dyldPaths.js";
import { dylibResolutionInputSchema, dylibResolutionResultSchema, traceDylibLoading, } from "../../domain/apple/dylibResolution.js";
import { projectInputIssues } from "../../domain/inputIssueProjection.js";
import { ArtifactReaderFailure } from "../ArtifactReader.js";
import { DirectoryArtifactReader } from "../DirectoryArtifactReader.js";
import { consumeWithOrderedReads } from "../OrderedReads.js";
import { DylibFileAccess, classifyDylibReadFailure, } from "./DylibFileAccess.js";
import { ArtifactResourceScope } from "../ArtifactResourceScope.js";
import { assertArtifactReadActive } from "../ArtifactFileOperation.js";
const OPERATION = "trace_dylib_resolution";
/** Concurrent four-byte magic reads while enumerating bundle roots. */
const MAGIC_READ_CONCURRENCY = 8;
/** Lazily probed, symlink-preserving view of one analyzed directory. */
class FilesystemTreeView {
    root;
    sourceRoot;
    files;
    signal;
    #entries = new Map();
    #images = new Map();
    #identities = new Map();
    constructor(root, sourceRoot, files, signal) {
        this.root = root;
        this.sourceRoot = sourceRoot;
        this.files = files;
        this.signal = signal;
    }
    rootRelativePath(absolutePath) {
        const roots = isAbsolute(this.sourceRoot)
            ? [this.root, this.sourceRoot]
            : [this.root];
        for (let root of roots) {
            while (root.length > 1 && root.endsWith(sep))
                root = root.slice(0, -1);
            if (absolutePath === root)
                return "";
            const prefix = root === sep ? sep : `${root}${sep}`;
            if (absolutePath.startsWith(prefix))
                return absolutePath.slice(prefix.length).split(sep).join("/");
        }
        return undefined;
    }
    entry(path) {
        const cached = this.#entries.get(path);
        if (cached !== undefined)
            return cached;
        const pending = this.#readEntry(path);
        this.#entries.set(path, pending);
        return pending;
    }
    image(path) {
        const cached = this.#images.get(path);
        if (cached !== undefined)
            return cached;
        const pending = this.files
            .image(join(this.root, path))
            .then(({ facts, identity }) => {
            this.#identities.set(path, identity);
            return facts;
        });
        this.#images.set(path, pending);
        return pending;
    }
    /** Identity of the file whose header bytes `image()` parsed. */
    identity(path) {
        return this.#identities.get(path);
    }
    async #readEntry(path) {
        assertArtifactReadActive(this.signal);
        const absolute = join(this.root, path);
        try {
            const metadata = await lstat(absolute);
            if (metadata.isSymbolicLink())
                return { kind: "symlink", target: await readlink(absolute) };
            if (metadata.isDirectory())
                return { kind: "directory" };
            return metadata.isFile() ? { kind: "file" } : undefined;
        }
        catch (cause) {
            if (missing(cause))
                return undefined;
            throw cause;
        }
    }
}
/** Resolve dyld load paths for the active Mach-O or every executable in its bundle. */
export const traceDylibResolution = async (options) => {
    const parsed = dylibResolutionInputSchema.safeParse(options.parameters);
    if (!parsed.success)
        throw new AnalysisInputError(OPERATION, { cause: parsed.error }, projectInputIssues(parsed.error.issues, options.parameters));
    const resources = options.resourceScope ?? new ArtifactResourceScope();
    return await resources.run(async () => {
        // Canonicalization is inside the translated region: a revoked permission
        // keeps its reason and path.
        let root = options.rootPath;
        try {
            assertArtifactReadActive(options.signal);
            root = await realpath(options.rootPath);
            assertArtifactReadActive(options.signal);
            const files = new DylibFileAccess(resources, root, options.signal);
            const target = relative(root, await realpath(options.targetPath))
                .split(sep)
                .join("/");
            assertArtifactReadActive(options.signal);
            const view = new FilesystemTreeView(root, options.rootPath, files, options.signal);
            const { roots: requested, unclassified } = parsed.data.roots !== undefined
                ? { roots: parsed.data.roots, unclassified: [] }
                : options.enumerateRoots
                    ? await executableRoots(root, view, files, options.signal)
                    : { roots: [target], unclassified: [] };
            const roots = await requireMachoRoots(view, requested, parsed.data.roots !== undefined);
            const trace = await traceDylibLoading(view, {
                roots,
                unclassified,
                ...(parsed.data.architecture === undefined
                    ? {}
                    : { architecture: parsed.data.architecture }),
                ...(options.signal === undefined ? {} : { signal: options.signal }),
            });
            // Each digest must describe the same file whose headers were parsed.
            const digests = new Map();
            for (const { path } of trace.images)
                digests.set(path, await files.sha256(join(root, path), view.identity(path)));
            const targetDigest = digests.get(target) ??
                (await files.sha256(join(root, target), undefined));
            if (targetDigest !== options.targetSha256)
                throw new ArtifactReaderFailure("integrity", `Active target digest changed: expected ${options.targetSha256}, observed ${targetDigest}`);
            assertArtifactReadActive(options.signal);
            return dylibResolutionResultSchema.parse({
                ...trace,
                root_path: options.rootPath,
                target_sha256: options.targetSha256,
                images: trace.images.map((image) => ({
                    ...image,
                    sha256: digests.get(image.path),
                })),
            });
        }
        catch (cause) {
            throw classifyDylibReadFailure(root, cause);
        }
    });
};
/**
 * Every Mach-O in the bundle with an executable slice is its own process root.
 * Mach-O files that do not parse are returned separately: whether they are
 * executables is unknown, so they make coverage partial instead of vanishing.
 */
const executableRoots = async (root, view, files, signal) => {
    const roots = [];
    const unclassified = [];
    // Bundles hold tens of thousands of files and few Mach-O images, so the
    // magic reads overlap the walk while results are classified in walk order.
    await consumeWithOrderedReads(new DirectoryArtifactReader(root).entries(signal), MAGIC_READ_CONCURRENCY, (entry) => entry.kind === "file" ? files.startsWithMachoMagic(entry) : undefined, async (entry, macho) => {
        if (!macho)
            return;
        const facts = await view.image(entry.path);
        if (facts.status === "malformed" || facts.status === "unsupported")
            unclassified.push(entry.path);
        else if (facts.status === "parsed" &&
            facts.slices.some(({ file_type: type }) => type === "execute"))
            roots.push(entry.path);
    });
    return {
        roots: roots.sort(compare),
        unclassified: unclassified.sort(compare),
    };
};
const compare = (left, right) => left < right ? -1 : left > right ? 1 : 0;
/**
 * Resolve each root segment by segment, as dependency candidates are, so a
 * symlink in an intermediate directory cannot lead outside the analyzed root.
 * A root the caller selected that fails is an input error on that root; a
 * root PhxRE derived itself keeps reporting an artifact failure.
 */
const requireMachoRoots = async (view, roots, callerSelected) => {
    const resolved = [];
    for (const [index, path] of roots.entries()) {
        const reject = (reason, message) => callerSelected
            ? new AnalysisInputError(OPERATION, undefined, [
                { path: ["roots", index], reason: "invalid_value", message },
            ])
            : new ArtifactReaderFailure(reason, message);
        const lookup = await resolveTreePath(view, path);
        if (lookup.kind === "escapes")
            throw reject("path", `Root ${path} resolves outside the analyzed root`);
        if (lookup.kind !== "file")
            throw reject("path", `Root ${path} is not a regular file in the analyzed root`);
        if ((await view.image(lookup.path)).status === "not-mach-o")
            throw reject("format", `Root ${path} is not a Mach-O image`);
        if (!resolved.includes(lookup.path))
            resolved.push(lookup.path);
    }
    return resolved;
};
const missing = (cause) => cause instanceof Error &&
    "code" in cause &&
    (cause.code === "ENOENT" || cause.code === "ENOTDIR");
