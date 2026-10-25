import { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import { readStableArtifact } from "../../artifacts/readStableArtifact.js";
import { WEB_SOURCE_MAP_LIMITS, } from "../../domain/webSourceLocation.js";
import { err, ok } from "../../domain/result.js";
import { webArtifactCleanupFailures } from "../WebArtifactCleanup.js";
import { LocalWebScriptArtifacts } from "./LocalWebScriptArtifacts.js";
import { decodeWebArtifact, webArtifactReadError } from "./WebArtifactReads.js";
/** Read one verified capture source and the caller-selected map, without fetching. */
export class LocalWebSourceLocationArtifacts {
    scripts;
    #resources;
    constructor(scripts, resources = scripts instanceof LocalWebScriptArtifacts
        ? scripts.resources
        : new ArtifactResourceScope()) {
        this.#resources = resources;
        this.scripts =
            scripts ??
                new LocalWebScriptArtifacts("trace_web_source_location", resources);
    }
    async close() {
        const closeScript = this.scripts instanceof LocalWebScriptArtifacts &&
            this.scripts.resources === this.#resources
            ? undefined
            : this.scripts.close?.bind(this.scripts);
        const results = await Promise.allSettled([
            Promise.resolve().then(() => this.#resources.close()),
            ...(closeScript === undefined
                ? []
                : [Promise.resolve().then(closeScript)]),
        ]);
        const failures = results.flatMap((result, index) => result.status === "rejected"
            ? [
                {
                    cause: result.reason,
                    resource: index === 0 ? "web source-location artifacts" : "web scripts",
                },
            ]
            : []);
        const error = webArtifactCleanupFailures("web-source-location-artifacts", "trace_web_source_location", failures);
        if (error !== undefined)
            throw error;
    }
    /** Preserve actual map identity separately from the selected deployment URL. */
    async load(input, options) {
        try {
            return await this.#resources.run(() => this.#load(input, options));
        }
        catch (cause) {
            return err(webArtifactReadError(cause, {
                operation: "trace_web_source_location",
                field: ["source_map", "path"],
                targetPath: input.source_map.path,
                callerSelected: true,
            }, options?.signal));
        }
    }
    async #load(input, options) {
        const loaded = await this.scripts.load(input, options);
        if (!loaded.ok)
            return loaded;
        try {
            const data = await readStableArtifact(input.source_map.path, WEB_SOURCE_MAP_LIMITS.mapBytes, options?.signal, undefined, this.#resources);
            return ok({
                ...loaded.value,
                sourceMap: {
                    file: {
                        path: input.source_map.path,
                        sha256: data.sha256,
                        bytes: data.bytes.length,
                    },
                    url: input.source_map.url,
                    text: decodeWebArtifact(data.bytes),
                },
            });
        }
        catch (cause) {
            return err(webArtifactReadError(cause, {
                operation: "trace_web_source_location",
                field: ["source_map", "path"],
                targetPath: input.source_map.path,
                callerSelected: true,
            }, options?.signal));
        }
    }
}
