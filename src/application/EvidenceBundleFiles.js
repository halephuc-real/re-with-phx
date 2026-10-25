import { absoluteCallerPath } from "../filesystem/callerPath.js";
import { describeEvidenceBundleFailure, describeValidationFailure, parseImmutableEvidenceBundle, parseEvidenceBundle, } from "../domain/evidenceBundle.js";
import { EvidenceFileError, EvidenceIntegrityError, } from "../domain/evidenceErrors.js";
import { err, ok } from "../domain/result.js";
import { AnalysisCancelledError, } from "../domain/analysisErrorCore.js";
import { parseProcessCapture } from "../domain/process/processCaptureParsing.js";
import { bufferedJsonParts, canonicalJsonParts, } from "../domain/jsonSerialization.js";
import { readJsonFile, writeTextParts } from "./JsonFiles.js";
/** Read and validate an evidence bundle at the caller-supplied path. */
export const readEvidenceBundle = (path, signal, resources) => readBundle(path, parseEvidenceBundle, signal, resources);
/** Read an authenticated immutable snapshot for a subsequent session import. */
export const readImmutableEvidenceBundle = (path, signal, resources) => readBundle(path, parseImmutableEvidenceBundle, signal, resources);
const readBundle = async (path, parseBundle, signal, resources) => {
    if (signal?.aborted)
        return err(new AnalysisCancelledError("import_evidence_bundle", {
            cause: signal.reason,
        }));
    const loaded = await readJsonFile(path, signal, resources);
    if (!loaded.ok) {
        if (loaded.error instanceof AnalysisCancelledError)
            return err(new AnalysisCancelledError("import_evidence_bundle", {
                cause: loaded.error.cause,
            }));
        return loaded;
    }
    if (signal?.aborted)
        return err(new AnalysisCancelledError("import_evidence_bundle", {
            cause: signal.reason,
        }));
    let bundle;
    try {
        bundle = parseBundle(loaded.value);
    }
    catch (cause) {
        const failure = describeEvidenceBundleFailure(loaded.value, cause);
        if (failure.kind === "single-record")
            return err(new EvidenceFileError("read", "wrong-kind", {
                path: absoluteCallerPath(path),
                cause,
                userMessage: failure.message,
            }));
        return err(new EvidenceIntegrityError("Evidence bundle validation failed", {
            cause,
            userMessage: failure.message,
        }));
    }
    for (const record of bundle.records) {
        if (record.predicate_type !== "phxre.process-capture")
            continue;
        try {
            parseProcessCapture(record.normalized_result);
        }
        catch (cause) {
            return err(new EvidenceIntegrityError("Evidence bundle validation failed", {
                cause,
                userMessage: `Process capture record ${record.evidence_id} has an invalid normalized_result (${describeValidationFailure(cause)}). Recreate or re-export the bundle, then try again.`,
            }));
        }
    }
    return ok(bundle);
};
/** Atomically write deterministic evidence JSON at the caller-supplied path. */
export const writeEvidenceBundle = async (bundle, path, overwrite, resources, signal) => {
    if (signal?.aborted === true)
        return err(new AnalysisCancelledError("export_evidence_bundle"));
    let checked;
    try {
        checked = parseEvidenceBundle(bundle);
    }
    catch (cause) {
        return err(new EvidenceIntegrityError("Evidence bundle validation failed", {
            cause,
        }));
    }
    return writeTextParts(bufferedJsonParts(canonicalJsonParts(checked)), path, overwrite, resources, signal === undefined
        ? undefined
        : { signal, operation: "export_evidence_bundle" });
};
