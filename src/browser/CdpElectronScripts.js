import { digestCanonicalValue } from "../domain/canonicalDigest.js";
import { createWebTextArtifact } from "../domain/webContentArtifact.js";
import { requiredScriptSource } from "./CdpCaptureValues.js";
import { authorizedElectronFile } from "./ElectronFileScope.js";
import { compareUnicodeCodePoints } from "../domain/unicodeCodePointOrder.js";
import { AnalysisCancelledError } from "../domain/analysisErrorCore.js";
import { CDP_SCRIPT_SOURCE_BYTES_OMISSION_REASON, CDP_SCRIPT_SOURCE_DEADLINE_OMISSION_REASON, CdpScriptSourceBudget, } from "./CdpScriptSourceBudget.js";
/** Normalize local script metadata and optionally approved source. */
export const captureElectronScripts = async (input) => {
    let total = 0;
    const items = [];
    const seen = new Set();
    const sourceBudget = input.request.include_script_sources && input.scripts.length > 0
        ? new CdpScriptSourceBudget(input.signal)
        : undefined;
    try {
        for (const script of input.scripts) {
            throwIfCallerCancelled(input.signal);
            const path = await authorizedElectronFile(script.rawUrl, input.signal, "inspect_electron_page");
            if (path === undefined) {
                input.completeness.exclude("scripts", "out_of_target_scope");
                continue;
            }
            const identity = {
                frame_id: script.frameId !== null && input.frameIds.has(script.frameId)
                    ? script.frameId
                    : null,
                file_path: path,
                cdp_hash: script.hash,
                length: script.length,
                is_module: script.isModule,
                language: script.language,
            };
            const scriptKey = `electron_script_${digestCanonicalValue(identity, "CDP capture")}`;
            if (seen.has(scriptKey))
                continue;
            seen.add(scriptKey);
            total += 1;
            let source = input.request.include_script_sources
                ? {
                    included: false,
                    reason: CDP_SCRIPT_SOURCE_DEADLINE_OMISSION_REASON,
                }
                : {
                    included: false,
                    reason: "source capture was not selected",
                };
            if (input.request.include_script_sources &&
                isSourceDeadlineExpired(sourceBudget)) {
                excludeScriptSource(input.completeness);
            }
            else if (input.request.include_script_sources &&
                sourceBudget !== undefined) {
                try {
                    source = await captureScriptSource(input, script, sourceBudget);
                }
                catch (cause) {
                    throwIfCallerCancelled(input.signal);
                    if (isSourceDeadlineExpired(sourceBudget)) {
                        excludeScriptSource(input.completeness);
                    }
                    else {
                        throw cause;
                    }
                }
            }
            items.push({ script_key: scriptKey, ...identity, source });
        }
    }
    finally {
        sourceBudget?.dispose();
    }
    if (!input.request.include_script_sources)
        input.completeness.exclude("script_sources", "not_approved", total);
    return {
        total,
        items: items.sort((left, right) => compareUnicodeCodePoints(left.script_key, right.script_key)),
    };
};
const captureScriptSource = async (input, script, sourceBudget) => {
    const response = await input.connection.send("Debugger.getScriptSource", { scriptId: script.scriptId }, input.sessionId, sourceBudget.signal);
    throwIfCallerCancelled(input.signal);
    const text = requiredScriptSource(response, "inspect_electron_page");
    if (sourceBudget.timedOut) {
        excludeScriptSource(input.completeness);
        return {
            included: false,
            reason: CDP_SCRIPT_SOURCE_DEADLINE_OMISSION_REASON,
        };
    }
    if (!sourceBudget.admit(text)) {
        excludeScriptSource(input.completeness);
        return { included: false, reason: CDP_SCRIPT_SOURCE_BYTES_OMISSION_REASON };
    }
    return {
        included: true,
        artifact: createWebTextArtifact(text, "text/javascript"),
    };
};
const excludeScriptSource = (completeness) => {
    completeness.exclude("script_sources", "resource_budget_exhausted");
};
const throwIfCallerCancelled = (signal) => {
    if (signal?.aborted === true)
        throw new AnalysisCancelledError("inspect_electron_page", {
            cause: signal.reason,
        });
};
const isSourceDeadlineExpired = (sourceBudget) => sourceBudget?.timedOut === true;
