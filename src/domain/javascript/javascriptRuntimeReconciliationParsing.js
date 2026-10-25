import { digestCanonicalValue } from "../canonicalDigest.js";
import { compareUnicodeCodePoints } from "../unicodeCodePointOrder.js";
import { parseEvidence } from "../evidence.js";
import { javascriptApplicationAnalysisResultSchema, } from "./javascriptApplicationAnalysis.js";
import { assertEvidenceIdentity, invalidInput, parseAtPath, } from "./javascriptRuntimeReconciliationInputValidation.js";
/** Parse and semantically bind every static analysis Evidence layer. */
export const parseStaticLayers = (layers, path = ["static_layers"]) => layers
    .map((layer, index) => parseStaticLayer(layer, [...path, index, "analysis"]))
    .sort((left, right) => compareUnicodeCodePoints(left.layerId, right.layerId));
const parseStaticLayer = (layer, evidencePath) => {
    const evidence = parseAtPath(parseEvidence, layer.analysis, evidencePath);
    const result = parseAtPath((value) => javascriptApplicationAnalysisResultSchema.parse(value), evidence.normalized_result, [...evidencePath, "normalized_result"]);
    assertEvidenceIdentity(evidence, {
        operation: "analyze_javascript_application",
        predicate: "phxre.javascript-application-analysis",
        providerId: "phxre-javascript-application",
        providerName: "PhxRE JavaScript application analyzer",
        providerVersion: "1",
        authority: "shipped-artifact",
        confidence: "derived",
    }, evidencePath);
    if (evidence.subject === null ||
        evidence.subject.digest.sha256 !== result.root_artifact_sha256 ||
        evidence.subject.format !== result.format ||
        evidence.subject.local_path !== result.input_path)
        throw invalidInput([...evidencePath, "subject"], "JavaScript application Evidence subject disagrees with its result");
    return {
        layerId: `jrl_${digestCanonicalValue({
            role: layer.role,
            evidence_id: evidence.evidence_id,
            runtime_mappings: layer.runtime_mappings,
        }, "Runtime reconciliation")}`,
        role: layer.role,
        evidence,
        result,
        graph: result.graph,
        runtimeMappings: layer.runtime_mappings,
    };
};
