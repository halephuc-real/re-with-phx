import { createEvidence } from "../evidence.js";
import { jsonObjectSchema } from "../jsonValue.js";
/** One owner commits packet aggregation provenance and caller intent into Evidence. */
export const createPcapEvidence = (request, observation) => createEvidence(observation.subject ?? undefined, observation.provider, {
    operation: request.operation,
    parameters: jsonObjectSchema.parse(request.input),
    result: observation.result,
    rawResult: observation.rawResult,
    limitations: observation.limitations,
    locations: observation.locations,
    confidence: request.operation === "inspect_pcap_capture" ? "derived" : "observed",
    ...(request.operation === "inspect_pcap_capture"
        ? { authority: "historical-reference" }
        : {}),
});
