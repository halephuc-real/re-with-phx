import { inspectSignalDecodersInputSchema, signalDecodersSchema, } from "../../domain/signals/signalDecoders.js";
import { isAbsolute } from "node:path";
import { AnalysisCancelledError, AnalysisInputError, AnalysisOutputError, } from "../../domain/analysisErrorCore.js";
import { createEvidence } from "../../domain/evidence.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { decodeSignalRecordingInputSchema, signalRecordingSchema, } from "../../domain/signals/signalRecording.js";
import { err, ok } from "../../domain/result.js";
/** One shared validation and Evidence owner for CLI and MCP. */
export class SignalRecordingService {
    provider;
    constructor(provider) {
        this.provider = provider;
    }
    close() {
        return this.provider.close();
    }
    async decode(raw, options) {
        const operation = "decode_signal_recording";
        if (options?.signal?.aborted)
            return err(new AnalysisCancelledError(operation, { cause: options.signal.reason }));
        const input = decodeSignalRecordingInputSchema.safeParse(raw);
        if (!input.success)
            return err(analysisInputErrorFromIssues(operation, input.error.issues, raw, {
                cause: input.error,
            }));
        if (!isAbsolute(input.data.path))
            return err(new AnalysisInputError(operation, undefined, [
                {
                    path: ["path"],
                    reason: "invalid_format",
                    message: "Expected an absolute local path.",
                },
            ]));
        const decoded = await this.provider.decode(input.data, options);
        if (!decoded.ok)
            return decoded;
        const execution = decoded.value;
        const report = signalRecordingSchema.safeParse(execution.result);
        if (!report.success ||
            report.data.artifact.path !== input.data.path ||
            execution.subject?.path !== input.data.path ||
            execution.subject.sha256 !== report.data.artifact.sha256 ||
            JSON.stringify(report.data.selection) !== JSON.stringify(input.data))
            return err(new AnalysisOutputError(operation, "Decoder returned malformed data or changed the selected recording identity/options."));
        return this.#evidence(operation, input.data, execution, options);
    }
    async inspectDecoders(raw, options) {
        const operation = "inspect_signal_decoders";
        if (options?.signal?.aborted)
            return err(new AnalysisCancelledError(operation, { cause: options.signal.reason }));
        const input = inspectSignalDecodersInputSchema.safeParse(raw);
        if (!input.success)
            return err(analysisInputErrorFromIssues(operation, input.error.issues, raw, {
                cause: input.error,
            }));
        const decoded = await this.provider.inspectDecoders(input.data, options);
        if (!decoded.ok)
            return decoded;
        const execution = decoded.value;
        const report = signalDecodersSchema.safeParse(execution.result);
        if (!report.success ||
            JSON.stringify(report.data.selection) !== JSON.stringify(input.data) ||
            execution.subject?.path !== report.data.tool.path ||
            execution.subject.sha256 !== report.data.tool.sha256)
            return err(new AnalysisOutputError(operation, "Decoder discovery returned malformed data or changed the selected installation/options."));
        return this.#evidence(operation, input.data, execution, options);
    }
    #evidence(operation, parameters, execution, options) {
        const evidence = createEvidence(execution.subject ?? undefined, execution.provider, {
            operation,
            parameters,
            result: execution.result,
            confidence: "observed",
            locations: execution.locations,
            limitations: execution.limitations,
        });
        return options?.signal?.aborted
            ? err(new AnalysisCancelledError(operation, {
                cause: options.signal.reason,
                partialObservation: evidence,
            }))
            : ok(evidence);
    }
}
