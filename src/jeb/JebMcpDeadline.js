import { SdkError, SdkErrorCode } from "@modelcontextprotocol/client";
import { AnalysisCancelledError, AnalysisTimeoutError, } from "../domain/analysisErrorCore.js";
import { ProviderStartupDeadline } from "../process/ProviderDeadline.js";
/** SDK 2.3.1 preserves an SdkError abort reason by identity. */
export class JebMcpDeadline {
    timeoutMs;
    #deadline;
    #controller = new AbortController();
    #interruption = new SdkError(SdkErrorCode.RequestTimeout, "JEB MCP interrupted");
    #onAbort = () => this.#controller.abort(this.#interruption);
    constructor(timeoutMs, signal) {
        this.timeoutMs = timeoutMs;
        this.#deadline = new ProviderStartupDeadline(timeoutMs, signal);
        if (this.#deadline.signal.aborted)
            this.#onAbort();
        else
            this.#deadline.signal.addEventListener("abort", this.#onAbort, {
                once: true,
            });
    }
    get signal() {
        return this.#controller.signal;
    }
    remainingMs() {
        return this.#deadline.remainingMs();
    }
    /** Classify only the rejection produced by this deadline's exact abort. */
    failure(operation, cause) {
        if (cause === this.#interruption) {
            return this.#deadline.interruption === "timeout"
                ? new AnalysisTimeoutError(operation, this.timeoutMs, {
                    cause: this.#deadline.signal.reason,
                })
                : new AnalysisCancelledError(operation, {
                    cause: this.#deadline.signal.reason,
                });
        }
        if (cause instanceof SdkError && cause.code === SdkErrorCode.RequestTimeout)
            return new AnalysisTimeoutError(operation, this.timeoutMs, { cause });
        return cause;
    }
    dispose() {
        this.#deadline.signal.removeEventListener("abort", this.#onAbort);
        this.#deadline.dispose();
    }
}
