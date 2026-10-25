import { AnalysisCancelledError, AnalysisTimeoutError, } from "../domain/analysisErrorCore.js";
export const NATIVE_UI_DEADLINE_MS = 180000;
/** Tracks whether the caller or the owned operation deadline stopped UI work. */
export class NativeUiInterruptionControl {
    signal;
    #controller = new AbortController();
    #interruption;
    #caller;
    #deadline;
    #onCallerAbort = () => {
        this.#interrupt("caller", this.#caller?.reason);
    };
    #onDeadlineAbort = () => {
        this.#interrupt("deadline", this.#deadline.reason);
    };
    constructor(caller, deadline) {
        this.#caller = caller;
        this.#deadline = deadline;
        this.signal = this.#controller.signal;
        // Match AbortSignal.any's iterable priority when both are already aborted.
        if (caller?.aborted)
            this.#interrupt("caller", caller.reason);
        else if (deadline.aborted)
            this.#interrupt("deadline", deadline.reason);
        else {
            caller?.addEventListener("abort", this.#onCallerAbort, { once: true });
            deadline.addEventListener("abort", this.#onDeadlineAbort, {
                once: true,
            });
        }
    }
    error(operation, partialObservation) {
        const interruption = this.#interruption;
        if (interruption === undefined)
            return undefined;
        return interruption.kind === "deadline"
            ? new AnalysisTimeoutError(operation, NATIVE_UI_DEADLINE_MS, {
                cause: interruption.reason,
                partialObservation,
            })
            : new AnalysisCancelledError(operation, {
                cause: interruption.reason,
                partialObservation,
            });
    }
    dispose() {
        this.#caller?.removeEventListener("abort", this.#onCallerAbort);
        this.#deadline.removeEventListener("abort", this.#onDeadlineAbort);
    }
    #interrupt(kind, reason) {
        if (this.#interruption !== undefined)
            return;
        this.#interruption = { kind, reason };
        this.#controller.abort(reason);
    }
}
