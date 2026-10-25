/** Expected failure when a runtime root's privacy boundary is unavailable. */
export class PrivateRuntimeRootUnavailableError extends Error {
    code = "private-runtime-root-authority-unavailable";
    retryable;
    constructor(message, options) {
        super(message, options);
        this.name = "PrivateRuntimeRootUnavailableError";
        this.retryable = options?.retryable ?? false;
    }
}
