export const failure = (code, message) => ({
    tag: "reference-source-reader",
    code,
    message,
});
export const cancelled = () => failure("cancelled", "Reference source traversal cancelled");
export const safeSize = (size) => {
    const value = Number(size);
    return Number.isSafeInteger(value) && value >= 0 ? value : undefined;
};
const FILESYSTEM_ERROR_CODES = new Set([
    "EACCES",
    "EBADF",
    "EEXIST",
    "EIO",
    "EISDIR",
    "ELOOP",
    "EMFILE",
    // A traversed child can exceed the platform's absolute path limit even
    // though the selected root and every component are valid.
    "ENAMETOOLONG",
    "ENFILE",
    "ENOENT",
    "ENOTDIR",
    "ENOSPC",
    "EPERM",
    "EROFS",
]);
/** Preserve actionable operating-system detail while leaving invariants visible. */
export const filesystemFailureDetail = (cause, operation) => {
    if (!(cause instanceof Error))
        return undefined;
    const code = Reflect.get(cause, "code");
    if (code === "ENAMETOOLONG")
        return `${operation}: ENAMETOOLONG (entry path exceeds the operating system path limit)`;
    return typeof code === "string" && FILESYSTEM_ERROR_CODES.has(code)
        ? `${operation}: ${cause.message}`
        : undefined;
};
/** Preserve root I/O detail while separating bad selections from access failures. */
export const rootFilesystemFailure = (cause, operation) => {
    if (!(cause instanceof Error))
        return undefined;
    const code = Reflect.get(cause, "code");
    if (typeof code !== "string" || !FILESYSTEM_ERROR_CODES.has(code))
        return undefined;
    return {
        code: code === "ENOENT" || code === "ENOTDIR" ? "invalid-root" : "io",
        message: `${operation}: ${cause.message}`,
    };
};
export const entryFailure = (...[path, kind, code, message, size]) => ({
    status: "failed",
    kind,
    path,
    code,
    message,
    ...(size === undefined ? {} : { size }),
});
