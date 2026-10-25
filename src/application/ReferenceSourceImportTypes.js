const IMPORT_FAILURE_GUIDANCE = {
    cancelled: {
        category: "cancelled",
        message: "Reference source import was cancelled. Start it again when ready.",
    },
    "invalid-root": {
        category: "invalid_input",
        message: "Reference source directory could not be opened. Check that the path exists, is readable, and points to a directory.",
    },
    unsupported: {
        category: "unsupported_host",
        message: "Safe no-follow file opens are unavailable on this host. Import the source tree with PhxRE on Linux (including WSL) or macOS.",
    },
    io: {
        category: "execution_failure",
        message: "Reference source files could not be read. Check directory permissions and try again.",
    },
    parse: {
        category: "execution_failure",
        message: "Reference source could not be indexed. Check that the source tree is readable, then try again.",
    },
};
/** Safe CLI projection for a historical-source import failure. */
export const projectReferenceSourceImportError = (error) => {
    const primary = IMPORT_FAILURE_GUIDANCE[error.code];
    const cleanupMessage = error.cleanup === undefined
        ? ""
        : ` Cleanup failed during import for ${error.cleanup.resources.join(", ")}: ${error.cleanup.reason}.`;
    return {
        category: primary.category,
        message: `${error.message} ${primary.message}${cleanupMessage}`,
        ...(error.cleanup === undefined ? {} : { cleanup: error.cleanup }),
        ...(error.partial === undefined ? {} : { partial: error.partial }),
    };
};
export const DEFAULT_REFERENCE_SOURCE_IGNORE_PATTERNS = [
    ".git/",
    ".git/hooks/",
    "node_modules/",
    "dist/",
    "build/",
    "coverage/",
    "htmlcov/",
    ".coverage",
    "*.log",
];
