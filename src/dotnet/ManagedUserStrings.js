import { admitManagedProjection, managedDecodeBudget, } from "./ManagedDecodeBudget.js";
import { readMetadataUserString } from "./ManagedMetadataHeaps.js";
import { readManagedValue } from "./ManagedReaderFailure.js";
/**
 * The literals with their own coverage, which never enters member coverage.
 * Issues are unique by construction, so they are not deduplicated: each
 * distinct token yields one failure or per-offset conformance issues, and a
 * missing stream is one issue.
 */
const inventory = (literals, issues, scanned) => ({
    state: issues.length === 0 && scanned ? "complete" : "partial",
    literals,
    issues,
});
/** Bookkeeping per distinct ldstr token: its set entry and its sorted slot. */
const USER_STRING_TOKEN_BYTES = 128;
/** Decode each distinct #US literal an inspected method loads, in token order. */
export const parseUserStrings = (bytes, layout, parsed) => {
    const { methods } = parsed;
    const budget = managedDecodeBudget(layout);
    const scanned = parsed.unscannedMethods === 0 &&
        (parsed.unreadableSelectedTypes ?? 0) === 0;
    const userStrings = [];
    const issues = [];
    const tokens = new Set();
    try {
        // Only ldstr loads a literal; a malformed ldtoken can carry a 0x70 token.
        for (const method of methods)
            for (const { opcode, operand } of method.body.anchors)
                if (opcode === "ldstr" && operand !== null && !tokens.has(operand)) {
                    budget.admitTransient(USER_STRING_TOKEN_BYTES, null);
                    tokens.add(operand);
                }
        // Tokens are fixed-width lowercase hex, so string order is token order.
        const references = [];
        for (const token of [...tokens].sort()) {
            if (token.startsWith("0x70"))
                references.push(token);
            // An operand from another table names no #US item, with or without
            // the stream.
            else
                issues.push(admitManagedProjection({
                    code: "invalid-heap-index",
                    scope: `metadata.#US:${token}`,
                    offset: null,
                    detail: "ldstr operand does not name an item inside #US",
                }, budget));
        }
        if (references.length > 0 && layout.userStrings === null) {
            // A missing stream is one fact about the metadata, not one per token.
            issues.push(admitManagedProjection({
                code: "missing-stream",
                scope: "metadata.#US",
                offset: null,
                detail: `${String(references.length)} distinct ldstr operand(s) reference #US, but the metadata has no #US stream`,
            }, budget));
            return inventory(userStrings, issues, scanned);
        }
        for (const token of references) {
            const failures = [];
            readManagedValue(() => {
                const { offset, value, issues: observed, } = readMetadataUserString(bytes, layout, token);
                for (const issue of observed)
                    failures.push(issue);
                userStrings.push(admitManagedProjection({ token, offset, value }, budget));
            }, failures);
            for (const failure of failures)
                issues.push(admitManagedProjection(failure, budget));
        }
        return inventory(userStrings, issues, scanned);
    }
    finally {
        budget.releaseTransient();
    }
};
