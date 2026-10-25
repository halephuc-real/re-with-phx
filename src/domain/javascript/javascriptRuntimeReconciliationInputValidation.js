import { z } from "zod";
/** Prefix caller paths on a nested Zod validation boundary. */
export const parseAtPath = (parse, input, path) => {
    try {
        return parse(input);
    }
    catch (cause) {
        if (cause instanceof z.ZodError)
            throw new z.ZodError(cause.issues.map((issue) => ({
                ...issue,
                path: [...path, ...issue.path],
            })));
        throw cause;
    }
};
/** Represent one semantic caller constraint as a standard validation issue. */
export const invalidInput = (path, message) => new z.ZodError([{ code: "custom", path: [...path], message }]);
/** Verify an authenticated Evidence record against one runtime workflow. */
export const assertEvidenceIdentity = (evidence, expected, path) => {
    if (evidence.operation !== expected.operation ||
        evidence.predicate_type !== expected.predicate ||
        evidence.provider.id !== expected.providerId ||
        evidence.provider.name !== expected.providerName ||
        evidence.provider.version !== expected.providerVersion ||
        evidence.authority !== expected.authority ||
        evidence.confidence !== expected.confidence)
        throw invalidInput(path, `Evidence does not match the supported ${expected.operation} contract`);
};
