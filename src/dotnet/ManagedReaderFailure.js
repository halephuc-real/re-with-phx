/** Bounded format failure retained as caller-visible managed coverage. */
export class ManagedReaderFailure extends Error {
    issue;
    constructor(issue, options) {
        super(issue.detail, options);
        this.issue = issue;
    }
}
/** Construct a typed managed parse failure at an exact byte location. */
export const managedFailure = (code, scope, detail, offset = null) => new ManagedReaderFailure({ code, scope, offset, detail });
/** Retain one malformed item's location while allowing independent items to be read. */
export const readManagedValue = (operation, issues) => {
    try {
        return operation();
    }
    catch (cause) {
        if (!(cause instanceof ManagedReaderFailure) ||
            cause.issue.code === "resource-limit")
            throw cause;
        issues.push(cause.issue);
        return undefined;
    }
};
/** Preserve issue order while collapsing the same malformed producer fact across facets. */
export const uniqueManagedParseIssues = (issues) => [
    ...new Map(issues.map((issue) => [JSON.stringify(issue), issue])).values(),
];
/**
 * Append issue lists one issue at a time. Spreading a list into `push` passes
 * one argument per issue, which overflows the stack on large malformed inputs.
 */
export const appendManagedParseIssues = (issues, ...found) => {
    for (const list of found)
        for (const issue of list)
            issues.push(issue);
};
