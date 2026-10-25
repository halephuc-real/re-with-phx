import { analysisInputErrorFromIssues } from "../inputIssueProjection.js";
import { err, ok } from "../result.js";
/** Parse a parent's result with its owning schema; issues point into the view source. */
export const parseAnalysisViewResult = (schema, parent) => {
    const parsed = schema.safeParse(parent.normalizedResult);
    if (parsed.success)
        return ok(parsed.data);
    return err(analysisInputErrorFromIssues("inspect_analysis_view", parsed.error.issues.map((issue) => ({
        ...issue,
        path: ["source", "normalized_result", ...issue.path],
    })), { source: { normalized_result: parent.normalizedResult } }, { cause: parsed.error }));
};
