/** Require configured facts to pass while preserving workflow and execution gates. */
export const agentEvaluationPassed = (result) => result.exitCode === 0 &&
    (result.expectedFirstTool === null
        ? !result.naturalUse
        : result.naturalUse) &&
    result.correctFirstTool &&
    result.repeatedCallCount === 0 &&
    result.inputValidationFailureCount === 0 &&
    result.requiredToolSubsequenceMet &&
    result.inputTokens > 0 &&
    (result.expectedFirstTool === null
        ? result.targetClarificationPassed === true
        : result.factualCorrectness === "passed" ||
            (result.factualCorrectness === "not_assessed" &&
                result.answerHeuristicsMet &&
                result.epistemicCuePresent));
/** Keep assessed fixture outcomes and scenarios without truth oracles distinct. */
export const summarizeFactualCorrectness = (results) => {
    const passed = results.filter(({ factualCorrectness }) => factualCorrectness === "passed").length;
    const failed = results.filter(({ factualCorrectness }) => factualCorrectness === "failed").length;
    const status = failed > 0 ? "failed" : passed > 0 ? "passed" : "not_assessed";
    return {
        status,
        scope: "configured_fixture_claims",
        counts: {
            assessed: passed + failed,
            passed,
            failed,
            notAssessed: results.length - passed - failed,
        },
    };
};
