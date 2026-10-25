import { AnalysisInputError } from "../domain/analysisErrorCore.js";
import { err } from "../domain/result.js";
export const invalidEnhancedInput = (name, cause) => Promise.resolve(err(new AnalysisInputError(name, { cause })));
