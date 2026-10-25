/** Whether an inventoried path has a source extension read by the analyzer. */
export const isJavaScriptSourcePath = (path) => /\.(?:cjs|cts|mjs|mts|js|jsx|ts|tsx)$/iu.test(path);
