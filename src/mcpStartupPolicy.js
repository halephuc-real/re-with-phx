/**
 * Supported MCP startup deadlines and operation headroom.
 *
 * Client timeouts are caller-facing configuration. The smaller phase budgets
 * preserve operational headroom, while the doctor deadline covers additional
 * inventory requests after initialization.
 */
export const MCP_STARTUP_POLICY = {
    codexStartupTimeoutSeconds: 30,
    kimiStartupTimeoutMs: 30000,
    toolOperationHeadroomMs: 120000,
    initializeBudgetMs: 15000,
    toolsListBudgetMs: 5000,
    firstCatalogBudgetMs: 20000,
    doctorDeadlineMs: 30000,
    doctorStderrBytes: 64 * 1024,
};
/** Allow for known startup phases and caller-selected upstream request budgets. */
export const mcpProviderDeadlineAllowanceMs = (inputs) => {
    const selectedProvider = inputs.analysisProvider;
    const selectedTimeout = selectedProvider === "ghidra"
        ? inputs.ghidraStartupTimeoutMs
        : selectedProvider === "hopper"
            ? inputs.hopperStartupTimeoutMs
            : Math.max(inputs.ghidraStartupTimeoutMs, inputs.hopperStartupTimeoutMs);
    return Math.max(selectedTimeout, inputs.jebMcpTimeoutMs ?? 0, inputs.providerRequestTimeoutMs ?? 0);
};
/** Add operation headroom to the parsed provider deadline allowance. */
export const recommendedMcpToolTimeoutMs = (inputs) => mcpProviderDeadlineAllowanceMs(inputs) +
    MCP_STARTUP_POLICY.toolOperationHeadroomMs;
/** Round up so Codex's whole-second deadline still covers the millisecond budget. */
export const recommendedMcpToolTimeoutSeconds = (inputs) => Math.ceil(recommendedMcpToolTimeoutMs(inputs) / 1000);
