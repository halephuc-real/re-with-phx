const errorMessage = (cause) => cause instanceof Error ? cause.message : String(cause);
/** Read only ownership tokens, using per-process fallback for missing batch rows. */
export async function* readProcessRunTokens(host, processes, signal) {
    signal?.throwIfAborted();
    if (processes.length === 0)
        return;
    let batch;
    let batchFailure;
    if (host.runTokens !== undefined) {
        try {
            batch =
                signal === undefined
                    ? await host.runTokens(processes)
                    : await host.runTokens(processes, signal);
        }
        catch (cause) {
            signal?.throwIfAborted();
            batchFailure = errorMessage(cause);
        }
    }
    for (const process of processes) {
        signal?.throwIfAborted();
        let observation = batch?.get(process.pid);
        if (observation === undefined) {
            try {
                const environment = signal === undefined
                    ? await host.environment(process.pid)
                    : await host.environment(process.pid, signal);
                observation = {
                    state: "readable",
                    runId: environment.PHXRE_PROCESS_RUN_ID,
                };
            }
            catch (cause) {
                signal?.throwIfAborted();
                const reason = errorMessage(cause);
                observation = {
                    state: "unavailable",
                    reason: batchFailure === undefined
                        ? reason
                        : `${reason}; run-token batch failed: ${batchFailure}`,
                };
            }
        }
        signal?.throwIfAborted();
        yield { process, observation };
    }
}
