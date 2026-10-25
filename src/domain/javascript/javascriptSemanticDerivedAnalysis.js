import { collectJavaScriptSemanticAsyncEffects } from "./javascriptSemanticAsyncEffects.js";
import { collectJavaScriptSemanticCalls } from "./javascriptSemanticCalls.js";
import { collectJavaScriptSemanticChildProcesses } from "./javascriptSemanticChildProcesses.js";
import { collectJavaScriptSemanticFingerprintsSteps } from "./javascriptSemanticFingerprints.js";
import { collectJavaScriptSemanticDataEffects } from "./javascriptSemanticDataEffects.js";
import { collectJavaScriptSemanticPromises } from "./javascriptSemanticPromises.js";
import { collectJavaScriptSemanticObjects } from "./javascriptSemanticObjects.js";
import { collectJavaScriptSemanticResources } from "./javascriptSemanticResources.js";
/** Compose bounded semantic passes after lexical definitions are available. */
/**
 * Collect derived semantics with a yield between collectors. Each collector
 * completes before the next starts, so results equal the synchronous form.
 */
export function* collectJavaScriptDerivedSemanticsSteps(program, state, callables, references, parserPartial) {
    const calls = collectJavaScriptSemanticCalls(program, state, callables);
    yield;
    const promiseOperations = collectJavaScriptSemanticPromises(program, state, callables);
    yield;
    const asyncEffects = collectJavaScriptSemanticAsyncEffects(program, state, callables);
    yield;
    const childProcesses = collectJavaScriptSemanticChildProcesses(program, state, callables);
    yield;
    const dataEffects = collectJavaScriptSemanticDataEffects(program, state, callables);
    yield;
    const resourceOperations = collectJavaScriptSemanticResources(program, state, callables);
    yield;
    const objectOperations = collectJavaScriptSemanticObjects(program, state, callables);
    yield;
    const functionFingerprints = yield* collectJavaScriptSemanticFingerprintsSteps({
        state,
        callables,
        calls,
        promises: promiseOperations,
        events: asyncEffects.eventOperations,
        timers: asyncEffects.timerOperations,
        childProcessSpawns: childProcesses.childProcessSpawns,
        childProcessInteractions: childProcesses.childProcessInteractions,
        requestOperations: dataEffects.requestOperations,
        resourceOperations,
        parserPartial,
    });
    return {
        ...calls,
        promiseOperations,
        ...asyncEffects,
        ...childProcesses,
        ...dataEffects,
        resourceOperations,
        objectOperations,
        functionFingerprints,
    };
}
