import { AnalysisError } from "../domain/analysisErrorBase.js";
import { analysisErrorWithCleanupFailure } from "../domain/analysisErrorCleanup.js";
import { BrowserObservationError } from "../domain/browserObservationError.js";
import { CdpConnection } from "./CdpConnection.js";
import { bindCdpTransportCleanup, } from "./CdpTargetSessionOwner.js";
import { cdpTargetWebSocket, discoverCdpBrowserSocket, discoverCdpEndpoint, withCdpDiscoveryDeadline, } from "./CdpEndpoint.js";
/**
 * Discover one passive browser endpoint through its selected transport. A
 * browser socket's handshake and discovery share one discovery deadline.
 */
export const openCdpEndpoint = async (endpoint, operation, signal, timeoutMs, owner) => {
    if (endpoint.transport === "http_discovery")
        return {
            discovery: await discoverCdpEndpoint(endpoint.url, operation, signal),
            connection: undefined,
        };
    return await withCdpDiscoveryDeadline(operation, signal, async (deadlineSignal) => {
        const connection = owner === undefined
            ? await CdpConnection.connect(endpoint.url, operation, deadlineSignal)
            : await owner.connect(endpoint.url, operation, { signal: deadlineSignal }, "browser-endpoint");
        try {
            return {
                discovery: await discoverCdpBrowserSocket(connection, endpoint.url, operation, deadlineSignal),
                connection,
            };
        }
        catch (cause) {
            if (owner === undefined) {
                await connection.close();
                throw cause;
            }
            try {
                await owner.finish(connection);
            }
            catch (cleanupCause) {
                throw combineOpenFailure(cause, cleanupCause, operation);
            }
            throw cause;
        }
    }, timeoutMs);
};
/** Open one authorized target through its supported browser or page transport. */
export const openCdpTargetSession = async (discovery, target, operation, signal, limits, owner) => {
    const webSocket = cdpTargetWebSocket(discovery, target, operation);
    const connection = owner === undefined
        ? await CdpConnection.connect(webSocket.url, operation, signal, limits)
        : await owner.connect(webSocket.url, operation, signal === undefined ? {} : { signal }, target.id, limits);
    if (webSocket.scope === "page")
        return { connection, sessionId: undefined };
    try {
        return await attachCdpTargetSession(connection, target, operation, signal, owner);
    }
    catch (cause) {
        if (owner === undefined)
            throw cause;
        try {
            await owner.finish(connection);
        }
        catch (cleanupCause) {
            throw combineOpenFailure(cause, cleanupCause, operation);
        }
        throw cause;
    }
};
/** Attach one target through an open browser socket, which the session then owns. */
export const attachCdpTargetSession = async (connection, target, operation, signal, owner) => {
    try {
        const attached = await connection.send("Target.attachToTarget", { targetId: target.id, flatten: true }, undefined, signal);
        return { connection, sessionId: attachedSessionId(attached, operation) };
    }
    catch (cause) {
        if (owner === undefined) {
            await connection.close();
            throw cause;
        }
        throw cause;
    }
};
const combineOpenFailure = (primary, cleanup, operation) => primary instanceof AnalysisError && cleanup instanceof AnalysisError
    ? bindCdpTransportCleanup(cleanup, analysisErrorWithCleanupFailure(primary, cleanup, operation))
    : new AggregateError([primary, cleanup], `CDP operation ${operation} failed and its transport cleanup is incomplete.`, { cause: primary });
/** Disable enabled domains, detach browser sessions, and close PhxRE's socket. */
export const closeCdpTargetSession = async (targetSession, enabledDomains, signal, owner) => {
    if (owner !== undefined) {
        await owner.finish(targetSession.connection, () => cleanupCdpTargetCommands(targetSession, enabledDomains, signal));
        return;
    }
    await cleanupCdpTargetCommands(targetSession, enabledDomains, signal);
    await targetSession.connection.close();
};
const cleanupCdpTargetCommands = async (targetSession, enabledDomains, signal) => {
    const { connection, sessionId } = targetSession;
    const cleanup = new AbortController();
    const domainSignal = signal === undefined
        ? cleanup.signal
        : AbortSignal.any([cleanup.signal, signal]);
    const timeout = setTimeout(() => cleanup.abort(), 1000);
    timeout.unref();
    try {
        if (signal?.aborted !== true) {
            for (const domain of enabledDomains) {
                if (domainSignal.aborted)
                    break;
                try {
                    await connection.send(`${domain}.disable`, {}, sessionId, domainSignal);
                }
                catch {
                    // Best-effort domain cleanup; transport close is the definitive boundary.
                }
            }
        }
        // Cancellation skips optional domain shutdown but still releases the
        // attached session using its independent, bounded cleanup signal.
        if (!cleanup.signal.aborted && sessionId !== undefined)
            try {
                await connection.send("Target.detachFromTarget", { sessionId }, undefined, cleanup.signal);
            }
            catch {
                // Best-effort detach; transport close is the definitive boundary.
            }
    }
    finally {
        clearTimeout(timeout);
        cleanup.abort();
    }
};
const attachedSessionId = (value, operation) => {
    if (typeof value !== "object" ||
        value === null ||
        !("sessionId" in value) ||
        typeof value.sessionId !== "string" ||
        value.sessionId.length === 0)
        throw new BrowserObservationError(operation, "protocol_error");
    return value.sessionId;
};
