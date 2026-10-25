import { isAbsolute } from "node:path";
import { z } from "zod";
import { AnalysisCleanupLease } from "../artifacts/AnalysisCleanupLease.js";
import { ConfigurationError } from "../domain/configurationErrors.js";
import { AnalysisCancelledError } from "../domain/analysisErrorCore.js";
import { err, ok } from "../domain/result.js";
import { withOwnedRegularFile, regularFileCancellation, RegularFileCleanupFailure, } from "../filesystem/OwnedRegularFile.js";
import { assertRegularFileActive, NonRegularFileReadError, } from "../filesystem/RegularFile.js";
const common = {
    mode: z.enum(["attached", "headless"]).default("attached"),
    protocol: z.literal("native").optional(),
    timeoutMs: z.number().int().positive().max(2147483647).default(300000),
    workspaceRoot: z
        .string()
        .refine(isAbsolute, "workspaceRoot must be absolute on the PhxRE host")
        .optional(),
};
const registrationSchema = z
    .union([
    z
        .object({
        ...common,
        type: z.literal("stdio").optional(),
        command: z.string().min(1),
        args: z.array(z.string()).default([]),
        env: z.record(z.string(), z.string()).default({}),
    })
        .strict(),
    z
        .object({
        ...common,
        type: z.literal("http").optional(),
        url: z.url().refine((value) => {
            const url = new URL(value);
            return (["http:", "https:"].includes(url.protocol) &&
                ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname) &&
                url.username === "" &&
                url.password === "");
        }, "IDA MCP must use a local HTTP endpoint without URL credentials"),
        headers: z.record(z.string(), z.string()).default({}),
    })
        .strict(),
])
    .refine((config) => config.protocol !== "native" || config.mode === "attached", "The native IDA MCP protocol requires attached mode");
/** Select a protocol without changing existing attached/headless registrations. */
export const idaProtocol = (config) => config.protocol ?? (config.mode === "attached" ? "legacy" : "modern");
/** Read one explicit registration without starting or installing a provider. */
export const readIdaConfiguration = (path, options) => options.resourceScope.run(async () => {
    let closeLease;
    try {
        const text = await withOwnedRegularFile(path, {
            ...(options.signal === undefined ? {} : { signal: options.signal }),
            retainFailedClose: (owner) => {
                closeLease = AnalysisCleanupLease.forCloseOwner(owner, path);
                options.resourceScope.retain({
                    close: () => closeLease.release(),
                    get cleanupResources() {
                        return closeLease.cleanupResources;
                    },
                }, path);
            },
        }, async (handle) => {
            const metadata = await handle.stat();
            if (metadata.size > MAXIMUM_REGISTRATION_BYTES)
                throw registrationTooLarge();
            const bytes = Buffer.alloc(MAXIMUM_REGISTRATION_BYTES + 1);
            let length = 0;
            while (length < bytes.length) {
                assertRegularFileActive(options.signal);
                const { bytesRead } = await handle.read(bytes, length, bytes.length - length, null);
                if (bytesRead === 0)
                    break;
                length += bytesRead;
            }
            if (length > MAXIMUM_REGISTRATION_BYTES)
                throw registrationTooLarge();
            return bytes.toString("utf8", 0, length);
        });
        const input = JSON.parse(text);
        const envelope = z
            .object({ mcpServers: z.object({ "ida-pro-mcp": z.unknown() }) })
            .safeParse(input);
        const parsed = registrationSchema.safeParse(envelope.success ? envelope.data.mcpServers["ida-pro-mcp"] : input);
        return parsed.success
            ? ok(parsed.data)
            : err(idaConfigurationError("PHXRE_IDA_MCP_CONFIG must contain an IDA MCP command/args or local url registration; see docs/ida-provider.md.", parsed.error));
    }
    catch (cause) {
        if (cause instanceof ConfigurationError)
            return err(cause);
        if (cause instanceof NonRegularFileReadError)
            return err(idaConfigurationError(`PHXRE_IDA_MCP_CONFIG must select a regular JSON file: ${path}`, cause));
        if (cause instanceof AnalysisCancelledError)
            throw cause;
        const cancellation = regularFileCancellation(cause);
        if (cancellation !== undefined) {
            if (cause instanceof RegularFileCleanupFailure) {
                const error = new AnalysisCancelledError("ida:registration", {
                    cause: cancellation.reason,
                    cleanup: {
                        reason: cause.cleanupCause instanceof Error
                            ? cause.cleanupCause.message
                            : String(cause.cleanupCause),
                        resources: [path],
                    },
                });
                closeLease?.bindCleanupError(error);
                throw error;
            }
            throw new AnalysisCancelledError("ida:registration", {
                cause: cancellation.reason,
            });
        }
        if (cause instanceof RegularFileCleanupFailure) {
            const primary = cause.outcome.kind === "failed"
                ? cause.outcome.cause
                : cause.cleanupCause;
            const primaryMessage = cause.outcome.kind === "failed"
                ? primary instanceof ConfigurationError
                    ? primary.message
                    : primary instanceof NonRegularFileReadError
                        ? `PHXRE_IDA_MCP_CONFIG must select a regular JSON file: ${path}`
                        : `Cannot read IDA MCP registration ${path}: ${primary instanceof Error ? primary.message : String(primary)}`
                : `Cannot close IDA MCP registration ${path}; provide a readable JSON configuration.`;
            const error = new ConfigurationError(primaryMessage, {
                cause,
                cleanup: {
                    reason: cause.cleanupCause instanceof Error
                        ? cause.cleanupCause.message
                        : String(cause.cleanupCause),
                    resources: [path],
                },
                settings: [
                    {
                        setting: "PHXRE_IDA_MCP_CONFIG",
                        constraint: `Close remains incomplete for ${path}`,
                    },
                ],
            });
            closeLease?.bindCleanupError(error);
            return err(error);
        }
        return err(idaConfigurationError(`Cannot read IDA MCP registration ${path}; provide a readable JSON configuration.`, cause));
    }
});
const MAXIMUM_REGISTRATION_BYTES = 65536;
/**
 * Read at most the registration limit from one regular file. Opening without
 * blocking and checking the descriptor's type keeps a FIFO, socket or device
 * from stalling diagnostics while it waits for a producer.
 */
const registrationTooLarge = () => idaConfigurationError("PHXRE_IDA_MCP_CONFIG exceeds the 64 KiB registration size.");
/** A PHXRE_IDA_MCP_CONFIG rejection that names the setting it concerns. */
export const idaConfigurationError = (constraint, cause) => new ConfigurationError(constraint, {
    ...(cause === undefined ? {} : { cause }),
    settings: [{ setting: "PHXRE_IDA_MCP_CONFIG", constraint }],
});
