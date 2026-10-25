import { isAbsolute } from "node:path";
import { AnalysisCapabilityUnavailableError } from "../domain/analysisErrorCore.js";
/** Environment keys selecting the caller's tshark and capinfos binaries. */
export const TSHARK_COMMAND_ENV = "PHXRE_TSHARK_COMMAND";
export const CAPINFOS_COMMAND_ENV = "PHXRE_CAPINFOS_COMMAND";
const TOOL_REMEDIATION = `Supply Wireshark 4.x tshark and capinfos on PATH or through absolute ${TSHARK_COMMAND_ENV} and ${CAPINFOS_COMMAND_ENV}; PhxRE does not install them.`;
/**
 * Host-tool refusals concern the caller's Wireshark installation, not the
 * target, so they carry their own guidance instead of the generic advice to
 * choose another target.
 */
export const pcapToolUnavailable = (operation, reason, options) => new AnalysisCapabilityUnavailableError("pcap", operation, reason, {
    ...options,
    userMessage: `${/[.!?]$/u.test(reason) ? reason : `${reason}.`} ${TOOL_REMEDIATION}`,
});
/**
 * Resolve the caller-supplied tshark and capinfos binaries. Each accepts an
 * absolute environment path or falls back to PATH resolution, mirroring the
 * mitmdump pattern. PhxRE never installs the Wireshark suite.
 */
export const resolvePcapTools = (environment) => {
    const tsharkEnv = environment[TSHARK_COMMAND_ENV];
    const capinfosEnv = environment[CAPINFOS_COMMAND_ENV];
    if (tsharkEnv !== undefined &&
        tsharkEnv.trim() !== "" &&
        !isAbsolute(tsharkEnv))
        throw new PcapConfigurationFailure("tshark_not_absolute", `${TSHARK_COMMAND_ENV} must be an absolute path to the tshark binary`, { configured: tsharkEnv });
    if (capinfosEnv !== undefined &&
        capinfosEnv.trim() !== "" &&
        !isAbsolute(capinfosEnv))
        throw new PcapConfigurationFailure("capinfos_not_absolute", `${CAPINFOS_COMMAND_ENV} must be an absolute path to the capinfos binary`, { configured: capinfosEnv });
    return {
        tshark: {
            command: tsharkEnv === undefined || tsharkEnv.trim() === ""
                ? "tshark"
                : tsharkEnv,
            source: tsharkEnv === undefined || tsharkEnv.trim() === ""
                ? "path"
                : "environment",
        },
        capinfos: {
            command: capinfosEnv === undefined || capinfosEnv.trim() === ""
                ? "capinfos"
                : capinfosEnv,
            source: capinfosEnv === undefined || capinfosEnv.trim() === ""
                ? "path"
                : "environment",
        },
    };
};
export class PcapConfigurationFailure extends Error {
    code;
    diagnostics;
    constructor(code, message, diagnostics = {}, options) {
        super(message, options);
        this.code = code;
        this.diagnostics = diagnostics;
    }
}
/** Recognize the selected Wireshark tool's version banner. */
const parseVersion = (stdout, tool) => {
    const line = stdout
        .split(/\r?\n/u)
        .map((entry) => entry.trim())
        .find((entry) => entry !== "");
    const parsed = line === undefined
        ? null
        : new RegExp(`^${tool} \\(Wireshark\\) (\\d+)\\.\\d+\\.\\d+`, "iu").exec(line);
    if (parsed === null || line === undefined)
        return null;
    if (parsed[1] !== "4")
        throw new PcapConfigurationFailure(`${tool}_version_unsupported`, "Packet summary inspection currently requires Wireshark 4.x tools; select an installation with the admitted output profile.", { version: line });
    return line;
};
/** Probe both tools without reading any capture file. */
export const inspectPcapClient = async (selection, probe) => ({
    tsharkVersion: parseVersion(await probe(selection.tshark.command), "tshark"),
    capinfosVersion: parseVersion(await probe(selection.capinfos.command), "capinfos"),
});
/** Availability in the shape shared by every provider. */
const rejectionCodeOf = (code) => code.includes("missing")
    ? "executable_missing"
    : code.includes("unsupported")
        ? "unsupported_version"
        : code.includes("not_absolute")
            ? "not_configured"
            : "version_unresolved";
export const pcapConfigurationAvailability = (cause) => ({
    status: "unavailable",
    code: rejectionCodeOf(cause.code),
    reason: cause.message,
    diagnostics: { ...cause.diagnostics },
});
