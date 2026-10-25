import { copyFile, lstat, mkdir, readFile, rm } from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import { dirname, join } from "node:path";
import writeFileAtomic from "write-file-atomic";
import { err, ok } from "../domain/result.js";
import { readBoundedFileBytes } from "../process/BoundedFileBytes.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { PRODUCT_IDENTITY } from "../identity.js";
import { NonRegularFileReadError, RegularFileChangedError, } from "../filesystem/RegularFile.js";
import { RegularFileCleanupFailure, withRegularFile, } from "./RegularFileRead.js";
import { clientSkillDirectories } from "./SupportedClients.js";
import { preserveCurrentRecoveryBackup } from "./SetupRecoveryBackup.js";
export const MANAGED_SKILL_FILES = [
    "SKILL.md",
    "references/connection-and-recovery.md",
    "references/native-and-artifacts.md",
    "references/javascript-applications.md",
    "references/android-applications.md",
    "references/runtime-observation.md",
    "references/evidence-workflows.md",
  "references/environments.md",
];
export const isManagedSkillManifest = (content) => content.startsWith(`---\nname: ${PRODUCT_IDENTITY.skillName}\n`) ||
    content.startsWith(`---\r\nname: ${PRODUCT_IDENTITY.skillName}\r\n`);
export const readSkillFile = (path, resources) => readSkillFileState(path, resources).then(({ bytes }) => bytes.toString("utf8"));
const readSkillFileState = async (path, resources) => withRegularFile(path, async (handle, stats) => {
    const bytes = await readBoundedFileBytes(handle, stats.size, {
        expectedSize: stats.size,
    });
    if (bytes === undefined || bytes.length !== stats.size)
        throw new RegularFileChangedError(path);
    return { bytes, mode: stats.mode & 0o7777 };
}, {
    symlinks: "reject",
    ...(resources === undefined ? {} : { resources }),
});
const canonicalSkillContent = (relativePath) => readFile(new URL(`../../skills/${PRODUCT_IDENTITY.skillName}/${relativePath}`, import.meta.url), "utf8");
/** Expected failure while replacing a managed skill bundle. */
export class SetupSkillInstallError extends Error {
    _tag = "SetupSkillInstallError";
    path;
    stage;
    reason;
    rollbackFailures;
    recoveryBackupPaths;
    constructor(input) {
        const message = [
            `PhxRE skill ${input.stage} failed at ${input.path}: ${input.reason}.`,
            ...(input.rollbackFailures.length === 0
                ? []
                : [
                    `Rollback also failed for ${input.rollbackFailures.map(({ path, reason }) => `${path} (${reason})`).join(", ")}.`,
                    ...(input.recoveryBackupPaths.length === 0
                        ? []
                        : [
                            `Existing-file backups remain at ${input.recoveryBackupPaths.join(", ")}.`,
                        ]),
                ]),
        ].join(" ");
        super(message, { cause: input.cause });
        this.path = input.path;
        this.stage = input.stage;
        this.reason = input.reason;
        this.rollbackFailures = input.rollbackFailures;
        this.recoveryBackupPaths = input.recoveryBackupPaths;
    }
    get remediation() {
        return `${this.message} Check permissions and rerun setup.`;
    }
}
const systemSkillInstallFileOperations = {
    mkdir: async (path) => {
        await mkdir(path, { recursive: true });
    },
    backup: (source, destination) => copyFile(source, destination, fsConstants.COPYFILE_EXCL),
    write: (path, content, mode) => writeFileAtomic(path, content, { encoding: "utf8", mode }),
    remove: (path) => rm(path, { force: true }),
};
/** Resolve the skill roots required by a client selection, or all owned roots. */
export const skillDestinations = (home, clientIds, environment = {}, platform = process.platform) => clientSkillDirectories(home, clientIds, environment, platform).map(({ client, directory }) => ({
    client,
    path: join(directory, PRODUCT_IDENTITY.skillName),
}));
/** Resolve existing PhxRE-owned skill roots using setup's canonical destinations. */
export const existingSkillDestinations = async (home, environment = {}, platform = process.platform, resources) => {
    const existing = [];
    for (const destination of skillDestinations(home, undefined, environment, platform)) {
        try {
            const issues = await skillDirectoryIssues([destination]);
            if (issues.some(({ kind }) => kind === "unreadable"))
                throw skillDirectoryFailure(issues);
            if (issues.length > 0)
                continue;
            const manifest = join(destination.path, "SKILL.md");
            const content = await readSkillFile(manifest, resources);
            if (isManagedSkillManifest(content))
                existing.push(destination);
        }
        catch (cause) {
            if (cause instanceof Error && "code" in cause && cause.code === "ENOENT")
                continue;
            if (cause instanceof RegularFileCleanupFailure ||
                cause instanceof ArtifactReaderFailure)
                throw cause;
            if (cause instanceof NonRegularFileReadError)
                continue;
            throw cause;
        }
    }
    return existing;
};
const readOptionalSkillState = async (path, resources) => {
    try {
        return await readSkillFileState(path, resources);
    }
    catch (cause) {
        if (cause instanceof Error && "code" in cause && cause.code === "ENOENT")
            return undefined;
        throw cause;
    }
};
const inspectSkillDirectory = async (path) => {
    try {
        const directory = await lstat(path);
        if (directory.isSymbolicLink())
            return err({
                path,
                kind: "symbolic_link",
                detail: "Skill directory is a symbolic link.",
            });
        if (!directory.isDirectory())
            return err({
                path,
                kind: "not_directory",
                detail: "Skill path is not a directory.",
            });
        return ok(undefined);
    }
    catch (cause) {
        if (cause instanceof Error && "code" in cause && cause.code === "ENOENT")
            return ok(undefined);
        return err({
            path,
            kind: "unreadable",
            detail: cause instanceof Error ? cause.message : String(cause),
        });
    }
};
const skillDirectoryIssues = async (destinations) => {
    const issues = [];
    for (const { path } of destinations) {
        const root = await inspectSkillDirectory(path);
        if (!root.ok) {
            issues.push(root.error);
            continue;
        }
        const references = await inspectSkillDirectory(join(path, "references"));
        if (!references.ok)
            issues.push(references.error);
    }
    return issues;
};
const skillDirectoryFailure = (issues) => new SetupSkillInstallError({
    path: issues[0]?.path ?? "skill bundle",
    stage: "prepare",
    reason: `${issues.map(({ path, detail }) => `${detail} (${path})`).join(" ")} Use a regular skill directory, or run setup with --skill=false to configure the client without installing the skill`,
    rollbackFailures: [],
    recoveryBackupPaths: [],
    cause: issues,
});
/** Validate only final selected roots; permission to install is separate from freshness. */
export const validateCanonicalSkillDirectories = async (home, clientIds, environment = {}, platform = process.platform) => {
    const issues = await skillDirectoryIssues(skillDestinations(home, clientIds, environment, platform));
    return issues.length === 0
        ? ok(undefined)
        : err(skillDirectoryFailure(issues));
};
const canonicalSkillFiles = async (home, clientIds, environment = {}, platform = process.platform, resources) => {
    const destinations = skillDestinations(home, clientIds, environment, platform);
    const admission = await validateCanonicalSkillDirectories(home, clientIds, environment, platform);
    if (!admission.ok)
        throw admission.error;
    return Promise.all(destinations.flatMap(({ path: root }) => MANAGED_SKILL_FILES.map(async (relativePath) => {
        const destination = join(root, relativePath);
        return {
            destination,
            content: await canonicalSkillContent(relativePath),
            original: await readOptionalSkillState(destination, resources),
        };
    })));
};
const inspectCanonicalSkill = async (home, clientIds, environment, platform, resources) => {
    const destinations = skillDestinations(home, clientIds, environment, platform);
    const issues = clientIds === undefined
        ? []
        : [...(await skillDirectoryIssues(destinations))];
    if (issues.length > 0)
        return err({
            _tag: "SkillInspectionFailure",
            issues,
            cause: issues,
            manifest: undefined,
        });
    let canonical = true;
    let manifest;
    let failureCause;
    let installedDestination = false;
    for (const destination of destinations) {
        const { path: root } = destination;
        const pathIssues = clientIds === undefined ? await skillDirectoryIssues([destination]) : [];
        if (pathIssues.length > 0) {
            issues.push(...pathIssues);
            if (failureCause === undefined)
                failureCause = pathIssues;
            installedDestination = true;
            canonical = false;
            continue;
        }
        let rootCanonical = true;
        let rootHasFiles = false;
        const rootIssues = [];
        for (const relativePath of MANAGED_SKILL_FILES) {
            const destination = join(root, relativePath);
            let original;
            try {
                original = await readOptionalSkillState(destination, resources);
            }
            catch (cause) {
                if (cause instanceof RegularFileCleanupFailure ||
                    cause instanceof ArtifactReaderFailure)
                    throw cause;
                rootIssues.push({
                    path: destination,
                    kind: "unreadable",
                    detail: causeReason(cause),
                });
                if (failureCause === undefined)
                    failureCause = cause;
                rootCanonical = false;
                rootHasFiles = true;
                continue;
            }
            if (original !== undefined)
                rootHasFiles = true;
            if (relativePath === "SKILL.md" && manifest === undefined)
                manifest = original?.bytes.toString("utf8");
            // A mismatch settles freshness, but not coverage of later read failures.
            if (original === undefined)
                rootCanonical = false;
            else if (rootCanonical) {
                const content = await canonicalSkillContent(relativePath);
                rootCanonical = original.bytes.equals(Buffer.from(content, "utf8"));
            }
        }
        if (clientIds !== undefined || rootHasFiles || rootIssues.length > 0) {
            installedDestination ||= rootHasFiles;
            canonical = canonical && rootCanonical;
            issues.push(...rootIssues);
        }
    }
    return issues.length === 0
        ? ok({ canonical, manifest, installedDestination })
        : err({
            _tag: "SkillInspectionFailure",
            issues,
            cause: failureCause,
            manifest,
        });
};
/** Report whether setup would change any file in the managed PhxRE skill bundle. */
export const canonicalSkillNeedsInstall = async (home, clientIds = [], environment = {}, platform = process.platform, resources) => {
    try {
        const inspection = await inspectCanonicalSkill(home, clientIds, environment, platform, resources);
        return !inspection.ok || !inspection.value.canonical;
    }
    catch (cause) {
        if (cause instanceof RegularFileCleanupFailure ||
            cause instanceof ArtifactReaderFailure)
            throw cause;
        // A copy needs attention; selected-root admission decides whether it may be installed.
        void cause;
        return true;
    }
};
const causeReason = (cause) => cause instanceof Error ? cause.message : String(cause);
const causePath = (cause) => cause instanceof Error && "path" in cause && typeof cause.path === "string"
    ? cause.path
    : undefined;
const restoreSkillFiles = async (attempted, operations) => {
    const failures = [];
    for (const { destination, original } of [...attempted].reverse()) {
        try {
            if (original === undefined)
                await operations.remove(destination);
            else
                await operations.write(destination, original.bytes, original.mode);
        }
        catch (cause) {
            failures.push({ path: destination, reason: causeReason(cause) });
        }
    }
    return failures;
};
/** Transactionally install the canonical skill bundle and optional references. */
export const installCanonicalSkill = async (home, clientIds = [], environment = {}, platform = process.platform, operations = systemSkillInstallFileOperations, resources) => {
    let attempted = [];
    let stage = "prepare";
    let failingPath = "skill bundle";
    const recoveryPaths = new Map();
    try {
        const canonical = await canonicalSkillFiles(home, clientIds, environment, platform, resources);
        const changed = canonical.filter(({ content, original }) => original?.bytes.equals(Buffer.from(content, "utf8")) !== true);
        if (changed.length === 0)
            return ok("unchanged");
        stage = "backup";
        for (const { destination, original } of changed) {
            failingPath = destination;
            await operations.mkdir(dirname(destination));
            if (original !== undefined) {
                const preserved = await preserveCurrentRecoveryBackup(`${destination}.phxre.backup`, destination, original.bytes, {
                    copy: operations.backup,
                    ...(resources === undefined ? {} : { resources }),
                });
                if (!preserved.ok)
                    throw new Error(preserved.error.detail);
                recoveryPaths.set(destination, preserved.value);
            }
        }
        stage = "write";
        for (const file of changed) {
            failingPath = file.destination;
            // An atomic writer can publish and then reject; include the target before
            // entering it so rollback covers that ambiguous outcome.
            attempted.push(file);
            await operations.write(file.destination, file.content, file.original?.mode ?? 0o600);
        }
        stage = "readback";
        for (const { destination, content } of changed) {
            failingPath = destination;
            if (!(await readSkillFileState(destination, resources)).bytes.equals(Buffer.from(content, "utf8")))
                throw new Error(`skill readback mismatch: ${destination}`);
        }
        return ok("installed");
    }
    catch (cause) {
        if (stage === "prepare" && cause instanceof SetupSkillInstallError)
            return err(cause);
        failingPath = causePath(cause) ?? failingPath;
        const rollbackFailures = await restoreSkillFiles(attempted, operations);
        return err(new SetupSkillInstallError({
            path: failingPath,
            stage,
            reason: causeReason(cause),
            rollbackFailures,
            recoveryBackupPaths: attempted.flatMap(({ destination, original }) => original === undefined || recoveryPaths.get(destination) === undefined
                ? []
                : [recoveryPaths.get(destination)]),
            cause,
        }));
    }
};
/** Read installed skill metadata and compare every managed location. */
export const readInstalledSkillIdentity = async (home, clientIds, environment = {}, platform = process.platform, resources) => {
    const inspection = await inspectCanonicalSkill(home, clientIds, environment, platform, resources);
    if (inspection.ok && !inspection.value.installedDestination)
        return undefined;
    const content = inspection.ok
        ? inspection.value.manifest
        : inspection.error.manifest;
    const issues = inspection.ok ? [] : inspection.error.issues;
    const toolCount = content === undefined
        ? undefined
        : /^\s{2}tool_count:\s*(\d+)\s*$/mu.exec(content)?.[1];
    return {
        canonical: inspection.ok && inspection.value.canonical,
        version: content === undefined
            ? null
            : (/^\s{2}version:\s*"([^"]+)"\s*$/mu.exec(content)?.[1] ?? null),
        toolCount: toolCount === undefined ? null : Number.parseInt(toolCount, 10),
        ...(issues.length === 0 ? {} : { issues }),
    };
};
