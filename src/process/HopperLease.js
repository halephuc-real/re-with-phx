import { createHash } from "node:crypto";
import { chmod, mkdir, open, realpath, rm, rmdir } from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import { createConnection, createServer, } from "node:net";
import { join } from "node:path";
import { HopperStartError } from "../domain/hopperErrors.js";
import { safeParseJson } from "../domain/safeJson.js";
/** Shared private parent of Hopper lease sockets; it outlives individual sessions. */
export const HOPPER_TARGET_LEASE_DIRECTORY = join("/tmp", `phxre-hopper-${process.getuid?.() ?? 0}`);
/** Keep two PhxRE processes from opening duplicate Hopper documents for one target/profile. */
export const acquireHopperTargetLease = async (input) => {
    // Canonicalization is required for lease identity. A lexical fallback could
    // let two aliases reserve independent sockets for the same Hopper document.
    let targetPath;
    try {
        targetPath = await realpath(input.targetPath);
    }
    catch (cause) {
        throw new HopperStartError({
            cause,
            userMessage: `PhxRE could not resolve Hopper target ${JSON.stringify(input.targetPath)} to a canonical path before reserving the document. Confirm that the target exists and its path is accessible.`,
        });
    }
    return acquireLease({
        ...input,
        identity: {
            targetPath,
            targetKind: input.targetKind,
            loaderArgs: input.loaderArgs,
        },
    });
};
/** Reserve the Linux demo's singleton application before it can forward a target to another owner. */
export const acquireLinuxHopperApplicationLease = (input) => acquireLease({ ...input, identity: { application: "linux-hopper-demo" } });
/** Serialize approved publication/repair of one canonical signed-package entry. */
export const acquireHopperReleaseCacheLease = async (input) => acquireLease({
    runId: input.runId,
    identity: {
        cacheDirectory: await realpath(input.cacheDirectory),
        launcherSha256: input.launcherSha256,
        operation: "signed-package-retention",
    },
});
const acquireLease = async (input) => {
    const directory = input.directory ?? HOPPER_TARGET_LEASE_DIRECTORY;
    await ensureLeaseDirectory(directory);
    const key = createHash("sha256")
        .update(JSON.stringify(input.identity))
        .digest("hex")
        .slice(0, 32);
    const socketPath = join(directory, `${key}.sock`);
    const owner = { runId: input.runId, processId: process.pid };
    const acquisition = await tryAcquireLease(socketPath, owner);
    if (typeof acquisition !== "string")
        return acquisition;
    // Serialize stale cleanup through the replacement bind: otherwise two
    // recoverers can unlink the socket that one of them has just acquired.
    const recoveryPath = `${socketPath}.recovery`;
    await reserveRecovery(recoveryPath);
    let recovered;
    try {
        recovered = await tryAcquireLease(socketPath, owner);
        if (recovered === "stale")
            await rm(socketPath, { force: true });
        if (typeof recovered === "string")
            recovered = await tryAcquireLease(socketPath, owner);
        if (typeof recovered !== "string")
            return recovered;
        throw new HopperStartError({
            userMessage: "PhxRE could not reserve Hopper for this request. Close competing PhxRE sessions and retry.",
        });
    }
    finally {
        try {
            await rmdir(recoveryPath);
        }
        catch (cause) {
            if (typeof recovered !== "string" && recovered?.acquired)
                await recovered.lease.release();
            throw new HopperStartError({
                cause,
                userMessage: `PhxRE could not remove its Hopper recovery directory at ${JSON.stringify(recoveryPath)}. Check this directory's write access before retrying.`,
            });
        }
    }
};
const reserveRecovery = async (recoveryPath) => {
    try {
        await mkdir(recoveryPath, { mode: 0o700 });
    }
    catch (cause) {
        const busy = typeof cause === "object" &&
            cause !== null &&
            Reflect.get(cause, "code") === "EEXIST";
        throw new HopperStartError({
            cause,
            userMessage: busy
                ? `PhxRE could not reserve Hopper lease recovery at ${JSON.stringify(recoveryPath)}; the existing socket was left unchanged. Retry after concurrent startup finishes. If recovery was interrupted, stop PhxRE sessions and remove this recovery directory before retrying.`
                : `PhxRE could not create its Hopper recovery directory at ${JSON.stringify(recoveryPath)}; the existing socket was left unchanged. Check the parent directory's write access before retrying.`,
        });
    }
};
const tryAcquireLease = async (socketPath, owner) => {
    const server = createServer((socket) => sendOwner(socket, owner));
    // The lease lives exactly as long as its owning process. A lease retained
    // after unconfirmed cleanup must not keep a completed one-shot command
    // alive; process exit leaves a stale socket that later acquirers recover.
    server.unref();
    if (!(await bind(server, socketPath))) {
        const existingOwner = await readOwner(socketPath);
        return typeof existingOwner === "string"
            ? existingOwner
            : { acquired: false, owner: existingOwner };
    }
    try {
        await chmod(socketPath, 0o600);
    }
    catch (cause) {
        await closeServer(server);
        throw cause;
    }
    let released = false;
    return {
        acquired: true,
        lease: {
            socketPath,
            release: async () => {
                if (released)
                    return;
                // Node removes a bound Unix socket on close. A second unlink here
                // could remove a new owner's socket bound after that close.
                await closeServer(server);
                released = true;
            },
        },
    };
};
const ensureLeaseDirectory = async (directory) => {
    try {
        await mkdir(directory, { recursive: true, mode: 0o700 });
    }
    catch (cause) {
        throw new HopperStartError({
            cause,
            userMessage: "PhxRE could not create its private Hopper lease directory.",
        });
    }
    // Use O_DIRECTORY|O_NOFOLLOW to open the directory without following symlinks,
    // then inspect and secure that descriptor. Later socket operations still use
    // the path and are not made atomic by this directory validation.
    let handle;
    try {
        handle = await open(directory, fsConstants.O_RDONLY |
            (fsConstants.O_DIRECTORY ?? 0) |
            (fsConstants.O_NOFOLLOW ?? 0));
        const directoryStat = await handle.stat();
        if (directoryStat.isSymbolicLink() ||
            directoryStat.isDirectory() === false ||
            (process.getuid !== undefined && directoryStat.uid !== process.getuid()))
            throw new HopperStartError({
                userMessage: "PhxRE's Hopper lease directory is not a private directory owned by this user.",
            });
        // POSIX permission hardening: chmod on the already-opened descriptor avoids
        // a second TOCTOU window where the directory could be swapped between check
        // and permission fix. Windows DACL-based security is handled separately.
        const posixPermissionsApply = process.getuid !== undefined;
        if (posixPermissionsApply && (directoryStat.mode & 0o077) !== 0) {
            await handle.chmod(0o700);
            // Re-verify permissions on the same opened directory.
            const afterChmod = await handle.stat();
            if (afterChmod.isSymbolicLink() ||
                afterChmod.isDirectory() === false ||
                (afterChmod.mode & 0o077) !== 0)
                throw new HopperStartError({
                    userMessage: "PhxRE's Hopper lease directory permissions could not be secured.",
                });
        }
    }
    catch (cause) {
        if (cause instanceof HopperStartError)
            throw cause;
        const accessDenied = process.getuid !== undefined &&
            cause instanceof Error &&
            "code" in cause &&
            cause.code === "EACCES";
        throw new HopperStartError({
            cause,
            userMessage: accessDenied
                ? `PhxRE could not access its Hopper lease directory at ${JSON.stringify(directory)}. Check its ownership and parent-directory access. For a directory you own, restore owner-only read, write, and search permissions (0700), then retry.`
                : "PhxRE could not inspect its private Hopper lease directory.",
        });
    }
    finally {
        await handle?.close();
    }
};
const bind = (server, socketPath) => new Promise((resolveBind, reject) => {
    const onError = (error) => {
        server.removeListener("listening", onListening);
        if (error.code === "EADDRINUSE")
            resolveBind(false);
        else
            reject(error);
    };
    const onListening = () => {
        server.removeListener("error", onError);
        resolveBind(true);
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(socketPath);
});
const sendOwner = (socket, owner) => {
    socket.end(`${JSON.stringify(owner)}\n`);
};
const readOwner = (socketPath) => new Promise((resolveOwner, rejectOwner) => {
    const socket = createConnection(socketPath);
    let response = "";
    let settled = false;
    const fail = (reason, cause) => {
        if (settled)
            return;
        settled = true;
        clearTimeout(timer);
        socket.destroy();
        rejectOwner(new HopperStartError({
            cause,
            userMessage: `PhxRE could not verify the existing Hopper lease (${reason}); it was left unchanged. Retry when the owning PhxRE session is responsive.`,
        }));
    };
    const timer = setTimeout(() => fail("owner response timed out"), 250);
    const finish = (owner) => {
        if (settled)
            return;
        settled = true;
        clearTimeout(timer);
        socket.destroy();
        resolveOwner(owner);
    };
    socket.on("data", (chunk) => {
        response += chunk.toString("utf8");
        const newline = response.indexOf("\n");
        if (newline < 0)
            return;
        const parsed = safeParseJson(response.slice(0, newline));
        if (!parsed.ok) {
            fail("malformed owner response");
            return;
        }
        const value = parsed.value;
        const runId = typeof value === "object" && value !== null
            ? Reflect.get(value, "runId")
            : undefined;
        const processId = typeof value === "object" && value !== null
            ? Reflect.get(value, "processId")
            : undefined;
        if (typeof runId === "string" &&
            runId.length > 0 &&
            typeof processId === "number" &&
            Number.isSafeInteger(processId) &&
            processId > 0)
            finish({ runId, processId });
        else
            fail("invalid owner identity");
    });
    socket.on("error", (cause) => {
        if (cause.code === "ENOENT")
            finish("missing");
        else if (cause.code === "ECONNREFUSED")
            finish("stale");
        else
            fail(cause.code ?? "owner connection failed", cause);
    });
    socket.on("end", () => fail("owner closed without a complete response"));
});
const closeServer = (server) => new Promise((resolveClose, reject) => {
    if (!server.listening) {
        resolveClose();
        return;
    }
    server.close((error) => (error ? reject(error) : resolveClose()));
});
