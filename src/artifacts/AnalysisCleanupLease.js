/** Link one resource's confirmed release to its originating analysis error. */
export class AnalysisCleanupLease {
    cleanup;
    #released = false;
    #releasePromise;
    #errors = [];
    #groups = new Set();
    /** Whether this exact owner has confirmed release. */
    get released() {
        return this.#released;
    }
    #resourceOwner;
    #resources;
    get cleanupResources() {
        return this.#resourceOwner === undefined
            ? this.#resources
            : this.#resourceOwner.cleanupResources;
    }
    /** Adopt exact close authority while retaining its live labels across retries. */
    static forCloseOwner(owner, resource) {
        return new AnalysisCleanupLease(() => owner.close(), !("cleanupResources" in owner)
            ? [resource]
            : {
                get cleanupResources() {
                    return owner.cleanupResources;
                },
            });
    }
    constructor(cleanup, resources) {
        this.cleanup = cleanup;
        if (resources !== undefined && "cleanupResources" in resources) {
            this.#resourceOwner = resources;
            this.#resources = undefined;
        }
        else {
            this.#resourceOwner = undefined;
            this.#resources = resources === undefined ? undefined : [...resources];
        }
    }
    release() {
        if (this.#released)
            return Promise.resolve();
        if (this.#releasePromise !== undefined)
            return this.#releasePromise;
        const attempt = Promise.resolve()
            .then(async () => {
            await this.cleanup();
            this.#released = true;
            this.#resolveBoundErrors();
            for (const group of this.#groups)
                group.ownerReleased(this);
            this.#groups.clear();
        })
            .finally(() => {
            if (this.#releasePromise === attempt)
                this.#releasePromise = undefined;
        });
        this.#releasePromise = attempt;
        return attempt;
    }
    /** Binding can follow a concurrent retry that already confirmed release. */
    bindCleanupError(error) {
        if (this.#released) {
            error.resolveCleanup();
            return;
        }
        this.#errors = [
            ...this.#errors.filter((reference) => reference.deref() !== undefined),
            new WeakRef(error),
        ];
    }
    /** Bind one aggregate error to every exact lease in a failed retry set. */
    bindCleanupGroup(group) {
        if (this.#released) {
            group.ownerReleased(this);
            return;
        }
        for (const retained of this.#groups)
            if (!retained.hasLiveError)
                this.#groups.delete(retained);
        this.#groups.add(group);
    }
    #resolveBoundErrors() {
        for (const reference of this.#errors)
            reference.deref()?.resolveCleanup();
        this.#errors = [];
    }
}
/** Conjunctive cleanup binding for an error covering multiple exact owners. */
export class AnalysisCleanupLeaseGroup {
    #error;
    #pending;
    constructor(error, owners) {
        this.#error = new WeakRef(error);
        this.#pending = new Set(owners);
        if (this.#pending.size === 0)
            return;
        error.bindCleanupResourceOwner(this);
        for (const owner of this.#pending)
            owner.bindCleanupGroup(this);
    }
    /** Unlabelled owners keep attribution unknown; never match resources by text. */
    get cleanupResources() {
        if ([...this.#pending].some((owner) => owner.cleanupResources === undefined))
            return undefined;
        return [
            ...new Set([...this.#pending].flatMap((owner) => owner.cleanupResources ?? [])),
        ];
    }
    get hasLiveError() {
        return this.#error.deref() !== undefined;
    }
    ownerReleased(owner) {
        if (!this.#pending.delete(owner) || this.#pending.size > 0)
            return;
        this.#error.deref()?.resolveCleanup();
        this.#pending.clear();
    }
}
