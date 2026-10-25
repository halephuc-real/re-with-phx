/** Stable tags exposed by safe analysis-error projections. */
const ANALYSIS_ERROR_TAGS = [
    "AnalysisProtocolError",
    "AnalysisInputError",
    "AnalysisAccessDeniedError",
    "AnalysisArtifactChangedError",
    "AnalysisOutputError",
    "AnalysisCapabilityUnavailableError",
    "AnalysisUnsupportedTargetError",
    "AnalysisCancelledError",
    "AnalysisTimeoutError",
    "AnalysisResourceConstraintError",
    "ProviderSelectionError",
    "ProviderAdapterError",
    "BrowserObservationError",
    "ArtifactOperationError",
    "ProcessCaptureError",
    "EvidenceIntegrityError",
    "EvidenceFileError",
    "UnknownRegistryError",
    "HopperTimeoutError",
    "HopperCancelledError",
    "HopperProtocolError",
    "HopperRemoteError",
    "HopperProcessError",
    "HopperStartError",
    "ConfigurationError",
    "NoBinaryOpenError",
    "BinaryTargetError",
];
/** Base class for expected analysis, provider, and session failures. */
export class AnalysisError extends Error {
    #cleanupPrimary;
    // Undefined means unbound; a bound empty set records confirmed completion.
    #cleanupDependencies;
    #cleanupResourceProjection;
    #cleanupDependents = [];
    diagnostics;
    capturedOutput;
    cleanup;
    cleanupIncomplete;
    #ownedCleanupResources;
    #cleanupResourceOwner;
    #secondaryFailures = [];
    constructor(message, options) {
        super(message, options);
        this.#cleanupPrimary = options?.cleanupPrimary;
        this.diagnostics =
            options?.diagnostics === undefined
                ? undefined
                : structuredClone(options.diagnostics);
        this.capturedOutput =
            options?.capturedOutput === undefined
                ? undefined
                : { ...options.capturedOutput };
        this.cleanup = options?.cleanup;
        this.cleanupIncomplete = options?.cleanup !== undefined;
        this.#ownedCleanupResources = [...(options?.cleanup?.resources ?? [])];
        this.partialObservation = options?.partialObservation;
    }
    userMessage = undefined;
    userCategory = undefined;
    executionFailure = undefined;
    partialObservation;
    get cleanupPrimary() {
        return this.#cleanupPrimary;
    }
    /** Later typed failures retained without changing the primary error cause. */
    get secondaryFailures() {
        return [...this.#secondaryFailures];
    }
    cleanupReport = undefined;
    /** Live dependencies own current resource attribution; cleanup keeps history. */
    get cleanupResources() {
        if (this.#cleanupDependencies === undefined)
            return (this.#cleanupResourceOwner?.cleanupResources ??
                this.#ownedCleanupResources);
        const pending = [...this.#cleanupDependencies].filter((dependency) => dependency.cleanupIncomplete);
        if (pending.length === 0)
            return [];
        if (this.#cleanupResourceProjection !== undefined)
            return this.#cleanupResourceProjection.cleanupResources;
        return [
            ...new Set(pending.flatMap((dependency) => dependency.cleanupResources)),
        ];
    }
    /** Bind attribution only to the producer that owns the complete cleanup set. */
    bindCleanupResourceOwner(owner) {
        this.#cleanupResourceOwner = owner;
        return this;
    }
    /** Initialize resource facts supplied by a more specific error producer. */
    setCleanupResources(resources) {
        this.#ownedCleanupResources = [...resources];
    }
    /** Retain diagnostic facts without replacing the original typed error. */
    retainDiagnostics(diagnostics) {
        Object.assign(this, {
            diagnostics: structuredClone({ ...this.diagnostics, ...diagnostics }),
        });
        return this;
    }
    retainSecondaryFailure(failure, diagnostics) {
        // Secondary resources remain owned by their cleanup lifecycle; preserve
        // the primary error's live cleanup status and original output.
        if (diagnostics !== undefined)
            this.retainDiagnostics(diagnostics);
        this.#secondaryFailures.push(failure);
        return this;
    }
    /** Keep a composed error incomplete until all explicitly owned source errors resolve. */
    bindCleanupDependencies(dependencies, resourceProjection) {
        const pending = (this.#cleanupDependencies ??= new Set());
        if (resourceProjection !== undefined)
            this.#cleanupResourceProjection = resourceProjection;
        for (const dependency of dependencies) {
            if (!dependency.cleanupIncomplete || pending.has(dependency))
                continue;
            pending.add(dependency);
            dependency.#cleanupDependents = [
                ...dependency.#cleanupDependents.filter((reference) => reference.deref() !== undefined),
                new WeakRef(this),
            ];
        }
        if (pending.size === 0)
            this.resolveCleanup();
        return this;
    }
    /** Clear live cleanup status only after its owning resource confirms retry success. */
    resolveCleanup() {
        if ([...(this.#cleanupDependencies ?? [])].some((dependency) => dependency.cleanupIncomplete))
            return this;
        this.#cleanupDependencies?.clear();
        this.cleanupIncomplete = false;
        for (const reference of this.#cleanupDependents)
            reference.deref()?.resolveCleanup();
        this.#cleanupDependents = [];
        return this;
    }
    /** Retain a completed observation when a later step fails. */
    retainPartialObservation(observation) {
        this.partialObservation ??= observation;
        return this;
    }
}
/** Confirmed cleanup reveals the typed primary; unresolved ownership stays visible. */
export const resolvedAnalysisError = (error) => {
    while (!error.cleanupIncomplete && error.cleanupPrimary !== undefined)
        error = error.cleanupPrimary;
    return error;
};
