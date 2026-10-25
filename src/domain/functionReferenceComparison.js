import { canonicalJson } from "./comparisonSemantics.js";
import { isAutoName, sorted } from "./functionComparisonNormalization.js";
import { referenceFactsCompatible, } from "./functionReferenceCompatibility.js";
import { nativeAddressInputSchema } from "./native/nativeAddress.js";
/** Names observed at different procedure entries do not uniquely identify an overload. */
const ambiguousProcedureNames = (snapshots) => {
    const ambiguous = new Set();
    for (const snapshot of snapshots) {
        const entries = new Map();
        const observe = (procedure) => {
            if (procedure === null)
                return;
            const address = nativeAddressInputSchema.safeParse(procedure.address);
            if (!address.success) {
                ambiguous.add(procedure.name);
                return;
            }
            const previous = entries.get(procedure.name);
            if (previous !== undefined && previous !== address.data)
                ambiguous.add(procedure.name);
            entries.set(procedure.name, address.data);
        };
        observe(snapshot.dossier.procedure);
        for (const edge of snapshot.dossier.incoming_references) {
            observe(edge.source_procedure);
            observe(edge.target_procedure);
        }
        for (const edge of snapshot.dossier.outgoing_references) {
            observe(edge.source_procedure);
            observe(edge.target_procedure);
        }
    }
    return ambiguous;
};
const endpoint = (procedure, address, sameArtifact, ambiguousNames) => {
    if (sameArtifact) {
        const parsed = nativeAddressInputSchema.safeParse(address);
        if (parsed.success)
            return { kind: "address", address: parsed.data };
        return {
            kind: "unknown",
            reason: "unparsed_address",
            reported_address: address,
            reported_name: procedure?.name ?? null,
        };
    }
    if (procedure === null ||
        procedure.name.length === 0 ||
        isAutoName(procedure.name))
        return {
            kind: "unknown",
            reason: procedure !== null && isAutoName(procedure.name)
                ? "generated_name"
                : "missing_name",
            reported_address: address,
            reported_name: procedure?.name ?? null,
        };
    return {
        kind: "name",
        name: procedure.name,
        ambiguous: ambiguousNames.has(procedure.name),
    };
};
const project = (snapshot, sameArtifact, ambiguousNames) => {
    const facts = [];
    const collect = (references, direction) => {
        for (const edge of references) {
            let kind = null;
            if (edge.kind.available) {
                const { available: _available, provenance: _provenance, ...known } = edge.kind;
                kind = known;
            }
            facts.push({
                direction,
                source: endpoint(edge.source_procedure, edge.source_address, sameArtifact, ambiguousNames),
                target: endpoint(edge.target_procedure, edge.target_address, sameArtifact, ambiguousNames),
                kind,
            });
        }
    };
    collect(snapshot.dossier.incoming_references, "in");
    collect(snapshot.dossier.outgoing_references, "out");
    return facts;
};
/** Ambiguity blocks equality, but a known label can still contradict another label. */
const endpointKey = (value) => {
    if (value.kind === "unknown")
        return null;
    return canonicalJson(value.kind === "address"
        ? { address: value.address }
        : { name: value.name });
};
const constraints = (facts) => facts.map((fact) => ({
    direction: fact.direction,
    source: endpointKey(fact.source),
    target: endpointKey(fact.target),
    kind: fact.kind === null ? null : canonicalJson(fact.kind),
}));
/** Compare parsed endpoint and kind facts without replacing partial knowledge with absence. */
export const compareFunctionReferences = (left, right) => {
    const sameArtifact = left.subject.digest.sha256 === right.subject.digest.sha256;
    const ambiguousNames = sameArtifact
        ? new Set()
        : ambiguousProcedureNames([left, right]);
    const leftFacts = project(left, sameArtifact, ambiguousNames);
    const rightFacts = project(right, sameArtifact, ambiguousNames);
    let unknownIdentity = false;
    let ambiguousIdentity = false;
    let unknownKinds = false;
    for (const facts of [leftFacts, rightFacts]) {
        for (const fact of facts) {
            unknownKinds ||= fact.kind === null;
            for (const value of [fact.source, fact.target]) {
                unknownIdentity ||= value.kind === "unknown";
                ambiguousIdentity ||= value.kind === "name" && value.ambiguous;
            }
        }
    }
    const limitations = [];
    if (unknownIdentity)
        limitations.push(sameArtifact
            ? "Reference endpoint coordinates could not be parsed, so their identity remains unknown."
            : "Unnamed reference endpoints and generated procedure names have no stable identity across different artifacts.");
    if (ambiguousIdentity)
        limitations.push("A reference name does not uniquely identify an observed procedure entry, so matching names do not establish equal endpoints.");
    if (unknownKinds)
        limitations.push("At least one provider did not expose reference kinds, so compatible endpoints do not prove equal edge semantics.");
    const context = {
        leftCount: leftFacts.length,
        rightCount: rightFacts.length,
        limitations,
    };
    if (!referenceFactsCompatible(constraints(leftFacts), constraints(rightFacts)))
        return {
            ...context,
            status: "changed",
            left: sorted(leftFacts),
            right: sorted(rightFacts),
            limitations: [
                "Known reference facts cannot be paired without contradicting an endpoint or reference kind.",
                ...limitations,
            ],
        };
    if (unknownIdentity || ambiguousIdentity || unknownKinds)
        return { ...context, status: "unknown" };
    return {
        ...context,
        status: "unchanged",
        left: sorted(leftFacts),
        right: sorted(rightFacts),
    };
};
