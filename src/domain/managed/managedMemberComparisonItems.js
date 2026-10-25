import canonicalize from "canonicalize";
import { sha256, } from "./managedMemberComparisonMatch.js";
import { signatureIdentity } from "./managedMemberSignatureIdentity.js";
/** Whether an inventory observed every member of this member's declaring type. */
const inventoryCovers = (complete, selection, member) => complete &&
    (selection === null ||
        (member.declaring_type !== null && selection.has(member.declaring_type)));
const methodDimensions = (left, right) => {
    const dimensions = [];
    if (left.flags !== right.flags || left.impl_flags !== right.impl_flags)
        dimensions.push("metadata");
    if (signatureIdentity(left.signature) !== signatureIdentity(right.signature))
        dimensions.push("signature");
    const leftBodyComplete = left.body.status === "present" && left.body.truncated_instructions === 0;
    const rightBodyComplete = right.body.status === "present" && right.body.truncated_instructions === 0;
    const bothAbsent = left.body.status === "absent" && right.body.status === "absent";
    if ((left.body.status === "absent" && rightBodyComplete) ||
        (right.body.status === "absent" && leftBodyComplete))
        dimensions.push("availability");
    if (bothAbsent)
        return { dimensions, bodyUnknown: false };
    if (!leftBodyComplete || !rightBodyComplete)
        return { dimensions, bodyUnknown: true };
    // The decoded fingerprint omits switch targets and is not exact CIL identity.
    if (left.body.il_sha256 !== right.body.il_sha256 ||
        left.body.normalized_il_sha256 !== right.body.normalized_il_sha256)
        dimensions.push("cil");
    if (canonicalize(left.body.opcode_counts) !==
        canonicalize(right.body.opcode_counts))
        dimensions.push("opcode-shape");
    if (callShape(left.body.anchors) !== callShape(right.body.anchors))
        dimensions.push("call-shape");
    if (fieldShape(left.body.anchors) !== fieldShape(right.body.anchors))
        dimensions.push("field-shape");
    if (canonicalize(left.body.exception_regions) !==
        canonicalize(right.body.exception_regions))
        dimensions.push("exception-shape");
    return { dimensions, bodyUnknown: false };
};
const callShape = (anchors) => JSON.stringify(anchors
    .filter(({ operand_kind }) => operand_kind === "method")
    .map(({ opcode, operand_kind }) => [opcode, operand_kind]));
const fieldShape = (anchors) => JSON.stringify(anchors
    .filter(({ operand_kind }) => operand_kind === "field")
    .map(({ opcode, operand_kind }) => [opcode, operand_kind]));
const methodIdentity = (item) => ({
    token: item.token,
    declaring_type: item.declaring_type,
    name: item.name,
    signature_sha256: item.signature.raw_sha256,
    normalized_il_sha256: item.body.normalized_il_sha256,
});
const fieldIdentity = (item) => ({
    token: item.token,
    declaring_type: item.declaring_type,
    name: item.name,
    signature_sha256: item.signature.raw_sha256,
});
const unmatchedComparison = () => ({
    status: "unmatched",
    basis: "none",
    confidence: "unknown",
    candidate_left_tokens: [],
    candidate_right_tokens: [],
});
const methodOnlyItem = (member, identity, identityUnavailable, context, undecoded) => {
    if (member.left !== undefined) {
        const limitations = absenceLimitations(member.left, identity, {
            oppositeComplete: inventoryCovers(context.rightComplete, context.rightSelection, member.left),
            unpaired: undecoded,
            ownIdentityUnavailable: identityUnavailable,
            opposite: "right",
            inventory: "method",
        });
        return {
            item_id: `mmc_method_${sha256({ token: member.left.token, side: "left" })}`,
            status: limitations.length === 0 ? "removed" : "unknown",
            left: methodIdentity(member.left),
            right: null,
            match: unmatchedComparison(),
            dimensions: ["availability"],
            evidence_links: [context.leftEvidenceId, context.rightEvidenceId],
            limitations,
        };
    }
    const limitations = absenceLimitations(member.right, identity, {
        oppositeComplete: inventoryCovers(context.leftComplete, context.leftSelection, member.right),
        unpaired: undecoded,
        ownIdentityUnavailable: identityUnavailable,
        opposite: "left",
        inventory: "method",
    });
    return {
        item_id: `mmc_method_${sha256({ token: member.right.token, side: "right" })}`,
        status: limitations.length === 0 ? "added" : "unknown",
        left: null,
        right: methodIdentity(member.right),
        match: unmatchedComparison(),
        dimensions: ["availability"],
        evidence_links: [context.leftEvidenceId, context.rightEvidenceId],
        limitations,
    };
};
/**
 * Why a one-sided member's absence from the other inventory was not
 * observed: that inventory is incomplete, the member's own signature was not
 * decoded, so no shape round could seek a changed counterpart, or the other
 * inventory has an unpaired (one-sided or ambiguous) same-named member whose
 * signature was not decoded, which may be this member with a changed
 * signature. A decoded signature that names a type PhxRE could not name, while
 * the comparison otherwise keys resolved signatures, is compared by raw bytes
 * that name types by build-local row, so it is treated the same way.
 */
const absenceLimitations = (member, identity, opposite) => [
    ...(opposite.ownIdentityUnavailable
        ? [
            "declaring-type-name-not-resolved: Declared type identity could not be resolved; a bare display name cannot establish a counterpart or absence.",
        ]
        : []),
    ...(opposite.unpaired.unknownOwners[opposite.opposite].has(member.name)
        ? [
            `counterpart-declaring-type-name-not-resolved: The ${opposite.opposite} ${opposite.inventory} inventory has an unpaired same-named member with unresolved enclosing-name identity, so absence was not established.`,
        ]
        : []),
    ...(opposite.oppositeComplete
        ? []
        : [
            `unknown-within-incomplete-metadata: The ${opposite.opposite} ${opposite.inventory} inventory is incomplete, so absence was not observed.`,
        ]),
    ...(member.signature.parse_status === "decoded"
        ? []
        : [
            `signature-not-decoded: The member's ${member.signature.parse_status} signature was compared only by exact declared type, name, and signature bytes, so a changed or renamed counterpart could not be sought.`,
        ]),
    ...(member.signature.parse_status === "decoded" &&
        opposite.unpaired.undecoded[opposite.opposite].has(identity)
        ? [
            `counterpart-signature-not-decoded: The ${opposite.opposite} ${opposite.inventory} inventory has an unpaired member with the same declared type and name whose signature was not decoded, so it may be this member with a changed signature.`,
        ]
        : []),
    ...(unresolved(member, opposite.unpaired.resolved)
        ? [
            `signature-not-resolved: The member's signature names a type PhxRE could not name, so it was compared by raw bytes, which name types by build-local metadata row; a counterpart whose referenced type moved rows could not be found.`,
        ]
        : []),
    ...(member.signature.parse_status === "decoded" &&
        !unresolved(member, opposite.unpaired.resolved) &&
        opposite.unpaired.unresolved[opposite.opposite].has(identity)
        ? [
            `counterpart-signature-not-resolved: The ${opposite.opposite} ${opposite.inventory} inventory has an unpaired member with the same declared type and name whose signature names a type PhxRE could not name, so it may be this member.`,
        ]
        : []),
];
/** A known signature form whose type operands still compare by raw bytes. */
const unresolved = (member, resolved) => resolved &&
    member.signature.kind !== "unknown" &&
    member.signature.resolved_sha256 === null;
/** Equal build-local bytes cannot establish equal unresolved type operands. */
const pairedSignatureLimitations = (left, right, examined) => unresolved(left, examined) || unresolved(right, examined)
    ? [
        "signature-not-resolved: At least one signature names a type PhxRE could not resolve; equal build-local row bytes do not establish equivalent signature types.",
    ]
    : [];
const undecodedOneSidedNames = (members, resolved) => {
    const sides = {
        left: [
            ...members.leftOnly,
            ...members.ambiguous.flatMap(({ left }) => left),
        ],
        right: [
            ...members.rightOnly,
            ...members.ambiguous.flatMap(({ right }) => right),
        ],
    };
    const names = (side, keep) => new Set(side.filter(({ item }) => keep(item)).map(({ identity }) => identity));
    const undecoded = (item) => item.signature.parse_status !== "decoded";
    const notResolved = (item) => unresolved(item, resolved);
    return {
        resolved,
        unknownOwners: {
            left: new Set(sides.left.filter((x) => x.identityUnavailable).map((x) => x.item.name)),
            right: new Set(sides.right
                .filter((x) => x.identityUnavailable)
                .map((x) => x.item.name)),
        },
        undecoded: {
            left: names(sides.left, undecoded),
            right: names(sides.right, undecoded),
        },
        unresolved: {
            left: names(sides.left, notResolved),
            right: names(sides.right, notResolved),
        },
    };
};
const fieldOnlyItem = (member, identity, identityUnavailable, context, undecoded) => {
    if (member.left !== undefined) {
        const limitations = absenceLimitations(member.left, identity, {
            oppositeComplete: inventoryCovers(context.rightComplete, context.rightSelection, member.left),
            unpaired: undecoded,
            ownIdentityUnavailable: identityUnavailable,
            opposite: "right",
            inventory: "field",
        });
        return {
            item_id: `mmc_field_${sha256({ token: member.left.token, side: "left" })}`,
            status: limitations.length === 0 ? "removed" : "unknown",
            left: fieldIdentity(member.left),
            right: null,
            match: unmatchedComparison(),
            evidence_links: [context.leftEvidenceId, context.rightEvidenceId],
            limitations,
        };
    }
    const limitations = absenceLimitations(member.right, identity, {
        oppositeComplete: inventoryCovers(context.leftComplete, context.leftSelection, member.right),
        unpaired: undecoded,
        ownIdentityUnavailable: identityUnavailable,
        opposite: "left",
        inventory: "field",
    });
    return {
        item_id: `mmc_field_${sha256({ token: member.right.token, side: "right" })}`,
        status: limitations.length === 0 ? "added" : "unknown",
        left: null,
        right: fieldIdentity(member.right),
        match: unmatchedComparison(),
        evidence_links: [context.leftEvidenceId, context.rightEvidenceId],
        limitations,
    };
};
/**
 * Name only evidence shared by the whole group. Exact-signature ambiguities
 * include both declared-identity collisions and unresolved signature choices.
 */
const ambiguityLimitation = (members, basis, identityUnavailable) => identityUnavailable
    ? "declaring-type-name-not-resolved: Declared type identity remains unresolved; PhxRE did not guess a counterpart from display names, signatures or CIL."
    : basis === "exact-signature"
        ? `Multiple managed ${members} share the same signature; PhxRE did not guess declared ownership or a token remap.`
        : basis === "exact-il-signature"
            ? "Multiple managed methods share the same CIL and signature; PhxRE did not guess a token remap."
            : members === "methods"
                ? "Multiple managed methods share the same structural shape; PhxRE did not guess a token remap."
                : "Multiple managed fields share the same signature; PhxRE did not guess a token remap.";
export const buildMethodItems = (matches, context) => {
    const items = [];
    for (const pair of matches.pairs) {
        const signatureLimitations = pairedSignatureLimitations(pair.left.item, pair.right.item, context.signatureResolutionExamined);
        const { dimensions: observedDimensions, bodyUnknown } = methodDimensions(pair.left.item, pair.right.item);
        const dimensions = bodyUnknown
            ? [...observedDimensions, "body-coverage"]
            : observedDimensions;
        const observedChange = observedDimensions.length > 0;
        items.push({
            item_id: `mmc_method_${sha256({
                left: pair.left.item.token,
                right: pair.right.item.token,
                basis: pair.basis,
            })}`,
            status: observedChange
                ? "changed"
                : bodyUnknown || signatureLimitations.length > 0
                    ? "unknown"
                    : "unchanged",
            left: methodIdentity(pair.left.item),
            right: methodIdentity(pair.right.item),
            match: {
                status: "matched",
                basis: pair.basis,
                confidence: pair.confidence,
                candidate_left_tokens: [],
                candidate_right_tokens: [],
            },
            dimensions,
            evidence_links: [context.leftEvidenceId, context.rightEvidenceId],
            limitations: [
                ...signatureLimitations,
                ...(bodyUnknown
                    ? [
                        "Method body facets are unknown because at least one side has unavailable or partial body data.",
                    ]
                    : []),
            ],
        });
    }
    for (const ambiguous of matches.ambiguous) {
        items.push({
            item_id: `mmc_method_${sha256({
                left: ambiguous.left.map(({ item }) => item.token),
                right: ambiguous.right.map(({ item }) => item.token),
                basis: ambiguous.basis,
            })}`,
            status: "unknown",
            left: null,
            right: null,
            match: {
                status: "ambiguous",
                basis: ambiguous.basis,
                confidence: "unknown",
                candidate_left_tokens: ambiguous.left.map(({ item }) => item.token),
                candidate_right_tokens: ambiguous.right.map(({ item }) => item.token),
            },
            dimensions: ["availability"],
            evidence_links: [context.leftEvidenceId, context.rightEvidenceId],
            limitations: [
                ambiguityLimitation("methods", ambiguous.basis, ambiguous.left.some((item) => item.identityUnavailable) ||
                    ambiguous.right.some((item) => item.identityUnavailable)),
            ],
        });
    }
    const undecoded = undecodedOneSidedNames(matches, context.signatureResolutionExamined);
    for (const item of matches.leftOnly)
        items.push(methodOnlyItem({ left: item.item }, item.identity, item.identityUnavailable, context, undecoded));
    for (const item of matches.rightOnly)
        items.push(methodOnlyItem({ right: item.item }, item.identity, item.identityUnavailable, context, undecoded));
    return items;
};
export const buildFieldItems = (matches, context) => {
    const items = [];
    for (const pair of matches.pairs) {
        const signatureLimitations = pairedSignatureLimitations(pair.left.item, pair.right.item, context.signatureResolutionExamined);
        const changed = signatureIdentity(pair.left.item.signature) !==
            signatureIdentity(pair.right.item.signature) ||
            pair.left.item.flags !== pair.right.item.flags;
        items.push({
            item_id: `mmc_field_${sha256({
                left: pair.left.item.token,
                right: pair.right.item.token,
            })}`,
            status: changed
                ? "changed"
                : signatureLimitations.length > 0
                    ? "unknown"
                    : "unchanged",
            left: fieldIdentity(pair.left.item),
            right: fieldIdentity(pair.right.item),
            match: {
                status: "matched",
                basis: pair.basis,
                confidence: pair.confidence,
                candidate_left_tokens: [],
                candidate_right_tokens: [],
            },
            evidence_links: [context.leftEvidenceId, context.rightEvidenceId],
            limitations: signatureLimitations,
        });
    }
    for (const ambiguous of matches.ambiguous)
        items.push({
            item_id: `mmc_field_${sha256({
                left: ambiguous.left.map(({ item }) => item.token),
                right: ambiguous.right.map(({ item }) => item.token),
            })}`,
            status: "unknown",
            left: null,
            right: null,
            match: {
                status: "ambiguous",
                basis: ambiguous.basis,
                confidence: "unknown",
                candidate_left_tokens: ambiguous.left.map(({ item }) => item.token),
                candidate_right_tokens: ambiguous.right.map(({ item }) => item.token),
            },
            evidence_links: [context.leftEvidenceId, context.rightEvidenceId],
            limitations: [
                ambiguityLimitation("fields", ambiguous.basis, ambiguous.left.some((item) => item.identityUnavailable) ||
                    ambiguous.right.some((item) => item.identityUnavailable)),
            ],
        });
    const undecoded = undecodedOneSidedNames(matches, context.signatureResolutionExamined);
    for (const item of matches.leftOnly)
        items.push(fieldOnlyItem({ left: item.item }, item.identity, item.identityUnavailable, context, undecoded));
    for (const item of matches.rightOnly)
        items.push(fieldOnlyItem({ right: item.item }, item.identity, item.identityUnavailable, context, undecoded));
    return items;
};
