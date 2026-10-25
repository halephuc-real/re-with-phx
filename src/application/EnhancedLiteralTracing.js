import { z } from "zod";
import { AnalysisOutputError } from "../domain/analysisErrorCore.js";
import { err, ok } from "../domain/result.js";
const LITERAL_SEARCH_SOURCES = [
    ["search_strings", "string"],
    ["search_procedures", "procedure"],
];
/** Trace matching strings and procedures through provider xrefs. */
export const traceLiteralFeature = async (call, observe, input, signal) => {
    const searched = await literalMatches(call, input, LITERAL_SEARCH_SOURCES, signal);
    if (!searched.ok)
        return searched;
    const traced = await traceReferences(call, observe, {
        matches: searched.value.matches,
        ...(signal === undefined ? {} : { signal }),
    });
    if (!traced.ok)
        return traced;
    return ok({
        query: input.query,
        search_mode: "literal",
        matches: searched.value.matches,
        references: traced.value.references,
        truncated: traced.value.residual.length > 0,
        residual_unknowns: traced.value.residual,
    });
};
const literalMatches = async (call, input, sources, signal) => {
    const matches = [];
    const matched = new Set();
    for (const [tool, type] of sources) {
        const result = await call(tool, {
            pattern: input.query,
            mode: "literal",
            case_sensitive: input.case_sensitive,
        }, signal);
        if (!result.ok)
            return result;
        const items = z
            .array(z.object({ address: z.string(), value: z.string() }))
            .safeParse(result.value);
        if (!items.success)
            return err(new AnalysisOutputError(tool, "provider returned an invalid search result"));
        addPageMatches({
            items: items.data.map(({ address, value: name }) => ({
                address,
                name,
            })),
            type,
            matches,
            matched,
        });
    }
    return ok({ matches });
};
const addPageMatches = (input) => {
    const { items, type, matches, matched } = input;
    for (const item of items) {
        const key = `${type}\u0000${item.address}`;
        if (matched.has(key))
            continue;
        matches.push({ type, address: item.address, value: item.name });
        matched.add(key);
    }
};
const traceReferences = async (call, observe, request) => {
    const references = [];
    const residual = [];
    // A source address is resolved once however many matches reference it.
    const containing = new Map();
    for (const match of request.matches) {
        const observed = await observe("xrefs", { address: match.address }, request.signal);
        if (!observed.ok)
            return observed;
        // Only an explicit producer report of truncation is a coverage gap; a
        // provider that reports nothing keeps its previous, unqualified result.
        const unknown = `References to ${match.address} were truncated by the provider; additional references may exist.`;
        if (observed.value.referencesTruncated === true &&
            !residual.includes(unknown))
            residual.push(unknown);
        const sources = observed.value.result;
        if (!Array.isArray(sources))
            return err(new AnalysisOutputError("xrefs", "provider returned a non-array result"));
        for (const source of sources) {
            if (typeof source !== "string")
                return err(new AnalysisOutputError("xrefs", "provider returned a non-address value"));
            let containingProcedure = containing.get(source);
            if (containingProcedure === undefined) {
                const resolved = await call("resolve_containing_procedure", { address: source }, request.signal);
                if (!resolved.ok)
                    return resolved;
                containingProcedure = resolved.value;
                containing.set(source, containingProcedure);
            }
            references.push({
                target_address: match.address,
                source_address: source,
                containing_procedure: containingProcedure,
            });
        }
    }
    return ok({ references, residual });
};
