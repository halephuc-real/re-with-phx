import { AnalysisUnsupportedTargetError } from "../analysisErrorCore.js";
import { browserScenarioCaptureSchema, } from "../browserScenarioCapture.js";
import { err, ok } from "../result.js";
import { analysisViewInputError } from "./analysisViewErrors.js";
import { textBytes } from "./webNetworkRouteTemplates.js";
const append = (map, key, value) => {
    const existing = map.get(key);
    if (existing === undefined)
        map.set(key, [value]);
    else
        existing.push(value);
};
const indexTransactions = (events) => {
    const index = {
        requests: [],
        requestCounts: new Map(),
        responses: new Map(),
        contents: new Map(),
    };
    for (const [item, event] of events.entries()) {
        if (event.kind === "request") {
            index.requests.push({ event, item });
            index.requestCounts.set(event.transaction_id, (index.requestCounts.get(event.transaction_id) ?? 0) + 1);
        }
        else if (event.kind === "response")
            append(index.responses, event.transaction_id, event);
        else if (event.kind === "network-content")
            append(index.contents, event.source_event_sequence, event);
    }
    return index;
};
/** The one content event of an exchange phase, or undefined when absent or ambiguous. */
const onlyContent = (index, sequence) => {
    const found = sequence === undefined ? undefined : index.contents.get(sequence);
    return found?.length === 1 ? found[0] : undefined;
};
const headerValue = (headers, name) => {
    if (headers?.state !== "captured")
        return undefined;
    const item = headers.items.find((candidate) => candidate.name.toLowerCase() === name);
    return item?.value ?? undefined;
};
const captured = (content) => content?.body.state === "captured" ? content.body : undefined;
/** A captured response body, unless redaction emptied it because a secret could not be cut out. */
const retainedBody = (content) => {
    const body = captured(content);
    return body?.redacted === true && body.bytes === 0 ? undefined : body;
};
/** Strictly decoded text, keeping a byte-order mark; undefined for bytes that are not UTF-8. */
const utf8Text = (body) => {
    try {
        return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(Buffer.from(body.content, "base64"));
    }
    catch {
        return undefined;
    }
};
const mediaType = (content) => captured(content)?.media_type ??
    headerValue(content?.headers, "content-type");
/** The request object HAR readers expect; a redacted URL is withheld so no path is templated from it. */
const reportedRequest = (request, content, purpose) => {
    const body = purpose === "manifest" ? captured(content) : undefined;
    const text = body === undefined ? undefined : utf8Text(body);
    const mimeType = mediaType(content);
    return {
        method: request.method,
        url: request.url.redacted ? null : request.url.url,
        ...(text === undefined || mimeType === undefined
            ? {}
            : { postData: { mimeType, text } }),
    };
};
const record = (ordinal, observed, index, purpose) => {
    const { item, event: request } = observed;
    const location = {
        kind: "json-pointer",
        pointer: `/events/items/${String(item)}`,
    };
    const empty = {
        binary_fields: [],
        numeric_literals: [],
        redactions: [],
        limitations: [],
    };
    const responses = index.responses.get(request.transaction_id) ?? [];
    const response = responses.length === 1 ? responses[0] : undefined;
    // One request, at most one response and one content event per phase: otherwise the
    // transaction cannot be attributed and is left unrepresented.
    if (index.requestCounts.get(request.transaction_id) !== 1 ||
        responses.length > 1 ||
        (index.contents.get(request.sequence)?.length ?? 0) > 1 ||
        (response !== undefined &&
            (index.contents.get(response.sequence)?.length ?? 0) > 1))
        return {
            record: { ordinal, location, reported: {}, ...empty },
            represented: false,
            body: false,
            redacted: false,
        };
    const requestContent = onlyContent(index, request.sequence);
    const responseContent = onlyContent(index, response?.sequence);
    const body = retainedBody(responseContent);
    const mimeType = mediaType(responseContent) ?? "";
    return {
        record: {
            ordinal,
            location,
            reported: {
                request: reportedRequest(request, requestContent, purpose),
                ...(response === undefined
                    ? {}
                    : {
                        response: {
                            status: response.status,
                            content: body === undefined
                                ? { mimeType }
                                : { mimeType, text: body.content, encoding: "base64" },
                        },
                    }),
            },
            ...empty,
            binary_fields: body === undefined
                ? []
                : [
                    {
                        pointer: "/response/content/text",
                        representation: "har-base64-content",
                        state: "retained",
                        bytes: body.bytes,
                        sha256: body.sha256,
                        content_base64: body.content,
                    },
                ],
        },
        represented: !request.url.redacted,
        body: body !== undefined,
        redacted: body?.redacted === true,
    };
};
/** Project each network transaction, in request order, as one record; the ordinal is its zero-based position. */
export const scenarioCaptureRecords = (capture, purpose) => {
    const index = indexTransactions(capture.events.items);
    const records = [];
    let withoutBody = 0;
    let representedCount = 0;
    let redactedBodies = 0;
    for (const [ordinal, observed] of index.requests.entries()) {
        const projected = record(ordinal, observed, index, purpose);
        records.push(projected.record);
        if (!projected.represented)
            continue;
        representedCount += 1;
        if (!projected.body)
            withoutBody += 1;
        if (projected.redacted)
            redactedBodies += 1;
    }
    return {
        records,
        totalRecords: records.length,
        limitations: [
            "Scenario records are the capture's network transactions in request order; each record ordinal is the transaction's zero-based position.",
            ...(capture.events.dropped > 0
                ? [
                    `The scenario capture omitted ${String(capture.events.dropped)} events; the manifest covers only retained transactions.`,
                ]
                : []),
            ...(withoutBody > 0
                ? [
                    `${String(withoutBody)} of ${String(representedCount)} scenario transactions with a usable request line retained no response body; tools citing them replay only the recorded status and content type, either of which may be absent.`,
                ]
                : []),
            ...(redactedBodies > 0
                ? [
                    `${String(redactedBodies)} of ${String(representedCount)} scenario transactions with a usable request line retained a response body with declared secret values replaced by redaction markers; tools citing them replay the redacted bytes.`,
                ]
                : []),
        ],
    };
};
/** An own data member of admitted parent data; the clone admission already refused accessors. */
const member = (value, key) => typeof value === "object" && value !== null && Object.hasOwn(value, key)
    ? value[key]
    : undefined;
/**
 * Bytes the manifest derives from a borrowed scenario: validation decodes and re-encodes one body at
 * a time (two bytes per base64 character), and projection keeps the decoded text of every request
 * body. Response bodies stay borrowed, as HAR response text does.
 */
const derivedTextBytes = (value) => {
    const items = member(member(value, "events"), "items");
    let largestBody = 0;
    let requestText = 0;
    // Each event is read on its own, so a body without content leaves the others counted.
    for (const event of Array.isArray(items) ? items : []) {
        const content = member(member(event, "body"), "content");
        if (member(event, "kind") !== "network-content" ||
            typeof content !== "string")
            continue;
        largestBody = Math.max(largestBody, content.length);
        if (member(event, "phase") === "request")
            requestText += textBytes(Math.ceil((content.length * 3) / 4));
    }
    return 64 + largestBody * 2 + requestText;
};
/** Admit a capture_browser_scenario parent whose network content identifies response media types; state also needs bodies. */
export const admitScenarioCaptureParent = (parent, viewKind, accumulator) => {
    const admitted = accumulator.admitCaptureClone(parent.normalizedResult);
    if (!admitted.ok)
        return admitted;
    // Reserve body validation and request text before either allocation, even for a parent read from
    // a file, without charging the borrowed response bodies a large capture is made of.
    const derived = accumulator.admitDerivedBytes(derivedTextBytes(parent.normalizedResult));
    if (!derived.ok)
        return derived;
    const parsed = browserScenarioCaptureSchema.safeParse(parent.normalizedResult);
    if (!parsed.success)
        return err(analysisViewInputError([
            {
                path: ["source"],
                reason: "invalid_value",
                message: "Parent Evidence result does not match capture_browser_scenario.",
            },
        ]));
    const content = parsed.data.scenario.network_content;
    // Tools are chosen by response media type, which only bodies or header values carry; state is read from bodies.
    if (viewKind === "environment-state"
        ? !content.response_body
        : !content.response_body && !content.header_values)
        return err(new AnalysisUnsupportedTargetError("inspect_analysis_view", parent.evidenceId, viewKind === "environment-state"
            ? "environment-state needs a capture_browser_scenario capture with capture.network.response_body selected."
            : "environment-manifest needs a capture_browser_scenario capture with capture.network.response_body or header_values selected."));
    return ok(scenarioCaptureRecords(parsed.data, "manifest"));
};
