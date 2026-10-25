import { digestCanonicalValue } from "./canonicalDigest.js";
import { BROWSER_SCENARIO_BUILT_IN_NORMALIZATION_RULES, } from "./browserScenarioDiffValues.js";
/** Canonically order and commit a parsed browser scenario normalization policy. */
export const commitBrowserScenarioNormalization = (input) => {
    const rules = [...input.rules]
        .map((rule) => ({
        ...rule,
        artifacts: [...rule.artifacts].sort(),
    }))
        .sort((left, right) => left.rule_id < right.rule_id ? -1 : left.rule_id > right.rule_id ? 1 : 0);
    const commitment = {
        built_in_rules: [...BROWSER_SCENARIO_BUILT_IN_NORMALIZATION_RULES],
        rules,
    };
    return {
        ...commitment,
        sha256: digestCanonicalValue(commitment, "Browser scenario"),
    };
};
/** Digest one artifact after applying committed exact-literal rules, then any artifact ordering. */
export const digestNormalizedScenarioValue = (value, artifact, rules, order = (normalized) => normalized) => digestCanonicalValue(order(normalizeScenarioValue(value, artifact, rules)), "Browser scenario");
export const normalizeScenarioValue = (value, artifact, rules) => {
    if (artifact === "screenshot")
        return value;
    if (typeof value === "string")
        return rules
            .filter(({ artifacts }) => artifacts.includes(artifact))
            .reduce((normalized, rule) => normalized.split(rule.match).join(rule.replacement), value);
    if (Array.isArray(value))
        return value.map((item) => normalizeScenarioValue(item, artifact, rules));
    if (typeof value !== "object" || value === null)
        return value;
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [
        key,
        normalizeScenarioValue(item, artifact, rules),
    ]));
};
