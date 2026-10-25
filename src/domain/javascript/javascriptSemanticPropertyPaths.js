/** Read only canonical JavaScript array indices, excluding named properties. */
export const semanticArrayIndex = (key) => {
    const index = Number(key);
    return Number.isInteger(index) &&
        index >= 0 &&
        index < 4294967295 &&
        String(index) === String(key)
        ? index
        : null;
};
/** Test an exact key, wildcard, or copied-slot selection against an own key. */
export const semanticPropertyPathKeyMatches = (key, name) => {
    if (key === null)
        return true;
    if (typeof key !== "object")
        return String(key) === name;
    if (key.excludedKeys.includes(name))
        return false;
    if (key.startIndex === undefined)
        return true;
    const index = semanticArrayIndex(name);
    return index !== null && index >= key.startIndex;
};
const coverageNode = () => ({
    terminal: false,
    exact: new Map(),
    selectors: new Map(),
});
/** Index exact effect prefixes without widening distinct member paths. */
export class SemanticPropertyPathCoverage {
    #root = coverageNode();
    /** Retain a path only when no previously retained prefix covers it. */
    retain(path) {
        if (this.covers(path))
            return false;
        let node = this.#root;
        for (const key of path) {
            if (key !== null && typeof key !== "object") {
                const name = String(key);
                let child = node.exact.get(name);
                if (child === undefined) {
                    child = coverageNode();
                    node.exact.set(name, child);
                }
                node = child;
            }
            else {
                const identity = JSON.stringify(key);
                let selected = node.selectors.get(identity);
                if (selected === undefined) {
                    selected = { key, node: coverageNode() };
                    node.selectors.set(identity, selected);
                }
                node = selected.node;
            }
        }
        node.terminal = true;
        node.exact.clear();
        node.selectors.clear();
        return true;
    }
    /** Query retained prefixes without changing the coverage index. */
    covers(path) {
        const pending = [{ node: this.#root, offset: 0 }];
        while (pending.length > 0) {
            const current = pending.pop();
            if (current === undefined)
                break;
            if (current.node.terminal)
                return true;
            const key = path[current.offset];
            if (key === undefined)
                continue;
            if (key !== null && typeof key !== "object") {
                const exact = current.node.exact.get(String(key));
                if (exact !== undefined)
                    pending.push({ node: exact, offset: current.offset + 1 });
            }
            for (const selected of current.node.selectors.values()) {
                if (keyCovers(selected.key, key))
                    pending.push({ node: selected.node, offset: current.offset + 1 });
            }
        }
        return false;
    }
}
const keyCovers = (covering, key) => {
    if (covering === null)
        return true;
    if (key === null)
        return false;
    if (typeof key !== "object")
        return typeof covering === "object"
            ? semanticPropertyPathKeyMatches(covering, String(key))
            : String(covering) === String(key);
    return (typeof covering === "object" &&
        covering.excludedKeys.every((name) => key.excludedKeys.includes(name)) &&
        (covering.startIndex === undefined ||
            (key.startIndex !== undefined && covering.startIndex <= key.startIndex)));
};
