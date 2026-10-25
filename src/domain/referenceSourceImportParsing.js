import { traverseJavaScriptAst } from "./javascript/javascriptSemanticTraversal.js";
import { parseRecoveredJavaScript, parserPluginsForPath, } from "./javascript/javascriptSourceParser.js";
import { unshadowedReferenceSourceRequireCalls } from "./referenceSourceRequireBindings.js";
import { isRelativeJavaScriptModuleSpecifier } from "./javascript/javascriptModuleSpecifier.js";
import { isCallExpression, isExportAllDeclaration, isExportNamedDeclaration, isIdentifier, isImport, isImportDeclaration, isImportExpression, isMemberExpression, isStringLiteral, isTSExternalModuleReference, isTSImportEqualsDeclaration, isTSModuleDeclaration, } from "@babel/types";
export const PARSEABLE_REFERENCE_SOURCE_LANGUAGES = new Set(["JavaScript", "TypeScript", "JSX", "TSX"]);
const safeModuleName = (node) => {
    if (isStringLiteral(node))
        return node.value;
    return undefined;
};
const resolveSpecifier = (specifier) => {
    if (isRelativeJavaScriptModuleSpecifier(specifier) ||
        specifier.startsWith("/"))
        return "internal";
    return "external";
};
const isModuleExpression = (expression) => isStringLiteral(expression) || isCallExpression(expression);
const moduleSpecifierFromExpression = (expression) => {
    if (isStringLiteral(expression))
        return { specifier: expression.value, parseState: "parsed" };
    if (isCallExpression(expression) &&
        isImport(expression.callee) &&
        expression.arguments.length > 0) {
        const first = expression.arguments[0];
        if (isStringLiteral(first)) {
            return { specifier: first.value, parseState: "parsed" };
        }
        return { specifier: "<dynamic-import>", parseState: "partial" };
    }
    return undefined;
};
const appendRelationship = (relationships, input) => {
    if (input.to === undefined)
        return;
    relationships.push({
        from_path: input.fromPath,
        to: input.to,
        kind: input.kind,
        resolution: input.resolution ?? resolveSpecifier(input.to),
        parse_state: input.parseState,
        ...(input.resolutionStrategy === undefined
            ? {}
            : { resolutionStrategy: input.resolutionStrategy }),
    });
};
const extractImportDeclarations = (body, from_path, relationships) => {
    for (const statement of body) {
        if (isImportDeclaration(statement)) {
            appendRelationship(relationships, {
                fromPath: from_path,
                to: safeModuleName(statement.source),
                kind: "imports",
                parseState: "parsed",
            });
            continue;
        }
        if (isExportNamedDeclaration(statement)) {
            if (statement.source !== null && statement.source !== undefined) {
                appendRelationship(relationships, {
                    fromPath: from_path,
                    to: safeModuleName(statement.source),
                    kind: "imports",
                    parseState: "parsed",
                });
            }
            continue;
        }
        if (isExportAllDeclaration(statement)) {
            appendRelationship(relationships, {
                fromPath: from_path,
                to: safeModuleName(statement.source),
                kind: "imports",
                parseState: "parsed",
            });
            continue;
        }
        if (isTSImportEqualsDeclaration(statement)) {
            const reference = statement.moduleReference;
            if (isTSExternalModuleReference(reference)) {
                appendRelationship(relationships, {
                    fromPath: from_path,
                    to: safeModuleName(reference.expression),
                    kind: "requires",
                    parseState: "parsed",
                });
            }
            continue;
        }
        if (isTSModuleDeclaration(statement)) {
            if (statement.declare === true && isStringLiteral(statement.id)) {
                appendRelationship(relationships, {
                    fromPath: from_path,
                    to: statement.id.value,
                    kind: "declares-module",
                    parseState: "parsed",
                    resolution: "unknown",
                });
            }
        }
    }
};
const isRequireCallee = (callee) => {
    if (isIdentifier(callee) && callee.name === "require")
        return true;
    if (isMemberExpression(callee) &&
        isIdentifier(callee.object) &&
        callee.object.name === "require" &&
        ((!callee.computed && isIdentifier(callee.property)) ||
            isStringLiteral(callee.property))) {
        const propertyName = isIdentifier(callee.property)
            ? callee.property.name
            : isStringLiteral(callee.property)
                ? callee.property.value
                : undefined;
        return propertyName === "resolve" || propertyName === "main";
    }
    return false;
};
const extractRequireAndDynamicImports = (body, from_path, relationships, unshadowedRequireCalls) => {
    // Single traversal owner: iterative, VISITOR_KEYS-gated, no recursion over
    // loc/comment objects. Survives deeply nested generated member chains that
    // overflowed the previous hand-rolled Object.values walker.
    const expressions = [];
    for (const statement of body)
        traverseJavaScriptAst(statement, {
            enter: (node) => {
                if (isCallExpression(node) || isImportExpression(node))
                    expressions.push(node);
            },
        });
    for (const call of expressions) {
        if (isImportExpression(call)) {
            const specifier = safeModuleName(call.source);
            appendRelationship(relationships, {
                fromPath: from_path,
                to: specifier ?? "<dynamic-import>",
                kind: "imports",
                parseState: specifier === undefined ? "partial" : "parsed",
                ...(specifier === undefined ? { resolution: "unknown" } : {}),
            });
            continue;
        }
        const first = call.arguments[0];
        if (isRequireCallee(call.callee) &&
            unshadowedRequireCalls.has(call) &&
            isModuleExpression(first)) {
            const result = moduleSpecifierFromExpression(first);
            if (result !== undefined) {
                appendRelationship(relationships, {
                    fromPath: from_path,
                    to: result.specifier,
                    kind: "requires",
                    parseState: result.parseState,
                    resolutionStrategy: "runtime-require",
                });
            }
            continue;
        }
        if (isImport(call.callee) && isModuleExpression(first)) {
            const result = moduleSpecifierFromExpression(first);
            if (result !== undefined) {
                appendRelationship(relationships, {
                    fromPath: from_path,
                    to: result.specifier,
                    kind: "imports",
                    parseState: result.parseState,
                });
            }
        }
    }
};
const parseWithBabel = (path, source, language) => {
    // Single parser-mode owner: path-driven plugins (dts/JSX/mts) shared with
    // the semantic pipeline. `language` only gates non-JS/TS callers upstream;
    // TypeScript syntax must parse identically here and in semantic analysis.
    void language;
    const plugins = parserPluginsForPath(path);
    try {
        const { file: ast, moduleOnlyErrors } = parseRecoveredJavaScript(source, path, {
            allowImportExportEverywhere: false,
            allowReturnOutsideFunction: true,
            allowUndeclaredExports: true,
            plugins,
        });
        return {
            ast,
            reasons: ast.errors.map((error) => error.message),
            moduleOnlyErrors,
        };
    }
    catch (cause) {
        return {
            ast: undefined,
            reasons: [cause instanceof Error ? cause.message : "Parse failed"],
            moduleOnlyErrors: [],
        };
    }
};
/** Parse ESM/CommonJS imports and dynamic imports from source bytes. */
export const parseReferenceSourceImports = (path, bytes, language) => {
    if (language !== null && !PARSEABLE_REFERENCE_SOURCE_LANGUAGES.has(language))
        return { relationships: [], parse_failures: [], limitations: [] };
    let source;
    try {
        source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    }
    catch {
        return {
            relationships: [],
            parse_failures: [
                {
                    path,
                    parser: "utf-8",
                    reason: "Source bytes are not valid UTF-8; import targets were not parsed.",
                },
            ],
            limitations: [],
        };
    }
    const { ast, reasons, moduleOnlyErrors } = parseWithBabel(path, source, language);
    const limitations = moduleOnlyErrors.length === 0
        ? []
        : [
            `Strict-mode errors apply only if this file is an ES module: ${moduleOnlyErrors.join("; ")}`,
        ];
    const parseFailures = reasons.map((reason) => ({
        path,
        parser: "babel",
        reason,
    }));
    if (ast === undefined) {
        return {
            relationships: [],
            parse_failures: parseFailures,
            limitations,
        };
    }
    const relationships = [];
    extractImportDeclarations(ast.program.body, path, relationships);
    extractRequireAndDynamicImports(ast.program.body, path, relationships, unshadowedReferenceSourceRequireCalls(ast, path));
    return {
        relationships: relationships.map((relationship) => ({
            ...relationship,
            parse_state: parseFailures.length > 0 && relationship.parse_state === "parsed"
                ? "partial"
                : relationship.parse_state,
        })),
        parse_failures: parseFailures,
        limitations,
    };
};
