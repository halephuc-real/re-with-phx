import { toolInputSchemaWithMetadata, toolOutputSchemaWithMetadata, } from "../contracts/toolSchemaMetadata.js";
/** Preserve advertised contracts while the application owns structured input failures. */
export const applicationValidatedInputSchema = (schema) => ({
    "~standard": {
        ...schema["~standard"],
        vendor: "phxre-application",
        validate: (value) => ({ value }),
    },
});
/** Project the canonical Zod contracts directly into SDK registration. */
export const toolRegistrationOptions = (contract) => ({
    title: contract.title,
    description: contract.description,
    inputSchema: toolInputSchemaWithMetadata(contract),
    outputSchema: toolOutputSchemaWithMetadata(contract),
    annotations: contract.annotations,
});
