import { z } from "zod";
import { RegularFileCleanupFailure } from "./RegularFileRead.js";
import { classifyClientRegistrationCommand } from "./ClientRegistrationIdentity.js";
import { readClientRegistrationInspections } from "./ClientRegistrationStatus.js";
import { existingSkillDestinations } from "./SetupSkill.js";
const setupPlanSchema = z.object({
    status: z.literal("planned"),
    plannedActions: z.array(z.object({
        id: z.string(),
        kind: z.enum(["configure_client", "install_skill"]),
        label: z.string(),
        target: z.string(),
        detail: z.string(),
        external: z.literal(false),
        operation: z.enum(["create", "update", "install"]),
        backupPath: z.string().optional(),
        commands: z.array(z.string()).optional(),
    })),
});
/** Discover owned registrations and PhxRE skills without writes. */
export const existingMaintenanceScope = async (home, entryPoint, environment, resources) => {
    const registrations = await readClientRegistrationInspections(home, entryPoint, {
        environment,
        ...(resources === undefined ? {} : { resources }),
    });
    const clients = [];
    for (const { status: registration, activation } of registrations) {
        if (activation !== "enabled" ||
            (registration.state !== "aligned" && registration.state !== "stale") ||
            classifyClientRegistrationCommand(registration.command, entryPoint) !==
                "owned")
            continue;
        clients.push(registration.client);
    }
    const skillDestinations = await existingSkillDestinations(home, environment, process.platform, resources);
    return {
        clients,
        skill: skillDestinations.length > 0,
        skillDestinations,
    };
};
/** Ask the verified new executable to plan only existing PhxRE integrations. */
export const planIntegrationMaintenance = async (home, entryPoint, environment, execute, resources) => {
    try {
        const scope = await existingMaintenanceScope(home, entryPoint, environment, resources);
        const skillDestinations = scope.skillDestinations ?? [];
        if (scope.clients.length === 0 && !scope.skill)
            return { status: "current", plannedActions: [] };
        const command = [
            process.execPath,
            entryPoint,
            "setup",
            ...scope.clients.flatMap((client) => ["--client", client]),
            ...skillDestinations.flatMap(({ client }) => ["--skill-client", client]),
            `--skill=${String(scope.skill)}`,
        ];
        const execution = await execute([...command, "--dry-run", "--json"]);
        if (!execution.ok)
            return { status: "unavailable", remediation: execution.error };
        const plan = setupPlanSchema.safeParse(JSON.parse(execution.value));
        if (!plan.success)
            return {
                status: "unavailable",
                remediation: `The updated setup executable returned an invalid maintenance plan: ${plan.error.message}`,
            };
        if (plan.data.plannedActions.length === 0)
            return { status: "current", plannedActions: [] };
        const allowedIds = new Set(scope.clients.map((client) => `configure_client:${client}`));
        const skillTargets = new Set(skillDestinations.map(({ path }) => path));
        if (plan.data.plannedActions.some((action) => action.kind === "install_skill"
            ? !skillTargets.has(action.target)
            : !allowedIds.has(action.id)))
            return {
                status: "unavailable",
                remediation: "The updated setup plan included an integration outside the existing PhxRE maintenance scope.",
            };
        return {
            status: "planned",
            scope,
            command,
            plannedActions: plan.data.plannedActions.map(({ backupPath, commands, ...action }) => ({
                ...action,
                ...(backupPath === undefined ? {} : { backupPath }),
                ...(commands === undefined ? {} : { commands }),
            })),
        };
    }
    catch (cause) {
        // Without a supplied scope, the typed failure is the caller's cleanup capability.
        if (resources === undefined && cause instanceof RegularFileCleanupFailure)
            throw cause;
        return {
            status: "unavailable",
            remediation: cause instanceof Error ? cause.message : String(cause),
        };
    }
};
