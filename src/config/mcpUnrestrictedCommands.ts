import { z } from "zod";

import { TOOL_EFFECTS } from "../contracts/toolEffects.js";
import { AnalysisInputError } from "../domain/analysisErrorCore.js";
import { ConfigurationError } from "../domain/configurationErrors.js";
import { err, ok, type Result } from "../domain/result.js";

/**
 * MCP tools whose input is free-form text that a host engine interprets with
 * the operator's privileges: Rizin and GDB command languages reach the shell
 * (`!cmd`, `shell`, `python`), and Frida scripts run arbitrary code inside the
 * target. An agent reads untrusted target content, so text planted in a
 * target can steer these calls. They refuse unless the operator opts in.
 * CLI commands are typed by the operator and are not gated.
 */
export const UNRESTRICTED_COMMAND_TOOLS: ReadonlySet<string> = new Set([
  "cutter_command",
  "execute_rizin_command",
  "rizin_debug_command",
  "gdb_console",
  "load_frida_script",
  "instrument_with_frida",
]);

/**
 * Every other tool whose declared effects run the analysis target (or the
 * application loaded into one) with the user's permissions. Derived from the
 * canonical effects so a new tool cannot silently skip the gate. Close tools
 * stay available: they release owned processes and must never be refused.
 */
export const TARGET_EXECUTION_TOOLS: ReadonlySet<string> = new Set(
  Object.entries(TOOL_EFFECTS)
    .filter(
      ([name, effects]) =>
        effects.executesForeignCode &&
        !UNRESTRICTED_COMMAND_TOOLS.has(name) &&
        !name.startsWith("close_"),
    )
    .map(([name]) => name),
);

export const MCP_UNRESTRICTED_COMMANDS_SETTING =
  "REA_MCP_UNRESTRICTED_COMMANDS";
export const MCP_TARGET_EXECUTION_SETTING = "REA_MCP_TARGET_EXECUTION";

const optInConstraint = (setting: string): string =>
  `${setting} must be "enabled" or "disabled"; unset means disabled.`;

export const mcpOptInSchema = z.enum(["enabled", "disabled"]);

/** Parse one opt-in; anything but an exact "enabled" keeps its tools refused. */
export const parseMcpOptIn = (
  setting: string,
  value: string | undefined,
): Result<boolean, ConfigurationError> => {
  if (value === undefined) return ok(false);
  const parsed = mcpOptInSchema.safeParse(value);
  const constraint = optInConstraint(setting);
  return parsed.success
    ? ok(parsed.data === "enabled")
    : err(
        new ConfigurationError(constraint, {
          settings: [{ setting, constraint }],
        }),
      );
};

/** The setting a gated tool waits for, or undefined when it is not gated. */
export const gatingSetting = (tool: string): string | undefined =>
  UNRESTRICTED_COMMAND_TOOLS.has(tool)
    ? MCP_UNRESTRICTED_COMMANDS_SETTING
    : TARGET_EXECUTION_TOOLS.has(tool)
      ? MCP_TARGET_EXECUTION_SETTING
      : undefined;

const REASONS: Readonly<Record<string, string>> = {
  [MCP_UNRESTRICTED_COMMANDS_SETTING]:
    "it runs free-form engine commands or scripts that can execute arbitrary code on this host",
  [MCP_TARGET_EXECUTION_SETTING]:
    "it runs the analyzed target or the application loaded into one with the user's permissions",
};

/**
 * The refusal a gated tool returns before doing any work. It is an input
 * refusal, not a configuration error: the setting is valid, the operator has
 * simply not opted in, and the agent must not retry or route around it.
 */
export const gatedToolRefusal = (
  tool: string,
  setting: string,
): AnalysisInputError =>
  new AnalysisInputError(tool, {
    userMessage: `${tool} is disabled on this server: ${REASONS[setting] ?? "it is gated"}, and text inside an analyzed target can steer an agent into calling it.`,
    remediationAction: `Do not retry this call. Tell the user what it would run; only they can enable it by setting ${setting}=enabled in the MCP server registration, and only if they accept that risk.`,
  });
