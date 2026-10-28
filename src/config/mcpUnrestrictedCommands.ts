import { z } from "zod";

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

export const MCP_UNRESTRICTED_COMMANDS_SETTING =
  "REA_MCP_UNRESTRICTED_COMMANDS";

export const unrestrictedCommandsConstraint = `${MCP_UNRESTRICTED_COMMANDS_SETTING} must be "enabled" or "disabled"; unset means disabled.`;

export const mcpUnrestrictedCommandsSchema = z.enum(["enabled", "disabled"]);

/** Parse the opt-in; anything but an exact "enabled" keeps the tools refused. */
export const parseMcpUnrestrictedCommands = (
  value: string | undefined,
): Result<boolean, ConfigurationError> => {
  if (value === undefined) return ok(false);
  const parsed = mcpUnrestrictedCommandsSchema.safeParse(value);
  return parsed.success
    ? ok(parsed.data === "enabled")
    : err(
        new ConfigurationError(unrestrictedCommandsConstraint, {
          settings: [
            {
              setting: MCP_UNRESTRICTED_COMMANDS_SETTING,
              constraint: unrestrictedCommandsConstraint,
            },
          ],
        }),
      );
};

/** The refusal an unrestricted command tool returns before doing any work. */
export const unrestrictedCommandRefusal = (tool: string): ConfigurationError =>
  new ConfigurationError(
    `${tool} is disabled: it runs free-form engine commands or scripts that can execute arbitrary code on this host, and text inside an analyzed target can steer an agent into calling it. Ask the user to set ${MCP_UNRESTRICTED_COMMANDS_SETTING}=enabled in the MCP server registration only if they accept that risk. Do not retry this call.`,
    {
      settings: [
        {
          setting: MCP_UNRESTRICTED_COMMANDS_SETTING,
          constraint: unrestrictedCommandsConstraint,
        },
      ],
    },
  );
