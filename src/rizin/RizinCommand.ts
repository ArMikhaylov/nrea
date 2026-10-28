import type { RizinInput } from "../domain/reverseEngineering.js";
import { absoluteCallerPath } from "../filesystem/callerPath.js";

export const RIZIN_PROVIDER_IDENTITY = {
  id: "rizin",
  name: "Rizin",
  version: null,
} as const;

/**
 * Default one-shot presentation to plain text while retaining plugin
 * availability. `cfg.sandbox` is set before `-c` runs, so the command cannot
 * reach the shell (`!`, `#!pipe`), write outside the target or clear the
 * setting again; the operator may disable it with REA_RIZIN_SANDBOX=disabled.
 */
export const rizinCommand = (
  input: RizinInput,
  sandbox = true,
): readonly string[] => [
  "-N",
  "-q",
  "-e",
  "scr.color=0",
  ...(sandbox ? ["-e", "cfg.sandbox=true"] : []),
  "-c",
  input.command,
  absoluteCallerPath(input.path),
];
