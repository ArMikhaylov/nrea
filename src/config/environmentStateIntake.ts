import { realpath, stat } from "node:fs/promises";
import { isAbsolute } from "node:path";

import { ConfigurationError } from "../domain/configurationErrors.js";
import { err, ok, type Result } from "../domain/result.js";

export const ENVIRONMENT_STATE_ROOT_SETTING = "REA_ENVIRONMENT_STATE_ROOT";
export const ENVIRONMENT_STATE_HTTPS_SETTING = "REA_ENVIRONMENT_STATE_HTTPS";

const ROOT_CONSTRAINT = `${ENVIRONMENT_STATE_ROOT_SETTING} must name an existing absolute directory.`;
const HTTPS_CONSTRAINT = `${ENVIRONMENT_STATE_HTTPS_SETTING} must be "enabled" or "disabled"; unset means disabled.`;

/** Which `data/add` uris an environment server may follow; both are off unless the operator opts in. */
export interface EnvironmentStateIntakeSettings {
  /** Canonical directory `file://` documents must resolve inside. */
  readonly stateFileRoot?: string;
  readonly allowHttpsState: boolean;
}

const refusal = (setting: string, constraint: string): ConfigurationError =>
  new ConfigurationError(constraint, { settings: [{ setting, constraint }] });

/** Resolve the root once at startup so later symlink checks compare canonical paths. */
export const resolveEnvironmentStateIntake = async (
  environment: Readonly<NodeJS.ProcessEnv>,
): Promise<Result<EnvironmentStateIntakeSettings, ConfigurationError>> => {
  const https = environment[ENVIRONMENT_STATE_HTTPS_SETTING];
  if (https !== undefined && https !== "enabled" && https !== "disabled")
    return err(refusal(ENVIRONMENT_STATE_HTTPS_SETTING, HTTPS_CONSTRAINT));
  const allowHttpsState = https === "enabled";
  const root = environment[ENVIRONMENT_STATE_ROOT_SETTING];
  if (root === undefined) return ok({ allowHttpsState });
  if (!isAbsolute(root))
    return err(refusal(ENVIRONMENT_STATE_ROOT_SETTING, ROOT_CONSTRAINT));
  try {
    const canonical = await realpath(root);
    if (!(await stat(canonical)).isDirectory())
      return err(refusal(ENVIRONMENT_STATE_ROOT_SETTING, ROOT_CONSTRAINT));
    return ok({ stateFileRoot: canonical, allowHttpsState });
  } catch {
    return err(refusal(ENVIRONMENT_STATE_ROOT_SETTING, ROOT_CONSTRAINT));
  }
};
