import { expect, it } from "vitest";

import { createReverseEngineeringCommandPort } from "../../src/composition/reverseEngineering.js";
import { rizinCommand } from "../../src/rizin/RizinCommand.js";

const input = { path: "/fixture/target", command: "!id" };

it("sandboxes the one-shot command before -c runs unless the operator disables it", () => {
  const sandboxed = rizinCommand(input);
  expect(sandboxed.indexOf("cfg.sandbox=true")).toBeGreaterThan(-1);
  expect(sandboxed.indexOf("cfg.sandbox=true")).toBeLessThan(
    sandboxed.indexOf("-c"),
  );
  expect(rizinCommand(input, false)).not.toContain("cfg.sandbox=true");
});

it("reads REA_RIZIN_SANDBOX from the provider environment", () => {
  const argumentsFor = (environment: NodeJS.ProcessEnv) =>
    createReverseEngineeringCommandPort(environment, "linux").rizin(input)
      .arguments;
  expect(argumentsFor({})).toContain("cfg.sandbox=true");
  expect(argumentsFor({ REA_RIZIN_SANDBOX: "enabled" })).toContain(
    "cfg.sandbox=true",
  );
  expect(argumentsFor({ REA_RIZIN_SANDBOX: "disabled" })).not.toContain(
    "cfg.sandbox=true",
  );
});
