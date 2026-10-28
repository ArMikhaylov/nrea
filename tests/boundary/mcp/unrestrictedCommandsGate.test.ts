import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { expect, it, onTestFinished } from "vitest";

import {
  createCacheProvider,
  createTestBinarySession,
} from "../../fixtures/binarySession.js";
import { UNRESTRICTED_COMMAND_TOOLS } from "../../../src/config/mcpUnrestrictedCommands.js";
import { TOOL_CONTRACTS } from "../../../src/contracts/toolContracts.js";
import { createServer } from "../../../src/server/createServer.js";
import { silentLogger } from "../../../src/logger.js";

const connect = async (environment: NodeJS.ProcessEnv): Promise<Client> => {
  const session = createTestBinarySession(createCacheProvider([]));
  const server = createServer(
    { kind: "session", session },
    { logger: silentLogger, environment },
  );
  const client = new Client({ name: "unrestricted-gate", version: "1" });
  onTestFinished(async () => {
    await client.close();
    await server.close();
    await session.close();
  });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return client;
};

const text = (result: Awaited<ReturnType<Client["callTool"]>>): string =>
  result.content
    .flatMap((part) => (part.type === "text" ? [part.text] : []))
    .join("\n");

it("names only published tools", () => {
  const published = new Set<string>(TOOL_CONTRACTS.map(({ name }) => name));
  for (const tool of UNRESTRICTED_COMMAND_TOOLS)
    expect(published.has(tool), tool).toBe(true);
});

it("refuses free-form engine commands unless the operator opts in", async () => {
  const environment = { ...process.env };
  delete environment.REA_MCP_UNRESTRICTED_COMMANDS;
  const client = await connect(environment);
  // The path does not exist: a handler that ran would report the path instead.
  const rizin = await client.callTool({
    name: "execute_rizin_command",
    arguments: { path: "/nonexistent/rea-gate-target", command: "!id" },
  });
  expect(rizin.isError).toBe(true);
  expect(text(rizin)).toContain("REA_MCP_UNRESTRICTED_COMMANDS");
  expect(text(rizin)).not.toContain("rea-gate-target");

  const cutter = await client.callTool({
    name: "cutter_command",
    arguments: {
      session_id: "00000000-0000-4000-8000-000000000001",
      expected_generation: 0,
      command: "!id",
    },
  });
  expect(cutter.isError).toBe(true);
  expect(text(cutter)).toContain("REA_MCP_UNRESTRICTED_COMMANDS");
});

it("keeps the refusal for an explicit disabled value", async () => {
  const client = await connect({
    ...process.env,
    REA_MCP_UNRESTRICTED_COMMANDS: "disabled",
  });
  const result = await client.callTool({
    name: "execute_rizin_command",
    arguments: { path: "/nonexistent/rea-gate-target", command: "iI" },
  });
  expect(result.isError).toBe(true);
  expect(text(result)).toContain("REA_MCP_UNRESTRICTED_COMMANDS");
});

it("rejects an unrecognized opt-in value at startup", () => {
  const session = createTestBinarySession(createCacheProvider([]));
  onTestFinished(async () => {
    await session.close();
  });
  expect(() =>
    createServer(
      { kind: "session", session },
      {
        logger: silentLogger,
        environment: { ...process.env, REA_MCP_UNRESTRICTED_COMMANDS: "yes" },
      },
    ),
  ).toThrow(/REA_MCP_UNRESTRICTED_COMMANDS/u);
});
