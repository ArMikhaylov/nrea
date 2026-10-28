import {
  Client,
  StreamableHTTPClientTransport,
} from "@modelcontextprotocol/client";
import { describe, expect, onTestFinished } from "vitest";

import { advertisedMcpToolSchemas } from "../../fixtures/advertisedMcpTool.js";
import {
  expectForeignHostRefused,
  rawHttpRequest,
} from "../../support/http/rawRequest.js";
import {
  mcpHttpTestAuthorization,
  startMcpHttpProcess,
} from "../../support/mcp/streamableHttpProcess.js";
import { processTest } from "../../support/process/processFixture.js";
import { assertAdvertisedMcpContracts } from "./mcpContractHarness.js";

const HTTP_BOUNDARY_TIMEOUT_MS = 90_000;

const openSession = async (url: URL, name: string) => {
  const transport = new StreamableHTTPClientTransport(url, {
    requestInit: { headers: mcpHttpTestAuthorization },
  });
  const client = new Client({ name, version: "1" });
  onTestFinished(() => client.close());
  await client.connect(transport);
  expect(transport.sessionId).toEqual(expect.any(String));
  const { toolDefinition } = await advertisedMcpToolSchemas(
    client,
    "binary_session",
  );
  assertAdvertisedMcpContracts(["binary_session"], [toolDefinition]);
  return { transport, client, toolDefinition };
};

/** The shared target answers with its identity only while its providers are still open. */
const expectIdentity = async ({
  client,
  toolDefinition,
}: Awaited<ReturnType<typeof openSession>>): Promise<void> => {
  const identity = await client.callTool(
    { name: "binary_session", arguments: {} },
    { toolDefinition },
  );
  expect(identity.isError).toBeFalsy();
  expect(identity.structuredContent).toMatchObject({
    result: {
      server_identity: { package: { version: expect.any(String) } },
    },
  });
};

describe("rea mcp --http", () => {
  processTest(
    "serves initialize, tools/list, a tool call and DELETE, then keeps serving later clients",
    async ({ processes }) => {
      const started = await startMcpHttpProcess(processes);
      expect(started.url.hostname).toBe("127.0.0.1");
      expect(started.url.pathname).toBe("/mcp");
      let stdout = "";
      started.child.stdout.on("data", (chunk: Buffer) => {
        stdout += chunk.toString("utf8");
      });
      const first = await openSession(started.url, "streamable-http-boundary");
      await expectIdentity(first);
      await first.transport.terminateSession();
      expect(first.transport.sessionId).toBeUndefined();
      await first.client.close();
      // DELETE ended the session, not the server: the next client's tools still work.
      const second = await openSession(started.url, "next-session");
      await expectIdentity(second);
      // A client that leaves without DELETE does not block the listener: the next initialize replaces it.
      const third = await openSession(started.url, "replacing-session");
      expect(third.transport.sessionId).not.toBe(second.transport.sessionId);
      await expectIdentity(third);
      await expect(expectIdentity(second)).rejects.toThrow("Session not found");
      await second.client.close();
      await third.transport.terminateSession();
      await third.client.close();
      expect(stdout).toBe("");
      expect(started.stderr()).toContain('"transport":"streamable-http"');
      expect(started.stderr()).toContain(
        "MCP HTTP session replaced by a new client",
      );
    },
    HTTP_BOUNDARY_TIMEOUT_MS,
  );

  processTest(
    "refuses a non-loopback Host header on the loopback bind",
    async ({ processes }) => {
      const { url } = await startMcpHttpProcess(processes);
      const refused = await expectForeignHostRefused(url);
      expect(refused.body).not.toContain("127.0.0.1");
    },
    HTTP_BOUNDARY_TIMEOUT_MS,
  );

  processTest(
    "refuses requests without the bearer token, including a wrong one",
    async ({ processes }) => {
      const { url } = await startMcpHttpProcess(processes);
      const initialize = JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-06-18",
          capabilities: {},
          clientInfo: { name: "unauthenticated", version: "1" },
        },
      });
      const headers = {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
      };
      for (const authorization of [
        undefined,
        "Bearer wrong-token-0123456789abcdefghijklmnop",
        "Basic cmVhOnJlYQ==",
      ]) {
        const refused = await rawHttpRequest(url, {
          method: "POST",
          headers:
            authorization === undefined
              ? headers
              : { ...headers, authorization },
          body: initialize,
        });
        expect(refused.status).toBe(401);
        expect(JSON.parse(refused.body)).toMatchObject({
          jsonrpc: "2.0",
          error: { code: -32001 },
        });
      }
    },
    HTTP_BOUNDARY_TIMEOUT_MS,
  );

  processTest(
    "generates and announces a per-process token when none is pinned",
    async ({ processes }) => {
      const started = await startMcpHttpProcess(processes, [], {});
      const announced = /Authorization: Bearer ([A-Za-z0-9_-]{43})/u.exec(
        started.stderr(),
      );
      expect(announced?.[1]).toEqual(expect.any(String));
      const refused = await rawHttpRequest(started.url);
      expect(refused.status).toBe(401);
      const admitted = await rawHttpRequest(started.url, {
        headers: { authorization: `Bearer ${announced?.[1] ?? ""}` },
      });
      // Past authentication, the transport refuses a GET without an event-stream Accept.
      expect(admitted.status).toBe(406);
    },
    HTTP_BOUNDARY_TIMEOUT_MS,
  );
});
