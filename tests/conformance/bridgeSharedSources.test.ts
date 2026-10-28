import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { expect, it } from "vitest";

import { CAPTURE_CREDENTIAL_HEADERS } from "../../src/browser/history/CaptureRedaction.js";

// Python bridges load inside foreign hosts (Hopper, Cutter, mitmdump) and cannot
// import shared REA modules, so the few duplicated definitions are pinned here.

const source = (path: string): string =>
  readFileSync(resolve(path), "utf8").replaceAll("\r\n", "\n");

/** The text of one top-level `def name(...)` through the line before the next top-level statement. */
const topLevelFunction = (text: string, name: string): string => {
  const start = text.indexOf(`\ndef ${name}(`);
  expect(start, name).toBeGreaterThan(-1);
  const rest = text.slice(start + 1);
  const end = rest.slice(1).search(/\n(?=[^\s#])/u);
  return end === -1 ? rest : rest.slice(0, end + 1);
};

const constant = (text: string, name: string): string => {
  const match = new RegExp(`^${name} = (.+)$`, "mu").exec(text);
  expect(match?.[1], name).toBeDefined();
  return match?.[1] ?? "";
};

it("keeps the bridge request ceiling parser identical in the Hopper and Cutter bridges", () => {
  const hopper = source("bridge/hopper_bridge.py");
  const cutter = source("bridge/cutter/rea_bridge.py");
  for (const name of [
    "_bridge_max_request_bytes_constraint",
    "_parse_bridge_max_request_bytes",
  ])
    expect(topLevelFunction(cutter, name), name).toBe(
      topLevelFunction(hopper, name),
    );
  for (const name of [
    "DEFAULT_BRIDGE_MAX_REQUEST_BYTES",
    "MINIMUM_BRIDGE_MAX_REQUEST_BYTES",
    "MAXIMUM_BRIDGE_MAX_REQUEST_BYTES",
  ])
    expect(constant(cutter, name), name).toBe(constant(hopper, name));
});

it("redacts the same credential headers in the mitmproxy adapter as in TypeScript captures", () => {
  const capture = source("bridge/mitmproxy/capture.py");
  const block = /^CREDENTIALS = \{([^}]*)\}/mu.exec(capture)?.[1];
  expect(block).toBeDefined();
  const python = [...(block ?? "").matchAll(/b"([^"]+)"/gu)].map(
    (match) => match[1],
  );
  expect(new Set(python).size).toBe(python.length);
  expect([...python].sort()).toEqual([...CAPTURE_CREDENTIAL_HEADERS].sort());
});
