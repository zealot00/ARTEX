import assert from "node:assert/strict";
import test from "node:test";
import {
  formatRulesText,
  formatSessionEndpoint,
  parseLineEntries,
  summarizeChecksProgress,
} from "./depth-ops.ts";

test("parseLineEntries trims, strips comments, and deduplicates", () => {
  const raw = `
    # comment
    10.10.0.0/16
    *.corp.local

    10.10.0.0/16
      https://portal.corp.local:8443  
  `;
  assert.deepEqual(parseLineEntries(raw), [
    "10.10.0.0/16",
    "*.corp.local",
    "https://portal.corp.local:8443",
  ]);
  assert.equal(formatRulesText(["10.10.0.0/16", "*.corp.local"]), "10.10.0.0/16\n*.corp.local");
});

test("summarizeChecksProgress computes completed percentage", () => {
  const res = summarizeChecksProgress([
    { status: "passed" },
    { status: "failed" },
    { status: "na" },
    { status: "pending" },
  ]);
  assert.deepEqual(res, {
    total: 4,
    completed: 3,
    passed: 1,
    failed: 1,
    percent: 75,
  });
  assert.equal(summarizeChecksProgress([]).percent, 0);
});

test("formatSessionEndpoint includes SOCKS5 listener when present", () => {
  assert.equal(
    formatSessionEndpoint({ kind: "ssh", target: "10.10.0.5", port: 22, socks_addr: "127.0.0.1:41234" }),
    "10.10.0.5:22 (SOCKS5 127.0.0.1:41234)",
  );
  assert.equal(formatSessionEndpoint({ kind: "pty" }), "local");
});
