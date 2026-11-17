import assert from "node:assert/strict";
import test from "node:test";
import { DEFAULT_LOCALE, normalizeLocale, translateFrom } from "./core.ts";
import { enMessages, MESSAGES, zhCNMessages } from "./messages.ts";

test("zh-CN and en dictionaries have identical keys and non-empty translations", () => {
  const enKeys = Object.keys(enMessages).sort();
  const zhKeys = Object.keys(zhCNMessages).sort();
  assert.deepEqual(zhKeys, enKeys);
  for (const k of enKeys) {
    assert.ok(enMessages[k].trim().length > 0, `empty en translation for ${k}`);
    assert.ok(zhCNMessages[k].trim().length > 0, `empty zh-CN translation for ${k}`);
  }
});

test("normalizeLocale resolves supported prefixes and falls back to default", () => {
  assert.equal(normalizeLocale("zh"), "zh-CN");
  assert.equal(normalizeLocale("zh-Hans"), "zh-CN");
  assert.equal(normalizeLocale("en-US"), "en");
  assert.equal(normalizeLocale("EN"), "en");
  assert.equal(normalizeLocale(null), DEFAULT_LOCALE);
  assert.equal(normalizeLocale("fr-FR"), DEFAULT_LOCALE);
});

test("translateFrom interpolates variables in both locales", () => {
  assert.equal(
    translateFrom(MESSAGES, "zh-CN", "wordlists.savedToast", { name: "top100" }),
    "加密密码本「top100」已存入保险库",
  );
  assert.equal(
    translateFrom(MESSAGES, "en", "wordlists.savedToast", { name: "top100" }),
    'Encrypted wordlist "top100" saved to vault',
  );
  assert.equal(
    translateFrom(MESSAGES, "zh-CN", "depth.checks.title", { completed: 3, total: 4, percent: 75 }),
    "合规检查清单 (3/4 · 75%)",
  );
});
