// Command-palette ranking (argus/web/js/fuzzy.js). Run: node --test tests/js/*.test.mjs
import assert from "node:assert/strict";
import { test } from "node:test";

import { rank, score } from "../../argus/web/js/fuzzy.js";

const ITEMS = [
  { label: "New investigation", keywords: "scan start" },
  { label: "Exposure", keywords: "breach dark web" },
  { label: "Ransomware", keywords: "leak sites groups" },
  { label: "Attack paths", keywords: "" },
  { label: "acme-corp.example", keywords: "investigation domain" },
  { label: "Settings", keywords: "keys members theme" },
];
const labels = (q) => rank(ITEMS, q).map((i) => i.label);

test("an empty query keeps every item, in order", () => {
  assert.deepEqual(labels(""), ITEMS.map((i) => i.label));
});

test("a prefix beats a word start, which beats a match inside a word", () => {
  assert.ok(score("Exposure", "exp") > score("Attack paths", "paths"));
  assert.ok(score("Attack paths", "paths") > score("acme-corp.example", "orp"));
  assert.equal(labels("paths")[0], "Attack paths");
});

test("every word must match, in label or keywords", () => {
  assert.deepEqual(labels("dark web"), ["Exposure"]);
  assert.deepEqual(labels("acme domain"), ["acme-corp.example"]);
  assert.deepEqual(labels("acme nothing"), []);
});

test("abbreviations and typos still find a page by its letters in order", () => {
  assert.equal(labels("rnsm")[0], "Ransomware");
  assert.equal(labels("sttngs")[0], "Settings");
  assert.equal(score("Ransomware", "z"), 0);  // one letter must really be there
});

test("the limit is respected and ties keep their order", () => {
  assert.equal(rank(ITEMS, "", 2).length, 2);
  const tie = rank([{ label: "b x" }, { label: "a x" }], "x").map((i) => i.label);
  assert.deepEqual(tie, ["b x", "a x"]);
});

test("letters-in-order never come from hidden keywords, nor from letters far apart", () => {
  const items = [
    { label: "Investigate a person", keywords: "people name username email phone one box" },  // r…n…s…m across words
    { label: "Ransomware", keywords: "leak sites" },
  ];
  assert.deepEqual(rank(items, "rnsm").map((i) => i.label), ["Ransomware"]);
  assert.equal(score("a very long label with r and later n then s and m", "rnsm"), 0);  // too spread out
});
