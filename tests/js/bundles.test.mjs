// Bundling of large graphs (argus/web/js/bundles.js). Run: node --test tests/js/*.test.mjs
import assert from "node:assert/strict";
import { test } from "node:test";

import { BUNDLE, computeView } from "../../argus/web/js/bundles.js";

const OPTIONS = { ...BUNDLE, minGraph: 50, minGroup: 10, target: 20 };

function model() {
  const entities = new Map();
  const relations = new Map();
  const add = (id, type, depth = 1) => entities.set(id, { id, type, depth, label: id });
  const link = (a, b, type = "REL") => relations.set(`${a}>${b}`, { id: `${a}>${b}`, source_id: a, target_id: b, type });
  return { entities, relations, add, link };
}

/** A domain with 60 subdomains, which resolve to 20 IPs, plus 15 lone IPs with a port each. */
function estate() {
  const m = model();
  m.add("seed", "domain", 0);
  for (let i = 0; i < 20; i++) m.add(`ip${i}`, "ip_address", 2);
  for (let i = 0; i < 60; i++) {
    m.add(`sub${i}`, "subdomain");
    m.link(`sub${i}`, "seed", "SUBDOMAIN_OF");
    m.link(`sub${i}`, `ip${i % 20}`, "RESOLVES_TO");
  }
  for (let i = 0; i < 15; i++) {
    m.add(`lone${i}`, "ip_address", 2);
    m.add(`port${i}`, "port", 3);
    m.link(`lone${i}`, `port${i}`, "EXPOSES");
  }
  return m;
}

test("small graphs are drawn as they are", () => {
  const m = model();
  for (let i = 0; i < 5; i++) m.add(`n${i}`, "domain");
  m.link("n0", "n1");
  const view = computeView(m.entities, m.relations, { options: OPTIONS });
  assert.equal(view.bundled, false);
  assert.equal(view.entities.length, 5);
  assert.equal(view.edges.length, 1);
  assert.equal(view.ownerOf.get("n3"), "n3");
  assert.equal(view.edgeOf.get("n0>n1"), "n0>n1");
});

test("crowds of same-type neighbours become bundles, recursively", () => {
  const m = estate();
  const view = computeView(m.entities, m.relations, { options: OPTIONS });
  const byType = Object.fromEntries(view.bundles.map((b) => [b.hub === "leaves" ? `leaf ${b.type}` : b.type, b.members.length]));
  assert.equal(byType.subdomain, 60); // the domain's sub-domains
  assert.equal(byType.ip_address, 20); // ...whose IPs share the sub-domain bundle as a hub
  assert.equal(byType["leaf port"], 15); // island ports, bundled across the graph
  assert.ok(view.entities.includes("seed"));
  // Every entity is drawn exactly once: itself, or inside one bundle.
  const inBundles = view.bundles.reduce((sum, b) => sum + b.members.length, 0);
  assert.equal(view.entities.length + inBundles, m.entities.size);
});

test("merged edges account for every relation between groups", () => {
  const m = estate();
  const view = computeView(m.entities, m.relations, { options: OPTIONS });
  let drawn = 0;
  for (const e of view.edges) drawn += e.relation ? 1 : e.count;
  let internal = 0;
  for (const r of m.relations.values()) if (view.ownerOf.get(r.source_id) === view.ownerOf.get(r.target_id)) internal++;
  assert.equal(drawn + internal, m.relations.size);
  const sub = view.bundles.find((b) => b.type === "subdomain");
  assert.equal(view.edgeOf.get("sub0>seed"), `merged:${sub.id}->seed`);
});

test("the target and pinned entities are never bundled", () => {
  const m = estate();
  const view = computeView(m.entities, m.relations, { pinned: new Set(["sub7"]), options: OPTIONS });
  assert.equal(view.ownerOf.get("seed"), "seed");
  assert.equal(view.ownerOf.get("sub7"), "sub7");
  assert.equal(view.bundles.find((b) => b.type === "subdomain").members.length, 59);
});

test("expanding shows a page of members, most connected first", () => {
  const m = estate();
  m.link("sub5", "ip3"); // sub5 is the best-connected sub-domain
  const first = computeView(m.entities, m.relations, { options: OPTIONS });
  const sub = first.bundles.find((b) => b.type === "subdomain");
  const view = computeView(m.entities, m.relations, { expanded: new Map([[sub.id, 12]]), options: OPTIONS });
  const rest = view.bundles.find((b) => b.id === sub.id);
  assert.equal(rest.shown, 12);
  assert.equal(rest.members.length, 48);
  assert.equal(rest.total, 60);
  assert.equal(view.ownerOf.get("sub5"), "sub5");
  const all = computeView(m.entities, m.relations, { expanded: new Map([[sub.id, 1000]]), options: OPTIONS });
  assert.equal(all.bundles.find((b) => b.id === sub.id), undefined); // fully expanded: no bundle left
});

test("bundle ids are stable between computations", () => {
  const m = estate();
  const a = computeView(m.entities, m.relations, { options: OPTIONS }).bundles.map((b) => b.id).sort();
  m.add("extra", "domain");
  const b = computeView(m.entities, m.relations, { options: OPTIONS }).bundles.map((x) => x.id).sort();
  assert.deepEqual(a, b);
});

test("50,000 entities are bundled quickly", () => {
  const m = model();
  m.add("seed", "domain", 0);
  const ips = 8000;
  for (let i = 0; i < ips; i++) m.add(`ip${i}`, "ip_address", 2);
  for (let i = 0; i < 25000; i++) {
    m.add(`s${i}`, "subdomain");
    m.link(`s${i}`, "seed");
    m.link(`s${i}`, `ip${(i * 7919) % ips}`);
  }
  for (let i = 0; i < 17000; i++) {
    m.add(`p${i}`, "port", 3);
    m.link(`ip${i % ips}`, `p${i}`);
  }
  const started = performance.now();
  const view = computeView(m.entities, m.relations);
  const elapsed = performance.now() - started;
  assert.ok(view.entities.length + view.bundles.length < 100, `drew ${view.entities.length} entities`);
  assert.ok(elapsed < 3000, `took ${Math.round(elapsed)} ms`);
});
