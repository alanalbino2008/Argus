// Bundling: how a very large graph stays readable and fast.
//
// Real investigations explode in a few typical ways: one domain with thousands of sub-domains,
// which resolve to thousands of IPs, which expose thousands of ports. Drawing every one of them
// makes the graph unreadable and the browser slow. Above BUNDLE.minGraph entities, a node with many
// neighbours of one type (BUNDLE.minGroup or more) shows them as one *bundle* ("10,000 subdomains").
// The pass repeats on the bundled graph, so the sub-domain bundle's IPs become a bundle of their
// own, and so on. Edges between bundles are merged into one edge with a count.
//
// Nothing is lost: the full model stays in memory, a bundle expands page by page (most connected
// first), and *pinned* entities (the target, the selection, a highlighted path or query result)
// are never bundled. Everything here is pure (no DOM), so it can be tested on its own. It works on
// integer indices and flat arrays: 50,000 entities and 70,000 relations take tens of milliseconds.

// minGraph: bundle above this many entities; minGroup: smallest bundle; page: members shown per
// expand; target: if more than this would still be drawn, leaves are bundled across the graph.
export const BUNDLE = { minGraph: 1500, minGroup: 40, page: 300, rounds: 4, target: 400 };

const bundleId = (hubKey, type) => `bundle:${type}:${hubKey}`;

/**
 * The view to draw for a model.
 * @param {Map<string, object>} entities  id -> entity ({id, type, depth, label, ...})
 * @param {Map<string, object>} relations id -> relation ({id, source_id, target_id, type, ...})
 * @param {{pinned?: Set<string>, expanded?: Map<string, number>, options?: object}} settings
 * @returns {{bundled: boolean, entities: string[], bundles: object[], edges: object[],
 *            ownerOf: Map<string, string>, edgeOf: Map<string, string>}}
 */
export function computeView(entities, relations, { pinned = new Set(), expanded = new Map(), options = BUNDLE } = {}) {
  const ids = [...entities.keys()];
  const n = ids.length;
  if (n < options.minGraph) {
    const edges = [];
    for (const r of relations.values()) {
      if (entities.has(r.source_id) && entities.has(r.target_id) && r.source_id !== r.target_id) {
        edges.push({ id: r.id, source: r.source_id, target: r.target_id, relation: r });
      }
    }
    const ownerOf = { get: (id) => (entities.has(id) ? id : undefined) };
    const edgeOf = { get: (relId) => (relations.has(relId) ? relId : undefined) };
    return { bundled: false, entities: ids, bundles: [], edges, ownerOf, edgeOf };
  }
  const { index, types, pairs, rels, degree, start, adjacent } = structure(entities, relations, ids);
  const keep = new Uint8Array(n);
  ids.forEach((id, i) => { if (pinned.has(id) || entities.get(id).depth === 0) keep[i] = 1; });

  // owner[i]: the group an entity is drawn in (itself, or a bundle numbered n, n+1, ...).
  const owner = new Int32Array(n);
  for (let i = 0; i < n; i++) owner[i] = i;
  const bundles = []; // bundle number - n -> { id, type, members (indices), shown, total }
  const groupKey = (g) => (g < n ? ids[g] : bundles[g - n].id);
  // Most connected first; ties keep model order (deterministic, and no string comparisons).
  const byImportance = (a, b) => degree[b] - degree[a] || a - b;

  const mark = new Int32Array(n).fill(-1);
  const shownForGood = new Uint8Array(n); // revealed by expanding a bundle: never bundled again
  // One pass of hub bundling: a group with many neighbouring entities of one type bundles them.
  const hubRound = () => {
    // Members of every current group.
    const groups = new Map();
    for (let i = 0; i < n; i++) {
      const g = owner[i];
      if (!groups.has(g)) groups.set(g, []);
      groups.get(g).push(i);
    }
    // Each group's neighbouring *individual* entities, de-duplicated with a stamp per group.
    const candidates = [];
    for (const [g, members] of groups) {
      const found = [];
      for (const i of members) {
        for (let k = start[i]; k < start[i + 1]; k++) {
          const j = adjacent[k];
          if (owner[j] !== j || j === g || keep[j] || shownForGood[j] || mark[j] === g) continue;
          mark[j] = g;
          found.push(j);
        }
      }
      if (found.length >= options.minGroup) candidates.push([g, found]);
    }
    candidates.sort((x, y) => y[1].length - x[1].length); // the biggest hubs claim first
    const claimed = new Uint8Array(n);
    let changed = false;
    for (const [g, found] of candidates) {
      if (g < n && claimed[g]) continue; // this hub was itself bundled in this round
      const byType = new Map();
      for (const j of found) {
        if (claimed[j] || owner[j] !== j) continue;
        if (!byType.has(types[j])) byType.set(types[j], []);
        byType.get(types[j]).push(j);
      }
      for (const [type, members] of byType) {
        if (members.length < options.minGroup) continue;
        const id = bundleId(groupKey(g), type);
        members.sort(byImportance);
        const shown = Math.min(expanded.get(id) || 0, members.length);
        for (let k = 0; k < shown; k++) { shownForGood[members[k]] = 1; claimed[members[k]] = 1; }
        const inside = members.slice(shown);
        if (!inside.length) continue;
        const number = n + bundles.length;
        for (const j of inside) { owner[j] = number; claimed[j] = 1; }
        bundles.push({ id, type, hub: groupKey(g), members: inside, shown, total: members.length });
        changed = true;
      }
    }
    return changed;
  };

  // Leaves (one neighbouring group or none) of one type across the whole graph: islands such as an
  // IP with two ports that nothing else points to. Bundling them lets their parents bundle next.
  const leafRound = () => {
    const byType = new Map();
    for (let i = 0; i < n; i++) {
      if (owner[i] !== i || keep[i] || shownForGood[i]) continue;
      let first = -1;
      let leaf = true;
      for (let k = start[i]; k < start[i + 1]; k++) {
        const g = owner[adjacent[k]];
        if (g === i) continue;
        if (first === -1) first = g;
        else if (g !== first) { leaf = false; break; }
      }
      if (!leaf) continue;
      if (!byType.has(types[i])) byType.set(types[i], []);
      byType.get(types[i]).push(i);
    }
    let changed = false;
    for (const [type, members] of byType) {
      if (members.length < options.minGroup) continue;
      const id = bundleId("leaves", type);
      members.sort(byImportance);
      const shown = Math.min(expanded.get(id) || 0, members.length);
      for (let k = 0; k < shown; k++) shownForGood[members[k]] = 1;
      const inside = members.slice(shown);
      if (!inside.length) continue;
      const number = n + bundles.length;
      for (const j of inside) owner[j] = number;
      bundles.push({ id, type, hub: "leaves", members: inside, shown, total: members.length });
      changed = true;
    }
    return changed;
  };

  const drawnCount = () => { let c = bundles.length; for (let i = 0; i < n; i++) if (owner[i] === i) c++; return c; };
  for (let round = 0; round < options.rounds; round++) if (!hubRound()) break;
  if (drawnCount() > options.target && leafRound()) {
    for (let round = 0; round < options.rounds; round++) if (!hubRound()) break;
  }

  // Edges: relations between two drawn entities as they are; the rest merged per pair of groups.
  const edges = [];
  const merged = new Map(); // numeric key (group a, group b) -> merged edge
  const span = n + bundles.length;
  for (let k = 0; k < rels.length; k++) {
    const r = rels[k];
    const ga = owner[pairs[2 * k]];
    const gb = owner[pairs[2 * k + 1]];
    if (ga === gb) continue;
    if (ga === pairs[2 * k] && gb === pairs[2 * k + 1]) {
      edges.push({ id: r.id, source: r.source_id, target: r.target_id, relation: r });
      continue;
    }
    const key = ga * span + gb;
    let edge = merged.get(key);
    if (!edge) {
      edge = { id: `merged:${groupKey(ga)}->${groupKey(gb)}`, source: groupKey(ga), target: groupKey(gb), count: 0, types: new Set() };
      merged.set(key, edge);
      edges.push(edge);
    }
    edge.count++;
    edge.types.add(r.type);
  }

  const visible = [];
  for (let i = 0; i < n; i++) if (owner[i] === i) visible.push(ids[i]);
  // Lookups computed on demand (building maps for every entity and relation would cost more).
  const ownerOf = { get: (id) => { const i = index.get(id); return i === undefined ? undefined : groupKey(owner[i]); } };
  const edgeOf = {
    get: (relId) => {
      const r = relations.get(relId);
      if (!r) return undefined;
      const a = ownerOf.get(r.source_id);
      const b = ownerOf.get(r.target_id);
      if (a === undefined || b === undefined || a === b) return undefined;
      return a === r.source_id && b === r.target_id ? r.id : `merged:${a}->${b}`;
    },
  };
  const views = bundles.map((b) => ({ ...b, members: b.members.map((i) => ids[i]) }));
  return { bundled: views.length > 0, entities: visible, bundles: views, edges, ownerOf, edgeOf };
}

// The adjacency structure depends only on the model, not on what is pinned or expanded: it is
// kept for the last model seen and rebuilt when entities or relations are added.
let cached = null;

function structure(entities, relations, ids) {
  if (cached && cached.entities === entities && cached.relations === relations
      && cached.nEntities === entities.size && cached.nRelations === relations.size) return cached.value;
  const n = ids.length;
  const index = new Map(ids.map((id, i) => [id, i]));
  const types = ids.map((id) => entities.get(id).type);
  // Compressed undirected adjacency (CSR), without self-loops.
  const pairs = [];
  const rels = [];
  for (const r of relations.values()) {
    const a = index.get(r.source_id);
    const b = index.get(r.target_id);
    if (a === undefined || b === undefined || a === b) continue;
    pairs.push(a, b);
    rels.push(r);
  }
  const degree = new Int32Array(n);
  for (let k = 0; k < pairs.length; k += 2) { degree[pairs[k]]++; degree[pairs[k + 1]]++; }
  const start = new Int32Array(n + 1);
  for (let i = 0; i < n; i++) start[i + 1] = start[i] + degree[i];
  const fill = start.slice(0, n);
  const adjacent = new Int32Array(start[n]);
  for (let k = 0; k < pairs.length; k += 2) {
    adjacent[fill[pairs[k]]++] = pairs[k + 1];
    adjacent[fill[pairs[k + 1]]++] = pairs[k];
  }
  const value = { index, types, pairs, rels, degree, start, adjacent };
  cached = { entities, relations, nEntities: entities.size, nRelations: relations.size, value };
  return value;
}
