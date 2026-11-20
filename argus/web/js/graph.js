// Intelligence graph (Cytoscape.js, vendored). Designed to stay calm as it grows:
// icons per entity type, size by importance, labels that fade out when zoomed out,
// edge labels only on hover, and batched, animated re-layouts during live scans.

import { BUNDLE, computeView } from "./bundles.js";
import { nodeGlyph, typeInfo } from "./icons.js";

/* global cytoscape */

let cy = null;
let handlers = {};
let layoutTimer = null;
const hiddenTypes = new Set();

const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

function shortLabel(text) {
  const s = String(text ?? "");
  return s.length > 28 ? `${s.slice(0, 26)}…` : s;
}

function styles() {
  const accent = css("--accent");
  const critical = css("--sev-critical");
  return [
    {
      selector: "node",
      style: {
        width: "data(size)",
        height: "data(size)",
        "background-color": "data(color)",
        "background-image": "data(icon)",
        "background-width": "52%",
        "background-height": "52%",
        "background-clip": "none",
        "border-width": 0,
        label: "data(lbl)", // managed by updateLabels(): constant on-screen size, important nodes first
        color: css("--label"),
        "font-family": "Inter, system-ui, sans-serif",
        "font-size": 12,
        "font-weight": 500,
        "text-valign": "bottom",
        "text-margin-y": 6,
        "text-background-color": css("--label-bg"),
        "text-background-opacity": 1,
        "text-background-padding": 2,
        "text-background-shape": "roundrectangle",
        "transition-property": "opacity, border-width, border-color, width, height",
        "transition-duration": "200ms",
      },
    },
    { selector: "node[?seed]", style: { "border-width": 5, "border-color": accent, "border-opacity": 0.25, "font-weight": 650 } },
    { selector: "node:selected", style: { "border-width": 4, "border-color": accent, "border-opacity": 1 } },
    {
      selector: "edge",
      style: {
        width: 1.4,
        "line-color": css("--edge"),
        "target-arrow-color": css("--edge"),
        "target-arrow-shape": "triangle",
        "arrow-scale": 0.7,
        "curve-style": "bezier",
        opacity: 0.9,
        label: "",
        "transition-property": "opacity, line-color, width",
        "transition-duration": "200ms",
      },
    },
    {
      selector: "edge.show-label",
      style: {
        label: "data(label)",
        "font-size": 10,
        color: css("--text-2"),
        "text-rotation": "autorotate",
        "text-background-color": css("--label-bg"),
        "text-background-opacity": 1,
        "text-background-padding": 2,
        "line-color": accent,
        "target-arrow-color": accent,
        width: 2,
      },
    },
    {
      selector: "node.bundle",
      style: {
        shape: "round-rectangle", "border-width": 3, "border-style": "dashed", "border-color": "data(color)",
        "border-opacity": 0.9, "background-opacity": 0.85, "font-weight": 650, label: "data(short)",
      },
    },
    { selector: "edge.merged", style: { width: "data(width)", "line-style": "solid", opacity: 0.55 } },
    { selector: ".faded", style: { opacity: 0.18 } },
    { selector: ".dimmed", style: { opacity: 0.08 } },
    { selector: "node.on-path", style: { opacity: 1, "border-width": 5, "border-color": critical, "border-opacity": 1, "z-index": 20 } },
    {
      selector: "edge.on-path",
      style: { opacity: 1, "line-color": critical, "target-arrow-color": critical, width: 3, label: "data(label)", "font-size": 10, color: css("--text-2"), "text-rotation": "autorotate", "z-index": 20 },
    },
    { selector: "node.is-new", style: { "border-width": 5, "border-color": css("--ok"), "border-opacity": 1 } },
    { selector: ".type-hidden", style: { display: "none" } },
  ];
}

export function initGraph(container, callbacks = {}) {
  handlers = callbacks;
  cy = cytoscape({
    container,
    elements: [],
    style: styles(),
    minZoom: 0.15,
    maxZoom: 3,
    wheelSensitivity: 0.25,
    boxSelectionEnabled: false,
  });

  // Labels restyle every node: on big views, update them once zooming pauses, not on every frame.
  let zoomTimer = null;
  cy.on("zoom", () => {
    if (cy.nodes().length <= 300) { scheduleLabelUpdate(); return; }
    clearTimeout(zoomTimer);
    zoomTimer = setTimeout(scheduleLabelUpdate, 140);
  });
  cy.on("select unselect", "node", scheduleLabelUpdate);
  cy.on("tap", "node", (evt) => {
    if (evt.target.data("bundle")) expandBundle(evt.target.id());
    else handlers.onSelect?.(evt.target.data());
  });
  cy.on("tap", (evt) => { if (evt.target === cy) { cy.$(":selected").unselect(); handlers.onDeselect?.(); } });

  // Hover focus: highlight a node's neighbourhood and show its edge labels.
  cy.on("mouseover", "node", (evt) => {
    if (cy.$(".on-path").length) return; // a path highlight takes priority
    const hood = evt.target.closedNeighborhood();
    cy.elements().not(hood).addClass("faded");
    hood.edges().addClass("show-label");
  });
  cy.on("mouseout", "node", () => {
    cy.elements().removeClass("faded");
    cy.edges().removeClass("show-label");
  });
  return cy;
}

export function applyTheme() {
  if (!cy) return;
  cy.style(styles());
  updateLabels();
}

// Labels: keep text at a constant, readable size on screen. When zoomed out, label only the
// nodes that matter (target, hubs, selection, highlighted path) so the overview stays calm;
// zoom in and the rest appear.
const LABEL_PX = 12;
const DETAIL_ZOOM = 0.85;
let labelFrame = null;

function scheduleLabelUpdate() {
  if (labelFrame) return;
  labelFrame = requestAnimationFrame(() => { labelFrame = null; updateLabels(); });
}

function updateLabels() {
  if (!cy) return;
  const zoom = cy.zoom();
  const scale = 1 / Math.min(zoom, 1);
  const detailed = zoom >= DETAIL_ZOOM;
  cy.batch(() => {
    cy.nodes().forEach((n) => {
      if (n.data("bundle")) return;
      const important = n.data("seed") || n.degree() >= 3 || n.selected() || n.hasClass("on-path") || n.hasClass("is-new");
      n.data("lbl", detailed || important ? n.data("short") : "");
    });
    cy.style()
      .selector("node").style({ "font-size": LABEL_PX * scale, "text-margin-y": 6 * scale, "text-background-padding": 2 * scale })
      .selector("edge.show-label, edge.on-path").style({ "font-size": 10 * scale })
      .update();
  });
}

function sizeFor(node) {
  if (node.data("seed")) return 70;
  return Math.min(60, 34 + node.degree() * 3);
}

function resize(nodes) {
  nodes.forEach((n) => { if (!n.data("bundle")) n.data("size", sizeFor(n)); });
}

// ------------------------------------------------------------------ model and view
// The model holds every entity and relation. Small graphs are drawn as they are. Large ones are
// drawn as a computed *view* where crowds of same-type neighbours become bundles (bundles.js).
const model = { entities: new Map(), relations: new Map() };
const pinned = new Set(); // entities that are never bundled (selection, highlighted paths and results)
const expanded = new Map(); // bundle id -> how many members are shown individually
let view = null;
let renderTimer = null;
const LIVE_RENDER_MS = 1500; // during a large live scan, re-bundle at most this often
const PIN_LIMIT = 300; // more hidden results than this are shown as their bundles instead

const bundling = () => model.entities.size >= BUNDLE.minGraph;

function nodeDef(entity) {
  const info = typeInfo(entity.type);
  const seed = entity.depth === 0;
  return {
    group: "nodes",
    data: {
      id: entity.id, type: entity.type, label: entity.label, short: shortLabel(entity.label), lbl: "",
      value: entity.value, depth: entity.depth, confidence: entity.confidence, source_module: entity.source_module,
      metadata: entity.metadata || {}, seed, color: info.color, icon: nodeGlyph(entity.type), size: seed ? 70 : 34,
    },
    classes: hiddenTypes.has(entity.type) ? "type-hidden" : "",
  };
}

function plural(type, count) {
  const label = typeInfo(type).label;
  return count === 1 ? label : label.endsWith("s") ? label : `${label}s`;
}

function bundleData(b) {
  const count = b.members.length;
  const text = `${count.toLocaleString()} ${b.shown ? "more " : ""}${plural(b.type, count).toLowerCase()}`;
  return {
    id: b.id, bundle: true, type: b.type, count, depth: 9, total: b.total, shown: b.shown, label: text, short: text, lbl: text,
    color: typeInfo(b.type).color, icon: nodeGlyph(b.type), size: Math.round(48 + Math.min(42, Math.log10(count) * 16)),
  };
}

function edgeDef(e) {
  if (e.relation) {
    return { group: "edges", data: { id: e.id, source: e.source, target: e.target, label: e.relation.label, type: e.relation.type } };
  }
  return {
    group: "edges",
    classes: "merged",
    data: {
      id: e.id, source: e.source, target: e.target, merged: true, count: e.count, type: [...e.types].join(", "),
      label: `${e.count.toLocaleString()} link${e.count === 1 ? "" : "s"}`, width: Math.min(8, 1.4 + Math.log10(e.count) * 2),
    },
  };
}

/** Recompute the view and bring the canvas in line with it (adds, removes and updates only). */
function render() {
  if (!cy) return;
  view = computeView(model.entities, model.relations, { pinned, expanded });
  const wanted = new Map();
  for (const id of view.entities) wanted.set(id, null);
  for (const b of view.bundles) wanted.set(b.id, b);
  for (const e of view.edges) wanted.set(e.id, e);
  const added = [];
  cy.batch(() => {
    cy.elements().forEach((el) => { if (!wanted.has(el.id())) el.remove(); });
    const nodes = [];
    const edges = [];
    for (const id of view.entities) if (!cy.getElementById(id).length) nodes.push(nodeDef(model.entities.get(id)));
    for (const b of view.bundles) {
      const existing = cy.getElementById(b.id);
      if (existing.length) existing.data(bundleData(b));
      else nodes.push({ group: "nodes", data: bundleData(b), classes: `bundle${hiddenTypes.has(b.type) ? " type-hidden" : ""}` });
    }
    for (const e of view.edges) {
      const existing = cy.getElementById(e.id);
      if (!existing.length) edges.push(edgeDef(e));
      else if (!e.relation) existing.data(edgeDef(e).data);
    }
    if (nodes.length) added.push(...cy.add(nodes));
    if (edges.length) cy.add(edges);
    resize(cy.nodes());
  });
  scheduleLabelUpdate();
  return cy.collection(added);
}

function scheduleRender() {
  if (renderTimer) return;
  renderTimer = setTimeout(() => {
    renderTimer = null;
    const added = render();
    if (added && added.length) scheduleRelayout();
    handlers.onRender?.();
  }, LIVE_RENDER_MS);
}

/** Put newly shown nodes in a ring around where they came from (their bundle or a neighbour). */
function placeAround(nodes, centre) {
  if (!nodes.length) return;
  const radius = 80 + Math.sqrt(nodes.length) * 28;
  nodes.forEach((n, i) => {
    const angle = (2 * Math.PI * i) / nodes.length;
    const ring = radius * (1 + 0.35 * (i % 3));
    n.position({ x: centre.x + ring * Math.cos(angle), y: centre.y + ring * Math.sin(angle) });
  });
}

/** Show the next page of a bundle's members (most connected first). */
export function expandBundle(id) {
  const node = cy?.getElementById(id);
  const bundle = view?.bundles.find((b) => b.id === id);
  if (!node || !node.length || !bundle) return;
  const centre = { ...node.position() };
  expanded.set(id, bundle.shown + BUNDLE.page);
  const added = render();
  placeAround(added, centre);
  const remaining = Math.max(0, bundle.members.length - BUNDLE.page);
  handlers.onBundle?.({ type: bundle.type, shown: Math.min(bundle.total, bundle.shown + BUNDLE.page), total: bundle.total, remaining });
  if (added.length) cy.animate({ fit: { eles: added.union(cy.getElementById(id)), padding: 80 } }, { duration: 400 });
}

/** Fold everything back into bundles (pinned entities stay visible). */
export function collapseAll() {
  if (!expanded.size) return;
  expanded.clear();
  render();
  relayout(currentLayout, false);
  fit();
}

/** Make sure entities are drawn individually (pin them), placing newly shown ones by their bundle. */
function reveal(ids) {
  if (!view?.bundled) return;
  const hidden = ids.filter((id) => model.entities.has(id) && !cy.getElementById(id).length);
  if (!hidden.length) return;
  const origin = new Map(hidden.map((id) => [id, view.ownerOf.get(id)]));
  hidden.forEach((id) => pinned.add(id));
  render();
  const byBundle = new Map();
  for (const id of hidden) {
    const from = cy.getElementById(origin.get(id));
    const key = from.length ? origin.get(id) : "";
    if (!byBundle.has(key)) byBundle.set(key, []);
    byBundle.get(key).push(cy.getElementById(id));
  }
  for (const [bundle, nodes] of byBundle) {
    const centre = bundle ? cy.getElementById(bundle).position() : { x: 0, y: 0 };
    placeAround(cy.collection(nodes), centre);
  }
}

/** The drawn element ids for entity and relation ids (an entity inside a bundle maps to the bundle). */
function drawnIds(nodeIds, edgeIds) {
  const nodes = new Set();
  const edges = new Set();
  for (const id of nodeIds) {
    const owner = view ? view.ownerOf.get(id) : id;
    if (owner) nodes.add(owner);
  }
  for (const id of edgeIds) {
    const edge = view ? view.edgeOf.get(id) : id;
    if (edge) edges.add(edge);
  }
  return { nodes: [...nodes], edges: [...edges] };
}

export function addEntity(entity) {
  if (!cy || model.entities.has(entity.id)) return false;
  model.entities.set(entity.id, entity);
  if (bundling() || view?.bundled) { scheduleRender(); return true; }
  const node = cy.add(nodeDef(entity));
  if (hiddenTypes.has(entity.type)) node.addClass("type-hidden");
  return true;
}

export function addRelation(rel) {
  if (!cy || model.relations.has(rel.id)) return false;
  if (!model.entities.has(rel.source_id) || !model.entities.has(rel.target_id)) return false;
  model.relations.set(rel.id, rel);
  if (bundling() || view?.bundled) { scheduleRender(); return true; }
  const edge = cy.add({ group: "edges", data: { id: rel.id, source: rel.source_id, target: rel.target_id, label: rel.label, type: rel.type } });
  resize(edge.connectedNodes());
  scheduleLabelUpdate();
  return true;
}

export function bulkLoad(entities, relations) {
  entities.forEach((e) => model.entities.set(e.id, e));
  relations.forEach((r) => { if (model.entities.has(r.source_id) && model.entities.has(r.target_id)) model.relations.set(r.id, r); });
  render();
}

/** Apply many additions as one redraw (live scans deliver discoveries in bursts). */
export function batch(fn) {
  if (!cy) { fn(); return; }
  cy.batch(fn);
}

export function clearGraph() {
  if (renderTimer) { clearTimeout(renderTimer); renderTimer = null; }
  model.entities.clear();
  model.relations.clear();
  pinned.clear();
  expanded.clear();
  view = null;
  if (cy) cy.elements().remove();
}

/** Entities and relations in the investigation, how many are drawn, and how many bundles. */
export function counts() {
  return {
    nodes: model.entities.size, edges: model.relations.size,
    drawn: cy ? cy.nodes().length : 0, bundles: view ? view.bundles.length : 0,
  };
}

const LAYOUTS = {
  cose: (animate) => ({
    name: "cose", animate, animationDuration: 600, nodeRepulsion: () => 6500, idealEdgeLength: () => 70,
    // cose costs ~n² per iteration: fewer iterations on big views keep a re-layout under a second.
    nodeOverlap: 16, gravity: 0.9, numIter: coseIterations(), padding: 50, randomize: false, componentSpacing: 60,
    nodeDimensionsIncludeLabels: true, // space nodes by their labels too, so labels don't collide
  }),
  concentric: (animate) => ({
    name: "concentric", animate, animationDuration: 600, padding: 60, minNodeSpacing: 36, nodeDimensionsIncludeLabels: true,
    concentric: (n) => (n.data("seed") ? 100 : 10 - n.data("depth")), levelWidth: () => 1,
  }),
  breadthfirst: (animate) => ({
    name: "breadthfirst", animate, animationDuration: 600, padding: 50, directed: false, spacingFactor: 1.25, nodeDimensionsIncludeLabels: true,
    roots: cy.nodes("[?seed]"),
  }),
  circle: (animate) => ({ name: "circle", animate, animationDuration: 600, padding: 60 }),
};

let currentLayout = "cose";

function coseIterations() {
  const drawn = cy ? cy.nodes().length : 0;
  return drawn > 800 ? 120 : drawn > 300 ? 400 : 1500;
}

export function relayout(name = currentLayout, animate = true) {
  if (!cy || !cy.nodes().length) return;
  currentLayout = name;
  const big = cy.nodes().length > 250;
  cy.layout(LAYOUTS[name](animate && !big)).run();
}

/** During live scans, re-settle the layout at most every 1.5 s instead of on every node. */
export function scheduleRelayout() {
  if (layoutTimer) return;
  layoutTimer = setTimeout(() => {
    layoutTimer = null;
    relayout(currentLayout, true);
  }, 1500);
}

export function fit() { cy?.animate({ fit: { eles: cy.elements(":visible"), padding: 60 } }, { duration: 400 }); }
export function zoomBy(factor) {
  if (!cy) return;
  cy.animate({ zoom: { level: cy.zoom() * factor, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } } }, { duration: 200 });
}
export function resizeCanvas() { cy?.resize(); }

export function highlightPath(path) {
  if (!cy) return;
  reveal(path.steps.map((st) => st.entity_id)); // a path is short: always shown in full
  clearHighlight();
  const ids = drawnIds(path.steps.map((st) => st.entity_id), path.edges);
  const nodes = cy.collection(ids.nodes.map((id) => cy.getElementById(id)).filter((n) => n.length));
  const edges = cy.collection(ids.edges.map((id) => cy.getElementById(id)).filter((e) => e.length));
  cy.elements().addClass("dimmed");
  nodes.union(edges).removeClass("dimmed").addClass("on-path");
  scheduleLabelUpdate();
  cy.animate({ fit: { eles: nodes, padding: 120 } }, { duration: 500 });
}

/** Highlight a query result: matching nodes and edges stay lit, everything else dims. */
export function highlightSet(nodeIds, edgeIds = [], { fit: shouldFit = true } = {}) {
  if (!cy) return 0;
  const hidden = nodeIds.filter((id) => !cy.getElementById(id).length);
  if (hidden.length && hidden.length <= PIN_LIMIT) reveal(nodeIds); // otherwise their bundles light up
  clearHighlight();
  const ids = drawnIds(nodeIds, edgeIds);
  const nodes = cy.collection(ids.nodes.map((id) => cy.getElementById(id)).filter((n) => n.length));
  const edges = cy.collection(ids.edges.map((id) => cy.getElementById(id)).filter((e) => e.length));
  if (!nodes.length) return 0;
  cy.batch(() => {
    cy.elements().addClass("dimmed");
    nodes.union(edges).removeClass("dimmed").addClass("on-path");
  });
  scheduleLabelUpdate();
  if (shouldFit) cy.animate({ fit: { eles: nodes, padding: 100 } }, { duration: 450 });
  return nodes.length;
}

// Distinct, theme-neutral hues for communities; the largest communities get the first ones.
const COMMUNITY_COLORS = ["#4f6bed", "#e8743b", "#19a979", "#ed4a7b", "#945ecf", "#13a4b4", "#d6a100", "#6c8893", "#c94f2c", "#2f9e44"];

/** Colour nodes by link-analysis community (null restores the per-type colours). */
export function colorByCommunity(communityOf) {
  if (!cy) return;
  cy.batch(() => {
    cy.nodes().forEach((n) => {
      if (n.data("bundle")) return; // a bundle keeps its type's colour
      if (!communityOf) {
        n.data("color", typeInfo(n.data("type")).color);
        return;
      }
      const c = communityOf[n.id()];
      n.data("color", c === undefined || c >= COMMUNITY_COLORS.length ? css("--text-3") : COMMUNITY_COLORS[c]);
    });
  });
}

export function communityColor(index) { return COMMUNITY_COLORS[index] || "var(--text-3)"; }

export function clearHighlight() {
  cy?.elements().removeClass("dimmed on-path faded");
  scheduleLabelUpdate();
}

export function markNew(ids) {
  if (!cy) return;
  cy.nodes().removeClass("is-new");
  ids.forEach((id) => cy.getElementById(id).addClass("is-new"));
  scheduleLabelUpdate();
}

export function setTypeVisible(type, visible) {
  if (visible) hiddenTypes.delete(type);
  else hiddenTypes.add(type);
  cy?.nodes(`[type = "${type}"]`).toggleClass("type-hidden", !visible);
}

export function isTypeVisible(type) { return !hiddenTypes.has(type); }

/** Entities per type in the whole investigation (bundled ones included). */
export function typeCounts() {
  const result = {};
  for (const e of model.entities.values()) result[e.type] = (result[e.type] || 0) + 1;
  return result;
}

export function selectNode(id) {
  if (!cy) return false;
  if (!cy.getElementById(id).length) reveal([id]); // inside a bundle: show it
  const node = cy.getElementById(id);
  if (!node.length) return false;
  cy.$(":selected").unselect();
  node.select();
  cy.animate({ center: { eles: node }, zoom: Math.max(cy.zoom(), 1.1) }, { duration: 400 });
  handlers.onSelect?.(node.data());
  return true;
}

/** The first entity whose label or value contains ``query`` (bundled ones included). */
export function findNode(query) {
  const q = query.trim().toLowerCase();
  if (!q) return null;
  for (const e of model.entities.values()) {
    if (String(e.label).toLowerCase().includes(q) || String(e.value).toLowerCase().includes(q)) return e.id;
  }
  return null;
}

/** An entity's neighbours in the investigation (bundled ones included). */
export function neighbors(id) {
  const ids = new Set();
  for (const r of model.relations.values()) {
    if (r.source_id === id) ids.add(r.target_id);
    else if (r.target_id === id) ids.add(r.source_id);
  }
  return [...ids].map((nid) => model.entities.get(nid)).filter(Boolean);
}
