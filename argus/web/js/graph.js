// Intelligence graph (Cytoscape.js, vendored). Designed to stay calm as it grows:
// icons per entity type, size by importance, labels that fade out when zoomed out,
// edge labels only on hover, and batched, animated re-layouts during live scans.

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

  cy.on("zoom", scheduleLabelUpdate);
  cy.on("select unselect", "node", scheduleLabelUpdate);
  cy.on("tap", "node", (evt) => handlers.onSelect?.(evt.target.data()));
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
  nodes.forEach((n) => n.data("size", sizeFor(n)));
}

export function addEntity(entity) {
  if (!cy || cy.getElementById(entity.id).length) return false;
  const info = typeInfo(entity.type);
  const seed = entity.depth === 0;
  const node = cy.add({
    group: "nodes",
    data: {
      id: entity.id,
      type: entity.type,
      label: entity.label,
      short: shortLabel(entity.label),
      lbl: "",
      value: entity.value,
      depth: entity.depth,
      confidence: entity.confidence,
      source_module: entity.source_module,
      metadata: entity.metadata || {},
      seed,
      color: info.color,
      icon: nodeGlyph(entity.type),
      size: seed ? 70 : 34,
    },
  });
  if (hiddenTypes.has(entity.type)) node.addClass("type-hidden");
  return true;
}

export function addRelation(rel) {
  if (!cy || cy.getElementById(rel.id).length) return false;
  if (!cy.getElementById(rel.source_id).length || !cy.getElementById(rel.target_id).length) return false;
  const edge = cy.add({
    group: "edges",
    data: { id: rel.id, source: rel.source_id, target: rel.target_id, label: rel.label, type: rel.type },
  });
  resize(edge.connectedNodes());
  scheduleLabelUpdate();
  return true;
}

export function bulkLoad(entities, relations) {
  cy.batch(() => {
    entities.forEach(addEntity);
    relations.forEach(addRelation);
    resize(cy.nodes());
  });
  scheduleLabelUpdate();
}

export function clearGraph() {
  if (cy) cy.elements().remove();
}

export function counts() {
  return { nodes: cy ? cy.nodes().length : 0, edges: cy ? cy.edges().length : 0 };
}

const LAYOUTS = {
  cose: (animate) => ({
    name: "cose", animate, animationDuration: 600, nodeRepulsion: () => 6500, idealEdgeLength: () => 70,
    nodeOverlap: 16, gravity: 0.9, numIter: 1500, padding: 50, randomize: false, componentSpacing: 60,
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
  clearHighlight();
  const nodes = cy.collection(path.steps.map((s) => cy.getElementById(s.entity_id)).filter((n) => n.length));
  const edges = cy.collection(path.edges.map((id) => cy.getElementById(id)).filter((e) => e.length));
  cy.elements().addClass("dimmed");
  nodes.union(edges).removeClass("dimmed").addClass("on-path");
  scheduleLabelUpdate();
  cy.animate({ fit: { eles: nodes, padding: 120 } }, { duration: 500 });
}

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

export function typeCounts() {
  const result = {};
  cy?.nodes().forEach((n) => { result[n.data("type")] = (result[n.data("type")] || 0) + 1; });
  return result;
}

export function selectNode(id) {
  const node = cy?.getElementById(id);
  if (!node || !node.length) return false;
  cy.$(":selected").unselect();
  node.select();
  cy.animate({ center: { eles: node }, zoom: Math.max(cy.zoom(), 1.1) }, { duration: 400 });
  handlers.onSelect?.(node.data());
  return true;
}

export function findNode(query) {
  const q = query.trim().toLowerCase();
  if (!q || !cy) return null;
  const match = cy.nodes().filter((n) => String(n.data("label")).toLowerCase().includes(q) || String(n.data("value")).toLowerCase().includes(q));
  return match.length ? match[0].id() : null;
}

export function neighbors(id) {
  const node = cy?.getElementById(id);
  return node && node.length ? node.neighborhood("node").map((n) => n.data()) : [];
}
