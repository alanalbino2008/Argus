/**
 * Argus OSINT Platform - Interactive Graph Controller & Real-Time Telemetry
 */

let cy = null;
let currentInvestigationId = null;
let activeSocket = null;
let currentGraphData = { nodes: [], edges: [] };

// Entity Category Color Palette
const ENTITY_COLORS = {
  domain: "#00f0ff",        // Cyan
  subdomain: "#38bdf8",     // Sky Blue
  ip_address: "#10b981",    // Emerald
  asn: "#059669",           // Dark Emerald
  email: "#ec4899",         // Pink
  username: "#a855f7",      // Purple
  social_profile: "#d946ef",// Fuchsia
  person: "#f43f5e",        // Rose
  organization: "#f97316",  // Orange
  certificate: "#eab308",   // Yellow/Gold
  technology: "#3b82f6",    // Blue
  dns_record: "#f59e0b",    // Amber
  generic: "#94a3b8"        // Slate Gray
};

document.addEventListener("DOMContentLoaded", () => {
  initCytoscape();
  setupUIEventListeners();
});

function initCytoscape() {
  cy = cytoscape({
    container: document.getElementById("cy"),
    boxSelectionEnabled: false,
    autounselectify: false,
    elements: [],
    style: [
      {
        selector: "node",
        style: {
          "label": "data(label)",
          "color": "#e2e8f0",
          "font-size": "11px",
          "font-family": "Inter, sans-serif",
          "text-valign": "bottom",
          "text-margin-y": 6,
          "background-color": function (ele) {
            const type = ele.data("type") || "generic";
            return ENTITY_COLORS[type] || "#64748b";
          },
          "width": function (ele) {
            if (ele.data("is_seed")) return 45;
            const deg = ele.data("degree") || 1;
            return Math.min(60, 24 + deg * 4);
          },
          "height": function (ele) {
            if (ele.data("is_seed")) return 45;
            const deg = ele.data("degree") || 1;
            return Math.min(60, 24 + deg * 4);
          },
          "border-width": function (ele) {
            return ele.data("is_seed") ? 3 : 1;
          },
          "border-color": function (ele) {
            return ele.data("is_seed") ? "#ffffff" : "rgba(255, 255, 255, 0.4)";
          },
          "shadow-blur": 12,
          "shadow-color": function (ele) {
            const type = ele.data("type") || "generic";
            return ENTITY_COLORS[type] || "#000";
          },
          "shadow-opacity": 0.6,
          "transition-property": "background-color, line-color, target-arrow-color",
          "transition-duration": "0.3s"
        }
      },
      {
        selector: "node:selected",
        style: {
          "border-color": "#ffffff",
          "border-width": 4,
          "shadow-blur": 25,
          "shadow-opacity": 0.95
        }
      },
      {
        selector: "edge",
        style: {
          "label": "data(label)",
          "font-size": "9px",
          "color": "#94a3b8",
          "font-family": "Inter, sans-serif",
          "text-rotation": "autorotate",
          "text-margin-y": -5,
          "curve-style": "bezier",
          "width": 1.5,
          "line-color": "rgba(56, 189, 248, 0.35)",
          "target-arrow-shape": "triangle",
          "target-arrow-color": "rgba(56, 189, 248, 0.6)",
          "arrow-scale": 0.8
        }
      },
      {
        selector: "edge:selected",
        style: {
          "line-color": "#00f0ff",
          "target-arrow-color": "#00f0ff",
          "width": 2.5
        }
      }
    ],
    layout: {
      name: "cose",
      animate: true,
      animationDuration: 800,
      randomize: false,
      idealEdgeLength: 100,
      nodeOverlap: 20
    }
  });

  // Node Click Selection Listener
  cy.on("tap", "node", function (evt) {
    const node = evt.target;
    displayNodeInspector(node.data());
  });

  // Background Tap: clear selection
  cy.on("tap", function (evt) {
    if (evt.target === cy) {
      clearNodeInspector();
    }
  });
}

function setupUIEventListeners() {
  const launchBtn = document.getElementById("launch-btn");
  const targetInput = document.getElementById("target-input");
  const typeSelect = document.getElementById("type-select");
  const depthInput = document.getElementById("depth-input");

  launchBtn.addEventListener("click", () => {
    const target = targetInput.value.trim();
    if (!target) return;

    const ttype = typeSelect.value ? typeSelect.value : null;
    const depth = parseInt(depthInput.value, 10) || 2;

    startInvestigation(target, ttype, depth);
  });

  targetInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      launchBtn.click();
    }
  });

  // Sidebar Tab Switching
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".tab-pane").forEach((p) => p.classList.remove("active"));

      btn.classList.add("active");
      const targetPane = document.getElementById(btn.dataset.tab);
      if (targetPane) targetPane.classList.add("active");
    });
  });

  // Graph Layout Controls
  document.getElementById("btn-fit")?.addEventListener("click", () => cy.fit(null, 50));
  document.getElementById("btn-zoom-in")?.addEventListener("click", () => cy.zoom(cy.zoom() * 1.25));
  document.getElementById("btn-zoom-out")?.addEventListener("click", () => cy.zoom(cy.zoom() * 0.8));
  document.getElementById("btn-relayout")?.addEventListener("click", () => {
    cy.layout({ name: "cose", animate: true, animationDuration: 600 }).run();
  });
}

async function startInvestigation(target, targetType, maxDepth) {
  const launchBtn = document.getElementById("launch-btn");
  const statusBadge = document.getElementById("status-badge");

  launchBtn.disabled = true;
  statusBadge.textContent = "Scanning...";
  statusBadge.style.color = "var(--accent-amber)";

  // Reset graph and counters
  cy.elements().remove();
  document.getElementById("node-counter").textContent = "0";
  document.getElementById("edge-counter").textContent = "0";
  document.getElementById("event-feed").innerHTML = "";

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target: target,
        target_type: targetType,
        max_depth: maxDepth
      })
    });

    const data = await response.json();
    currentInvestigationId = data.investigation_id;

    // Setup Export Links
    document.getElementById("btn-export-json").href = `/api/investigation/${currentInvestigationId}/export/json`;
    document.getElementById("btn-export-csv").href = `/api/investigation/${currentInvestigationId}/export/csv`;

    connectWebSocket(currentInvestigationId);
  } catch (err) {
    console.error("Failed to start scan:", err);
    launchBtn.disabled = false;
    statusBadge.textContent = "Error";
    statusBadge.style.color = "var(--accent-crimson)";
  }
}

function connectWebSocket(invId) {
  if (activeSocket) {
    activeSocket.close();
  }

  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/ws/stream/${invId}`;
  activeSocket = new WebSocket(wsUrl);

  activeSocket.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      handleLiveEvent(msg);
    } catch (e) {
      console.error("Malformed WebSocket payload:", e);
    }
  };

  activeSocket.onclose = () => {
    console.log("WebSocket stream closed.");
  };
}

function handleLiveEvent(msg) {
  const { type, data } = msg;

  if (type === "entity_discovered") {
    const ent = data.entity;
    addEntityToGraph(ent);
    addEventToFeed(`Found ${ent.type.toUpperCase()}: ${ent.label} (via ${data.source_module})`);
  } else if (type === "relation_discovered") {
    const rel = data.relation;
    addRelationToGraph(rel);
  } else if (type === "scan_progress") {
    document.getElementById("node-counter").textContent = data.total_nodes;
    document.getElementById("edge-counter").textContent = data.total_edges;
  } else if (type === "scan_completed") {
    document.getElementById("launch-btn").disabled = false;
    const statusBadge = document.getElementById("status-badge");
    statusBadge.textContent = "Complete";
    statusBadge.style.color = "var(--accent-emerald)";

    if (data.analytics) {
      renderAnalytics(data.analytics);
    }

    // Trigger optimal layout
    cy.layout({ name: "cose", animate: true, animationDuration: 800 }).run();
  }
}

function addEntityToGraph(entity) {
  if (cy.getElementById(entity.id).length > 0) return;

  cy.add({
    group: "nodes",
    data: {
      id: entity.id,
      label: entity.label,
      value: entity.value,
      type: entity.type,
      confidence: entity.confidence,
      depth: entity.depth,
      source_module: entity.source_module,
      is_seed: entity.depth === 0,
      metadata: entity.metadata || {}
    }
  });

  document.getElementById("node-counter").textContent = cy.nodes().length;
}

function addRelationToGraph(relation) {
  if (cy.getElementById(relation.id).length > 0) return;
  if (cy.getElementById(relation.source_id).length === 0 || cy.getElementById(relation.target_id).length === 0) return;

  cy.add({
    group: "edges",
    data: {
      id: relation.id,
      source: relation.source_id,
      target: relation.target_id,
      label: relation.label,
      type: relation.type
    }
  });

  document.getElementById("edge-counter").textContent = cy.edges().length;
}

function addEventToFeed(desc) {
  const feed = document.getElementById("event-feed");
  const time = new Date().toLocaleTimeString();

  const item = document.createElement("div");
  item.className = "event-item";
  item.innerHTML = `
    <span class="event-time">${time}</span>
    <span class="event-desc">${desc}</span>
  `;

  feed.prepend(item);
  if (feed.children.length > 50) {
    feed.removeChild(feed.lastChild);
  }
}

function displayNodeInspector(nodeData) {
  // Switch to inspector tab automatically
  document.querySelector('.tab-btn[data-tab="tab-inspector"]')?.click();

  const type = nodeData.type || "generic";
  const color = ENTITY_COLORS[type] || "#64748b";

  document.getElementById("inspector-content").innerHTML = `
    <div class="inspector-card">
      <div class="entity-header">
        <span class="entity-badge" style="background-color: ${color}; color: #000;">${type}</span>
        <span style="font-size: 0.8rem; color: var(--text-muted);">Hop Depth: ${nodeData.depth}</span>
      </div>
      <div class="entity-main-val">${escapeHtml(nodeData.value)}</div>
    </div>

    <div class="inspector-card">
      <div class="inspector-title">Reconnaissance Metadata</div>
      <div class="meta-row"><span class="meta-key">Confidence</span><span class="meta-val">${Math.round(nodeData.confidence * 100)}%</span></div>
      <div class="meta-row"><span class="meta-key">Discovered By</span><span class="meta-val">${nodeData.source_module}</span></div>
      ${renderMetadataRows(nodeData.metadata)}
    </div>
  `;
}

function clearNodeInspector() {
  document.getElementById("inspector-content").innerHTML = `
    <div style="text-align: center; color: var(--text-muted); margin-top: 40px; font-size: 0.85rem;">
      Click on any entity node in the intelligence graph to inspect attributes and connections.
    </div>
  `;
}

function renderMetadataRows(meta) {
  if (!meta || Object.keys(meta).length === 0) return '<div class="meta-row"><span class="meta-key">No attributes</span></div>';

  let html = "";
  for (const [k, v] of Object.entries(meta)) {
    let displayVal = typeof v === "object" ? JSON.stringify(v) : String(v);
    html += `
      <div class="meta-row">
        <span class="meta-key">${escapeHtml(k)}</span>
        <span class="meta-val">${escapeHtml(displayVal)}</span>
      </div>
    `;
  }
  return html;
}

function renderAnalytics(analytics) {
  // Threat Score
  const scoreNum = document.getElementById("threat-score-num");
  if (scoreNum) scoreNum.textContent = analytics.threat_exposure_score || "10";

  // Top Pivots
  const hubsList = document.getElementById("hubs-list");
  if (hubsList && analytics.top_pivots) {
    hubsList.innerHTML = analytics.top_pivots.map(h => `
      <div class="meta-row">
        <span class="meta-key">${escapeHtml(h.label)} (${h.type})</span>
        <span class="meta-val">${h.connections} links</span>
      </div>
    `).join("");
  }

  // Risk Flags
  const riskList = document.getElementById("risk-flags-list");
  if (riskList && analytics.risk_flags) {
    riskList.innerHTML = analytics.risk_flags.length > 0
      ? analytics.risk_flags.map(f => `<div class="risk-tag">⚠ ${escapeHtml(f)}</div>`).join("")
      : '<div style="color: var(--text-muted); font-size: 0.8rem;">No critical exposures flagged.</div>';
  }
}

function escapeHtml(str) {
  return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
