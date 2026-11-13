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
  port: "#06b6d4",          // Cyan/Teal
  vulnerability: "#ef4444", // Crimson Red
  phone: "#14b8a6",         // Mint Teal
  generic: "#94a3b8"        // Slate Gray
};

document.addEventListener("DOMContentLoaded", () => {
  initCytoscape();
  setupUIEventListeners();
  setupHistoryPanel();
  // Deep link: /?inv=<investigation_id> reopens a saved investigation.
  const deepLink = new URLSearchParams(window.location.search).get("inv");
  if (deepLink) openInvestigation(deepLink);
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
    const layoutEngine = document.getElementById("layout-select")?.value || "cose";
    cy.layout({ name: layoutEngine, animate: true, animationDuration: 600 }).run();
  });

  // Layout Engine Dropdown
  document.getElementById("layout-select")?.addEventListener("change", (e) => {
    const engine = e.target.value || "cose";
    cy.layout({ name: engine, animate: true, animationDuration: 600 }).run();
  });

  // Theme Switcher Dropdown
  document.getElementById("theme-select")?.addEventListener("change", (e) => {
    document.body.classList.remove("theme-matrix", "theme-soc");
    if (e.target.value === "matrix") document.body.classList.add("theme-matrix");
    if (e.target.value === "soc") document.body.classList.add("theme-soc");
  });

  // Executive Dossier Modal Controls
  document.getElementById("btn-open-report")?.addEventListener("click", openExecutiveReport);
  document.getElementById("btn-close-report")?.addEventListener("click", () => {
    document.getElementById("report-modal")?.classList.remove("active");
  });
  document.getElementById("btn-print-report")?.addEventListener("click", () => {
    window.print();
  });
}

function openExecutiveReport() {
  const nodes = cy.nodes();
  const edges = cy.edges();
  const targetVal = document.getElementById("target-input")?.value || "Unknown Target";
  const threatScore = document.getElementById("threat-score-num")?.textContent || "0";

  // Group entities by type
  const byType = {};
  nodes.forEach((n) => {
    const t = n.data("type") || "generic";
    if (!byType[t]) byType[t] = [];
    byType[t].push(n.data("label") || n.data("value"));
  });

  // Collect Vulnerabilities & Open Ports
  const vulns = byType["vulnerability"] || [];
  const ports = byType["port"] || [];

  let html = `
    <div style="margin-bottom: 20px; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 15px;">
      <h1 style="font-size: 1.6rem; color: #fff; margin-bottom: 4px;">Executive Threat & OSINT Intelligence Dossier</h1>
      <div style="font-size: 0.85rem; color: #94a3b8;">
        Target Seed: <strong style="color: #38bdf8;">${escapeHtml(targetVal)}</strong> | Generated: ${new Date().toUTCString()}
      </div>
    </div>

    <h2>1. Executive Summary & Attack Surface Posture</h2>
    <p>
      Argus conducted multi-hop recursive reconnaissance across public surface vectors, discovering 
      <strong>${nodes.length} entities</strong> connected by <strong>${edges.length} verified relationships</strong>.
      The target presents a calculated <strong>Attack Surface Score of ${threatScore}/100</strong>.
    </p>

    <h2>2. Discovered Vulnerabilities & Exposed Services</h2>
    <table class="report-table">
      <thead>
        <tr><th>Category</th><th>Count</th><th>Identified Assets & CVEs</th></tr>
      </thead>
      <tbody>
        <tr>
          <td><strong style="color: #ef4444;">Known CVEs</strong></td>
          <td>${vulns.length}</td>
          <td>${vulns.length > 0 ? vulns.map(v => `<span style="background: rgba(239,68,68,0.2); padding: 2px 6px; border-radius: 4px; margin-right: 4px;">${escapeHtml(v)}</span>`).join("") : "No known CVEs indexed."}</td>
        </tr>
        <tr>
          <td><strong style="color: #06b6d4;">Open Services/Ports</strong></td>
          <td>${ports.length}</td>
          <td>${ports.length > 0 ? ports.map(p => escapeHtml(p)).join(", ") : "None detected."}</td>
        </tr>
      </tbody>
    </table>

    <h2>3. Topology Breakdown by Intelligence Category</h2>
    <table class="report-table">
      <thead>
        <tr><th>Entity Category</th><th>Total Nodes</th><th>Discovered Assets (Sample)</th></tr>
      </thead>
      <tbody>
  `;

  for (const [cat, items] of Object.entries(byType)) {
    const sample = items.slice(0, 5).join(", ") + (items.length > 5 ? `, +${items.length - 5} more` : "");
    html += `
      <tr>
        <td><strong>${cat.toUpperCase()}</strong></td>
        <td>${items.length}</td>
        <td>${escapeHtml(sample)}</td>
      </tr>
    `;
  }

  html += `
      </tbody>
    </table>

    <h2>4. Methodology & Compliance Notice</h2>
    <p style="font-size: 0.8rem; color: #94a3b8;">
      All findings in this report were gathered via non-intrusive, passive Open Source Intelligence (OSINT) 
      methods conforming to industry standard guidelines. Protocols queried include public DNS records, Certificate 
      Transparency logs, standardized RDAP queries (RFC 7480), and public service fingerprints.
    </p>
  `;

  document.getElementById("report-modal-body").innerHTML = html;
  document.getElementById("report-modal").classList.add("active");
}

async function startInvestigation(target, targetType, maxDepth) {
  const launchBtn = document.getElementById("launch-btn");
  const statusBadge = document.getElementById("status-badge");

  launchBtn.disabled = true;
  setStatus("running");
  resetWorkspace();

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
    if (!response.ok) throw new Error(JSON.stringify(data.detail || data));
    attachInvestigation(data.investigation_id);
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

// ---------------------------------------------------------------- workspace state
const STATUS_STYLES = {
  initializing: ["Starting...", "var(--accent-amber)"],
  running: ["Scanning...", "var(--accent-amber)"],
  completed: ["Complete", "var(--accent-emerald)"],
  cancelled: ["Cancelled", "var(--accent-amber, #f5a524)"],
  failed: ["Failed", "var(--accent-crimson, #ff4d6d)"],
};

function setStatus(status) {
  const [text, color] = STATUS_STYLES[status] || [status, "var(--text-muted)"];
  const badge = document.getElementById("status-badge");
  badge.textContent = text;
  badge.style.color = color;
  document.getElementById("launch-btn").disabled = status === "running" || status === "initializing";
}

function resetWorkspace() {
  cy.elements().remove();
  document.getElementById("node-counter").textContent = "0";
  document.getElementById("edge-counter").textContent = "0";
  document.getElementById("event-feed").innerHTML = "";
  clearNodeInspector();
}

function attachInvestigation(invId) {
  currentInvestigationId = invId;
  const base = `/api/investigation/${encodeURIComponent(invId)}`;
  document.getElementById("btn-export-json").href = `${base}/export/json`;
  document.getElementById("btn-export-csv").href = `${base}/export/csv`;
  connectWebSocket(invId);
}

function openInvestigation(invId) {
  resetWorkspace();
  setStatus("initializing");
  attachInvestigation(invId);
}

// Server sends everything found so far on connect, so late joiners and
// historical investigations render identically to a live scan.
function applySnapshot(data) {
  const inv = data.investigation;
  cy.batch(() => {
    data.entities.forEach(addEntityToGraph);
    data.relations.forEach(addRelationToGraph);
  });
  setStatus(inv.status);
  addEventToFeed(`Loaded ${inv.target}: ${data.entities.length} entities, ${data.relations.length} relations (${inv.status})`);
  (inv.warnings || []).slice(-5).forEach((w) => addEventToFeed(`[WARNING] ${w}`));
  if (data.analytics) renderAnalytics(data.analytics);
  cy.layout({ name: "cose", animate: false }).run();
}

// ---------------------------------------------------------------- history
async function loadHistory() {
  const list = document.getElementById("history-list");
  const filter = document.getElementById("history-filter").value.trim();
  const params = new URLSearchParams({ limit: "100" });
  if (filter) params.set("target", filter);
  try {
    const res = await fetch(`/api/investigations?${params}`);
    const rows = await res.json();
    if (!rows.length) {
      list.innerHTML = '<div class="history-empty">No investigations yet.</div>';
      return;
    }
    list.innerHTML = rows.map((r) => `
      <div class="history-item${r.id === currentInvestigationId ? " active" : ""}" data-id="${escapeHtml(r.id)}">
        <div class="history-main">
          <span class="history-target">${escapeHtml(r.target)}</span>
          <span class="history-status status-${escapeHtml(r.status)}">${escapeHtml(r.status)}</span>
        </div>
        <div class="history-meta">
          ${escapeHtml(r.target_type)} · ${r.nodes_count} nodes · ${new Date(r.created_at).toLocaleString()}
          ${r.threat_exposure_score != null ? ` · score ${r.threat_exposure_score}` : ""}
        </div>
        <button class="history-delete" title="Delete investigation" data-id="${escapeHtml(r.id)}">✕</button>
      </div>`).join("");
  } catch (err) {
    list.innerHTML = '<div class="history-empty">Could not load history.</div>';
  }
}

async function deleteInvestigation(invId) {
  if (!confirm("Permanently delete this investigation and all of its findings?")) return;
  const res = await fetch(`/api/investigation/${encodeURIComponent(invId)}`, { method: "DELETE" });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    alert(`Delete failed: ${body.detail || res.status}`);
  }
  if (invId === currentInvestigationId) {
    currentInvestigationId = null;
    resetWorkspace();
    setStatus("idle");
  }
  loadHistory();
}

function setupHistoryPanel() {
  const list = document.getElementById("history-list");
  list.addEventListener("click", (e) => {
    const del = e.target.closest(".history-delete");
    if (del) {
      e.stopPropagation();
      deleteInvestigation(del.dataset.id);
      return;
    }
    const item = e.target.closest(".history-item");
    if (item) openInvestigation(item.dataset.id);
  });
  let debounce;
  document.getElementById("history-filter").addEventListener("input", () => {
    clearTimeout(debounce);
    debounce = setTimeout(loadHistory, 250);
  });
  document.querySelector('.tab-btn[data-tab="tab-history"]').addEventListener("click", loadHistory);
}

// Cross-investigation pivot: has this value appeared in any other investigation?
async function loadPivots(nodeData) {
  const box = document.getElementById("pivot-results");
  if (!box || String(nodeData.value).length < 2) return;
  try {
    const params = new URLSearchParams({ q: nodeData.value, type: nodeData.type, limit: "20" });
    const hits = (await (await fetch(`/api/entities/search?${params}`)).json())
      .filter((h) => h.investigation_id !== currentInvestigationId && h.entity.value === nodeData.value);
    box.innerHTML = hits.length
      ? hits.map((h) => `
          <div class="meta-row pivot-link" data-id="${escapeHtml(h.investigation_id)}">
            <span class="meta-key">${escapeHtml(h.investigation_target)}</span>
            <span class="meta-val">${new Date(h.investigation_created_at).toLocaleDateString()}</span>
          </div>`).join("")
      : '<div class="meta-row"><span class="meta-key">Not seen in other investigations</span></div>';
    box.querySelectorAll(".pivot-link").forEach((el) =>
      el.addEventListener("click", () => openInvestigation(el.dataset.id)));
  } catch (err) {
    box.innerHTML = "";
  }
}

function handleLiveEvent(msg) {
  const { type, data } = msg;

  if (type === "snapshot") {
    applySnapshot(data);
  } else if (type === "entity_discovered") {
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
    setStatus("completed");

    if (data.analytics) {
      renderAnalytics(data.analytics);
    }

    // Trigger optimal layout
    cy.layout({ name: "cose", animate: true, animationDuration: 800 }).run();
  } else if (type === "scan_failed" || type === "scan_cancelled") {
    const failed = type === "scan_failed";
    setStatus(failed ? "failed" : "cancelled");
    addEventToFeed(failed ? `Scan failed: ${data.error || "unknown error"}` : "Scan cancelled by operator");
  } else if (type === "log_message" && data.level !== "DEBUG") {
    addEventToFeed(`[${data.level}] ${data.message}`);
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
    <span class="event-desc">${escapeHtml(desc)}</span>
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

    <div class="inspector-card">
      <div class="inspector-title">Seen In Other Investigations</div>
      <div id="pivot-results"><div class="meta-row"><span class="meta-key">Searching...</span></div></div>
    </div>
  `;
  loadPivots(nodeData);
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
  // All OSINT data is attacker-controllable (DNS TXT, HTTP headers, profile names...),
  // so every value rendered via innerHTML must pass through here.
  return String(str ?? "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
