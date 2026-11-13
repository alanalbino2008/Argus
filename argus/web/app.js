/**
 * Argus OSINT Platform - Interactive Graph Controller & Real-Time Telemetry
 */

let cy = null;
let currentInvestigationId = null;
let activeSocket = null;
let currentGraphData = { nodes: [], edges: [] };

// Entity Category Color Palette
const ENTITY_COLORS = {
  breach: "#f43f5e",        // Rose
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
  setupAuth();
  setupRulesOfEngagement();
  setupExports();
  setupAttackPaths();
  setupMonitoring();
  // Deep link: /?inv=<investigation_id> reopens a saved investigation.
  const deepLink = new URLSearchParams(window.location.search).get("inv");
  ensureSignedIn().then((ok) => { if (ok && deepLink) openInvestigation(deepLink); });
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
      },
      // Drift: assets that appeared since the previous scan.
      { selector: "node.is-new", style: { "border-width": 4, "border-color": "#22c55e", "border-style": "double" } },
      // Attack path highlighting: everything else fades, the chain glows.
      { selector: ".dimmed", style: { "opacity": 0.12 } },
      {
        selector: "node.on-path",
        style: { "border-width": 4, "border-color": "#ff4d6d", "opacity": 1, "z-index": 20 }
      },
      {
        selector: "edge.on-path",
        style: {
          "line-color": "#ff4d6d", "target-arrow-color": "#ff4d6d", "width": 4,
          "opacity": 1, "z-index": 20, "line-style": "solid"
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

    openRulesOfEngagement(target, ttype, depth);
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

async function openExecutiveReport() {
  if (!currentPaths.length) await loadAttackPaths();
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

    <h2>3. Prioritised Attack Paths</h2>
    ${currentPaths.length ? `
    <table class="report-table">
      <thead><tr><th>Risk</th><th>Scenario</th><th>Attack route (MITRE ATT&amp;CK)</th><th>First fix</th></tr></thead>
      <tbody>${currentPaths.slice(0, 8).map((p) => `
        <tr>
          <td><strong>${p.score}</strong><br>${escapeHtml(p.severity.toUpperCase())}</td>
          <td><strong>${escapeHtml(p.title)}</strong><br>${escapeHtml(p.narrative)}</td>
          <td>${p.techniques.map((t) => `${escapeHtml(t.id)} ${escapeHtml(t.name)}`).join(" →<br>")}</td>
          <td>${escapeHtml(p.remediation[0] || "")}</td>
        </tr>`).join("")}
      </tbody>
    </table>` : "<p>No attack paths were identified.</p>"}

    <h2>4. Topology Breakdown by Intelligence Category</h2>
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

    <h2>5. Methodology & Compliance Notice</h2>
    <p style="font-size: 0.8rem; color: #94a3b8;">
      Findings were gathered from public Open Source Intelligence: DNS, Certificate Transparency logs, RDAP (RFC 7480),
      public scan databases and public profiles. Two modules are <em>active</em> and contacted the target directly with
      ordinary, single requests: a TLS handshake (certificate inspection) and an HTTP request (header fingerprinting).
      No exploitation, credential testing or brute forcing was performed. Attack paths are rule-based assessments of
      plausible attacker routes, not confirmed exploitation; verify before acting.
    </p>
  `;

  document.getElementById("report-modal-body").innerHTML = html;
  document.getElementById("report-modal").classList.add("active");
}

async function startInvestigation(target, targetType, maxDepth, purpose) {
  const launchBtn = document.getElementById("launch-btn");
  const statusBadge = document.getElementById("status-badge");

  launchBtn.disabled = true;
  setStatus("running");
  resetWorkspace();

  try {
    const response = await authFetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target: target,
        target_type: targetType,
        max_depth: maxDepth,
        purpose: purpose,
        authorized: true
      })
    });

    const data = await response.json();
    if (!response.ok) throw new Error(describeError(data));
    attachInvestigation(data.investigation_id);
  } catch (err) {
    console.error("Failed to start scan:", err);
    addEventToFeed(`Scan rejected: ${err.message}`);
    launchBtn.disabled = false;
    statusBadge.textContent = "Error";
    statusBadge.style.color = "var(--accent-crimson)";
  }
}

async function connectWebSocket(invId) {
  if (activeSocket) {
    activeSocket.close();
  }

  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/ws/stream/${invId}`;
  let ticket;
  try {
    // Browsers can't send auth headers on WebSockets: trade the key for a one-time ticket.
    ticket = (await (await authFetch("/api/ws-ticket", { method: "POST" })).json()).ticket;
  } catch (err) {
    addEventToFeed("Could not open live stream (authentication failed)");
    return;
  }
  activeSocket = new WebSocket(`${wsUrl}?ticket=${encodeURIComponent(ticket)}`);

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
    const res = await authFetch(`/api/investigations?${params}`);
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
        <div class="history-actions">
          <button class="link-btn history-compare" data-id="${escapeHtml(r.id)}" title="Compare with the previous scan of this target">Compare</button>
          <button class="link-btn history-watch" data-target="${escapeHtml(r.target)}" data-type="${escapeHtml(r.target_type)}" title="Re-scan on a schedule and alert on changes">Watch</button>
        </div>
        <button class="history-delete" title="Delete investigation" data-id="${escapeHtml(r.id)}">✕</button>
      </div>`).join("");
  } catch (err) {
    list.innerHTML = '<div class="history-empty">Could not load history.</div>';
  }
}

async function deleteInvestigation(invId) {
  if (!confirm("Permanently delete this investigation and all of its findings?")) return;
  const res = await authFetch(`/api/investigation/${encodeURIComponent(invId)}`, { method: "DELETE" });
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
    const compareBtn = e.target.closest(".history-compare");
    if (compareBtn) {
      e.stopPropagation();
      openDiff(compareBtn.dataset.id);
      return;
    }
    const watchBtn = e.target.closest(".history-watch");
    if (watchBtn) {
      e.stopPropagation();
      openRulesOfEngagement(watchBtn.dataset.target, watchBtn.dataset.type, 2, "monitor");
      return;
    }
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
  document.querySelector('.tab-btn[data-tab="tab-history"]').addEventListener("click", () => {
    loadHistory();
    loadMonitoring();
  });
}

// Cross-investigation pivot: has this value appeared in any other investigation?
async function loadPivots(nodeData) {
  const box = document.getElementById("pivot-results");
  if (!box || String(nodeData.value).length < 2) return;
  try {
    const params = new URLSearchParams({ q: nodeData.value, type: nodeData.type, limit: "20" });
    const hits = (await (await authFetch(`/api/entities/search?${params}`)).json())
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

// ================================================================ MITRE ATT&CK
async function loadAttackMapping() {
  if (!currentInvestigationId) return;
  const box = document.getElementById("attack-list");
  try {
    const res = await authFetch(`/api/investigation/${encodeURIComponent(currentInvestigationId)}/attack`);
    const mapping = await res.json();
    box.innerHTML = mapping.techniques.length
      ? mapping.techniques.map((t) => `
          <div class="attack-row" title="${escapeHtml(t.defence)}">
            <a class="attack-id" href="${escapeHtml(t.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(t.id)}</a>
            <span class="attack-name">${escapeHtml(t.parent === t.id ? t.name : `${t.parent_name}: ${t.name}`)}</span>
            <span class="attack-count">${t.count}</span>
            <div class="attack-defence">🛡 ${escapeHtml(t.defence)}</div>
          </div>`).join("")
      : '<div style="color: var(--text-muted); font-size: 0.8rem;">No reconnaissance exposure mapped.</div>';
  } catch (err) {
    box.innerHTML = "";
  }
}

function renderAnalytics(analytics) {
  loadAttackMapping();
  loadAttackPaths();
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

// ================================================================ authentication
// The API key lives in sessionStorage (cleared when the tab closes) and is sent as a
// Bearer header. The strict Content-Security-Policy makes script injection - the main
// way such a token could be stolen - far harder.
const KEY_STORAGE = "argus_api_key";

function storedKey() {
  try { return sessionStorage.getItem(KEY_STORAGE) || ""; } catch (e) { return ""; }
}

async function authFetch(url, options = {}) {
  const headers = new Headers(options.headers || {});
  const key = storedKey();
  if (key) headers.set("Authorization", `Bearer ${key}`);
  const res = await fetch(url, { ...options, headers });
  if (res.status === 401) {
    showLogin("Your session is not signed in or the key was revoked.");
    throw new Error("Authentication required");
  }
  return res;
}

function describeError(body) {
  const d = body && body.detail;
  if (Array.isArray(d)) return d.map((e) => e.msg).join("; ");
  return d || "Request failed";
}

function showLogin(message = "") {
  document.getElementById("login-error").textContent = message;
  document.getElementById("login-modal").classList.add("active");
  document.getElementById("api-key-input").focus();
}

function setUser(me) {
  document.getElementById("user-name").textContent = `${me.name} · ${me.role}`;
  document.getElementById("user-pill").hidden = false;
  document.body.dataset.role = me.role;
  loadMonitoring();  // alerts badge as soon as we know who you are
}

async function ensureSignedIn() {
  const res = await fetch("/api/me", { headers: storedKey() ? { Authorization: `Bearer ${storedKey()}` } : {} });
  if (res.ok) {
    setUser(await res.json());
    return true;
  }
  showLogin();
  return false;
}

function setupAuth() {
  document.getElementById("login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const key = document.getElementById("api-key-input").value.trim();
    const res = await fetch("/api/me", { headers: { Authorization: `Bearer ${key}` } });
    if (!res.ok) {
      document.getElementById("login-error").textContent = "That key was not accepted.";
      return;
    }
    try { sessionStorage.setItem(KEY_STORAGE, key); } catch (err) { /* storage blocked: key held for this page only */ }
    document.getElementById("api-key-input").value = "";
    document.getElementById("login-modal").classList.remove("active");
    setUser(await res.json());
    loadHistory();
  });

  document.getElementById("btn-logout").addEventListener("click", () => {
    try { sessionStorage.removeItem(KEY_STORAGE); } catch (e) { /* ignore */ }
    if (activeSocket) activeSocket.close();
    currentInvestigationId = null;
    resetWorkspace();
    setStatus("idle");
    document.getElementById("user-pill").hidden = true;
    showLogin("Signed out.");
  });
}

// ================================================================ rules of engagement
let pendingScan = null;

function openRulesOfEngagement(target, ttype, depth, mode = "scan") {
  pendingScan = { target, ttype, depth, mode };
  document.getElementById("roe-interval-row").hidden = mode !== "monitor";
  document.querySelector("#roe-form button[type=submit]").textContent = mode === "monitor" ? "Start Monitoring" : "Launch Recon";
  document.getElementById("roe-target").textContent = target;
  try { document.getElementById("roe-purpose").value = sessionStorage.getItem("argus_last_purpose") || ""; } catch (e) { /* ignore */ }
  document.getElementById("roe-authorized").checked = false;
  document.getElementById("roe-error").textContent = "";
  document.getElementById("roe-modal").classList.add("active");
  document.getElementById("roe-purpose").focus();
}

function setupRulesOfEngagement() {
  const modal = document.getElementById("roe-modal");
  document.getElementById("roe-cancel").addEventListener("click", () => modal.classList.remove("active"));
  const clearError = () => { document.getElementById("roe-error").textContent = ""; };
  document.getElementById("roe-purpose").addEventListener("input", clearError);
  document.getElementById("roe-authorized").addEventListener("change", clearError);
  document.getElementById("roe-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const purpose = document.getElementById("roe-purpose").value.trim();
    const error = document.getElementById("roe-error");
    if (purpose.length < 5) {
      error.textContent = "Describe the engagement (at least 5 characters).";
      return;
    }
    if (!document.getElementById("roe-authorized").checked) {
      error.textContent = "You must confirm you are authorised to investigate this target.";
      return;
    }
    try { sessionStorage.setItem("argus_last_purpose", purpose); } catch (err) { /* ignore */ }
    modal.classList.remove("active");
    const { target, ttype, depth, mode } = pendingScan;
    if (mode === "monitor") {
      createMonitor(target, ttype, depth, purpose, Number(document.getElementById("roe-interval").value));
    } else {
      startInvestigation(target, ttype, depth, purpose);
    }
  });
}

// ================================================================ authenticated exports
// Plain <a href> links cannot carry the Authorization header, so download via fetch.
function setupExports() {
  const exports = [
    ["btn-export-json", "json", "json"],
    ["btn-export-csv", "csv", "maltego.csv"],
    ["btn-export-stix", "stix", "stix.json"],
    ["btn-export-navigator", "navigator", "attack_layer.json"],
  ];
  for (const [id, path, suffix] of exports) {
    document.getElementById(id).addEventListener("click", async (e) => {
      e.preventDefault();
      if (!currentInvestigationId) return;
      const res = await authFetch(`/api/investigation/${encodeURIComponent(currentInvestigationId)}/export/${path}`);
      if (!res.ok) return addEventToFeed(`Export failed (${res.status})`);
      const url = URL.createObjectURL(await res.blob());
      const a = document.createElement("a");
      a.href = url;
      a.download = `argus_${currentInvestigationId}_${suffix}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    });
  }
}

// ================================================================ attack paths
const SEVERITY_ORDER = ["critical", "high", "medium", "low"];
let currentPaths = [];

async function loadAttackPaths() {
  if (!currentInvestigationId) return;
  try {
    const res = await authFetch(`/api/investigation/${encodeURIComponent(currentInvestigationId)}/paths`);
    const data = await res.json();
    currentPaths = data.paths;
    renderAttackPaths(data);
  } catch (err) {
    /* leave previous state */
  }
}

function renderAttackPaths(data) {
  const badge = document.getElementById("paths-badge");
  badge.textContent = data.summary.total;
  badge.hidden = data.summary.total === 0;
  badge.className = "tab-badge" + (data.summary.by_severity.critical ? " sev-critical" : data.summary.by_severity.high ? " sev-high" : "");

  document.getElementById("paths-summary").innerHTML = SEVERITY_ORDER
    .map((s) => `<span class="sev-pill sev-${s}">${data.summary.by_severity[s]} ${s}</span>`).join("");

  const list = document.getElementById("paths-list");
  if (!data.paths.length) {
    list.innerHTML = `<div class="history-empty">No attack paths found across ${data.summary.rules_evaluated} rules. 🎉</div>`;
    return;
  }
  list.innerHTML = data.paths.map((p, i) => `
    <article class="path-card sev-border-${escapeHtml(p.severity)}" data-index="${i}">
      <div class="path-head">
        <span class="sev-pill sev-${escapeHtml(p.severity)}">${escapeHtml(p.severity)}</span>
        <span class="path-score" title="Risk = impact ${p.impact}/5 × likelihood ${p.likelihood}">${p.score}</span>
      </div>
      <h3 class="path-title">${escapeHtml(p.title)}</h3>
      <div class="path-chain">${p.steps.map((s) => `
        <span class="chain-step" style="border-color:${ENTITY_COLORS[s.type] || "#64748b"}" title="${escapeHtml(s.role)}">
          <span class="chain-role">${escapeHtml(s.role)}</span>${escapeHtml(s.label)}
        </span>`).join('<span class="chain-arrow">→</span>')}
      </div>
      <p class="path-narrative">${escapeHtml(p.narrative)}</p>
      <div class="path-ttps">${p.techniques.map((t) => `
        <a class="ttp" href="${escapeHtml(t.url)}" target="_blank" rel="noopener noreferrer" title="${escapeHtml(t.name)}">
          <span class="ttp-tactic">${escapeHtml(t.tactic)}</span>${escapeHtml(t.id)}
        </a>`).join('<span class="chain-arrow">›</span>')}
      </div>
      <details class="path-details">
        <summary>Evidence &amp; remediation</summary>
        <ul class="path-evidence">${p.evidence.map((e) => `<li>${escapeHtml(e)}</li>`).join("")}</ul>
        <ol class="path-fixes">${p.remediation.map((r) => `<li>${escapeHtml(r)}</li>`).join("")}</ol>
      </details>
      <button class="btn-secondary path-show">Show on graph</button>
    </article>`).join("");
}

function highlightPath(path) {
  cy.elements().removeClass("on-path").addClass("dimmed");
  const nodes = cy.collection(path.steps.map((s) => cy.getElementById(s.entity_id)).filter((n) => n.length));
  const edges = cy.collection(path.edges.map((id) => cy.getElementById(id)).filter((e) => e.length));
  nodes.union(edges).removeClass("dimmed").addClass("on-path");
  cy.animate({ fit: { eles: nodes, padding: 120 } }, { duration: 500 });
  document.getElementById("btn-clear-path").hidden = false;
}

function clearPathHighlight() {
  cy.elements().removeClass("dimmed on-path");
  document.getElementById("btn-clear-path").hidden = true;
  document.querySelectorAll(".path-card.selected").forEach((c) => c.classList.remove("selected"));
}

function setupAttackPaths() {
  document.getElementById("paths-list").addEventListener("click", (e) => {
    const card = e.target.closest(".path-card");
    if (!card || !e.target.closest(".path-show")) return;
    document.querySelectorAll(".path-card.selected").forEach((c) => c.classList.remove("selected"));
    card.classList.add("selected");
    highlightPath(currentPaths[Number(card.dataset.index)]);
  });
  document.getElementById("btn-clear-path").addEventListener("click", clearPathHighlight);
  document.querySelector('.tab-btn[data-tab="tab-paths"]').addEventListener("click", loadAttackPaths);
}

// ================================================================ monitoring & drift
function timeAgo(iso) {
  const mins = Math.round((Date.now() - new Date(iso).getTime()) / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins} min ago`;
  if (mins < 1440) return `${Math.round(mins / 60)} h ago`;
  return `${Math.round(mins / 1440)} d ago`;
}

async function loadMonitoring() {
  try {
    const [alerts, monitors] = await Promise.all([
      authFetch("/api/alerts?limit=20").then((r) => r.json()),
      authFetch("/api/monitors").then((r) => r.json()),
    ]);
    const open = alerts.filter((a) => !a.acknowledged_at);
    const badge = document.getElementById("alerts-badge");
    badge.textContent = open.length;
    badge.hidden = open.length === 0;

    document.getElementById("alerts-list").innerHTML = alerts.length ? alerts.map((a) => `
      <div class="alert-item${a.acknowledged_at ? " acked" : ""}">
        <div class="alert-head">
          <span class="sev-pill sev-${escapeHtml(a.severity)}">${escapeHtml(a.severity)}</span>
          <span class="alert-time">${timeAgo(a.created_at)}</span>
        </div>
        <div class="alert-headline">${escapeHtml(a.headline)}</div>
        <div class="alert-actions">
          <button class="link-btn alert-view" data-inv="${escapeHtml(a.investigation_id)}" data-prev="${escapeHtml(a.previous_investigation_id)}">View changes</button>
          ${a.acknowledged_at ? `<span class="alert-acked">✓ ${escapeHtml(a.acknowledged_by || "")}</span>`
            : `<button class="link-btn alert-ack" data-id="${escapeHtml(a.id)}">Acknowledge</button>`}
        </div>
      </div>`).join("") : '<div class="history-empty small">No alerts. Watch a target to be told when it changes.</div>';

    document.getElementById("monitors-list").innerHTML = monitors.length ? monitors.map((m) => `
      <div class="monitor-item${m.enabled ? "" : " paused"}">
        <div class="history-main">
          <span class="history-target">${escapeHtml(m.target)}</span>
          <span class="history-status">${m.enabled ? `every ${m.interval_hours} h` : "paused"}</span>
        </div>
        <div class="history-meta">
          ${m.last_run_at ? `last run ${timeAgo(m.last_run_at)}` : "first scan pending"} ·
          <button class="link-btn monitor-toggle" data-id="${escapeHtml(m.id)}" data-enabled="${m.enabled}">${m.enabled ? "Pause" : "Resume"}</button> ·
          <button class="link-btn monitor-delete" data-id="${escapeHtml(m.id)}">Stop watching</button>
        </div>
      </div>`).join("") : '<div class="history-empty small">No monitored targets.</div>';
  } catch (err) {
    /* monitoring is optional; leave the panels as they are */
  }
}

async function createMonitor(target, targetType, depth, purpose, intervalHours) {
  const res = await authFetch("/api/monitors", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target, target_type: targetType || null, max_depth: depth, purpose,
                           interval_hours: intervalHours, authorized: true }),
  });
  const body = await res.json();
  addEventToFeed(res.ok ? `Now monitoring ${target} every ${intervalHours} h` : `Monitor rejected: ${describeError(body)}`);
  loadMonitoring();
  loadHistory();
}

async function openDiff(invId, againstId) {
  const qs = againstId ? `?against=${encodeURIComponent(againstId)}` : "";
  const res = await authFetch(`/api/investigation/${encodeURIComponent(invId)}/diff${qs}`);
  const d = await res.json();
  const body = document.getElementById("diff-body");
  document.getElementById("diff-subtitle").textContent = res.ok
    ? `${d.headline.split(":")[0]} · compared with the scan of ${new Date(d.previous_completed_at).toLocaleString()}`
    : "";
  if (!res.ok) {
    body.innerHTML = `<p>${escapeHtml(describeError(d))}</p>`;
  } else {
    const s = d.summary;
    const trendClass = s.trend === "worse" ? "sev-critical" : s.trend === "better" ? "trend-better" : "sev-low";
    const pathList = (items, cls, fmt) => items.length
      ? `<ul class="diff-list">${items.map((p) => `<li><span class="sev-pill sev-${escapeHtml(p.severity)}">${escapeHtml(p.severity)}</span> ${escapeHtml(p.title)} ${fmt(p)}</li>`).join("")}</ul>`
      : '<p class="diff-none">None</p>';
    const assetList = (groups) => {
      const entries = Object.entries(groups);
      return entries.length ? entries.map(([type, items]) => `
        <div class="diff-group"><strong>${escapeHtml(type)}</strong> ${items.map((i) => `<code>${escapeHtml(i.value)}</code>`).join(" ")}</div>`).join("")
        : '<p class="diff-none">None</p>';
    };
    body.innerHTML = `
      <div class="diff-stats">
        <div class="diff-stat"><span class="sev-pill ${trendClass}">${escapeHtml(s.trend)}</span><small>risk ${s.risk_before} → ${s.risk_after} (${s.risk_delta >= 0 ? "+" : ""}${s.risk_delta})</small></div>
        <div class="diff-stat"><b>${s.new_paths}</b><small>new paths</small></div>
        <div class="diff-stat"><b>${s.escalated_paths}</b><small>escalated</small></div>
        <div class="diff-stat"><b>${s.resolved_paths}</b><small>resolved</small></div>
        <div class="diff-stat"><b>${s.added}</b><small>new assets</small></div>
        <div class="diff-stat"><b>${s.removed}</b><small>gone</small></div>
      </div>
      <h2>New attack paths</h2>${pathList(d.new_paths, "", () => "")}
      <h2>Escalated</h2>${pathList(d.escalated_paths, "", (p) => `<small>(${p.score_before} → ${p.score})</small>`)}
      <h2>Resolved ✓</h2>${pathList(d.resolved_paths, "", () => "")}
      <h2>New assets</h2>${assetList(d.added)}
      <h2>No longer seen</h2>${assetList(d.removed)}
      <h2>Security-relevant changes</h2>${d.changed.length ? `<ul class="diff-list">${d.changed.map((c) =>
        `<li><code>${escapeHtml(c.value)}</code> ${Object.entries(c.changes).map(([k, v]) =>
          `${escapeHtml(k)}: ${escapeHtml(JSON.stringify(v.before))} → <b>${escapeHtml(JSON.stringify(v.after))}</b>`).join("; ")}</li>`).join("")}</ul>`
        : '<p class="diff-none">None</p>'}`;
    if (currentInvestigationId === invId) markNewOnGraph(d.added);
  }
  document.getElementById("diff-modal").classList.add("active");
}

function markNewOnGraph(added) {
  cy.nodes().removeClass("is-new");
  Object.values(added).flat().forEach((e) => cy.getElementById(e.id).addClass("is-new"));
}

function setupMonitoring() {
  document.getElementById("btn-close-diff").addEventListener("click", () =>
    document.getElementById("diff-modal").classList.remove("active"));
  document.getElementById("alerts-list").addEventListener("click", async (e) => {
    const view = e.target.closest(".alert-view");
    if (view) {
      openInvestigation(view.dataset.inv);
      setTimeout(() => openDiff(view.dataset.inv, view.dataset.prev), 600);
      return;
    }
    const ack = e.target.closest(".alert-ack");
    if (ack) {
      await authFetch(`/api/alerts/${encodeURIComponent(ack.dataset.id)}/acknowledge`, { method: "POST" });
      loadMonitoring();
    }
  });
  document.getElementById("monitors-list").addEventListener("click", async (e) => {
    const toggle = e.target.closest(".monitor-toggle");
    if (toggle) {
      await authFetch(`/api/monitors/${encodeURIComponent(toggle.dataset.id)}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: toggle.dataset.enabled !== "true" }),
      });
      loadMonitoring();
      return;
    }
    const del = e.target.closest(".monitor-delete");
    if (del && confirm("Stop monitoring this target? Past investigations and alerts are kept.")) {
      await authFetch(`/api/monitors/${encodeURIComponent(del.dataset.id)}`, { method: "DELETE" });
      loadMonitoring();
    }
  });
  // Initial load happens in setUser(), i.e. only once signed in.
  setInterval(() => { if (storedKey()) loadMonitoring(); }, 60000);  // alert badge stays current
}
