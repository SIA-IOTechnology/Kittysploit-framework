/* global cytoscape */

const RISK_ORDER = {
  info: 1,
  low: 2,
  read: 2,
  medium: 3,
  active: 3,
  high: 4,
  intrusive: 4,
  critical: 5,
  destructive: 5,
};

const KIND_LABELS = {
  host: "Host",
  machine: "Machine",
  service: "Service",
  tech: "Tech",
  endpoint: "Endpoint",
  vulnerability: "Vulnerability",
  finding: "Finding",
  credential: "Credential",
  session: "Session",
  pivot: "Pivot",
  module: "Module",
  exploit_path: "Exploit",
  action: "Action",
  auth: "Auth",
  capability: "Capability",
  observation: "Observation",
  param: "Param",
};

const state = {
  payload: null,
  cy: null,
  activePathId: null,
  showLabels: false,
  showFullGraph: false,
  filters: {
    search: "",
    host: "",
    risk: "",
    sort: "confidence",
    actionable: false,
  },
};

async function fetchGraph(refresh = false) {
  const response = await fetch(`/api/graph${refresh ? "?refresh=1" : ""}`);
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function formatRisk(risk) {
  return risk ? String(risk).toUpperCase() : "—";
}

function riskClass(risk) {
  return `risk-badge risk-${String(risk || "low").toLowerCase()}`;
}

function nodeLookup() {
  const map = new Map();
  for (const node of state.payload?.nodes || []) {
    map.set(node.id, node);
  }
  return map;
}

function pathHost(path, lookup) {
  for (const nodeId of path.nodes || []) {
    const node = lookup.get(nodeId);
    if (node && (node.kind === "host" || node.kind === "machine")) {
      return node.label;
    }
  }
  const label = String(path.label || "");
  const first = label.split("→")[0]?.trim();
  return first || "—";
}

function pathStepsHtml(path, lookup) {
  const labels = (path.nodes || [])
    .map((id) => lookup.get(id)?.label)
    .filter(Boolean);
  if (!labels.length) return escapeHtml(path.label || "");
  return labels
    .map((label) => escapeHtml(label))
    .join('<span class="sep">→</span>');
}

function modulesHtml(modules, limit = 2) {
  const list = modules || [];
  if (!list.length) return "—";
  const shown = list.slice(0, limit).map((item) => `<span class="module-chip">${escapeHtml(item)}</span>`).join("");
  const more = list.length > limit ? `<span class="module-chip">+${list.length - limit}</span>` : "";
  return shown + more;
}

function filteredPaths() {
  const lookup = nodeLookup();
  const search = state.filters.search.trim().toLowerCase();
  const host = state.filters.host;
  const risk = state.filters.risk.toLowerCase();
  let paths = [...(state.payload?.paths || [])];

  paths = paths.map((path, index) => ({
    ...path,
    _index: index + 1,
    _host: pathHost(path, lookup),
  }));

  if (host) {
    paths = paths.filter((path) => path._host === host);
  }
  if (risk) {
    paths = paths.filter((path) => String(path.risk || "").toLowerCase() === risk);
  }
  if (state.filters.actionable) {
    paths = paths.filter((path) => (path.modules || []).length > 0);
  }
  if (search) {
    paths = paths.filter((path) => {
      const hay = [
        path.label,
        path._host,
        ...(path.modules || []),
        ...(path.nodes || []).map((id) => lookup.get(id)?.label || ""),
      ].join(" ").toLowerCase();
      return hay.includes(search);
    });
  }

  if (state.filters.sort === "risk") {
    paths.sort((a, b) => (RISK_ORDER[String(b.risk || "").toLowerCase()] || 0) - (RISK_ORDER[String(a.risk || "").toLowerCase()] || 0));
  } else if (state.filters.sort === "host") {
    paths.sort((a, b) => String(a._host).localeCompare(String(b._host)) || (b.confidence || 0) - (a.confidence || 0));
  } else {
    paths.sort((a, b) => (b.confidence || 0) - (a.confidence || 0));
  }
  return paths;
}

function renderStats(payload) {
  const kinds = payload.summary?.kinds || {};
  const hosts = kinds.host || kinds.machine || 0;
  const bar = document.getElementById("stats-bar");
  bar.innerHTML = [
    ["Paths", (payload.paths || []).length],
    ["Hosts", hosts],
    ["Nodes", (payload.nodes || []).length],
    ["Edges", (payload.edges || []).length],
  ].map(([label, value]) => `<span class="stat">${label} <strong>${value}</strong></span>`).join("");
}

function renderHostFilter(payload) {
  const lookup = nodeLookup();
  const hosts = [...new Set((payload.paths || []).map((path) => pathHost(path, lookup)).filter(Boolean))].sort();
  const select = document.getElementById("host-filter");
  const current = state.filters.host;
  select.innerHTML = `<option value="">All hosts (${hosts.length})</option>` +
    hosts.map((host) => `<option value="${escapeHtml(host)}">${escapeHtml(host)}</option>`).join("");
  select.value = hosts.includes(current) ? current : "";
  state.filters.host = select.value;
}

function renderLegend(payload) {
  const kinds = [...new Set((payload.nodes || []).map((node) => node.kind))].sort();
  const container = document.getElementById("kind-legend");
  container.innerHTML = kinds.map((kind) => {
    const color = (payload.nodes || []).find((node) => node.kind === kind)?.color || "#64748b";
    return `<span class="chip"><span class="dot" style="background:${color}"></span>${escapeHtml(KIND_LABELS[kind] || kind)}</span>`;
  }).join("");
}

function renderPaths() {
  const tbody = document.getElementById("path-list");
  const paths = filteredPaths();
  const lookup = nodeLookup();
  document.getElementById("path-count").textContent =
    `${paths.length} of ${(state.payload?.paths || []).length} paths`;

  if (!paths.length) {
    tbody.innerHTML = `<tr><td colspan="6" style="color:var(--muted);padding:1.2rem">No paths match the current filters.</td></tr>`;
    return;
  }

  tbody.innerHTML = paths.map((path) => `
    <tr data-path-id="${escapeHtml(path.path_id)}" class="${path.path_id === state.activePathId ? "active" : ""}">
      <td class="col-num">${path._index}</td>
      <td class="col-host">${escapeHtml(path._host)}</td>
      <td class="col-path"><div class="path-steps">${pathStepsHtml(path, lookup)}</div></td>
      <td class="col-conf">${Math.round((path.confidence || 0) * 100)}%</td>
      <td class="col-risk"><span class="${riskClass(path.risk)}">${escapeHtml(formatRisk(path.risk))}</span></td>
      <td class="col-modules">${modulesHtml(path.modules, 2)}</td>
    </tr>
  `).join("");

  tbody.querySelectorAll("tr[data-path-id]").forEach((row) => {
    row.addEventListener("click", () => selectPath(row.dataset.pathId));
  });
}

function renderNextAction(payload) {
  const box = document.getElementById("next-action");
  const next = payload.next_action;
  if (!next?.action) {
    box.classList.add("hidden");
    box.innerHTML = "";
    return;
  }
  box.classList.remove("hidden");
  box.innerHTML = `
    <strong>Suggested next action</strong>
    ${escapeHtml(next.action)}
    <div style="margin-top:0.25rem;color:var(--muted)">confidence ${Math.round((next.confidence || 0) * 100)}%</div>
  `;
}

function setDetailsHtml(html, empty = false) {
  const panel = document.getElementById("details");
  panel.classList.toggle("empty", empty);
  panel.innerHTML = html;
}

function selectedPath() {
  return (state.payload?.paths || []).find((item) => item.path_id === state.activePathId) || null;
}

function showPathDetails(path) {
  const lookup = nodeLookup();
  const steps = (path.nodes || []).map((id, index) => {
    const node = lookup.get(id);
    if (!node) return "";
    return `<li>
      <span class="n">${index + 1}</span>
      <div>
        <span class="kind">${escapeHtml(KIND_LABELS[node.kind] || node.kind)}</span>
        ${escapeHtml(node.label)}
      </div>
    </li>`;
  }).join("");

  const modules = (path.modules || []).length
    ? (path.modules || []).map((item) => `<span class="module-chip">${escapeHtml(item)}</span>`).join("")
    : "—";

  setDetailsHtml(`
    <div class="detail-block">
      <h3 class="detail-title">Path</h3>
      <p class="detail-body">${escapeHtml(path.label || "")}</p>
    </div>
    <div class="detail-block">
      <h3 class="detail-title">Score</h3>
      <p class="detail-body">
        Confidence <strong>${Math.round((path.confidence || 0) * 100)}%</strong>
        · Risk <span class="${riskClass(path.risk)}">${escapeHtml(formatRisk(path.risk))}</span>
      </p>
    </div>
    <div class="detail-block">
      <h3 class="detail-title">Steps (${(path.nodes || []).length})</h3>
      <ol class="step-list">${steps}</ol>
    </div>
    <div class="detail-block">
      <h3 class="detail-title">Validation modules</h3>
      <div>${modules}</div>
    </div>
  `);
}

function showNodeDetails(data) {
  const modules = (data.modules || []).map((item) => `<span class="module-chip">${escapeHtml(item)}</span>`).join("") || "—";
  const metaEntries = Object.entries(data.metadata || {});
  const meta = metaEntries.length
    ? metaEntries.map(([key, value]) => `<div><strong>${escapeHtml(key)}</strong>: ${escapeHtml(typeof value === "object" ? JSON.stringify(value) : value)}</div>`).join("")
    : "—";
  setDetailsHtml(`
    <div class="detail-block">
      <h3 class="detail-title">${escapeHtml(KIND_LABELS[data.kind] || data.kind)}</h3>
      <p class="detail-body">${escapeHtml(data.label)}</p>
    </div>
    <div class="detail-block">
      <h3 class="detail-title">Score</h3>
      <p class="detail-body">
        Confidence <strong>${Math.round((data.confidence || 0) * 100)}%</strong>
        ${data.risk ? ` · Risk <span class="${riskClass(data.risk)}">${escapeHtml(formatRisk(data.risk))}</span>` : ""}
      </p>
    </div>
    <div class="detail-block">
      <h3 class="detail-title">Modules</h3>
      <div>${modules}</div>
    </div>
    <div class="detail-block">
      <h3 class="detail-title">Metadata</h3>
      <div class="detail-body">${meta}</div>
    </div>
  `);
}

function visibleNodeIdsForGraph() {
  if (state.showFullGraph) {
    return new Set((state.payload?.nodes || []).map((node) => node.id));
  }
  if (!state.activePathId) return new Set();
  const path = (state.payload?.paths || []).find((item) => item.path_id === state.activePathId);
  if (!path) return new Set();
  return new Set(path.nodes || []);
}

function buildElements() {
  const visible = visibleNodeIdsForGraph();
  const nodes = (state.payload?.nodes || [])
    .filter((node) => visible.has(node.id))
    .map((node) => ({
      data: {
        id: node.id,
        label: node.label,
        kind: node.kind,
        confidence: node.confidence,
        risk: node.risk,
        color: node.color,
        modules: node.modules || [],
        metadata: node.metadata || {},
      },
    }));

  const nodeIds = new Set(nodes.map((node) => node.data.id));
  const edges = (state.payload?.edges || [])
    .filter((edge) => nodeIds.has(edge.source) && nodeIds.has(edge.target))
    .map((edge) => ({
      data: {
        id: edge.id,
        source: edge.source,
        target: edge.target,
        label: edge.label || edge.action || edge.kind || "",
        kind: edge.kind,
        confidence: edge.confidence,
        risk: edge.risk,
        action: edge.action,
        abandoned: !!edge.abandoned,
      },
    }));

  return [...nodes, ...edges];
}

function resizeGraph() {
  if (!state.cy) return;
  state.cy.resize();
  state.cy.fit(undefined, 40);
}

function applyLabelVisibility() {
  if (!state.cy) return;
  const value = state.showLabels ? "data(label)" : "";
  state.cy.style().selector("node").style("label", value).update();
  state.cy.style().selector("edge").style("label", state.showLabels ? "data(label)" : "").update();
}

function renderGraph() {
  const empty = document.getElementById("graph-empty");
  const elements = buildElements();

  if (!elements.length) {
    empty.classList.remove("hidden");
    empty.textContent = state.showFullGraph
      ? "No nodes to display."
      : "Select a path to visualize it.";
    if (state.cy) {
      state.cy.destroy();
      state.cy = null;
    }
    return;
  }
  empty.classList.add("hidden");

  if (state.cy) {
    state.cy.destroy();
    state.cy = null;
  }

  state.cy = cytoscape({
    container: document.getElementById("cy"),
    elements,
    layout: {
      name: state.showFullGraph ? "cose" : "breadthfirst",
      animate: false,
      padding: 36,
      directed: true,
      spacingFactor: state.showFullGraph ? 1.1 : 1.35,
      nodeRepulsion: state.showFullGraph ? 14000 : 9000,
      idealEdgeLength: 100,
    },
    wheelSensitivity: 0.15,
    style: [
      {
        selector: "node",
        style: {
          "background-color": "data(color)",
          label: state.showLabels ? "data(label)" : "",
          color: "#e6edf3",
          "font-size": 11,
          "text-wrap": "ellipsis",
          "text-max-width": 140,
          "text-valign": "bottom",
          "text-margin-y": 6,
          width: 28,
          height: 28,
          "border-width": 2,
          "border-color": "#30363d",
        },
      },
      {
        selector: "node[kind = 'host'], node[kind = 'machine']",
        style: { width: 42, height: 42, "font-weight": 700 },
      },
      {
        selector: "node[kind = 'vulnerability'], node[kind = 'finding'], node[kind = 'exploit_path']",
        style: { "background-color": "#f85149" },
      },
      {
        selector: "node[kind = 'credential']",
        style: { shape: "diamond", "background-color": "#da70d6" },
      },
      {
        selector: "node[kind = 'session']",
        style: { shape: "round-rectangle", "background-color": "#ffd700", color: "#111" },
      },
      {
        selector: "node[kind = 'pivot']",
        style: { shape: "hexagon", "background-color": "#00ced1", color: "#111" },
      },
      {
        selector: "node:selected",
        style: { "border-color": "#58a6ff", "border-width": 4 },
      },
      {
        selector: "edge",
        style: {
          width: 2,
          "line-color": "#484f58",
          "target-arrow-color": "#484f58",
          "target-arrow-shape": "triangle",
          "curve-style": "bezier",
          label: state.showLabels ? "data(label)" : "",
          "font-size": 9,
          color: "#8b949e",
          "text-rotation": "autorotate",
          "text-background-color": "#0d1117",
          "text-background-opacity": 0.8,
          "text-background-padding": 2,
        },
      },
      {
        selector: "edge[abandoned = true]",
        style: { "line-style": "dashed", opacity: 0.4 },
      },
    ],
  });

  state.cy.on("tap", "node", (event) => {
    showNodeDetails(event.target.data());
    activateTab("detail");
  });
  state.cy.on("tap", "edge", (event) => {
    const data = event.target.data();
    setDetailsHtml(`
      <div class="detail-block">
        <h3 class="detail-title">Edge</h3>
        <p class="detail-body">${escapeHtml(data.label || data.kind || "")}</p>
      </div>
      <div class="detail-block">
        <h3 class="detail-title">Module / action</h3>
        <p class="detail-body">${escapeHtml(data.action || "—")}</p>
      </div>
      <div class="detail-block">
        <h3 class="detail-title">Score</h3>
        <p class="detail-body">
          Confidence <strong>${Math.round((data.confidence || 0) * 100)}%</strong>
          ${data.risk ? ` · Risk <span class="${riskClass(data.risk)}">${escapeHtml(formatRisk(data.risk))}</span>` : ""}
        </p>
      </div>
    `);
    activateTab("detail");
  });

  requestAnimationFrame(resizeGraph);
}

function selectPath(pathId) {
  const path = (state.payload?.paths || []).find((item) => item.path_id === pathId);
  if (!path) return;
  state.activePathId = pathId;
  document.querySelectorAll("#path-list tr[data-path-id]").forEach((row) => {
    row.classList.toggle("active", row.dataset.pathId === pathId);
  });
  showPathDetails(path);
  document.getElementById("detail-actions").classList.remove("hidden");
  renderGraph();
  activateTab("detail");
}

function clearSelection() {
  state.activePathId = null;
  document.querySelectorAll("#path-list tr[data-path-id]").forEach((row) => row.classList.remove("active"));
  document.getElementById("detail-actions").classList.add("hidden");
  setDetailsHtml(
    "Select a path in the table to see steps, risk, and validation modules.",
    true
  );
  renderGraph();
}

function activateTab(name) {
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.classList.toggle("active", tab.dataset.tab === name);
  });
  document.querySelectorAll(".tab-pane").forEach((pane) => {
    pane.classList.toggle("active", pane.id === `tab-${name}`);
  });
  if (name === "graph") requestAnimationFrame(resizeGraph);
}

async function copyText(value, button) {
  if (!value) return;
  try {
    await navigator.clipboard.writeText(value);
    const original = button.textContent;
    button.textContent = "Copied";
    window.setTimeout(() => {
      button.textContent = original;
    }, 1200);
  } catch (error) {
    setDetailsHtml(`Copy failed: ${escapeHtml(error.message)}`);
  }
}

function resetFilters() {
  state.filters = {
    search: "",
    host: "",
    risk: "",
    sort: "confidence",
    actionable: false,
  };
  document.getElementById("search").value = "";
  document.getElementById("host-filter").value = "";
  document.getElementById("risk-filter").value = "";
  document.getElementById("sort-by").value = "confidence";
  document.getElementById("actionable-filter").checked = false;
  renderPaths();
}

function moveSelection(delta) {
  const rows = [...document.querySelectorAll("#path-list tr[data-path-id]")];
  if (!rows.length) return;
  let index = rows.findIndex((row) => row.dataset.pathId === state.activePathId);
  if (index < 0) index = delta > 0 ? -1 : 0;
  index = Math.max(0, Math.min(rows.length - 1, index + delta));
  const row = rows[index];
  selectPath(row.dataset.pathId);
  row.scrollIntoView({ block: "nearest" });
}

function initializeSplitter() {
  const handle = document.getElementById("split-handle");
  const layout = document.querySelector(".layout");
  let dragging = false;

  handle.addEventListener("pointerdown", (event) => {
    if (window.innerWidth <= 1100) return;
    dragging = true;
    handle.classList.add("dragging");
    handle.setPointerCapture(event.pointerId);
  });
  handle.addEventListener("pointermove", (event) => {
    if (!dragging) return;
    const minLeft = 520;
    const minRight = 360;
    const left = Math.max(minLeft, Math.min(event.clientX, window.innerWidth - minRight));
    layout.style.gridTemplateColumns = `${left}px 5px minmax(${minRight}px, 1fr)`;
    localStorage.setItem("attackExplorerLeftWidth", String(left));
    requestAnimationFrame(resizeGraph);
  });
  const stop = () => {
    dragging = false;
    handle.classList.remove("dragging");
  };
  handle.addEventListener("pointerup", stop);
  handle.addEventListener("pointercancel", stop);

  const saved = Number(localStorage.getItem("attackExplorerLeftWidth"));
  if (saved > 0 && window.innerWidth > 1100) {
    const left = Math.max(520, Math.min(saved, window.innerWidth - 360));
    layout.style.gridTemplateColumns = `${left}px 5px minmax(360px, 1fr)`;
  }
}

function updateSubtitle(payload) {
  document.getElementById("subtitle").textContent = [
    payload.workspace || "workspace",
    payload.source || "merged",
    payload.generated_at || "",
  ].filter(Boolean).join(" · ");
}

async function bootstrap(refresh = false) {
  try {
    if (typeof cytoscape === "undefined") {
      throw new Error("Cytoscape.js could not be loaded (CDN / network).");
    }
    const payload = await fetchGraph(refresh);
    state.payload = payload;
    state.activePathId = null;
    updateSubtitle(payload);
    renderStats(payload);
    renderHostFilter(payload);
    renderLegend(payload);
    renderNextAction(payload);
    renderPaths();
    renderGraph();
    activateTab("detail");
  } catch (error) {
    setDetailsHtml(`Load error: ${escapeHtml(error.message)}`);
  }
}

document.getElementById("btn-refresh").addEventListener("click", () => bootstrap(true));
document.getElementById("btn-clear").addEventListener("click", () => clearSelection());
document.getElementById("btn-fit").addEventListener("click", () => resizeGraph());
document.getElementById("btn-reset-filters").addEventListener("click", () => resetFilters());
document.getElementById("btn-view-graph").addEventListener("click", () => activateTab("graph"));
document.getElementById("btn-copy-path").addEventListener("click", (event) => {
  copyText(selectedPath()?.label || "", event.currentTarget);
});
document.getElementById("btn-copy-modules").addEventListener("click", (event) => {
  copyText((selectedPath()?.modules || []).join("\n"), event.currentTarget);
});

document.getElementById("search").addEventListener("input", (event) => {
  state.filters.search = event.target.value;
  renderPaths();
});
document.getElementById("host-filter").addEventListener("change", (event) => {
  state.filters.host = event.target.value;
  renderPaths();
});
document.getElementById("risk-filter").addEventListener("change", (event) => {
  state.filters.risk = event.target.value;
  renderPaths();
});
document.getElementById("sort-by").addEventListener("change", (event) => {
  state.filters.sort = event.target.value;
  renderPaths();
});
document.getElementById("actionable-filter").addEventListener("change", (event) => {
  state.filters.actionable = event.target.checked;
  renderPaths();
});

document.getElementById("toggle-labels").addEventListener("change", (event) => {
  state.showLabels = event.target.checked;
  applyLabelVisibility();
});
document.getElementById("toggle-full-graph").addEventListener("change", (event) => {
  state.showFullGraph = event.target.checked;
  renderGraph();
});

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => activateTab(tab.dataset.tab));
});

document.addEventListener("keydown", (event) => {
  const target = event.target;
  const typing = target instanceof HTMLInputElement || target instanceof HTMLSelectElement;
  if (event.key === "/" && !typing) {
    event.preventDefault();
    document.getElementById("search").focus();
    return;
  }
  if (event.key === "Escape") {
    if (typing) target.blur();
    clearSelection();
    return;
  }
  if (typing) return;
  if (event.key === "ArrowDown") {
    event.preventDefault();
    moveSelection(1);
  } else if (event.key === "ArrowUp") {
    event.preventDefault();
    moveSelection(-1);
  } else if (event.key === "Enter" && state.activePathId) {
    event.preventDefault();
    activateTab("graph");
  }
});

window.addEventListener("resize", () => requestAnimationFrame(resizeGraph));

initializeSplitter();
bootstrap(false);
