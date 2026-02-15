(function () {
    "use strict";

    const state = {
        target: "",
        loading: false,
        modules: [],
        moduleQuery: "",
        selectedModuleId: null,
        selectedNodeId: null,
        selectedEdgeId: null,
        linkSourceId: null,
        activityLog: [],
        physicsEnabled: true,
    };

    const nodes = new vis.DataSet([]);
    const edges = new vis.DataSet([]);
    let network = null;

    const entityAliasMap = new Map();
    const ENTITY_GROUPS = new Set(["target", "domain", "subdomain", "ip", "email", "hostname", "fqdn"]);
    const emailRx = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const ipRx = /^(?:\d{1,3}\.){3}\d{1,3}$/;
    const fqdnRx = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\.?$/i;

    const basePhysics = {
        enabled: true,
        stabilization: false,
        barnesHut: {
            gravitationalConstant: -3100,
            centralGravity: 0.23,
            springLength: 165,
            springConstant: 0.035,
            damping: 0.87,
        },
    };

    function byId(id) {
        return document.getElementById(id);
    }

    const el = {
        targetInput: byId("targetInput"),
        runAllBtn: byId("runAllBtn"),
        moduleUnits: byId("moduleUnits"),
        moduleSearch: byId("moduleSearch"),
        modulesEmpty: byId("modulesEmpty"),
        modulesList: byId("modulesList"),
        logsList: byId("logsList"),
        metricNodes: byId("metricNodes"),
        metricEdges: byId("metricEdges"),
        metricStatus: byId("metricStatus"),
        loadingOverlay: byId("loadingOverlay"),
        network: byId("network"),
        focusBtn: byId("focusBtn"),
        clearBtn: byId("clearBtn"),
        physicsBtn: byId("physicsBtn"),
        exportBtn: byId("exportBtn"),
        linkModeBanner: byId("linkModeBanner"),
        linkModeSource: byId("linkModeSource"),
        inspectorEmpty: byId("inspectorEmpty"),
        nodeSection: byId("nodeSection"),
        edgeSection: byId("edgeSection"),
        nodeLabel: byId("nodeLabel"),
        nodeId: byId("nodeId"),
        nodeGroup: byId("nodeGroup"),
        nodeMeta: byId("nodeMeta"),
        pivotBtn: byId("pivotBtn"),
        linkRelationInput: byId("linkRelationInput"),
        startLinkBtn: byId("startLinkBtn"),
        cancelLinkBtn: byId("cancelLinkBtn"),
        purgeNodeBtn: byId("purgeNodeBtn"),
        edgeLabel: byId("edgeLabel"),
        edgeFrom: byId("edgeFrom"),
        edgeTo: byId("edgeTo"),
        deleteEdgeBtn: byId("deleteEdgeBtn"),
        manualNodeLabel: byId("manualNodeLabel"),
        manualNodeGroup: byId("manualNodeGroup"),
        injectNodeBtn: byId("injectNodeBtn"),
    };

    function normalizeEntityToken(value) {
        let v = (value || "").toString().trim();
        if (!v) return "";

        if (/^https?:\/\//i.test(v)) {
            try {
                v = new URL(v).hostname || v;
            } catch (_err) {
                // ignore malformed url
            }
        }

        v = v.split("/")[0];
        if (v.includes(":") && !v.includes("@") && !v.includes(" ")) {
            const portIdx = v.lastIndexOf(":");
            const maybePort = v.slice(portIdx + 1);
            if (/^\d+$/.test(maybePort)) {
                v = v.slice(0, portIdx);
            }
        }

        return v.toLowerCase().replace(/\.$/, "");
    }

    function looksLikeEntity(value, group) {
        const v = (value || "").toString().trim();
        const g = (group || "").toString().trim().toLowerCase();
        if (ENTITY_GROUPS.has(g)) return true;
        return emailRx.test(v) || ipRx.test(v) || fqdnRx.test(v);
    }

    function resolveNodeIdentity(node) {
        const rawId = (node && node.id !== undefined ? node.id : "").toString().trim();
        const rawLabel = (node && node.label !== undefined ? node.label : "").toString().trim();
        const group = (node && node.group ? node.group : "").toString().trim().toLowerCase();
        const seed = rawLabel || rawId;

        if (!seed) return { id: "", key: "", label: "" };
        if (!looksLikeEntity(seed, group)) return { id: rawId || seed, key: "", label: rawLabel || seed };

        const key = normalizeEntityToken(seed);
        if (entityAliasMap.has(key)) {
            const canonical = entityAliasMap.get(key);
            return { id: canonical, key: key, label: rawLabel || canonical };
        }

        entityAliasMap.set(key, key);
        if (rawId) {
            const idKey = normalizeEntityToken(rawId);
            if (idKey) entityAliasMap.set(idKey, key);
        }
        return { id: key, key: key, label: rawLabel || key };
    }

    function resolveEdgeEndpoint(value) {
        const raw = (value || "").toString().trim();
        if (!raw) return "";
        const key = normalizeEntityToken(raw);
        if (entityAliasMap.has(key)) return entityAliasMap.get(key);
        if (nodes.get(key)) return key;
        if (nodes.get(raw)) return raw;
        return raw;
    }

    function getNodeStyle(group) {
        const map = {
            target: { background: "#ffffff", border: "#31c6ff" },
            domain: { background: "#31c6ff", border: "#1a4f66" },
            ip: { background: "#2680eb", border: "#15417a" },
            email: { background: "#818cf8", border: "#4338ca" },
            subdomain: { background: "#f59e0b", border: "#b45309" },
            registrar: { background: "#94a3b8", border: "#475569" },
            generic: { background: "#64748b", border: "#334155" },
        };
        return map[group] || map.generic;
    }

    function buildNodeTitle(node) {
        const info = node.custom_info ? '<div style="margin-top:4px;color:#cbd5e1">' + escapeHtml(node.custom_info) + "</div>" : "";
        return (
            '<div style="font-family:\'JetBrains Mono\',monospace;font-size:12px;padding:4px">' +
            "<strong>" + escapeHtml(node.label || node.id || "") + "</strong>" +
            '<div style="color:#94a3b8">' + escapeHtml(node.group || "generic") + "</div>" +
            info +
            "</div>"
        );
    }

    function buildEdgeTitle(edge) {
        const label = edge.label || "relation";
        const info = edge.custom_info ? '<div style="margin-top:4px;color:#cbd5e1">' + escapeHtml(edge.custom_info) + "</div>" : "";
        return (
            '<div style="font-family:\'JetBrains Mono\',monospace;font-size:12px;padding:4px">' +
            "<strong>" + escapeHtml(label) + "</strong>" +
            '<div style="color:#94a3b8">' + escapeHtml(edge.from + " -> " + edge.to) + "</div>" +
            info +
            "</div>"
        );
    }

    function addNodeSafe(node) {
        if (!node) return;
        const resolved = resolveNodeIdentity(node);
        if (!resolved.id) return;

        const group = (node.group || "generic").toString().toLowerCase();
        const style = getNodeStyle(group);
        const payload = {
            id: resolved.id,
            label: resolved.label,
            group: group,
            custom_info: node.custom_info || "",
            shape: "dot",
            size: group === "target" ? 32 : 16,
            color: {
                background: style.background,
                border: style.border,
                highlight: { background: "#fff", border: "#31c6ff" },
            },
            borderWidth: 2,
            font: { color: "#e2e8f0", face: "Outfit", size: 14, strokeWidth: 0, strokeColor: "transparent" },
            shadow: { enabled: true, color: "rgba(0,0,0,0.5)", size: 10, x: 0, y: 4 },
        };
        payload.title = buildNodeTitle(payload);

        const current = nodes.get(payload.id);
        if (current) {
            nodes.update({
                id: payload.id,
                label: payload.label,
                group: payload.group,
                custom_info: payload.custom_info || current.custom_info,
                title: payload.title,
            });
        } else {
            nodes.add(payload);
        }
    }

    function edgeDisplayLabel(rawLabel) {
        const text = (rawLabel || "").toString().replace(/_/g, " ").trim();
        return text.toUpperCase();
    }

    function addEdgeSafe(edge) {
        if (!edge || !edge.from || !edge.to) return;
        const fromId = resolveEdgeEndpoint(edge.from);
        const toId = resolveEdgeEndpoint(edge.to);
        if (!fromId || !toId) return;

        const rawLabel = (edge.raw_label !== undefined ? edge.raw_label : edge.label || "").toString().trim().toUpperCase();
        const label = edgeDisplayLabel(rawLabel);
        const edgeId = fromId + "->" + toId + "->" + rawLabel;
        if (edges.get(edgeId)) return;

        edges.add({
            id: edgeId,
            from: fromId,
            to: toId,
            raw_label: rawLabel,
            label: label,
            custom_info: edge.custom_info || "",
            width: 1.5,
            color: { color: "rgba(49, 198, 255, 0.35)", highlight: "#31c6ff", hover: "#fff" },
            arrows: { to: { enabled: true, scaleFactor: 0.4 } },
            smooth: { type: "cubicBezier", forceDirection: "none", roundness: 0.35 },
            shadow: { enabled: false },
            labelHighlightBold: true,
            font: {
                size: 11,
                color: "#cbd5e1",
                face: "JetBrains Mono",
                strokeWidth: 0,
                strokeColor: "transparent",
                align: "middle",
                vadjust: -10,
            },
            title: buildEdgeTitle({ from: fromId, to: toId, label: label, custom_info: edge.custom_info || "" }),
        });
    }

    function removeNodeAndAttachedEdges(nodeId) {
        if (!nodeId) return;
        const edgeIds = edges.get().filter(function (e) { return e.from === nodeId || e.to === nodeId; }).map(function (e) { return e.id; });
        if (edgeIds.length) edges.remove(edgeIds);
        nodes.remove(nodeId);
    }

    function setLoading(flag) {
        state.loading = !!flag;
        el.loadingOverlay.style.display = state.loading ? "flex" : "none";
        el.metricStatus.textContent = state.loading ? "ACTIVE" : "IDLE";
    }

    function pushActivity(moduleName, targetValue, errorText) {
        const now = new Date();
        state.activityLog.unshift({
            id: String(Date.now()) + "-" + String(Math.random()),
            module: moduleName || "SYSTEM",
            target: targetValue || "",
            error: errorText || "",
            time: now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
        });
        if (state.activityLog.length > 80) state.activityLog = state.activityLog.slice(0, 80);
        renderLogs();
        refreshCounters();
    }

    function refreshCounters() {
        el.metricNodes.textContent = String(nodes.length);
        el.metricEdges.textContent = String(edges.length);
        if (!state.loading) {
            el.metricStatus.textContent = state.activityLog.length > 0 ? "ACTIVE" : "IDLE";
        }
    }

    function renderLogs() {
        if (!state.activityLog.length) {
            el.logsList.innerHTML = '<div style="color: var(--text-dim);">No operational logs.</div>';
            return;
        }
        el.logsList.innerHTML = state.activityLog.map(function (log) {
            const msg = log.error ? "Error: " + log.error : "Ran " + log.module + " on " + log.target;
            return '<div class="feed-item"><span class="feed-time">[' + escapeHtml(log.time) + ']</span><span class="feed-msg">' + escapeHtml(msg) + "</span></div>";
        }).join("");
    }

    function filteredModules() {
        const q = (state.moduleQuery || "").trim().toLowerCase();
        if (!q) return state.modules;
        return state.modules.filter(function (m) {
            const hay = ((m.name || "") + " " + (m.desc || "") + " " + (m.id || "")).toLowerCase();
            return hay.indexOf(q) !== -1;
        });
    }

    function renderModules() {
        const list = filteredModules();
        el.moduleUnits.textContent = String(state.modules.length) + " Units";
        el.modulesEmpty.style.display = list.length ? "none" : "block";
        el.modulesList.innerHTML = "";

        list.forEach(function (mod) {
            const card = document.createElement("div");
            card.className = "mod-card" + (state.selectedModuleId === mod.id ? " active" : "");

            const header = document.createElement("div");
            header.className = "mod-header";
            if ((mod.type || "").toLowerCase() === "pro") {
                const badge = document.createElement("span");
                badge.className = "pro-badge";
                badge.textContent = "PRO";
                header.appendChild(badge);
            }

            const name = document.createElement("div");
            name.className = "mod-name";
            name.textContent = mod.name || mod.id || "module";

            const desc = document.createElement("div");
            desc.className = "mod-desc";
            desc.textContent = mod.desc || "";

            const runBtn = document.createElement("button");
            runBtn.className = "module-run-btn";
            runBtn.textContent = "Run";
            runBtn.addEventListener("click", function (event) {
                event.stopPropagation();
                state.selectedModuleId = mod.id;
                renderModules();
                runTransform(mod.id);
            });

            card.addEventListener("click", function () {
                state.selectedModuleId = mod.id;
                renderModules();
            });

            card.appendChild(header);
            card.appendChild(name);
            card.appendChild(desc);
            card.appendChild(runBtn);
            el.modulesList.appendChild(card);
        });
    }

    function setSelectedNode(node) {
        state.selectedNodeId = node ? node.id : null;
        state.selectedEdgeId = null;
        if (!node) {
            el.nodeSection.style.display = "none";
            el.edgeSection.style.display = "none";
            el.inspectorEmpty.style.display = "block";
            return;
        }

        el.inspectorEmpty.style.display = "none";
        el.edgeSection.style.display = "none";
        el.nodeSection.style.display = "grid";
        el.nodeLabel.textContent = node.label || node.id || "";
        el.nodeId.textContent = node.id || "";
        el.nodeGroup.textContent = node.group || "unknown";
        el.nodeMeta.textContent = node.custom_info || "None";
    }

    function setSelectedEdge(edge) {
        state.selectedEdgeId = edge ? edge.id : null;
        state.selectedNodeId = null;
        if (!edge) {
            el.nodeSection.style.display = "none";
            el.edgeSection.style.display = "none";
            el.inspectorEmpty.style.display = "block";
            return;
        }

        el.inspectorEmpty.style.display = "none";
        el.nodeSection.style.display = "none";
        el.edgeSection.style.display = "grid";
        el.edgeLabel.textContent = edge.label || "relation";
        const fromNode = nodes.get(edge.from);
        const toNode = nodes.get(edge.to);
        el.edgeFrom.textContent = (fromNode && (fromNode.label || fromNode.id)) || edge.from || "";
        el.edgeTo.textContent = (toNode && (toNode.label || toNode.id)) || edge.to || "";
    }

    function setLinkMode(sourceId) {
        state.linkSourceId = sourceId || null;
        if (state.linkSourceId) {
            const node = nodes.get(state.linkSourceId);
            el.linkModeSource.textContent = (node && (node.label || node.id)) || state.linkSourceId;
            el.linkModeBanner.style.display = "block";
            el.cancelLinkBtn.disabled = false;
        } else {
            el.linkModeSource.textContent = "";
            el.linkModeBanner.style.display = "none";
            el.cancelLinkBtn.disabled = true;
        }
    }

    async function fetchModules() {
        const res = await fetch("/api/modules");
        const data = await res.json();
        state.modules = Array.isArray(data) ? data : [];
        renderModules();
    }

    async function runTransform(moduleId) {
        const target = normalizeEntityToken(el.targetInput.value || state.target);
        if (!target) return;

        state.target = target;
        setLoading(true);
        addNodeSafe({ id: target, label: target, group: "target" });

        try {
            const modulesToRun = moduleId === "all"
                ? state.modules.map(function (m) { return m.id; })
                : [moduleId];

            for (const mId of modulesToRun) {
                const response = await fetch("/api/transform", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ module: mId, target: target }),
                });
                const data = await response.json();

                if (data && data.graph) {
                    if (Array.isArray(data.graph.nodes)) data.graph.nodes.forEach(addNodeSafe);
                    if (Array.isArray(data.graph.edges)) data.graph.edges.forEach(addEdgeSafe);
                }

                pushActivity(mId, target, data && data.error ? data.error : "");
            }
        } catch (err) {
            pushActivity("ERROR", target, err && err.message ? err.message : "Unknown error");
        } finally {
            setLoading(false);
            refreshCounters();
            fitGraph();
        }
    }

    function initGraph() {
        network = new vis.Network(
            el.network,
            { nodes: nodes, edges: edges },
            {
                autoResize: true,
                physics: basePhysics,
                interaction: {
                    hover: true,
                    hoverConnectedEdges: true,
                    tooltipDelay: 150,
                    navigationButtons: false,
                    keyboard: true,
                },
                edges: { selectionWidth: 2.2 },
            }
        );

        nodes.on("*", refreshCounters);
        edges.on("*", refreshCounters);

        network.on("click", function (params) {
            if (params.nodes && params.nodes.length) {
                const nodeId = params.nodes[0];
                const clickedNode = nodes.get(nodeId) || null;

                if (state.linkSourceId && clickedNode && clickedNode.id !== state.linkSourceId) {
                    const relation = (el.linkRelationInput.value || "related_to").trim();
                    addEdgeSafe({
                        from: state.linkSourceId,
                        to: clickedNode.id,
                        label: relation,
                        custom_info: "Manual Link",
                    });
                    pushActivity("MANUAL", state.linkSourceId + " -> " + clickedNode.id + " (" + relation + ")", "");
                    setLinkMode(null);
                }

                setSelectedNode(clickedNode);
                return;
            }

            if (params.edges && params.edges.length) {
                const edgeId = params.edges[0];
                setSelectedEdge(edges.get(edgeId) || null);
                return;
            }

            setSelectedNode(null);
        });

        refreshCounters();
    }

    function fitGraph() {
        if (!network) return;
        network.fit({
            animation: {
                duration: 600,
                easingFunction: "easeInOutQuad",
            },
        });
    }

    function clearGraph() {
        nodes.clear();
        edges.clear();
        entityAliasMap.clear();
        state.selectedNodeId = null;
        state.selectedEdgeId = null;
        state.linkSourceId = null;
        state.activityLog = [];
        setSelectedNode(null);
        setLinkMode(null);
        renderLogs();
        refreshCounters();
        pushActivity("SYSTEM", "Graph Memory Purged", "");
    }

    function injectNode() {
        const label = (el.manualNodeLabel.value || "").trim();
        if (!label) return;
        const group = (el.manualNodeGroup.value || "generic").trim().toLowerCase();
        const id = normalizeEntityToken(label) || label.toLowerCase().replace(/[^a-z0-9]/g, "_");

        addNodeSafe({
            id: id,
            label: label,
            group: group,
            custom_info: "Manual Entry",
        });
        pushActivity("MANUAL", "Node injected: " + label, "");
        el.manualNodeLabel.value = "";
        refreshCounters();
    }

    function pivotFromSelected() {
        if (!state.selectedNodeId) return;
        const node = nodes.get(state.selectedNodeId);
        if (!node) return;
        el.targetInput.value = node.label || node.id || "";
        runTransform("all");
    }

    function startLinkFromSelected() {
        if (!state.selectedNodeId) return;
        setLinkMode(state.selectedNodeId);
    }

    function deleteSelectedEdge() {
        if (!state.selectedEdgeId) return;
        const edge = edges.get(state.selectedEdgeId);
        edges.remove(state.selectedEdgeId);
        setSelectedEdge(null);
        pushActivity("MANUAL", "Relation removed: " + ((edge && edge.label) || "relation"), "");
    }

    function purgeSelectedNode() {
        if (!state.selectedNodeId) return;
        const node = nodes.get(state.selectedNodeId);
        removeNodeAndAttachedEdges(state.selectedNodeId);
        setSelectedNode(null);
        pushActivity("MANUAL", "Entity purged: " + ((node && (node.label || node.id)) || state.selectedNodeId), "");
    }

    function togglePhysics() {
        state.physicsEnabled = !state.physicsEnabled;
        if (network) {
            network.setOptions({ physics: Object.assign({}, basePhysics, { enabled: state.physicsEnabled }) });
        }
        el.physicsBtn.textContent = state.physicsEnabled ? "Freeze" : "Release";
    }

    function exportGraph() {
        const payload = {
            version: 2,
            exported_at: new Date().toISOString(),
            nodes: nodes.get(),
            edges: edges.get(),
        };
        const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "nexus_export_" + Date.now() + ".json";
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
    }

    function escapeHtml(text) {
        return String(text)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    function bindEvents() {
        el.runAllBtn.addEventListener("click", function () { runTransform("all"); });
        el.targetInput.addEventListener("keydown", function (event) {
            if (event.key === "Enter") runTransform("all");
        });
        el.moduleSearch.addEventListener("input", function () {
            state.moduleQuery = el.moduleSearch.value || "";
            renderModules();
        });

        el.focusBtn.addEventListener("click", fitGraph);
        el.clearBtn.addEventListener("click", clearGraph);
        el.physicsBtn.addEventListener("click", togglePhysics);
        el.exportBtn.addEventListener("click", exportGraph);

        el.injectNodeBtn.addEventListener("click", injectNode);
        el.pivotBtn.addEventListener("click", pivotFromSelected);
        el.startLinkBtn.addEventListener("click", startLinkFromSelected);
        el.cancelLinkBtn.addEventListener("click", function () { setLinkMode(null); });
        el.purgeNodeBtn.addEventListener("click", purgeSelectedNode);
        el.deleteEdgeBtn.addEventListener("click", deleteSelectedEdge);
    }

    async function init() {
        initGraph();
        bindEvents();
        renderLogs();
        renderModules();
        setSelectedNode(null);
        setLinkMode(null);
        await fetchModules();
    }

    document.addEventListener("DOMContentLoaded", function () {
        init().catch(function (err) {
            console.error("KittyOSINT init failed:", err);
        });
    });
})();
