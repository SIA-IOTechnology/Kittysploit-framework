(function () {
    "use strict";

    const state = {
        target: "",
        loading: false,
        modules: [],
        moduleQuery: "",
        targetInputValue: "",
        selectedModuleId: null,
        selectedNodeId: null,
        selectedEdgeId: null,
        linkSourceId: null,
        activityLog: [],
        physicsEnabled: true,
        denseMode: false,
        visualUpdating: false,
        renderingGraphView: false,
        viewMode: "overview",
        layoutMode: "detailed",
        pivotSourceId: null,
        radialPinned: false,
        radialArcSpacing: 74,
        radialRingSpacing: 180,
        lastModuleOutput: null,
        groupClustersEnabled: false,
        activeClusterIds: [],
        expandedClusterId: null,
        expandedGroupName: null,
        subsetBubbleNodeId: null,
        expandedCategory: null,
        categoryExpandLimit: 42,
        criticalNodeLimit: 18,
    };

    const nodes = new vis.DataSet([]);
    const edges = new vis.DataSet([]);
    const rawNodes = new Map();
    const rawEdges = new Map();
    let network = null;

    const entityAliasMap = new Map();
    const ENTITY_GROUPS = new Set(["target", "domain", "subdomain", "ip", "email", "hostname", "fqdn"]);
    const emailRx = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const ipRx = /^(?:\d{1,3}\.){3}\d{1,3}$/;
    const fqdnRx = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\.?$/i;

    const CATEGORY_ORDER = [
        "risk",
        "secret",
        "credential",
        "exposure",
        "cloud",
        "storage",
        "endpoint",
        "domain",
        "subdomain",
        "ip",
        "email",
        "identity",
        "organization",
        "technology",
        "service",
        "generic",
    ];
    const CATEGORY_LABELS = {
        risk: "Risk",
        secret: "Secrets",
        credential: "Credentials",
        exposure: "Exposures",
        cloud: "Cloud",
        storage: "Storage",
        endpoint: "Endpoints",
        domain: "Domains",
        subdomain: "Subdomains",
        ip: "IPs",
        email: "Emails",
        identity: "Identities",
        organization: "Organizations",
        technology: "Tech",
        service: "Services",
        generic: "Other",
    };
    const CATEGORY_ALIASES = {
        bucket: "storage",
        blob: "storage",
        container: "storage",
        gcs: "storage",
        s3: "storage",
        azure: "cloud",
        aws: "cloud",
        gcp: "cloud",
        kubernetes: "cloud",
        url: "endpoint",
        uri: "endpoint",
        api: "endpoint",
        path: "endpoint",
        hostname: "subdomain",
        fqdn: "subdomain",
        nameserver: "domain",
        registrar: "domain",
        person: "identity",
        account: "identity",
        handle: "identity",
        user: "identity",
        org: "organization",
        company: "organization",
        repository: "technology",
        repo: "technology",
        package: "technology",
        secret_leak: "secret",
        api_key: "secret",
        token: "secret",
        password: "credential",
        login: "credential",
        vulnerability: "risk",
        takeover: "risk",
        misconfiguration: "exposure",
        misconfig: "exposure",
    };
    const CRITICAL_CATEGORIES = new Set(["risk", "secret", "credential", "exposure"]);

    const basePhysics = {
        enabled: true,
        stabilization: false,
        barnesHut: {
            gravitationalConstant: -3100,
            centralGravity: 0.23,
            springLength: 165,
            springConstant: 0.035,
            damping: 0.87,
            avoidOverlap: 0.85,
        },
    };

    const compactPhysics = {
        enabled: true,
        stabilization: false,
        barnesHut: {
            gravitationalConstant: -5200,
            centralGravity: 0.12,
            springLength: 245,
            springConstant: 0.028,
            damping: 0.9,
            avoidOverlap: 1,
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
        clusterBtn: byId("clusterBtn"),
        densityBtn: byId("densityBtn"),
        radialBtn: byId("radialBtn"),
        layoutControls: byId("layoutControls"),
        arcSpacingRange: byId("arcSpacingRange"),
        arcSpacingValue: byId("arcSpacingValue"),
        ringSpacingRange: byId("ringSpacingRange"),
        ringSpacingValue: byId("ringSpacingValue"),
        physicsBtn: byId("physicsBtn"),
        exportBtn: byId("exportBtn"),
        linkModeBanner: byId("linkModeBanner"),
        linkModeSource: byId("linkModeSource"),
        inspectorEmpty: byId("inspectorEmpty"),
        categorySection: byId("categorySection"),
        categoryLabel: byId("categoryLabel"),
        categorySummary: byId("categorySummary"),
        categoryMembers: byId("categoryMembers"),
        expandCategoryBtn: byId("expandCategoryBtn"),
        collapseCategoryBtn: byId("collapseCategoryBtn"),
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
        edgeMeta: byId("edgeMeta"),
        rawModuleMeta: byId("rawModuleMeta"),
        rawModuleBody: byId("rawModuleBody"),
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

    function normalizeExecutionTarget(value) {
        const raw = (value || "").toString().trim();
        if (!raw) return "";
        if (/^https?:\/\//i.test(raw)) return raw;
        if (raw.indexOf("@") !== -1 && emailRx.test(raw)) return raw.toLowerCase();
        return normalizeEntityToken(raw);
    }

    function classifyTargetInput(value) {
        const raw = (value || "").toString().trim();
        if (!raw) return "empty";
        if (/^https?:\/\//i.test(raw)) return "url";
        if (emailRx.test(raw)) return "email";
        if (ipRx.test(raw)) return "ip";
        if (fqdnRx.test(raw)) return "domain";
        return "keyword";
    }

    function extractPivotCandidate(text) {
        const raw = (text || "").toString().trim();
        if (!raw) return "";

        const urlMatch = raw.match(/https?:\/\/[^\s<>"']+/i);
        if (urlMatch) return urlMatch[0];

        const emailMatch = raw.match(/[^\s@]+@[^\s@]+\.[^\s@]+/);
        if (emailMatch) return emailMatch[0];

        const ipMatch = raw.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
        if (ipMatch) return ipMatch[0];

        const domainMatch = raw.match(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/i);
        if (domainMatch) return domainMatch[0];

        return "";
    }

    function derivePivotTarget(node) {
        if (!node || node.synthetic || node.is_category || node.is_more) return "";
        const candidates = [
            node.full_label,
            node.label,
            node.id,
            node.raw_node_id,
            node.custom_info,
        ];
        for (let i = 0; i < candidates.length; i += 1) {
            const candidate = extractPivotCandidate(candidates[i]);
            if (candidate) return candidate;
        }
        return "";
    }

    function canPivotNode(node) {
        return !!derivePivotTarget(node);
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
        if (rawNodes.has(key)) return key;
        if (rawNodes.has(raw)) return raw;
        if (nodes.get(key)) return key;
        if (nodes.get(raw)) return raw;
        return raw;
    }

    function getNodeStyle(group) {
        const map = {
            target: { background: "#ffffff", border: "#31c6ff" },
            category: { background: "#172033", border: "#31c6ff" },
            category_more: { background: "#1e293b", border: "#64748b" },
            subset_container: { background: "#172033", border: "#31c6ff" },
            domain: { background: "#31c6ff", border: "#1a4f66" },
            ip: { background: "#2680eb", border: "#15417a" },
            email: { background: "#818cf8", border: "#4338ca" },
            subdomain: { background: "#f59e0b", border: "#b45309" },
            registrar: { background: "#94a3b8", border: "#475569" },
            risk: { background: "#f43f5e", border: "#be123c" },
            secret: { background: "#fb7185", border: "#be123c" },
            credential: { background: "#f97316", border: "#c2410c" },
            exposure: { background: "#facc15", border: "#a16207" },
            cloud: { background: "#38bdf8", border: "#0369a1" },
            storage: { background: "#22c55e", border: "#15803d" },
            endpoint: { background: "#14b8a6", border: "#0f766e" },
            identity: { background: "#a78bfa", border: "#6d28d9" },
            organization: { background: "#e879f9", border: "#a21caf" },
            technology: { background: "#60a5fa", border: "#1d4ed8" },
            service: { background: "#2dd4bf", border: "#0f766e" },
            generic: { background: "#64748b", border: "#334155" },
        };
        return map[group] || map.generic;
    }

    function truncateLabel(text, maxLen) {
        const t = (text || "").toString();
        if (t.length <= maxLen) return t;
        return t.slice(0, Math.max(3, maxLen - 3)) + "...";
    }

    function shouldKeepNodeLabelInDenseMode(group, nodeId) {
        // Always keep node labels visible; density is handled by layout + truncation.
        return true;
    }

    function shouldKeepEdgeLabelInDenseMode(rawLabel) {
        const r = (rawLabel || "").toString().toLowerCase();
        return r.indexOf("risk") !== -1 || r.indexOf("takeover") !== -1 || r.indexOf("exposure") !== -1;
    }

    function computeNodeDegrees() {
        const deg = new Map();
        nodes.getIds().forEach(function (id) { deg.set(id, 0); });
        edges.get().forEach(function (e) {
            deg.set(e.from, (deg.get(e.from) || 0) + 1);
            deg.set(e.to, (deg.get(e.to) || 0) + 1);
        });
        return deg;
    }

    function refreshVisualDensity() {
        if (state.visualUpdating) return;
        state.visualUpdating = true;
        try {
            const dense = state.layoutMode === "compact" || state.layoutMode === "radial" || nodes.length >= 45 || edges.length >= 70;
            state.denseMode = dense;
            const degree = computeNodeDegrees();

            const nodeUpdates = [];
            nodes.get().forEach(function (n) {
                const full = n.full_label || n.label || n.id || "";
                const keepLabel = n.is_category || n.is_more || !dense || shouldKeepNodeLabelInDenseMode(n.group, n.id);
                const display = keepLabel ? truncateLabel(full, n.is_category ? 28 : (dense ? 20 : 42)) : "";
                const g = (n.group || "generic").toLowerCase();
                const d = degree.get(n.id) || 0;
                let size = 14;
                if (n.is_category) size = n.size || Math.max(28, Math.min(52, 22 + (n.member_count || 0) * 1.1));
                else if (n.is_more) size = n.size || 24;
                else if (g === "target") size = 34;
                else if (g === "risk") size = 22;
                else size = Math.max(11, Math.min(22, 11 + d * 0.8));
                nodeUpdates.push({
                    id: n.id,
                    full_label: full,
                    label: display,
                    size: size,
                    font: {
                        color: n.font && n.font.color ? n.font.color : "#e2e8f0",
                        face: n.font && n.font.face ? n.font.face : "Outfit",
                        size: n.is_category ? 13 : (dense ? 11 : 14),
                        strokeWidth: 0,
                        strokeColor: "transparent",
                    },
                    title: buildNodeTitle({
                        label: full,
                        id: n.id,
                        group: n.group,
                        custom_info: n.custom_info || "",
                    }),
                });
            });
            if (nodeUpdates.length) nodes.update(nodeUpdates);

            const edgeUpdates = [];
            edges.get().forEach(function (e) {
                const raw = (e.raw_label || e.label || "").toString();
                const pretty = edgeDisplayLabel(raw);
                const keepLabel = !dense || shouldKeepEdgeLabelInDenseMode(raw);
                edgeUpdates.push({
                    id: e.id,
                    raw_label: raw,
                    label: keepLabel ? pretty : "",
                    title: buildEdgeTitle({
                        from: e.from,
                        to: e.to,
                        label: pretty,
                        custom_info: e.custom_info || "",
                    }),
                });
            });
            if (edgeUpdates.length) edges.update(edgeUpdates);
        } finally {
            state.visualUpdating = false;
        }
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

    function serializeForInspector(value) {
        if (value === undefined || value === null) return "";
        if (typeof value === "string") return value;
        try {
            return JSON.stringify(value, null, 2);
        } catch (_err) {
            return String(value);
        }
    }

    function enrichNodeCustomInfo(node) {
        if (!node) return "";
        if (node.custom_info && String(node.custom_info).trim()) return String(node.custom_info);
        const extra = {};
        const ignore = new Set([
            "id", "label", "group", "icon", "x", "y", "shape", "size", "color",
            "borderWidth", "font", "shadow", "full_label", "title", "fixed",
        ]);
        Object.keys(node).forEach(function (k) {
            if (ignore.has(k)) return;
            if (node[k] === undefined || node[k] === null || node[k] === "") return;
            extra[k] = node[k];
        });
        if (!Object.keys(extra).length) return "No extended metadata";
        return serializeForInspector(extra);
    }

    function enrichEdgeCustomInfo(edge) {
        if (!edge) return "";
        if (edge.custom_info && String(edge.custom_info).trim()) return String(edge.custom_info);
        const extra = {};
        const ignore = new Set([
            "id", "from", "to", "label", "raw_label", "title", "width", "color",
            "arrows", "smooth", "shadow", "labelHighlightBold", "font",
        ]);
        Object.keys(edge).forEach(function (k) {
            if (ignore.has(k)) return;
            if (edge[k] === undefined || edge[k] === null || edge[k] === "") return;
            extra[k] = edge[k];
        });
        if (!Object.keys(extra).length) return "No extended metadata";
        return serializeForInspector(extra);
    }

    function renderLastModuleOutput() {
        if (!el.rawModuleMeta || !el.rawModuleBody) return;
        if (!state.lastModuleOutput) {
            el.rawModuleMeta.textContent = "No module output yet";
            el.rawModuleBody.textContent = "";
            return;
        }
        const meta = state.lastModuleOutput.meta || {};
        const moduleName = meta.module || "unknown";
        const ts = meta.timestamp || "";
        el.rawModuleMeta.textContent = moduleName + (ts ? " @ " + ts : "");
        el.rawModuleBody.textContent = serializeForInspector(state.lastModuleOutput.raw || {});
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
            label: truncateLabel(resolved.label, 42),
            full_label: resolved.label,
            group: group,
            custom_info: enrichNodeCustomInfo(node),
            raw_node_id: node.raw_node_id || resolved.id,
            is_category: !!node.is_category,
            is_more: !!node.is_more,
            synthetic: !!node.synthetic,
            category: node.category || "",
            member_count: Number(node.member_count || 0),
            more_count: Number(node.more_count || 0),
            shape: "dot",
            size: group === "target" ? 32 : 15,
            color: {
                background: node.color && node.color.background ? node.color.background : style.background,
                border: node.color && node.color.border ? node.color.border : style.border,
                highlight: node.color && node.color.highlight ? node.color.highlight : { background: "#fff", border: "#31c6ff" },
            },
            borderWidth: 2,
            font: { color: "#e2e8f0", face: "Outfit", size: 14, strokeWidth: 0, strokeColor: "transparent" },
            shadow: { enabled: true, color: "rgba(0,0,0,0.5)", size: 10, x: 0, y: 4 },
        };
        if (typeof node.x === "number" && typeof node.y === "number") {
            payload.x = node.x;
            payload.y = node.y;
            payload.fixed = false;
        }
        payload.title = buildNodeTitle(payload);

        const current = nodes.get(payload.id);
        if (current) {
            nodes.update({
                id: payload.id,
                label: payload.label,
                full_label: payload.full_label || current.full_label || payload.label,
                group: payload.group,
                custom_info: payload.custom_info || current.custom_info,
                raw_node_id: payload.raw_node_id || current.raw_node_id,
                is_category: payload.is_category,
                is_more: payload.is_more,
                synthetic: payload.synthetic,
                category: payload.category || current.category || "",
                member_count: payload.member_count || current.member_count || 0,
                more_count: payload.more_count || current.more_count || 0,
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
        const edgeId = edge.id || (fromId + "->" + toId + "->" + rawLabel);
        if (edges.get(edgeId)) return;

        edges.add({
            id: edgeId,
            from: fromId,
            to: toId,
            raw_label: rawLabel,
            label: label,
            raw_edge_id: edge.raw_edge_id || edge.id || edgeId,
            synthetic: !!edge.synthetic,
            category: edge.category || "",
            custom_info: enrichEdgeCustomInfo(edge),
            width: edge.width || 1.5,
            color: edge.color || { color: "rgba(49, 198, 255, 0.35)", highlight: "#31c6ff", hover: "#fff" },
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

    function inferGroupFromValue(value) {
        const v = (value || "").toString().trim();
        if (!v) return "generic";
        if (emailRx.test(v)) return "email";
        if (ipRx.test(v)) return "ip";
        if (/^https?:\/\//i.test(v) || v.indexOf("/") !== -1) return "endpoint";
        if (fqdnRx.test(v)) return "subdomain";
        return "generic";
    }

    function canonicalCategoryName(group) {
        const g = (group || "generic").toString().trim().toLowerCase().replace(/[^a-z0-9_:-]+/g, "_");
        if (!g) return "generic";
        if (g === "target") return "target";
        if (CATEGORY_ALIASES[g]) return CATEGORY_ALIASES[g];
        if (CATEGORY_LABELS[g]) return g;
        if (g.indexOf("secret") !== -1 || g.indexOf("token") !== -1 || g.indexOf("key") !== -1) return "secret";
        if (g.indexOf("cred") !== -1 || g.indexOf("password") !== -1 || g.indexOf("login") !== -1) return "credential";
        if (g.indexOf("risk") !== -1 || g.indexOf("vuln") !== -1 || g.indexOf("takeover") !== -1) return "risk";
        if (g.indexOf("exposure") !== -1 || g.indexOf("misconfig") !== -1 || g.indexOf("public") !== -1) return "exposure";
        if (g.indexOf("cloud") !== -1 || g.indexOf("aws") !== -1 || g.indexOf("azure") !== -1 || g.indexOf("gcp") !== -1) return "cloud";
        if (g.indexOf("bucket") !== -1 || g.indexOf("blob") !== -1 || g.indexOf("storage") !== -1) return "storage";
        if (g.indexOf("endpoint") !== -1 || g.indexOf("url") !== -1 || g.indexOf("api") !== -1) return "endpoint";
        return "generic";
    }

    function getNodeCategory(node) {
        if (!node) return "generic";
        let category = canonicalCategoryName(node.group || inferGroupFromValue(node.full_label || node.label || node.id));
        if (category !== "generic") return category;

        const hay = [
            node.full_label,
            node.label,
            node.id,
            node.custom_info,
        ].join(" ").toLowerCase();
        if (hay.indexOf("secret") !== -1 || hay.indexOf("token") !== -1 || hay.indexOf("api key") !== -1) return "secret";
        if (hay.indexOf("credential") !== -1 || hay.indexOf("password") !== -1) return "credential";
        if (hay.indexOf("risk") !== -1 || hay.indexOf("takeover") !== -1 || hay.indexOf("vulnerab") !== -1) return "risk";
        if (hay.indexOf("public") !== -1 || hay.indexOf("expos") !== -1 || hay.indexOf("misconfig") !== -1) return "exposure";
        if (hay.indexOf("bucket") !== -1 || hay.indexOf("blob") !== -1 || hay.indexOf("storage") !== -1) return "storage";
        if (hay.indexOf("aws") !== -1 || hay.indexOf("azure") !== -1 || hay.indexOf("gcp") !== -1) return "cloud";
        return category;
    }

    function categoryLabel(category) {
        return CATEGORY_LABELS[category] || category.replace(/_/g, " ").toUpperCase();
    }

    function categoryNodeId(category) {
        return "category::" + category;
    }

    function computeRawNodeDegrees() {
        const deg = new Map();
        rawNodes.forEach(function (_n, id) { deg.set(id, 0); });
        rawEdges.forEach(function (e) {
            deg.set(e.from, (deg.get(e.from) || 0) + 1);
            deg.set(e.to, (deg.get(e.to) || 0) + 1);
        });
        return deg;
    }

    function rawNodeScore(node, degreeMap) {
        const category = getNodeCategory(node);
        let score = degreeMap.get(node.id) || 0;
        if (CRITICAL_CATEGORIES.has(category)) score += 1000;
        if ((node.group || "").toLowerCase() === "target") score += 2000;
        const text = [node.full_label, node.label, node.custom_info].join(" ").toLowerCase();
        if (text.indexOf("high") !== -1 || text.indexOf("critical") !== -1) score += 120;
        if (text.indexOf("public") !== -1 || text.indexOf("exposed") !== -1) score += 80;
        return score;
    }

    function sortRawNodesForDisplay(items) {
        const degreeMap = computeRawNodeDegrees();
        return items.slice().sort(function (a, b) {
            const scoreDelta = rawNodeScore(b, degreeMap) - rawNodeScore(a, degreeMap);
            if (scoreDelta !== 0) return scoreDelta;
            const la = (a.full_label || a.label || a.id || "").toString().toLowerCase();
            const lb = (b.full_label || b.label || b.id || "").toString().toLowerCase();
            return la.localeCompare(lb);
        });
    }

    function getOverviewRootNode() {
        if (state.target && rawNodes.has(state.target)) return rawNodes.get(state.target);
        const targetNode = Array.from(rawNodes.values()).find(function (n) {
            return (n.group || "").toLowerCase() === "target";
        });
        if (targetNode) return targetNode;
        const first = rawNodes.values().next();
        return first.done ? null : first.value;
    }

    function buildCategoryBuckets(rootId) {
        const buckets = new Map();
        rawNodes.forEach(function (node) {
            if (!node || node.id === rootId) return;
            const category = getNodeCategory(node);
            if (category === "target") return;
            if (!buckets.has(category)) buckets.set(category, []);
            buckets.get(category).push(node);
        });
        buckets.forEach(function (items, category) {
            buckets.set(category, sortRawNodesForDisplay(items));
        });
        return buckets;
    }

    function sortedCategoryEntries(buckets) {
        return Array.from(buckets.entries()).sort(function (a, b) {
            const wa = CATEGORY_ORDER.indexOf(a[0]);
            const wb = CATEGORY_ORDER.indexOf(b[0]);
            const oa = wa === -1 ? 999 : wa;
            const ob = wb === -1 ? 999 : wb;
            if (oa !== ob) return oa - ob;
            if (b[1].length !== a[1].length) return b[1].length - a[1].length;
            return categoryLabel(a[0]).localeCompare(categoryLabel(b[0]));
        });
    }

    function addRawNodeSafe(node) {
        if (!node) return "";
        const resolved = resolveNodeIdentity(node);
        if (!resolved.id) return "";

        const existing = rawNodes.get(resolved.id);
        const incomingGroup = (node.group || inferGroupFromValue(resolved.label || resolved.id) || "generic").toString().toLowerCase();
        let group = incomingGroup;
        if (existing && existing.group === "target") group = "target";
        else if (existing && (!incomingGroup || incomingGroup === "generic") && existing.group) group = existing.group;

        const payload = Object.assign({}, existing || {}, node, {
            id: resolved.id,
            label: resolved.label,
            full_label: resolved.label,
            group: group,
        });
        payload.custom_info = node.custom_info && String(node.custom_info).trim()
            ? String(node.custom_info)
            : (existing && existing.custom_info) || enrichNodeCustomInfo(payload);
        rawNodes.set(payload.id, payload);
        return payload.id;
    }

    function addRawEdgeSafe(edge) {
        if (!edge || !edge.from || !edge.to) return "";
        const fromId = resolveEdgeEndpoint(edge.from);
        const toId = resolveEdgeEndpoint(edge.to);
        if (!fromId || !toId) return "";

        if (!rawNodes.has(fromId)) {
            addRawNodeSafe({ id: fromId, label: fromId, group: inferGroupFromValue(fromId) });
        }
        if (!rawNodes.has(toId)) {
            addRawNodeSafe({ id: toId, label: toId, group: inferGroupFromValue(toId) });
        }

        const rawLabel = (edge.raw_label !== undefined ? edge.raw_label : edge.label || "related_to").toString().trim().toUpperCase();
        const edgeId = edge.id || (fromId + "->" + toId + "->" + rawLabel);
        if (rawEdges.has(edgeId)) return edgeId;

        const payload = Object.assign({}, edge, {
            id: edgeId,
            from: fromId,
            to: toId,
            raw_label: rawLabel,
            label: edgeDisplayLabel(rawLabel),
            raw_edge_id: edgeId,
            synthetic: false,
        });
        payload.custom_info = edge.custom_info && String(edge.custom_info).trim()
            ? String(edge.custom_info)
            : enrichEdgeCustomInfo(payload);
        rawEdges.set(edgeId, payload);
        return edgeId;
    }

    function removeRawNodeAndAttachedEdges(nodeId) {
        if (!nodeId || !rawNodes.has(nodeId)) return;
        rawNodes.delete(nodeId);
        Array.from(rawEdges.values()).forEach(function (edge) {
            if (edge.from === nodeId || edge.to === nodeId) rawEdges.delete(edge.id);
        });
    }

    function addFixedRawNode(node, x, y, options) {
        const opts = options || {};
        addNodeSafe(Object.assign({}, node, opts.node || {}));
        const update = {
            id: node.id,
            x: x,
            y: y,
            fixed: true,
            physics: false,
        };
        if (opts.size) update.size = opts.size;
        if (opts.label !== undefined) update.label = opts.label;
        if (opts.font) update.font = opts.font;
        if (opts.color) update.color = opts.color;
        nodes.update(update);
    }

    function addCategoryDisplayNode(category, members, x, y, expanded) {
        const style = getNodeStyle(category);
        const label = categoryLabel(category).toUpperCase() + " (" + members.length + ")";
        const categoryId = categoryNodeId(category);
        addNodeSafe({
            id: categoryId,
            label: label,
            group: "category",
            is_category: true,
            synthetic: true,
            category: category,
            member_count: members.length,
            color: {
                background: expanded ? "#ffffff" : style.background,
                border: style.border,
                highlight: { background: "#ffffff", border: style.border },
            },
            custom_info: categoryLabel(category) + " category containing " + members.length + " entities",
            x: x,
            y: y,
        });
        nodes.update({
            id: categoryId,
            x: x,
            y: y,
            fixed: true,
            physics: false,
            size: Math.max(28, Math.min(52, 22 + members.length * 1.1)),
            borderWidth: expanded ? 4 : 2,
            font: {
                color: expanded ? "#07111f" : "#e2e8f0",
                face: "Outfit",
                size: 13,
                strokeWidth: 0,
                strokeColor: "transparent",
            },
        });
    }

    function addAggregateCategoryEdges(rootId, buckets) {
        const aggregate = new Map();
        rawEdges.forEach(function (edge) {
            const fromNode = rawNodes.get(edge.from);
            const toNode = rawNodes.get(edge.to);
            if (!fromNode || !toNode) return;

            const fromCategory = edge.from === rootId ? "target" : getNodeCategory(fromNode);
            const toCategory = edge.to === rootId ? "target" : getNodeCategory(toNode);
            if (fromCategory === toCategory) return;
            if (fromCategory === "target" || toCategory === "target") return;

            const fromDisplay = fromCategory === "target" ? rootId : categoryNodeId(fromCategory);
            const toDisplay = toCategory === "target" ? rootId : categoryNodeId(toCategory);
            if (!nodes.get(fromDisplay) || !nodes.get(toDisplay)) return;

            const key = fromDisplay + "=>" + toDisplay;
            if (!aggregate.has(key)) {
                aggregate.set(key, { from: fromDisplay, to: toDisplay, count: 0 });
            }
            aggregate.get(key).count += 1;
        });

        Array.from(aggregate.values())
            .sort(function (a, b) { return b.count - a.count; })
            .slice(0, 36)
            .forEach(function (item) {
                addEdgeSafe({
                    id: "overview::agg::" + item.from + "::" + item.to,
                    from: item.from,
                    to: item.to,
                    label: String(item.count) + " rels",
                    synthetic: true,
                    width: Math.max(1, Math.min(4, 1 + item.count * 0.15)),
                    color: { color: "rgba(148, 163, 184, 0.22)", highlight: "#94a3b8", hover: "#cbd5e1" },
                    custom_info: "Aggregated category relation across " + item.count + " raw edges",
                });
            });

        buckets.forEach(function (members, category) {
            const categoryId = categoryNodeId(category);
            if (!nodes.get(rootId) || !nodes.get(categoryId)) return;
            addEdgeSafe({
                id: "overview::root::" + category,
                from: rootId,
                to: categoryId,
                label: String(members.length) + " items",
                synthetic: true,
                width: Math.max(1.5, Math.min(5, 1.4 + members.length * 0.08)),
                color: { color: "rgba(49, 198, 255, 0.28)", highlight: "#31c6ff", hover: "#ffffff" },
                custom_info: "Category summary edge",
            });
        });
    }

    function addVisibleRawEdges(visibleIds, maxEdges) {
        let added = 0;
        rawEdges.forEach(function (edge) {
            if (added >= maxEdges) return;
            if (!visibleIds.has(edge.from) || !visibleIds.has(edge.to)) return;
            addEdgeSafe(Object.assign({}, edge, {
                id: "raw::" + edge.id,
                raw_edge_id: edge.id,
                synthetic: false,
                color: { color: "rgba(49, 198, 255, 0.33)", highlight: "#31c6ff", hover: "#ffffff" },
            }));
            added += 1;
        });
    }

    function renderCriticalHighlights(rootId, buckets) {
        const critical = [];
        buckets.forEach(function (members, category) {
            if (!CRITICAL_CATEGORIES.has(category)) return;
            members.forEach(function (member) { critical.push(member); });
        });
        const selected = sortRawNodesForDisplay(critical).slice(0, state.criticalNodeLimit);
        if (!selected.length) return;

        const radius = 155;
        const spread = Math.min(Math.PI * 1.25, Math.max(0.7, selected.length * 0.24));
        const start = -Math.PI / 2 - spread / 2;
        selected.forEach(function (node, idx) {
            const angle = selected.length === 1 ? -Math.PI / 2 : start + (spread * idx) / Math.max(1, selected.length - 1);
            const x = Math.cos(angle) * radius;
            const y = Math.sin(angle) * radius;
            addFixedRawNode(node, x, y, { size: 20 });
            const category = getNodeCategory(node);
            const categoryId = categoryNodeId(category);
            if (nodes.get(categoryId)) {
                addEdgeSafe({
                    id: "overview::critical::" + category + "::" + node.id,
                    from: categoryId,
                    to: node.id,
                    label: "critical",
                    synthetic: true,
                    color: { color: "rgba(244, 63, 94, 0.38)", highlight: "#fb7185", hover: "#ffffff" },
                    custom_info: "Pinned critical entity",
                });
            } else if (nodes.get(rootId)) {
                addEdgeSafe({
                    id: "overview::critical::root::" + node.id,
                    from: rootId,
                    to: node.id,
                    label: "critical",
                    synthetic: true,
                    color: { color: "rgba(244, 63, 94, 0.38)", highlight: "#fb7185", hover: "#ffffff" },
                    custom_info: "Pinned critical entity",
                });
            }
        });
    }

    function renderExpandedCategoryMembers(category, members) {
        const categoryId = categoryNodeId(category);
        const categoryNode = nodes.get(categoryId);
        if (!categoryNode) return;

        const pos = network ? network.getPositions([categoryId])[categoryId] : { x: categoryNode.x || 0, y: categoryNode.y || 0 };
        const anchorX = pos && typeof pos.x === "number" ? pos.x : categoryNode.x || 0;
        const anchorY = pos && typeof pos.y === "number" ? pos.y : categoryNode.y || 0;
        const angle = Math.atan2(anchorY || 1, anchorX || 1);
        const dirX = Math.cos(angle);
        const dirY = Math.sin(angle);
        const tangentX = -dirY;
        const tangentY = dirX;
        const visible = members.slice(0, state.categoryExpandLimit);
        const omitted = Math.max(0, members.length - visible.length);
        const cols = Math.max(3, Math.min(7, Math.ceil(Math.sqrt(Math.max(1, visible.length)) * 1.35)));
        const cellT = 184;
        const cellD = 88;
        const baseD = 205;
        const visibleIds = new Set([categoryId]);

        visible.forEach(function (node, idx) {
            const col = idx % cols;
            const row = Math.floor(idx / cols);
            const t = (col - (cols - 1) / 2) * cellT;
            const d = baseD + row * cellD;
            const x = anchorX + dirX * d + tangentX * t;
            const y = anchorY + dirY * d + tangentY * t;
            addFixedRawNode(node, x, y, { size: CRITICAL_CATEGORIES.has(category) ? 22 : 17 });
            visibleIds.add(node.id);
            addEdgeSafe({
                id: "overview::member::" + category + "::" + node.id,
                from: categoryId,
                to: node.id,
                label: "member",
                synthetic: true,
                category: category,
                color: { color: "rgba(148, 163, 184, 0.24)", highlight: "#94a3b8", hover: "#ffffff" },
                custom_info: "Visible member of " + categoryLabel(category),
            });
        });

        if (omitted > 0) {
            const row = Math.floor(visible.length / cols) + 1;
            const x = anchorX + dirX * (baseD + row * cellD);
            const y = anchorY + dirY * (baseD + row * cellD);
            const moreId = "more::" + category;
            addNodeSafe({
                id: moreId,
                label: "+" + omitted + " more",
                group: "category_more",
                is_more: true,
                synthetic: true,
                category: category,
                more_count: omitted,
                custom_info: omitted + " additional " + categoryLabel(category) + " entities hidden to keep the graph readable",
                x: x,
                y: y,
            });
            nodes.update({
                id: moreId,
                x: x,
                y: y,
                fixed: true,
                physics: false,
                size: 24,
                font: { color: "#cbd5e1", face: "JetBrains Mono", size: 12, strokeWidth: 0, strokeColor: "transparent" },
            });
            addEdgeSafe({
                id: "overview::more::" + category,
                from: categoryId,
                to: moreId,
                label: "hidden",
                synthetic: true,
                category: category,
                color: { color: "rgba(148, 163, 184, 0.2)", highlight: "#94a3b8", hover: "#ffffff" },
                custom_info: "Hidden category remainder",
            });
        }

        addVisibleRawEdges(visibleIds, 120);
    }

    function renderFullGraphDisplay() {
        rawNodes.forEach(function (node) { addNodeSafe(node); });
        rawEdges.forEach(function (edge) { addEdgeSafe(edge); });
    }

    function renderOverviewDisplay() {
        const root = getOverviewRootNode();
        if (!root) return;

        const rootNode = Object.assign({}, root, { group: "target" });
        addFixedRawNode(rootNode, 0, 0, { size: 38 });

        const buckets = buildCategoryBuckets(root.id);
        const entries = sortedCategoryEntries(buckets);
        const radius = Math.max(310, Math.min(620, 260 + entries.length * 18));
        const count = Math.max(1, entries.length);
        entries.forEach(function (entry, idx) {
            const category = entry[0];
            const members = entry[1];
            const angle = -Math.PI / 2 + (idx * 2 * Math.PI) / count;
            const x = Math.cos(angle) * radius;
            const y = Math.sin(angle) * radius;
            addCategoryDisplayNode(category, members, x, y, state.expandedCategory === category);
        });

        addAggregateCategoryEdges(root.id, buckets);

        if (state.expandedCategory && buckets.has(state.expandedCategory)) {
            renderExpandedCategoryMembers(state.expandedCategory, buckets.get(state.expandedCategory));
        } else {
            state.expandedCategory = null;
            renderCriticalHighlights(root.id, buckets);
        }
    }

    function updateViewButtons() {
        if (el.clusterBtn) {
            el.clusterBtn.textContent = state.viewMode === "overview" ? "Show All" : "Overview";
        }
        const overview = state.viewMode === "overview";
        [el.densityBtn, el.radialBtn, el.physicsBtn].forEach(function (btn) {
            if (btn) btn.disabled = overview;
        });
        if (el.layoutControls && overview) {
            el.layoutControls.style.display = "none";
        }
    }

    function applyGraphViewOptions() {
        updateViewButtons();
        if (!network) return;
        if (state.viewMode === "overview") {
            clearRadialPinning();
            network.setOptions({
                physics: { enabled: false },
                edges: {
                    smooth: { type: "cubicBezier", forceDirection: "none", roundness: 0.28 },
                    selectionWidth: 2.2,
                },
            });
            refreshVisualDensity();
            return;
        }
        applyLayoutMode();
    }

    function renderGraphView(options) {
        const opts = options || {};
        if (state.renderingGraphView) return;
        state.renderingGraphView = true;
        try {
            state.activeClusterIds = [];
            state.expandedClusterId = null;
            state.expandedGroupName = null;
            state.subsetBubbleNodeId = null;
            nodes.clear();
            edges.clear();
            if (state.viewMode === "overview") renderOverviewDisplay();
            else renderFullGraphDisplay();
        } finally {
            state.renderingGraphView = false;
        }
        applyGraphViewOptions();
        refreshCounters();
        if (opts.fit) fitGraph();
    }

    function removeNodeAndAttachedEdges(nodeId) {
        if (!nodeId) return;
        const edgeIds = edges.get().filter(function (e) { return e.from === nodeId || e.to === nodeId; }).map(function (e) { return e.id; });
        if (edgeIds.length) edges.remove(edgeIds);
        nodes.remove(nodeId);
    }

    function focusNode(nodeId) {
        if (!network || !nodeId || !nodes.get(nodeId)) return;
        network.selectNodes([nodeId]);
        network.focus(nodeId, {
            scale: 1.05,
            animation: {
                duration: 500,
                easingFunction: "easeInOutQuad",
            },
        });
    }

    function clearGroupClusters() {
        if (!network || !state.activeClusterIds.length) {
            state.activeClusterIds = [];
            state.expandedClusterId = null;
            return;
        }
        state.activeClusterIds.slice().forEach(function (cid) {
            try {
                if (network.isCluster(cid)) network.openCluster(cid);
            } catch (_err) {
                // Ignore stale cluster references.
            }
        });
        state.activeClusterIds = [];
        state.expandedClusterId = null;
    }

    function clearSubsetBubble() {
        if (state.subsetBubbleNodeId && nodes.get(state.subsetBubbleNodeId)) {
            removeNodeAndAttachedEdges(state.subsetBubbleNodeId);
        }
        state.subsetBubbleNodeId = null;
        state.expandedGroupName = null;
    }

    function applyGroupClusters(skipGroupName) {
        if (!network) return;
        clearSubsetBubble();
        clearGroupClusters();

        const groupCounts = new Map();
        nodes.get().forEach(function (n) {
            const g = (n.group || "generic").toLowerCase();
            if (g === "target") return;
            groupCounts.set(g, (groupCounts.get(g) || 0) + 1);
        });

        const clusterableGroups = Array.from(groupCounts.entries())
            .filter(function (entry) { return entry[1] >= 4; })
            .map(function (entry) { return entry[0]; });

        clusterableGroups.forEach(function (groupName) {
            if (skipGroupName && groupName === skipGroupName) return;
            const clusterId = "cluster_group_" + groupName;
            try {
                network.cluster({
                    joinCondition: function (nodeOptions) {
                        if (String(nodeOptions.id || "").indexOf("subset_bubble_") === 0) return false;
                        return ((nodeOptions.group || "generic").toLowerCase() === groupName);
                    },
                    processProperties: function (clusterOptions, childNodes, _childEdges) {
                        const size = childNodes.length;
                        clusterOptions.label = groupName.toUpperCase() + " (" + size + ")";
                        clusterOptions.full_label = clusterOptions.label;
                        clusterOptions.group = groupName;
                        clusterOptions.shape = "dot";
                        clusterOptions.size = Math.max(24, Math.min(40, 18 + size * 0.9));
                        clusterOptions.font = {
                            color: "#e2e8f0",
                            face: "Outfit",
                            size: 13,
                            strokeWidth: 0,
                            strokeColor: "transparent",
                        };
                        clusterOptions.custom_info = "Category cluster for group '" + groupName + "' with " + size + " nodes";
                        clusterOptions.title = buildNodeTitle({
                            label: clusterOptions.label,
                            id: clusterId,
                            group: groupName,
                            custom_info: clusterOptions.custom_info,
                        });
                        return clusterOptions;
                    },
                    clusterNodeProperties: {
                        id: clusterId,
                        borderWidth: 2,
                        shadow: { enabled: true, color: "rgba(0,0,0,0.45)", size: 10, x: 0, y: 3 },
                    },
                });
                if (network.isCluster(clusterId)) state.activeClusterIds.push(clusterId);
            } catch (_err) {
                // Ignore clustering errors per group.
            }
        });
    }

    function syncGroupClusters() {
        if (!network) return;
        if (!state.groupClustersEnabled) {
            clearSubsetBubble();
            clearGroupClusters();
            return;
        }
        applyGroupClusters();
    }

    function renderExpandedSubsetBubble(groupName, anchorPos) {
        if (!network || !groupName) return;
        clearSubsetBubble();

        const members = nodes.get().filter(function (n) {
            return (n.group || "").toLowerCase() === groupName;
        });
        if (!members.length) return;

        const bubbleId = "subset_bubble_" + groupName;
        const centerX = anchorPos && typeof anchorPos.x === "number" ? anchorPos.x : 0;
        const centerY = anchorPos && typeof anchorPos.y === "number" ? anchorPos.y : 0;
        const radius = Math.max(180, Math.min(460, 90 + members.length * 12));

        addNodeSafe({
            id: bubbleId,
            label: "Subset: " + groupName.toUpperCase() + " (" + members.length + ")",
            group: "subset_container",
            custom_info: "Visual container for expanded subset '" + groupName + "'",
            x: centerX,
            y: centerY,
        });
        nodes.update({
            id: bubbleId,
            shape: "dot",
            size: radius / 5,
            physics: false,
            fixed: true,
            color: {
                background: "rgba(49, 198, 255, 0.07)",
                border: "rgba(49, 198, 255, 0.38)",
                highlight: { background: "rgba(49, 198, 255, 0.11)", border: "#31c6ff" },
            },
            font: {
                color: "#9ddcf5",
                face: "JetBrains Mono",
                size: 12,
                strokeWidth: 0,
                strokeColor: "transparent",
            },
            borderWidth: 2,
        });

        const helperEdges = [];
        const reposition = [];
        const step = (2 * Math.PI) / Math.max(1, members.length);
        members.forEach(function (m, idx) {
            const angle = idx * step;
            const x = centerX + Math.cos(angle) * radius;
            const y = centerY + Math.sin(angle) * radius;
            reposition.push({ id: m.id, x: x, y: y, fixed: false });
            helperEdges.push({
                from: bubbleId,
                to: m.id,
                label: "subset_member",
                custom_info: "Grouped under subset '" + groupName + "'",
            });
        });
        if (reposition.length) nodes.update(reposition);
        helperEdges.forEach(addEdgeSafe);

        state.subsetBubbleNodeId = bubbleId;
        state.expandedGroupName = groupName;
    }

    function expandOnlyOneCluster(clusterId) {
        if (!network || !clusterId || !network.isCluster(clusterId)) return;
        const prefix = "cluster_group_";
        const groupName = clusterId.indexOf(prefix) === 0 ? clusterId.slice(prefix.length) : "";
        let anchorPos = null;
        try {
            const pos = network.getPositions([clusterId]);
            if (pos && pos[clusterId]) anchorPos = pos[clusterId];
        } catch (_err) {
            // ignore
        }
        try {
            network.openCluster(clusterId);
        } catch (_err) {
            return;
        }
        state.expandedClusterId = clusterId;
        if (state.groupClustersEnabled) {
            // Rebuild all clusters except the opened one.
            applyGroupClusters(groupName);
            renderExpandedSubsetBubble(groupName, anchorPos);
        }
    }

    function setLoading(flag) {
        state.loading = !!flag;
        el.loadingOverlay.style.display = state.loading ? "flex" : "none";
        el.metricStatus.textContent = state.loading ? "ACTIVE" : "IDLE";
    }

    function currentPhysicsPreset() {
        if (state.layoutMode === "compact") return compactPhysics;
        return basePhysics;
    }

    function buildAdjacency() {
        const adj = new Map();
        nodes.getIds().forEach(function (id) { adj.set(id, new Set()); });
        edges.get().forEach(function (e) {
            if (!adj.has(e.from)) adj.set(e.from, new Set());
            if (!adj.has(e.to)) adj.set(e.to, new Set());
            adj.get(e.from).add(e.to);
            adj.get(e.to).add(e.from);
        });
        return adj;
    }

    function computeDepths(rootId) {
        const depths = new Map();
        if (!rootId || !nodes.get(rootId)) return depths;
        const adj = buildAdjacency();
        const queue = [rootId];
        depths.set(rootId, 0);
        while (queue.length) {
            const cur = queue.shift();
            const d = depths.get(cur) || 0;
            const neigh = adj.get(cur) || new Set();
            neigh.forEach(function (n) {
                if (!depths.has(n)) {
                    depths.set(n, d + 1);
                    queue.push(n);
                }
            });
        }
        return depths;
    }

    function applyRadialLayout() {
        if (!network || !nodes.length) return;
        const rootId = state.target && nodes.get(state.target) ? state.target : nodes.getIds()[0];
        if (!rootId) return;

        const depths = computeDepths(rootId);
        const buckets = new Map();
        nodes.getIds().forEach(function (id) {
            const d = depths.has(id) ? depths.get(id) : 999;
            if (!buckets.has(d)) buckets.set(d, []);
            buckets.get(d).push(id);
        });

        const updates = [];
        const baseRadius = 190;
        const stepRadius = Math.max(90, Number(state.radialRingSpacing) || 180);
        const minArcSpacing = Math.max(30, Number(state.radialArcSpacing) || 74); // desired pixel spacing between neighbors on same ring
        const groupWeight = {
            target: 0,
            risk: 1,
            domain: 2,
            subdomain: 3,
            hostname: 4,
            ip: 5,
            email: 6,
            registrar: 7,
            nameserver: 8,
            generic: 9,
        };
        const groupAnchors = {
            target: -Math.PI / 2,
            risk: -Math.PI / 2,
            domain: -0.15,
            subdomain: 0.45,
            hostname: 1.05,
            ip: 1.75,
            email: 2.35,
            registrar: 2.95,
            nameserver: 3.55,
            generic: 4.35,
        };

        function sortIdsForRing(ids) {
            return ids.slice().sort(function (a, b) {
                const na = nodes.get(a) || {};
                const nb = nodes.get(b) || {};
                const ga = (na.group || "generic").toLowerCase();
                const gb = (nb.group || "generic").toLowerCase();
                const wa = (groupWeight[ga] !== undefined ? groupWeight[ga] : 99);
                const wb = (groupWeight[gb] !== undefined ? groupWeight[gb] : 99);
                if (wa !== wb) return wa - wb;
                const la = (na.full_label || na.label || a).toString().toLowerCase();
                const lb = (nb.full_label || nb.label || b).toString().toLowerCase();
                return la.localeCompare(lb);
            });
        }

        function distributeRing(ids, radius, depth) {
            const groups = {};
            ids.forEach(function (id) {
                const n = nodes.get(id) || {};
                const g = (n.group || "generic").toLowerCase();
                if (!groups[g]) groups[g] = [];
                groups[g].push(id);
            });

            const points = [];
            Object.keys(groups).forEach(function (g) {
                const list = sortIdsForRing(groups[g]);
                const anchor = (groupAnchors[g] !== undefined ? groupAnchors[g] : groupAnchors.generic);
                const spread = Math.max(0.22, Math.min(1.35, list.length * 0.16));
                if (list.length === 1) {
                    points.push({ id: list[0], angle: anchor });
                    return;
                }
                const step = spread / Math.max(1, list.length - 1);
                for (let i = 0; i < list.length; i += 1) {
                    const angle = anchor - spread / 2 + i * step;
                    points.push({ id: list[i], angle: angle });
                }
            });

            // Fallback order stability.
            points.sort(function (a, b) { return a.angle - b.angle; });

            // Light local anti-collision pass for same ring.
            const minDist = Math.max(24, minArcSpacing * 0.68);
            for (let pass = 0; pass < 2; pass += 1) {
                for (let i = 0; i < points.length; i += 1) {
                    for (let j = i + 1; j < points.length; j += 1) {
                        const pa = points[i];
                        const pb = points[j];
                        const ax = Math.cos(pa.angle) * radius;
                        const ay = Math.sin(pa.angle) * radius;
                        const bx = Math.cos(pb.angle) * radius;
                        const by = Math.sin(pb.angle) * radius;
                        const dx = bx - ax;
                        const dy = by - ay;
                        const dist = Math.sqrt(dx * dx + dy * dy) || 0.0001;
                        if (dist >= minDist) continue;
                        const bump = (minDist - dist) / (radius || 1);
                        pa.angle -= bump * 0.5;
                        pb.angle += bump * 0.5;
                    }
                }
            }

            points.forEach(function (p) {
                const ringOffset = (depth % 2 === 0 ? 0 : 0.06);
                const angle = p.angle + ringOffset;
                updates.push({
                    id: p.id,
                    x: Math.cos(angle) * radius,
                    y: Math.sin(angle) * radius,
                    fixed: false,
                });
            });
        }

        const sortedDepths = Array.from(buckets.keys()).sort(function (a, b) { return a - b; });
        sortedDepths.forEach(function (depth) {
            const ids = sortIdsForRing(buckets.get(depth) || []);
            if (!ids.length) return;
            if (depth === 0) {
                updates.push({ id: ids[0], x: 0, y: 0, fixed: false });
                return;
            }
            if (depth >= 999) {
                // Disconnected/orphan nodes: push them far away in a dedicated arc.
                const orphanRadius = baseRadius + stepRadius * 4;
                const start = Math.PI * 0.65;
                const end = Math.PI * 1.35;
                const step = (end - start) / Math.max(1, ids.length - 1);
                for (let i = 0; i < ids.length; i += 1) {
                    const angle = start + i * step;
                    updates.push({
                        id: ids[i],
                        x: Math.cos(angle) * orphanRadius,
                        y: Math.sin(angle) * orphanRadius,
                        fixed: false,
                    });
                }
                return;
            }
            const baseRing = baseRadius + (Math.min(depth, 8) - 1) * stepRadius;
            // Dynamic ring expansion to preserve readable spacing for crowded rings.
            const neededCirc = Math.max(1, ids.length) * minArcSpacing;
            const neededRadius = neededCirc / (2 * Math.PI);
            const r = Math.max(baseRing, neededRadius);
            distributeRing(ids, r, depth);
        });

        if (updates.length) nodes.update(updates);
        state.radialPinned = true;
        network.stabilize(140);
    }

    function clearRadialPinning() {
        if (!state.radialPinned) return;
        const updates = nodes.getIds().map(function (id) { return { id: id, fixed: false }; });
        if (updates.length) nodes.update(updates);
        state.radialPinned = false;
    }

    function applyLayoutMode() {
        if (!network) return;
        const radial = state.layoutMode === "radial";
        const veryDense = nodes.length >= 90 || edges.length >= 150;
        network.setOptions({
            physics: radial ? { enabled: false } : Object.assign(
                {},
                currentPhysicsPreset(),
                veryDense ? {
                    barnesHut: Object.assign({}, currentPhysicsPreset().barnesHut, {
                        springLength: Math.max(260, currentPhysicsPreset().barnesHut.springLength || 200),
                        centralGravity: 0.08,
                        avoidOverlap: 1,
                    }),
                } : {},
                { enabled: state.physicsEnabled }
            ),
            edges: {
                smooth: state.layoutMode === "compact"
                    ? { type: "dynamic", roundness: 0.22 }
                    : { type: "cubicBezier", forceDirection: "none", roundness: 0.35 },
                selectionWidth: 2.2,
            },
        });
        if (el.densityBtn) {
            el.densityBtn.textContent = state.layoutMode === "compact" ? "Detailed" : "Compact";
        }
        if (el.radialBtn) {
            el.radialBtn.textContent = radial ? "Radial On" : "Radial";
        }
        if (el.layoutControls) {
            el.layoutControls.style.display = radial ? "flex" : "none";
        }
        if (radial) applyRadialLayout();
        else clearRadialPinning();
        refreshVisualDensity();
        if (!radial && veryDense && state.physicsEnabled) {
            network.stabilize(260);
        }
        syncGroupClusters();
    }

    function toggleDensityMode() {
        if (state.viewMode === "overview") return;
        if (state.layoutMode === "radial") {
            state.layoutMode = "detailed";
        }
        state.layoutMode = state.layoutMode === "compact" ? "detailed" : "compact";
        applyLayoutMode();
        if (network) {
            network.stabilize(180);
            fitGraph();
        }
    }

    function toggleRadialMode() {
        if (state.viewMode === "overview") return;
        state.layoutMode = state.layoutMode === "radial" ? "detailed" : "radial";
        applyLayoutMode();
        fitGraph();
    }

    function updateLayoutControlReadout() {
        if (el.arcSpacingValue) el.arcSpacingValue.textContent = String(state.radialArcSpacing);
        if (el.ringSpacingValue) el.ringSpacingValue.textContent = String(state.radialRingSpacing);
    }

    function onLayoutControlChanged() {
        const arc = Number(el.arcSpacingRange && el.arcSpacingRange.value);
        const ring = Number(el.ringSpacingRange && el.ringSpacingRange.value);
        if (Number.isFinite(arc)) state.radialArcSpacing = arc;
        if (Number.isFinite(ring)) state.radialRingSpacing = ring;
        updateLayoutControlReadout();
        if (state.layoutMode === "radial") {
            applyRadialLayout();
            fitGraph();
        }
    }

    function getTargetPlacement(targetId) {
        if (!network || nodes.length === 0 || nodes.get(targetId)) return null;
        const ids = nodes.getIds();
        if (!ids.length) return null;

        let positions = {};
        try {
            positions = network.getPositions(ids);
        } catch (_err) {
            return null;
        }

        let minX = Infinity;
        let maxX = -Infinity;
        let sumY = 0;
        let count = 0;
        ids.forEach(function (id) {
            const p = positions[id];
            if (!p) return;
            minX = Math.min(minX, p.x);
            maxX = Math.max(maxX, p.x);
            sumY += p.y;
            count += 1;
        });
        if (!count || !isFinite(minX) || !isFinite(maxX)) return null;

        const spread = Math.max(280, (maxX - minX) * 0.45);
        const distance = Math.min(1200, 360 + spread + nodes.length * 3.5);
        const avgY = sumY / count;

        if (state.pivotSourceId && positions[state.pivotSourceId]) {
            const src = positions[state.pivotSourceId];
            return { x: src.x + distance, y: src.y + 120 };
        }
        return { x: maxX + distance, y: avgY };
    }

    function pushActivity(moduleName, targetValue, errorText, statusText) {
        const now = new Date();
        state.activityLog.unshift({
            id: String(Date.now()) + "-" + String(Math.random()),
            module: moduleName || "SYSTEM",
            target: targetValue || "",
            error: errorText || "",
            status: statusText || "",
            time: now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
        });
        if (state.activityLog.length > 80) state.activityLog = state.activityLog.slice(0, 80);
        renderLogs();
        refreshCounters();
    }

    function refreshCounters() {
        if (state.visualUpdating || state.renderingGraphView) return;
        el.metricNodes.textContent = String(rawNodes.size || nodes.length);
        el.metricEdges.textContent = String(rawEdges.size || edges.length);
        if (!state.loading) {
            el.metricStatus.textContent = state.activityLog.length > 0 ? "ACTIVE" : "IDLE";
        }
        refreshVisualDensity();
        // Auto-switch to radial for heavy graphs to keep labels readable.
        if (state.viewMode === "full" && state.layoutMode !== "radial" && nodes.length >= 120) {
            state.layoutMode = "radial";
            applyLayoutMode();
        }
    }

    function renderLogs() {
        if (!state.activityLog.length) {
            el.logsList.innerHTML = '<div style="color: var(--text-dim);">No operational logs.</div>';
            return;
        }
        el.logsList.innerHTML = state.activityLog.map(function (log) {
            let msg = "Ran " + log.module + " on " + log.target;
            if (log.error) msg = "Error: " + log.error;
            else if (log.status) msg = log.status;
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
            if (mod.compatible === false) {
                card.style.opacity = "0.62";
            }

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
            desc.textContent = mod.compatible === false && mod.compatibility_reason
                ? (mod.desc || "") + " [" + mod.compatibility_reason + "]"
                : (mod.desc || "");

            const runBtn = document.createElement("button");
            runBtn.className = "module-run-btn";
            runBtn.textContent = mod.compatible === false ? "Skip" : "Run";
            runBtn.disabled = mod.compatible === false;
            runBtn.addEventListener("click", function (event) {
                event.stopPropagation();
                if (mod.compatible === false) return;
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

    function hideInspectorSections() {
        if (el.categorySection) el.categorySection.style.display = "none";
        el.nodeSection.style.display = "none";
        el.edgeSection.style.display = "none";
        el.inspectorEmpty.style.display = "block";
    }

    function renderCategoryMembersList(category) {
        if (!el.categoryMembers) return;
        const root = getOverviewRootNode();
        const buckets = buildCategoryBuckets(root ? root.id : "");
        const members = buckets.get(category) || [];
        const limit = state.categoryExpandLimit;
        const rows = members.slice(0, limit).map(function (node) {
            const label = truncateLabel(node.full_label || node.label || node.id, 46);
            const meta = truncateLabel((node.group || getNodeCategory(node) || "generic").toString(), 20);
            return (
                '<button class="category-row" data-node-id="' + escapeHtml(node.id) + '">' +
                '<span class="category-row-label">' + escapeHtml(label) + "</span>" +
                '<span class="category-row-meta">' + escapeHtml(meta) + "</span>" +
                "</button>"
            );
        });
        if (members.length > limit) {
            rows.push('<div class="category-row is-muted">+' + String(members.length - limit) + " hidden in this list</div>");
        }
        el.categoryMembers.innerHTML = rows.length ? rows.join("") : '<div class="empty">No entities in this category.</div>';
    }

    function setSelectedCategoryNode(node) {
        state.selectedNodeId = node ? node.id : null;
        state.selectedEdgeId = null;
        if (!node || !el.categorySection) {
            hideInspectorSections();
            return;
        }

        const category = node.category || "generic";
        const root = getOverviewRootNode();
        const buckets = buildCategoryBuckets(root ? root.id : "");
        const members = buckets.get(category) || [];

        el.inspectorEmpty.style.display = "none";
        el.nodeSection.style.display = "none";
        el.edgeSection.style.display = "none";
        el.categorySection.style.display = "grid";
        el.categoryLabel.textContent = categoryLabel(category);
        el.categorySummary.textContent = String(members.length) + " entities grouped under " + categoryLabel(category);
        if (el.expandCategoryBtn) {
            el.expandCategoryBtn.textContent = state.expandedCategory === category ? "Refresh Category" : "Expand Category";
            el.expandCategoryBtn.disabled = false;
            el.expandCategoryBtn.dataset.category = category;
        }
        if (el.collapseCategoryBtn) {
            el.collapseCategoryBtn.disabled = state.expandedCategory !== category;
            el.collapseCategoryBtn.dataset.category = category;
        }
        if (el.pivotBtn) {
            el.pivotBtn.disabled = true;
        }
        renderCategoryMembersList(category);
    }

    function setSelectedNode(node) {
        state.selectedNodeId = node ? node.id : null;
        state.selectedEdgeId = null;
        if (!node) {
            hideInspectorSections();
            if (el.pivotBtn) el.pivotBtn.disabled = true;
            return;
        }
        if (node.is_category) {
            setSelectedCategoryNode(node);
            return;
        }
        if (node.is_more && node.category) {
            setSelectedCategoryNode({
                id: categoryNodeId(node.category),
                category: node.category,
                is_category: true,
            });
            return;
        }

        el.inspectorEmpty.style.display = "none";
        if (el.categorySection) el.categorySection.style.display = "none";
        el.edgeSection.style.display = "none";
        el.nodeSection.style.display = "grid";
        el.nodeLabel.textContent = node.full_label || node.label || node.id || "";
        el.nodeId.textContent = node.id || "";
        el.nodeGroup.textContent = node.group || "unknown";
        el.nodeMeta.textContent = node.custom_info || "No extended metadata";
        if (el.pivotBtn) {
            el.pivotBtn.disabled = !canPivotNode(node);
        }
    }

    function setSelectedEdge(edge) {
        state.selectedEdgeId = edge ? edge.id : null;
        state.selectedNodeId = null;
        if (!edge) {
            hideInspectorSections();
            return;
        }

        el.inspectorEmpty.style.display = "none";
        if (el.categorySection) el.categorySection.style.display = "none";
        el.nodeSection.style.display = "none";
        el.edgeSection.style.display = "grid";
        el.edgeLabel.textContent = edge.label || "relation";
        const fromNode = nodes.get(edge.from);
        const toNode = nodes.get(edge.to);
        el.edgeFrom.textContent = (fromNode && (fromNode.full_label || fromNode.label || fromNode.id)) || edge.from || "";
        el.edgeTo.textContent = (toNode && (toNode.full_label || toNode.label || toNode.id)) || edge.to || "";
        if (el.edgeMeta) {
            el.edgeMeta.textContent = edge.custom_info || "No extended metadata";
        }
        if (el.deleteEdgeBtn) {
            el.deleteEdgeBtn.disabled = !!edge.synthetic;
        }
        if (el.pivotBtn) {
            el.pivotBtn.disabled = true;
        }
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
        const target = (
            el.targetInput && el.targetInput.value
                ? el.targetInput.value
                : (state.targetInputValue || state.target || "")
        ).trim();
        const suffix = target ? ("?target=" + encodeURIComponent(target)) : "";
        const res = await fetch("/api/modules" + suffix);
        const data = await res.json();
        state.modules = Array.isArray(data) ? data : [];
        renderModules();
    }

    async function runTransform(moduleId) {
        const requestedTarget = (el.targetInput.value || state.targetInputValue || state.target || "").trim();
        const target = normalizeExecutionTarget(requestedTarget);
        if (!target) return;
        const graphTargetId = normalizeEntityToken(target) || target;
        const targetKind = classifyTargetInput(target);
        const pivoted = !!state.pivotSourceId;

        state.target = graphTargetId;
        state.targetInputValue = target;
        if (el.targetInput && el.targetInput.value !== target) {
            el.targetInput.value = target;
        }
        setLoading(true);
        await fetchModules();
        const placement = getTargetPlacement(graphTargetId);
        const targetNode = { id: graphTargetId, label: target, group: "target" };
        if (placement) {
            targetNode.x = placement.x;
            targetNode.y = placement.y;
        }
        addRawNodeSafe(targetNode);
        renderGraphView({ fit: false });

        if (state.pivotSourceId && state.pivotSourceId !== graphTargetId && rawNodes.has(state.pivotSourceId)) {
            addRawEdgeSafe({
                from: state.pivotSourceId,
                to: graphTargetId,
                label: "pivot_" + targetKind,
                custom_info: "Pivot relation to " + target,
            });
        }

        try {
            const modulesToRun = moduleId === "all"
                ? state.modules
                    .filter(function (m) { return m.compatible !== false; })
                    .sort(function (a, b) {
                        const as = Array.isArray(a.supported_target_types) ? a.supported_target_types : [];
                        const bs = Array.isArray(b.supported_target_types) ? b.supported_target_types : [];
                        const aExact = as.indexOf(targetKind) !== -1 ? 1 : 0;
                        const bExact = bs.indexOf(targetKind) !== -1 ? 1 : 0;
                        if (aExact !== bExact) return bExact - aExact;
                        return (a.name || a.id || "").localeCompare(b.name || b.id || "");
                    })
                    .map(function (m) { return m.id; })
                : [moduleId];

            if (!modulesToRun.length) {
                pushActivity("SYSTEM", target, "", "Skipped: no compatible transforms for this target type");
                return;
            }

            for (const mId of modulesToRun) {
                const response = await fetch("/api/transform", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ module: mId, target: target }),
                });
                const data = await response.json();

                if (data && data.graph) {
                    if (Array.isArray(data.graph.nodes)) data.graph.nodes.forEach(addRawNodeSafe);
                    if (Array.isArray(data.graph.edges)) data.graph.edges.forEach(addRawEdgeSafe);
                }
                if (data && (data.raw || data.meta)) {
                    state.lastModuleOutput = data;
                    renderLastModuleOutput();
                }

                if (data && data.skipped) {
                    pushActivity(mId, target, "", "Skipped " + mId + ": " + String(data.reason || "module not applicable"));
                } else {
                    pushActivity(mId, target, data && data.error ? data.error : "");
                }
            }
        } catch (err) {
            pushActivity("ERROR", target, err && err.message ? err.message : "Unknown error");
        } finally {
            setLoading(false);
            state.pivotSourceId = null;
            renderGraphView({ fit: !pivoted });
            if (pivoted) focusNode(graphTargetId);
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
                if (network.isCluster(nodeId)) {
                    expandOnlyOneCluster(nodeId);
                    setSelectedNode(null);
                    return;
                }
                const clickedNode = nodes.get(nodeId) || null;

                if (state.viewMode === "overview" && clickedNode && clickedNode.is_category) {
                    const category = clickedNode.category || "";
                    state.expandedCategory = state.expandedCategory === category ? null : category;
                    renderGraphView({ fit: true });
                    setSelectedNode(nodes.get(nodeId) || clickedNode);
                    return;
                }

                if (state.linkSourceId && clickedNode && clickedNode.id !== state.linkSourceId) {
                    if (clickedNode.synthetic || clickedNode.is_more || clickedNode.is_category) {
                        setSelectedNode(clickedNode);
                        return;
                    }
                    const relation = (el.linkRelationInput.value || "related_to").trim();
                    addRawEdgeSafe({
                        from: state.linkSourceId,
                        to: clickedNode.id,
                        label: relation,
                        custom_info: "Manual Link",
                    });
                    renderGraphView({ fit: false });
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

        network.on("doubleClick", function (_params) {
            // Intentionally disabled: single-click already handles one-cluster expansion.
        });

        renderGraphView({ fit: false });
        renderLastModuleOutput();
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
        clearSubsetBubble();
        clearGroupClusters();
        rawNodes.clear();
        rawEdges.clear();
        nodes.clear();
        edges.clear();
        entityAliasMap.clear();
        state.selectedNodeId = null;
        state.selectedEdgeId = null;
        state.linkSourceId = null;
        state.expandedCategory = null;
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

        addRawNodeSafe({
            id: id,
            label: label,
            group: group,
            custom_info: "Manual Entry",
        });
        pushActivity("MANUAL", "Node injected: " + label, "");
        el.manualNodeLabel.value = "";
        renderGraphView({ fit: true });
    }

    function pivotFromSelected() {
        if (!state.selectedNodeId) return;
        const node = nodes.get(state.selectedNodeId);
        const pivotTarget = derivePivotTarget(node);
        if (!pivotTarget) {
            pushActivity("SYSTEM", state.selectedNodeId, "", "Skipped: selected node is not pivotable");
            return;
        }
        state.pivotSourceId = node.id;
        state.expandedCategory = null;
        el.targetInput.value = pivotTarget;
        state.targetInputValue = pivotTarget;
        runTransform("all");
    }

    function startLinkFromSelected() {
        if (!state.selectedNodeId) return;
        const node = nodes.get(state.selectedNodeId);
        if (!node || node.synthetic || node.is_category || node.is_more) return;
        setLinkMode(state.selectedNodeId);
    }

    function deleteSelectedEdge() {
        if (!state.selectedEdgeId) return;
        const edge = edges.get(state.selectedEdgeId);
        if (edge && edge.raw_edge_id && rawEdges.has(edge.raw_edge_id)) {
            rawEdges.delete(edge.raw_edge_id);
            renderGraphView({ fit: false });
        } else {
            edges.remove(state.selectedEdgeId);
        }
        setSelectedEdge(null);
        pushActivity("MANUAL", "Relation removed: " + ((edge && edge.label) || "relation"), "");
    }

    function purgeSelectedNode() {
        if (!state.selectedNodeId) return;
        const node = nodes.get(state.selectedNodeId);
        if (node && (node.is_category || node.is_more || node.synthetic)) {
            if (node.is_category) {
                state.expandedCategory = state.expandedCategory === node.category ? null : node.category;
                renderGraphView({ fit: true });
            }
            setSelectedNode(null);
            return;
        }
        removeRawNodeAndAttachedEdges(state.selectedNodeId);
        renderGraphView({ fit: true });
        setSelectedNode(null);
        pushActivity("MANUAL", "Entity purged: " + ((node && (node.label || node.id)) || state.selectedNodeId), "");
    }

    function togglePhysics() {
        if (state.viewMode === "overview") return;
        if (state.layoutMode === "radial") {
            // Radial mode is deterministic by design.
            return;
        }
        state.physicsEnabled = !state.physicsEnabled;
        if (network) {
            network.setOptions({ physics: Object.assign({}, currentPhysicsPreset(), { enabled: state.physicsEnabled }) });
        }
        el.physicsBtn.textContent = state.physicsEnabled ? "Freeze" : "Release";
    }

    function exportGraph() {
        const payload = {
            version: 3,
            exported_at: new Date().toISOString(),
            view: {
                mode: state.viewMode,
                expanded_category: state.expandedCategory,
            },
            nodes: Array.from(rawNodes.values()),
            edges: Array.from(rawEdges.values()),
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

    function toggleGroupClusters() {
        state.viewMode = state.viewMode === "overview" ? "full" : "overview";
        state.expandedCategory = null;
        state.expandedClusterId = null;
        renderGraphView({ fit: true });
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
        el.targetInput.addEventListener("input", function () {
            fetchModules().catch(function (_err) {
                // Keep typing resilient even if module refresh fails transiently.
            });
        });
        el.moduleSearch.addEventListener("input", function () {
            state.moduleQuery = el.moduleSearch.value || "";
            renderModules();
        });

        el.focusBtn.addEventListener("click", fitGraph);
        el.clearBtn.addEventListener("click", clearGraph);
        if (el.clusterBtn) el.clusterBtn.addEventListener("click", toggleGroupClusters);
        if (el.densityBtn) el.densityBtn.addEventListener("click", toggleDensityMode);
        if (el.radialBtn) el.radialBtn.addEventListener("click", toggleRadialMode);
        if (el.arcSpacingRange) el.arcSpacingRange.addEventListener("input", onLayoutControlChanged);
        if (el.ringSpacingRange) el.ringSpacingRange.addEventListener("input", onLayoutControlChanged);
        el.physicsBtn.addEventListener("click", togglePhysics);
        el.exportBtn.addEventListener("click", exportGraph);

        el.injectNodeBtn.addEventListener("click", injectNode);
        el.pivotBtn.addEventListener("click", pivotFromSelected);
        el.startLinkBtn.addEventListener("click", startLinkFromSelected);
        el.cancelLinkBtn.addEventListener("click", function () { setLinkMode(null); });
        el.purgeNodeBtn.addEventListener("click", purgeSelectedNode);
        el.deleteEdgeBtn.addEventListener("click", deleteSelectedEdge);
        if (el.expandCategoryBtn) {
            el.expandCategoryBtn.addEventListener("click", function () {
                const category = el.expandCategoryBtn.dataset.category || "";
                if (!category) return;
                state.expandedCategory = category;
                renderGraphView({ fit: true });
                setSelectedNode(nodes.get(categoryNodeId(category)) || null);
            });
        }
        if (el.collapseCategoryBtn) {
            el.collapseCategoryBtn.addEventListener("click", function () {
                state.expandedCategory = null;
                renderGraphView({ fit: true });
                setSelectedNode(null);
            });
        }
        if (el.categoryMembers) {
            el.categoryMembers.addEventListener("click", function (event) {
                const target = event.target;
                const row = target && target.closest ? target.closest("[data-node-id]") : null;
                if (!row) return;
                const nodeId = row.getAttribute("data-node-id");
                const category = el.expandCategoryBtn ? el.expandCategoryBtn.dataset.category : "";
                if (category && state.expandedCategory !== category) {
                    state.expandedCategory = category;
                    renderGraphView({ fit: false });
                }
                if (nodeId && nodes.get(nodeId)) {
                    network.selectNodes([nodeId]);
                    network.focus(nodeId, {
                        scale: 1.1,
                        animation: { duration: 350, easingFunction: "easeInOutQuad" },
                    });
                    setSelectedNode(nodes.get(nodeId));
                }
            });
        }
    }

    async function init() {
        initGraph();
        bindEvents();
        renderLogs();
        renderModules();
        setSelectedNode(null);
        setLinkMode(null);
        if (el.layoutControls) el.layoutControls.style.display = "none";
        updateViewButtons();
        updateLayoutControlReadout();
        await fetchModules();
    }

    document.addEventListener("DOMContentLoaded", function () {
        init().catch(function (err) {
            console.error("KittyOSINT init failed:", err);
        });
    });
})();
