(function () {
    "use strict";

    const el = {
        sidebar: document.querySelector(".sidebar"),
        sidebarToggle: document.getElementById("sidebarToggleBtn"),
        sidebarToggleIcon: document.getElementById("sidebarToggleIcon"),
        navItems: Array.from(document.querySelectorAll(".nav-item[data-view]")),
        viewPanels: Array.from(document.querySelectorAll(".view-panel[data-view-panel]")),
        globalSearch: document.getElementById("globalSearchInput"),
        globalSearchResults: document.getElementById("globalSearchResults"),
        pcap: document.getElementById("pcapInput"),
        pcapSelectedName: document.getElementById("pcapSelectedName"),
        filter: document.getElementById("filterInput"),
        protocolFilter: document.getElementById("protocolFilterInput"),
        severityFilter: document.getElementById("severityFilterInput"),
        hostFilter: document.getElementById("hostFilterInput"),
        portFilter: document.getElementById("portFilterInput"),
        search: document.getElementById("searchInput"),
        maxPackets: document.getElementById("maxPacketsInput"),
        includeRaw: document.getElementById("includeRawInput"),
        analyze: document.getElementById("analyzeBtn"),
        recordingName: document.getElementById("recordingNameInput"),
        saveRecording: document.getElementById("saveRecordingBtn"),
        refreshRecordings: document.getElementById("refreshRecordingsBtn"),
        recordings: document.getElementById("recordingsContainer"),
        replayRecordingSelect: document.getElementById("replayRecordingSelect"),
        replayFlowSelect: document.getElementById("replayFlowSelect"),
        loadReplay: document.getElementById("loadReplayBtn"),
        replayNext: document.getElementById("replayNextBtn"),
        replayPlay: document.getElementById("replayPlayBtn"),
        replayPause: document.getElementById("replayPauseBtn"),
        replayDirection: document.getElementById("replayDirectionSelect"),
        replaySpeed: document.getElementById("replaySpeedInput"),
        replayStatus: document.getElementById("replayStatusBox"),
        replayEvents: document.getElementById("replayEventsContainer"),
        exportJson: document.getElementById("exportJsonBtn"),
        exportHtml: document.getElementById("exportHtmlBtn"),
        interfaceSelect: document.getElementById("interfaceSelect"),
        refreshInterfaces: document.getElementById("refreshInterfacesBtn"),
        liveFilter: document.getElementById("liveFilterInput"),
        liveProtocolFilter: document.getElementById("liveProtocolFilterInput"),
        liveSearch: document.getElementById("liveSearchInput"),
        liveMaxPackets: document.getElementById("liveMaxPacketsInput"),
        startLive: document.getElementById("startLiveBtn"),
        stopLive: document.getElementById("stopLiveBtn"),
        liveStatus: document.getElementById("liveStatusBox"),
        status: document.getElementById("statusBox"),
        flowCount: document.getElementById("flowCount"),
        patternCount: document.getElementById("patternCount"),
        packetCount: document.getElementById("packetCount"),
        protocolStats: document.getElementById("protocolStats"),
        datasetHint: document.getElementById("datasetHint"),
        missionScore: document.getElementById("missionScore"),
        missionHighlights: document.getElementById("missionHighlights"),
        missionFocusHighRisk: document.getElementById("missionFocusHighRiskBtn"),
        missionOpenTopFinding: document.getElementById("missionOpenTopFindingBtn"),
        missionJumpInvestigation: document.getElementById("missionJumpInvestigationBtn"),
        missionExportCase: document.getElementById("missionExportCaseBtn"),
        missionCopyExec: document.getElementById("missionCopyExecBtn"),
        missionExportExec: document.getElementById("missionExportExecBtn"),
        onboardingChecklist: document.getElementById("onboardingChecklist"),
        onboardingStart: document.getElementById("onboardingStartBtn"),
        onboardingDemo: document.getElementById("onboardingDemoBtn"),
        onboardingInstantDemo: document.getElementById("onboardingInstantDemoBtn"),
        flowPagerMeta: document.getElementById("flowPagerMeta"),
        findingPagerMeta: document.getElementById("findingPagerMeta"),
        flowPrev: document.getElementById("flowPrevBtn"),
        flowNext: document.getElementById("flowNextBtn"),
        findingPrev: document.getElementById("findingPrevBtn"),
        findingNext: document.getElementById("findingNextBtn"),
        flows: document.getElementById("flowsContainer"),
        patterns: document.getElementById("patternsContainer"),
        decTlsKeylog: document.getElementById("decTlsKeylogInput"),
        decPersistSecrets: document.getElementById("decPersistSecretsInput"),
        decSave: document.getElementById("decSaveBtn"),
        decClear: document.getElementById("decClearBtn"),
        decStatus: document.getElementById("decStatusBox"),
        decSummary: document.getElementById("decSummaryMeta"),
        decItems: document.getElementById("decItemsContainer"),
        inspector: document.getElementById("flowInspector"),
        quickFilterBar: document.getElementById("quickFilterBar"),
        pinnedFlowsBar: document.getElementById("pinnedFlowsBar"),
        compareTray: document.getElementById("flowCompareTray"),
        gridHandle: document.getElementById("flowGridHandle"),
        error: document.getElementById("errorBox"),
        flowsQuickSearch: document.getElementById("flowsQuickSearchInput"),
        flowsSort: document.getElementById("flowsSortSelect"),
        flowsRiskMin: document.getElementById("flowsRiskMinSelect"),
        bpf: document.getElementById("bpfInput"),
        ftsIndex: document.getElementById("ftsIndexInput"),
        liveBpf: document.getElementById("liveBpfInput"),
    };

    const inv = {
        sessionBadge: document.getElementById("invSessionBadge"),
        provenancePre: document.getElementById("invProvenancePre"),
        copySession: document.getElementById("invCopySessionBtn"),
        copyProv: document.getElementById("invCopyProvBtn"),
        refreshViews: document.getElementById("invRefreshViewsBtn"),
        viewsList: document.getElementById("invViewsList"),
        viewName: document.getElementById("invViewNameInput"),
        viewDesc: document.getElementById("invViewDescInput"),
        saveView: document.getElementById("invSaveViewBtn"),
        compareA: document.getElementById("invCompareAInput"),
        compareB: document.getElementById("invCompareBInput"),
        compareRun: document.getElementById("invCompareRunBtn"),
        comparePre: document.getElementById("invComparePre"),
        timelineList: document.getElementById("invTimelineList"),
        ftsQuery: document.getElementById("invFtsQueryInput"),
        ftsRun: document.getElementById("invFtsRunBtn"),
        ftsHits: document.getElementById("invFtsHits"),
        annFlow: document.getElementById("invAnnFlowInput"),
        annNote: document.getElementById("invAnnNoteInput"),
        annAssignee: document.getElementById("invAnnAssigneeInput"),
        annTicket: document.getElementById("invAnnTicketInput"),
        annTags: document.getElementById("invAnnTagsInput"),
        annStatus: document.getElementById("invAnnStatusSelect"),
        annSave: document.getElementById("invAnnSaveBtn"),
        annRefresh: document.getElementById("invAnnRefreshBtn"),
        exportIocJson: document.getElementById("invExportIocJsonBtn"),
        exportIocCsv: document.getElementById("invExportIocCsvBtn"),
        exportCaseBundle: document.getElementById("invExportCaseBundleBtn"),
        annList: document.getElementById("invAnnList"),
        toast: document.getElementById("invToast"),
    };
    let livePollTimer = null;
    let replayTimer = null;
    let wsClient = null;
    let selectedFlowId = null;
    let lastFlowDetail = null;
    let pendingDeepFrameIndex = null;
    /** 0-based frame index in this flow (server-aligned via flow_packet_index). */
    let selectedFlowPacketIndex = null;
    const PACKET_TABLE_CAP = 400;
    let currentRecordings = [];
    let replayState = { recordingId: "", flowId: "", cursor: 0, total: 0 };
    let lastReplayEvents = [];
    const STORE_KEYS = {
        pinned: "kittyprotocol.pinnedFlows",
        sidebarExpanded: "kittyprotocol.sidebarExpanded",
        listWidth: "kittyprotocol.flowListWidth",
        packetCols: "kittyprotocol.packetCols",
        frameBookmarks: "kittyprotocol.frameBookmarks",
        investigationContext: "kittyprotocol.investigationContext",
        onboardingState: "kittyprotocol.onboardingState",
    };
    const viewScrollState = {};
    let activeViewName = "overview";
    let pinnedFlowIds = readJsonStore(STORE_KEYS.pinned, []);
    let quickFilterState = { protocol: "", risk: "all", pinnedOnly: false };
    let compareSlots = { a: null, b: null };
    let packetColumnState = readJsonStore(STORE_KEYS.packetCols, {});
    let frameBookmarks = readJsonStore(STORE_KEYS.frameBookmarks, {});
    let decryptionState = { config: {}, items: [], tls_like_flows: 0, decryptable_candidates: 0, total_flows: 0 };
    let demoFlowDetails = null;
    let flowRenderLimit = 80;
    let findingRenderLimit = 80;
    const queryCache = new Map();
    let pagerState = {
        flow_page: 1,
        finding_page: 1,
        flow_per_page: 24,
        finding_per_page: 18,
    };
    let currentAnalysis = {
        flows: [],
        patterns: [],
        suggestions: [],
        session_id: "",
        provenance: null,
        global_timeline: [],
        fts_indexed: false,
        local_demo: false,
    };
    const LIMITS = {
        flows: 24,
        patterns: 18,
        timeline: 6,
        evidence: 5,
    };

    function readJsonStore(key, fallback) {
        try {
            const raw = window.localStorage.getItem(key);
            return raw ? JSON.parse(raw) : fallback;
        } catch (_err) {
            return fallback;
        }
    }

    function writeJsonStore(key, value) {
        try {
            window.localStorage.setItem(key, JSON.stringify(value));
        } catch (_err) {
            /* ignore storage quota/private mode */
        }
    }

    function persistInvestigationContext() {
        const payload = {
            activeViewName,
            selectedFlowId,
            selectedFlowPacketIndex,
            pagerState,
            quickFilterState,
            filters: {
                protocol: el.protocolFilter && el.protocolFilter.value || "",
                severity: el.severityFilter && el.severityFilter.value || "",
                host: el.hostFilter && el.hostFilter.value || "",
                port: el.portFilter && el.portFilter.value || "",
                search: el.search && el.search.value || "",
                flowsQuickSearch: el.flowsQuickSearch && el.flowsQuickSearch.value || "",
                flowsSort: el.flowsSort && el.flowsSort.value || "risk_desc",
                flowsRiskMin: el.flowsRiskMin && el.flowsRiskMin.value || "all",
            },
            scroll: viewScrollState,
        };
        writeJsonStore(STORE_KEYS.investigationContext, payload);
    }

    function restoreInvestigationContext() {
        const ctx = readJsonStore(STORE_KEYS.investigationContext, null);
        if (!ctx || typeof ctx !== "object") return;
        if (ctx.filters) {
            if (el.protocolFilter) el.protocolFilter.value = String(ctx.filters.protocol || "");
            if (el.severityFilter) el.severityFilter.value = String(ctx.filters.severity || "");
            if (el.hostFilter) el.hostFilter.value = String(ctx.filters.host || "");
            if (el.portFilter) el.portFilter.value = String(ctx.filters.port || "");
            if (el.search) el.search.value = String(ctx.filters.search || "");
            if (el.flowsQuickSearch) el.flowsQuickSearch.value = String(ctx.filters.flowsQuickSearch || "");
            if (el.flowsSort) el.flowsSort.value = String(ctx.filters.flowsSort || "risk_desc");
            if (el.flowsRiskMin) el.flowsRiskMin.value = String(ctx.filters.flowsRiskMin || "all");
        }
        if (ctx.quickFilterState && typeof ctx.quickFilterState === "object") {
            quickFilterState = {
                protocol: String(ctx.quickFilterState.protocol || ""),
                risk: String(ctx.quickFilterState.risk || "all"),
                pinnedOnly: Boolean(ctx.quickFilterState.pinnedOnly),
            };
        }
        if (ctx.pagerState && typeof ctx.pagerState === "object") {
            pagerState.flow_page = Math.max(1, Number(ctx.pagerState.flow_page || pagerState.flow_page || 1));
            pagerState.finding_page = Math.max(1, Number(ctx.pagerState.finding_page || pagerState.finding_page || 1));
        }
        if (ctx.activeViewName) activeViewName = String(ctx.activeViewName);
        if (ctx.selectedFlowId) selectedFlowId = String(ctx.selectedFlowId);
        if (Number.isFinite(Number(ctx.selectedFlowPacketIndex))) {
            selectedFlowPacketIndex = Math.max(0, Number(ctx.selectedFlowPacketIndex));
        }
    }

    function queryCacheKey(isLive) {
        return JSON.stringify({
            live: Boolean(isLive),
            sid: currentAnalysis.session_id || "",
            filters: currentFilters(Boolean(isLive)),
        });
    }

    function applyUiPreferences() {
        const sidebarExpanded = window.localStorage.getItem(STORE_KEYS.sidebarExpanded);
        const expanded = sidebarExpanded == null ? true : sidebarExpanded === "true";
        document.body.classList.remove("theme-dark");
        document.body.classList.remove("compact");
        if (el.sidebar) el.sidebar.classList.toggle("expanded", expanded);
        if (el.sidebarToggleIcon) el.sidebarToggleIcon.textContent = expanded ? "menu_open" : "menu";
        if (el.sidebarToggle) {
            el.sidebarToggle.setAttribute("data-label", expanded ? "Collapse menu" : "Expand menu");
            el.sidebarToggle.title = expanded ? "Collapse menu" : "Expand menu";
        }
        const width = window.localStorage.getItem(STORE_KEYS.listWidth);
        if (width) {
            document.documentElement.style.setProperty("--flows-list-width", width);
        }
    }

    function toggleSidebar() {
        const expanded = !el.sidebar || !el.sidebar.classList.contains("expanded");
        window.localStorage.setItem(STORE_KEYS.sidebarExpanded, expanded ? "true" : "false");
        applyUiPreferences();
    }

    function flowBookmarkKey(flowId) {
        return String(flowId || "").trim();
    }

    function scheduleScrollRestore(el, top, left) {
        if (!el) return;
        const go = () => {
            el.scrollTop = top;
            el.scrollLeft = left;
        };
        requestAnimationFrame(go);
        requestAnimationFrame(() => requestAnimationFrame(go));
    }

    function setStatus(kind, text) {
        el.status.className = "status " + kind;
        el.status.textContent = text;
    }

    function setLiveStatus(kind, text) {
        el.liveStatus.className = "status " + kind;
        el.liveStatus.textContent = text;
    }

    function setReplayStatus(kind, text) {
        el.replayStatus.className = "status " + kind;
        el.replayStatus.textContent = text;
    }

    function updateSelectedPcapName() {
        if (!el.pcapSelectedName || !el.pcap) return;
        const file = el.pcap.files && el.pcap.files[0];
        if (!file) {
            el.pcapSelectedName.textContent = "No file selected.";
            return;
        }
        const sizeKb = Math.max(1, Math.round(Number(file.size || 0) / 1024));
        el.pcapSelectedName.textContent = `Selected: ${file.name} (${sizeKb} KB)`;
    }

    function setDecryptionStatus(kind, text) {
        if (!el.decStatus) return;
        el.decStatus.className = "status " + kind;
        el.decStatus.textContent = text;
    }

    function buildExecutiveSummaryData() {
        const flows = currentAnalysis.flows || [];
        const findings = uniqueBy(currentAnalysis.patterns || [], (pattern) => [
            pattern.flow_id || "",
            pattern.type || "",
            pattern.message || "",
        ].join("|"));
        const protocols = (currentAnalysis.protocols || []).slice(0, 5).map((p) => p.protocol).filter(Boolean);
        const highRiskFlows = flows.filter((flow) => Number(flow.risk_score || 0) >= 5);
        const criticalFindings = findings.filter((f) => String(f.severity || "").toLowerCase() === "high");
        const topFlow = flows.slice().sort((a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0))[0] || null;
        const topFinding = findings.slice().sort((a, b) => Number(b.criticality_score || 0) - Number(a.criticality_score || 0))[0] || null;
        return {
            sessionId: currentAnalysis.session_id || "n/a",
            generatedAt: new Date().toISOString(),
            processedPackets: Number(currentAnalysis.processed_packets || 0),
            flowCount: flows.length,
            findingCount: findings.length,
            highRiskCount: highRiskFlows.length,
            criticalFindingCount: criticalFindings.length,
            protocols,
            topFlow,
            topFinding,
        };
    }

    function buildExecutiveSummaryText() {
        const d = buildExecutiveSummaryData();
        const lines = [
            "KittyProtocol Executive Summary",
            `Session: ${d.sessionId}`,
            `Generated: ${d.generatedAt}`,
            "",
            "Scope",
            `- Packets processed: ${d.processedPackets}`,
            `- Flows analyzed: ${d.flowCount}`,
            `- Findings detected: ${d.findingCount}`,
            `- High-risk flows (risk >= 5): ${d.highRiskCount}`,
            `- High-severity findings: ${d.criticalFindingCount}`,
            `- Top protocols: ${(d.protocols || []).join(", ") || "n/a"}`,
            "",
            "Top risk",
            `- Flow: ${d.topFlow ? `${d.topFlow.protocol || "UNKNOWN"} ${d.topFlow.client || "?"} -> ${d.topFlow.server || "?"} (risk ${d.topFlow.risk_score || 0})` : "n/a"}`,
            `- Finding: ${d.topFinding ? `${d.topFinding.type || "Unknown"} (${d.topFinding.severity || "n/a"}): ${d.topFinding.message || ""}` : "n/a"}`,
            "",
            "Immediate actions",
            "- Contain/verify top risky flow and related endpoints.",
            "- Validate high-severity findings and mark false positives.",
            "- Export case bundle and share with SOC/IR stakeholders.",
        ];
        return lines.join("\n");
    }

    function buildExecutiveSummaryHtml() {
        const text = buildExecutiveSummaryText();
        const body = escapeHtml(text).replaceAll("\n", "<br>");
        return `<!doctype html><html><head><meta charset="utf-8"><title>KittyProtocol Executive Summary</title></head><body style="font-family:Inter,Arial,sans-serif;padding:24px;line-height:1.5;"><h1>KittyProtocol Executive Summary</h1><div>${body}</div></body></html>`;
    }

    async function copyExecutiveSummary() {
        const summary = buildExecutiveSummaryText();
        await copyText(summary);
        setStatus("success", "Executive summary copied.");
    }

    async function exportExecutiveSummaryHtml() {
        const html = buildExecutiveSummaryHtml();
        const blob = new Blob([html], { type: "text/html;charset=utf-8" });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = "kittyprotocol-executive-summary.html";
        document.body.appendChild(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(url);
        setStatus("success", "Executive summary HTML exported.");
    }

    function renderOnboardingCard() {
        if (!el.onboardingChecklist) return;
        const state = readJsonStore(STORE_KEYS.onboardingState, {});
        const flows = currentAnalysis.flows || [];
        const findings = currentAnalysis.patterns || [];
        const steps = [
            {
                key: "loaded_data",
                label: "Load data (PCAP or saved recording)",
                done: Boolean(state.loaded_data || currentAnalysis.session_id || flows.length),
            },
            {
                key: "reviewed_flow",
                label: "Open at least one flow inspector",
                done: Boolean(state.reviewed_flow || selectedFlowId),
            },
            {
                key: "reviewed_finding",
                label: "Review a finding and draft annotation",
                done: Boolean(state.reviewed_finding || findings.length),
            },
            {
                key: "exported_bundle",
                label: "Export executive output for handoff",
                done: Boolean(state.exported_bundle),
            },
        ];
        el.onboardingChecklist.className = "onboarding-checklist";
        el.onboardingChecklist.innerHTML = steps.map((s) => `
            <article class="onboarding-step ${s.done ? "done" : ""}">
                <span class="onboarding-step-icon">${s.done ? "✓" : "○"}</span>
                <div class="meta">${escapeHtml(s.label)}</div>
            </article>
        `).join("");
    }

    function markOnboardingStep(stepKey) {
        const state = readJsonStore(STORE_KEYS.onboardingState, {});
        state[stepKey] = true;
        writeJsonStore(STORE_KEYS.onboardingState, state);
        renderOnboardingCard();
    }

    async function startGuidedMode() {
        if (el.maxPackets) el.maxPackets.value = "3000";
        if (el.includeRaw) el.includeRaw.checked = true;
        if (el.ftsIndex) el.ftsIndex.checked = true;
        if (el.flowsSort) el.flowsSort.value = "risk_desc";
        if (el.flowsRiskMin) el.flowsRiskMin.value = "3";
        switchView("overview");
        setStatus("loading", "Guided mode ready: load a PCAP or use demo context.");
    }

    async function loadDemoContext() {
        if (!currentRecordings.length) {
            await loadRecordings();
        }
        if (currentRecordings.length) {
            const candidate = currentRecordings[0];
            if (candidate && candidate.recording_id) {
                await loadRecording(String(candidate.recording_id));
                switchView("flows");
                markOnboardingStep("loaded_data");
                setStatus("success", `Demo context loaded from recording ${candidate.name || candidate.recording_id}.`);
                return;
            }
        }
        if (el.filter) el.filter.value = "http or dns or tls";
        if (el.search) el.search.value = "login token admin";
        if (el.flowsRiskMin) el.flowsRiskMin.value = "3";
        switchView("overview");
        setStatus("loading", "No recording available. Demo filters pre-filled; run analysis on a sample PCAP.");
    }

    function buildInstantDemoDataset() {
        const now = new Date();
        const ts = now.toISOString();
        const flowA = {
            id: "demo-flow-1",
            protocol: "HTTP",
            transport: "TCP",
            client: "10.10.10.12:54210",
            server: "10.10.10.5:8080",
            packet_count: 12,
            request_count: 4,
            response_count: 4,
            avg_packet_size: 412,
            protocol_confidence: 93,
            risk_score: 7,
            first_seen: ts,
            last_seen: ts,
            narrative: "Repeated login attempts expose cleartext token reuse.",
            request_preview: "POST /api/login",
            response_preview: "HTTP/1.1 200 OK",
            timeline: [{ request: "POST /api/login", response: "200 token=..." }],
            ioc_count: 2,
        };
        const flowB = {
            id: "demo-flow-2",
            protocol: "TLS",
            transport: "TCP",
            client: "10.10.10.20:52771",
            server: "172.16.10.2:443",
            packet_count: 20,
            request_count: 6,
            response_count: 6,
            avg_packet_size: 628,
            protocol_confidence: 88,
            risk_score: 4,
            first_seen: ts,
            last_seen: ts,
            narrative: "Outbound encrypted traffic to unusual SNI fingerprint.",
            request_preview: "ClientHello SNI=cdn-sync-update.net",
            response_preview: "ServerHello cert mismatch",
            timeline: [{ request: "TLS ClientHello", response: "TLS ServerHello" }],
            ioc_count: 1,
        };
        const mkPackets = (flow) => ([
            {
                number: 1201, timestamp: ts, direction: "request", src: flow.client, dst: flow.server, length: 320,
                protocol: flow.protocol, summary: flow.request_preview, fields: { host: "demo.local" }, payload_excerpt: "username=admin&password=demo",
                flow_packet_index: 0,
            },
            {
                number: 1202, timestamp: ts, direction: "response", src: flow.server, dst: flow.client, length: 512,
                protocol: flow.protocol, summary: flow.response_preview, fields: { status: "200" }, payload_excerpt: "token=eyJhbGciOiJIUzI1NiIsInR5cCI...",
                flow_packet_index: 1,
            },
        ]);
        demoFlowDetails = {
            [flowA.id]: {
                ...flowA,
                duration_seconds: 4.2,
                protocol_why: [{ reason: "HTTP verbs and headers", count: 7 }],
                iocs: { domains: ["demo.local"], tokens: ["eyJhbGci..."] },
                endpoint_map: { nodes: [{ id: "10.10.10.12", internal: true }, { id: "10.10.10.5", internal: true }], edges: [{ source: "10.10.10.12", target: "10.10.10.5", protocols: ["HTTP"], packets: 12 }] },
                risk_reasons: [{ severity: "high", points: 5, type: "cleartext_credentials_or_tokens", message: "Credentials found in payload", evidence: ["username/password pair in request"] }],
                framework_actions: [],
                protocol_views: { http: { requests: [{ method: "POST", host: "demo.local", uri: "/api/login" }], responses: [{ code: "200", phrase: "OK" }] } },
                replay_packets: mkPackets(flowA),
                replay_packets_total: 2,
                field_summary: { auth_fields: 2, token_hits: 1 },
                requests: [],
                responses: [],
            },
            [flowB.id]: {
                ...flowB,
                duration_seconds: 8.1,
                protocol_why: [{ reason: "TLS handshake signatures", count: 8 }],
                iocs: { domains: ["cdn-sync-update.net"] },
                endpoint_map: { nodes: [{ id: "10.10.10.20", internal: true }, { id: "172.16.10.2", internal: false }], edges: [{ source: "10.10.10.20", target: "172.16.10.2", protocols: ["TLS"], packets: 20 }] },
                risk_reasons: [{ severity: "medium", points: 3, type: "suspicious_field_lengths_or_anomalies", message: "Unusual JA3 profile", evidence: ["JA3 not in baseline"] }],
                framework_actions: [],
                protocol_views: { tls: { sni: [{ name: "cdn-sync-update.net", count: 4 }], ja3: [{ hash: "d4f31f..." , count: 3 }] } },
                replay_packets: mkPackets(flowB),
                replay_packets_total: 2,
                field_summary: { tls_client_hello: 1 },
                requests: [],
                responses: [],
            },
        };
        return {
            local_demo: true,
            session_id: "demo-session-kittyprotocol",
            processed_packets: 32,
            flow_count: 2,
            flows: [flowA, flowB],
            patterns: [
                { flow_id: flowA.id, type: "cleartext_credentials_or_tokens", severity: "high", message: "Credentials and token visible in cleartext", criticality_score: 9, occurrences: 2, evidence: ["POST /api/login payload"] },
                { flow_id: flowB.id, type: "suspicious_field_lengths_or_anomalies", severity: "medium", message: "JA3 fingerprint anomaly", criticality_score: 5, occurrences: 1, evidence: ["Unknown JA3 hash"] },
            ],
            suggestions: [],
            protocols: [{ protocol: "HTTP", flow_count: 1, packet_count: 12, risk_score: 7 }, { protocol: "TLS", flow_count: 1, packet_count: 20, risk_score: 4 }],
            pagination: { flows: { page: 1, total_pages: 1, total: 2, has_prev: false, has_next: false }, findings: { page: 1, total_pages: 1, total: 2, has_prev: false, has_next: false } },
            provenance: { source: "instant_demo", generated_at: ts },
            global_timeline: [],
            fts_indexed: true,
            iocs: { domains: ["demo.local", "cdn-sync-update.net"] },
            endpoint_map: {},
            decryption: { config: {}, items: [], tls_like_flows: 1, decryptable_candidates: 0, total_flows: 2 },
            pcap: "demo.pcapng",
            mode: "demo",
        };
    }

    async function runInstantDemo() {
        queryCache.clear();
        pagerState.flow_page = 1;
        pagerState.finding_page = 1;
        const data = buildInstantDemoDataset();
        applyAnalysis(data);
        switchView("flows");
        markOnboardingStep("loaded_data");
        setStatus("success", "Instant product demo loaded.");
    }

    function escapeHtml(value) {
        return String(value || "")
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;");
    }

    function renderList(items) {
        if (!items || !items.length) return "<div class='meta'>No</div>";
        return "<ul class='list compact'>" + items.map((item) => "<li>" + escapeHtml(item) + "</li>").join("") + "</ul>";
    }

    function uniqueBy(items, keyBuilder) {
        const seen = new Set();
        const output = [];
        for (const item of items || []) {
            const key = keyBuilder(item);
            if (seen.has(key)) continue;
            seen.add(key);
            output.push(item);
        }
        return output;
    }

    function limitWithMeta(items, limit) {
        const all = items || [];
        return {
            items: all.slice(0, limit),
            hidden: Math.max(0, all.length - limit),
            total: all.length,
        };
    }

    function switchView(viewName) {
        saveViewScroll(activeViewName);
        activeViewName = viewName;
        el.navItems.forEach((item) => {
            item.classList.toggle("active", item.dataset.view === viewName);
        });
        el.viewPanels.forEach((panel) => {
            panel.classList.toggle("active", panel.dataset.viewPanel === viewName);
        });
        restoreViewScroll(viewName);
        syncUrlState();
        if (viewName === "investigation") {
            refreshInvestigationPanel();
        }
        if (viewName === "decryption") {
            fetchDecryptionConfig();
            renderDecryptionPanel();
        }
        persistInvestigationContext();
    }

    function activeScrollElement(viewName) {
        if (viewName === "flows") return el.inspector;
        const panel = document.querySelector(`.view-panel[data-view-panel="${CSS.escape(String(viewName || ""))}"]`);
        return panel ? panel.querySelector(".view-scroll, .inv-column--scroll, .scroll-cards") : null;
    }

    function saveViewScroll(viewName) {
        const target = activeScrollElement(viewName);
        if (!target) return;
        viewScrollState[viewName] = { top: target.scrollTop || 0, left: target.scrollLeft || 0 };
    }

    function restoreViewScroll(viewName) {
        const target = activeScrollElement(viewName);
        const state = viewScrollState[viewName];
        if (!target || !state) return;
        scheduleScrollRestore(target, state.top, state.left);
    }

    function syncUrlState() {
        const params = new URLSearchParams(window.location.search);
        params.set("view", activeViewName);
        if (selectedFlowId) params.set("flow", selectedFlowId);
        else params.delete("flow");
        if (selectedFlowPacketIndex != null) params.set("frame", String(Number(selectedFlowPacketIndex) + 1));
        else params.delete("frame");
        const next = `${window.location.pathname}?${params.toString()}`;
        window.history.replaceState(null, "", next);
        persistInvestigationContext();
    }

    function isLiveActive() {
        return Boolean(currentAnalysis.live_capture && currentAnalysis.live_capture.running);
    }

    function showInvToast(message) {
        if (!inv.toast) return;
        inv.toast.textContent = String(message || "");
        inv.toast.classList.remove("hidden");
        window.clearTimeout(showInvToast._t);
        showInvToast._t = window.setTimeout(() => inv.toast.classList.add("hidden"), 3200);
    }

    async function copyText(text) {
        const t = String(text || "");
        try {
            await navigator.clipboard.writeText(t);
            showInvToast("Copied to clipboard.");
        } catch (_err) {
            showInvToast("Clipboard copy failed in this browser.");
        }
    }

    function attachPivotActions(root) {
        if (!root) return;
        root.querySelectorAll("[data-copy-text]").forEach((btn) => {
            btn.addEventListener("click", () => copyText(btn.getAttribute("data-copy-text") || ""));
        });
        root.querySelectorAll("[data-filter-host]").forEach((btn) => {
            btn.addEventListener("click", () => {
                if (!el.hostFilter) return;
                el.hostFilter.value = String(btn.getAttribute("data-filter-host") || "");
                pagerState.flow_page = 1;
                refreshQuery(isLiveActive());
            });
        });
        root.querySelectorAll("[data-filter-search]").forEach((btn) => {
            btn.addEventListener("click", () => {
                if (!el.search) return;
                el.search.value = String(btn.getAttribute("data-filter-search") || "");
                pagerState.finding_page = 1;
                refreshQuery(isLiveActive());
            });
        });
    }

    function buildViewFilterPayload() {
        const live = isLiveActive();
        return {
            ...currentFilters(live),
            pcap: "",
            bpf_offline: live ? "" : (el.bpf && el.bpf.value.trim()) || "",
            bpf_live: live ? (el.liveBpf && el.liveBpf.value.trim()) || "" : "",
            enable_fts: Boolean(el.ftsIndex && el.ftsIndex.checked),
            include_raw: Boolean(el.includeRaw.checked),
            max_packets: Number((live ? el.liveMaxPackets : el.maxPackets).value || 0),
            live_interface: live ? el.interfaceSelect.value : "",
        };
    }

    function applySavedViewFilters(f) {
        if (!f || typeof f !== "object") return;
        if (f.protocol_filter != null) el.protocolFilter.value = String(f.protocol_filter);
        if (f.severity_filter != null) el.severityFilter.value = String(f.severity_filter);
        if (f.host_filter != null) el.hostFilter.value = String(f.host_filter);
        if (f.port_filter != null) el.portFilter.value = String(f.port_filter);
        if (f.search != null) el.search.value = String(f.search);
        if (f.display_filter != null) el.filter.value = String(f.display_filter);
        if (f.bpf_offline != null && el.bpf) el.bpf.value = String(f.bpf_offline);
        if (f.enable_fts != null && el.ftsIndex) el.ftsIndex.checked = Boolean(f.enable_fts);
        if (f.max_packets != null && !isLiveActive()) el.maxPackets.value = String(f.max_packets);
        showInvToast("View filters applied (verify PCAP path then run analysis).");
    }

    function renderInvestigationProvenance() {
        if (!inv.sessionBadge || !inv.provenancePre) return;
        const sid = currentAnalysis.session_id || "";
        const prov = currentAnalysis.provenance;
        inv.sessionBadge.textContent = sid ? `session_id: ${sid}` : "No loaded session";
        if (!prov && !sid) {
            inv.provenancePre.textContent = "Run an offline or live analysis to display provenance.";
            inv.provenancePre.classList.add("empty-block");
            return;
        }
        inv.provenancePre.classList.remove("empty-block");
        const block = prov || { session_id: sid, note: "Detailed provenance unavailable for this session." };
        inv.provenancePre.textContent = JSON.stringify(block, null, 2);
    }

    function renderGlobalTimeline() {
        if (!inv.timelineList) return;
        const items = currentAnalysis.global_timeline || [];
        if (!items.length) {
            inv.timelineList.className = "scroll-cards timeline-cards empty";
            inv.timelineList.textContent = "No events (run an analysis).";
            return;
        }
        inv.timelineList.className = "scroll-cards timeline-cards";
        const cap = 400;
        const slice = items.slice(0, cap);
        inv.timelineList.innerHTML = slice.map((ev) => {
            const fid = escapeHtml(ev.flow_id || "");
            const summary = escapeHtml(ev.summary || "");
            const proto = escapeHtml(ev.protocol || "");
            const ts = escapeHtml(ev.timestamp || "");
            const kind = escapeHtml(ev.event_kind || "normal");
            return `<article class="card tl-row" data-tl-flow="${fid}" role="button" tabindex="0">
                <div class="tl-row-inner">
                    <div class="tl-time">${ts}</div>
                    <div class="tl-main">
                        <div class="tl-flow">${proto} · ${fid} <span class="pill">${kind}</span></div>
                        <div>${summary}</div>
                    </div>
                </div>
            </article>`;
        }).join("");
        inv.timelineList.querySelectorAll("[data-tl-flow]").forEach((row) => {
            const fid = row.getAttribute("data-tl-flow");
            const open = () => {
                if (!fid) return;
                if (inv.annFlow) inv.annFlow.value = fid;
                switchView("flows");
                selectFlow(fid);
            };
            row.addEventListener("click", open);
            row.addEventListener("keydown", (event) => {
                if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    open();
                }
            });
        });
    }

    async function refreshViewsList() {
        if (!inv.viewsList) return;
        try {
            const response = await fetch("/api/views");
            const data = await response.json();
            const views = data.views || [];
            if (!views.length) {
                inv.viewsList.className = "scroll-cards scroll-cards--compact empty";
                inv.viewsList.textContent = "No saved view.";
                return;
            }
            inv.viewsList.className = "scroll-cards scroll-cards--compact";
            inv.viewsList.innerHTML = views.map((v) => {
                const name = escapeHtml(v.name || v.id || "");
                const desc = escapeHtml(v.description || "");
                const id = escapeHtml(v.name || v.id || "");
                return `<article class="card">
                    <h4>${name}</h4>
                    <div class="meta">${desc || "—"}</div>
                    <div class="button-row button-row-split">
                        <button type="button" class="btn btn-secondary btn-compact" data-apply-view="${id}">Appliquer filters</button>
                        <button type="button" class="btn btn-secondary btn-compact" data-del-view="${id}">Supprimer</button>
                    </div>
                </article>`;
            }).join("");
            inv.viewsList.querySelectorAll("[data-apply-view]").forEach((btn) => {
                btn.addEventListener("click", async () => {
                    const id = btn.getAttribute("data-apply-view");
                    try {
                        const r = await fetch(`/api/views/${encodeURIComponent(id)}`);
                        const d = await r.json();
                        if (!r.ok || d.error) throw new Error(d.error || "Vue not found");
                        const view = d.view || {};
                        applySavedViewFilters(view.filters || {});
                    } catch (err) {
                        showInvToast(String(err.message || err));
                    }
                });
            });
            inv.viewsList.querySelectorAll("[data-del-view]").forEach((btn) => {
                btn.addEventListener("click", async () => {
                    const id = btn.getAttribute("data-del-view");
                    try {
                        const r = await fetch(`/api/views/${encodeURIComponent(id)}`, { method: "DELETE" });
                        const d = await r.json();
                        if (!r.ok) throw new Error(d.error || "Delete failed");
                        showInvToast("View deleted.");
                        await refreshViewsList();
                    } catch (err) {
                        showInvToast(String(err.message || err));
                    }
                });
            });
        } catch (error) {
            inv.viewsList.className = "scroll-cards scroll-cards--compact empty";
            inv.viewsList.textContent = String(error.message || error);
        }
    }

    async function saveCurrentView() {
        if (!inv.viewName || !inv.saveView) return;
        const name = inv.viewName.value.trim();
        if (!name) {
            showInvToast("Please provide a view name.");
            return;
        }
        try {
            const response = await fetch("/api/views", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    name,
                    description: (inv.viewDesc && inv.viewDesc.value.trim()) || "",
                    filters: buildViewFilterPayload(),
                }),
            });
            const data = await response.json();
            if (!response.ok || data.error) {
                throw new Error(data.error || "Unable to save view");
            }
            showInvToast(`View saved: ${data.view_id || name}`);
            inv.viewName.value = "";
            if (inv.viewDesc) inv.viewDesc.value = "";
            await refreshViewsList();
        } catch (error) {
            showInvToast(String(error.message || error));
        }
    }

    async function runCompareCaptures() {
        if (!inv.compareA || !inv.compareB || !inv.comparePre) return;
        const a = inv.compareA.value.trim();
        const b = inv.compareB.value.trim();
        if (!a || !b) {
            showInvToast("Provide two PCAP paths.");
            return;
        }
        inv.comparePre.textContent = "Comparison in progress...";
        inv.comparePre.classList.remove("empty-block");
        try {
            const response = await fetch("/api/compare", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ pcap_a: a, pcap_b: b, max_packets: Number(el.maxPackets.value || 2000) }),
            });
            const data = await response.json();
            if (!response.ok || data.error) {
                throw new Error(data.error || "Comparison failed");
            }
            inv.comparePre.innerHTML = renderPcapCompareResult(data);
        } catch (error) {
            inv.comparePre.textContent = String(error.message || error);
        }
    }

    function renderPcapCompareResult(data) {
        const c = data.compare || {};
        const added = c.added || [];
        const removed = c.removed || [];
        const changed = c.changed || c.changed_risk || [];
        const changedMetadata = c.changed_metadata || [];
        const changedProtocol = c.changed_protocol || [];
        const changedDestination = c.changed_destination || [];
        const summary = c.summary || {};
        const section = (title, rows) => `
            <div class="protocol-view" style="margin-bottom:8px;">
                <strong>${escapeHtml(title)} (${rows.length})</strong>
                <ul class="list">${rows.slice(0, 20).map((row) =>
                    row.before || row.after
                        ? `<li>${escapeHtml(row.key || "")} | pkt ${escapeHtml(row.before && row.before.packet_count || 0)}→${escapeHtml(row.after && row.after.packet_count || 0)} | risk ${escapeHtml(row.before && row.before.risk_score || 0)}→${escapeHtml(row.after && row.after.risk_score || 0)}</li>`
                        : `<li>${escapeHtml(row.protocol || row.id || "")} ${escapeHtml(row.client || "")} → ${escapeHtml(row.server || "")}</li>`
                ).join("") || "<li>—</li>"}</ul>
            </div>`;
        const sectionProtocol = (rows) => `
            <div class="protocol-view" style="margin-bottom:8px;">
                <strong>Protocol changes (${rows.length})</strong>
                <ul class="list">${rows.slice(0, 20).map((row) =>
                    `<li>${escapeHtml(row.client || "")} → ${escapeHtml(row.server || "")} : ${escapeHtml(row.before_protocol || "—")} → ${escapeHtml(row.after_protocol || "—")} (${escapeHtml(row.before_packets || 0)}→${escapeHtml(row.after_packets || 0)} pkt)</li>`
                ).join("") || "<li>—</li>"}</ul>
            </div>`;
        const sectionDestination = (rows) => `
            <div class="protocol-view" style="margin-bottom:8px;">
                <strong>Destination changes (${rows.length})</strong>
                <ul class="list">${rows.slice(0, 20).map((row) =>
                    `<li>${escapeHtml(row.client || "")} | + ${escapeHtml((row.added_servers || []).join(", ") || "—")} | - ${escapeHtml((row.removed_servers || []).join(", ") || "—")}</li>`
                ).join("") || "<li>—</li>"}</ul>
            </div>`;
        const sectionMetadata = (rows) => `
            <div class="protocol-view" style="margin-bottom:8px;">
                <strong>Metadata/field changes (${rows.length})</strong>
                <ul class="list">${rows.slice(0, 20).map((row) =>
                    `<li>${escapeHtml(row.client || "")} → ${escapeHtml(row.server || "")}: ${escapeHtml((row.changed_fields || []).map((f) => f.field).join(", ") || "—")}</li>`
                ).join("") || "<li>—</li>"}</ul>
            </div>`;
        return `
            <div class="meta" style="margin-bottom:8px;">A:${escapeHtml(summary.flows_a || 0)} · B:${escapeHtml(summary.flows_b || 0)} · +${escapeHtml(summary.added || 0)} · -${escapeHtml(summary.removed || 0)} · Δ${escapeHtml(summary.changed || 0)}</div>
            ${section("New flows", added)}
            ${section("Removed flows", removed)}
            ${section("Changed flows", changed)}
            ${sectionProtocol(changedProtocol)}
            ${sectionDestination(changedDestination)}
            ${sectionMetadata(changedMetadata)}
            <details class="filter-details"><summary>JSON complet</summary><pre class="code-box">${escapeHtml(JSON.stringify(data, null, 2))}</pre></details>
        `;
    }

    async function runFtsSearch() {
        if (!inv.ftsQuery || !inv.ftsHits) return;
        const q = inv.ftsQuery.value.trim();
        if (!q) {
            showInvToast("Enter an FTS query.");
            return;
        }
        inv.ftsHits.innerHTML = "Recherche…";
        inv.ftsHits.classList.remove("empty-block");
        try {
            const response = await fetch(`/api/search?q=${encodeURIComponent(q)}&limit=60`);
            const data = await response.json();
            const hits = data.hits || [];
            if (data.error && !hits.length) {
                inv.ftsHits.innerHTML = `<div class="meta">${escapeHtml(data.error)}</div>`;
                return;
            }
            if (!hits.length) {
                inv.ftsHits.classList.add("empty-block");
                inv.ftsHits.textContent = "No results.";
                return;
            }
            inv.ftsHits.classList.remove("empty-block");
            inv.ftsHits.innerHTML = hits.map((h) =>
                `<div class="inv-fts-hit" data-fts-flow="${escapeHtml(h.flow_id)}">` +
                `<strong>#${escapeHtml(h.packet_number)}</strong> ` +
                `<span class="meta">${escapeHtml(h.flow_id || "")}</span>` +
                `<div>${escapeHtml(h.snippet || "")}</div></div>`
            ).join("");
            inv.ftsHits.querySelectorAll("[data-fts-flow]").forEach((hit) => {
                hit.addEventListener("click", () => {
                    const fid = hit.getAttribute("data-fts-flow");
                    if (!fid) return;
                    if (inv.annFlow) inv.annFlow.value = fid;
                    switchView("flows");
                    selectFlow(fid);
                });
            });
        } catch (error) {
            inv.ftsHits.innerHTML = `<div class="meta">${escapeHtml(String(error.message || error))}</div>`;
        }
    }

    async function refreshAnnotationsList() {
        if (!inv.annList) return;
        const sid = currentAnalysis.session_id || "";
        if (!sid) {
            inv.annList.className = "scroll-cards scroll-cards--compact empty";
            inv.annList.textContent = "Run an analysis to link annotations to this session.";
            return;
        }
        try {
            const response = await fetch(`/api/annotations?session_id=${encodeURIComponent(sid)}`);
            const data = await response.json();
            const rows = data.annotations || [];
            if (!rows.length) {
                inv.annList.className = "scroll-cards scroll-cards--compact empty";
                inv.annList.textContent = "No annotation for this session.";
                return;
            }
            inv.annList.className = "scroll-cards scroll-cards--compact";
            inv.annList.innerHTML = rows.map((row) => `
                <article class="card">
                    <div class="meta">${escapeHtml(row.created_at || "")} · ${escapeHtml(row.flow_id || "")} · ${escapeHtml(row.status || "to verify")}${row.assignee ? ` · assignee ${escapeHtml(row.assignee)}` : ""}</div>
                    <p>${escapeHtml(row.note || "")}</p>
                    ${(row.tags && row.tags.length) ? `<div class="meta">Tags: ${escapeHtml(row.tags.join(", "))}</div>` : ""}
                    ${row.ticket_url ? `<a href="${encodeURI(String(row.ticket_url).trim())}" target="_blank" rel="noopener noreferrer">Ticket</a>` : ""}
                </article>
            `).join("");
        } catch (error) {
            inv.annList.className = "scroll-cards scroll-cards--compact empty";
            inv.annList.textContent = String(error.message || error);
        }
    }

    async function saveAnnotation() {
        if (!inv.annFlow || !inv.annNote) return;
        const flowId = inv.annFlow.value.trim();
        const note = inv.annNote.value.trim();
        if (!flowId || !note) {
            showInvToast("flow_id and note are required.");
            return;
        }
        const assignee = (inv.annAssignee && inv.annAssignee.value.trim()) || "";
        const tagsRaw = (inv.annTags && inv.annTags.value.trim()) || "";
        const tags = tagsRaw ? tagsRaw.split(",").map((t) => t.trim()).filter(Boolean) : [];
        try {
            const response = await fetch("/api/annotations", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    session_id: currentAnalysis.session_id || "",
                    flow_id: flowId,
                    note,
                    tags,
                    assignee,
                    ticket_url: (inv.annTicket && inv.annTicket.value.trim()) || "",
                    status: (inv.annStatus && inv.annStatus.value) || "to verify",
                }),
            });
            const data = await response.json();
            if (!response.ok || data.error) {
                throw new Error(data.error || "Unable to save annotation");
            }
            showInvToast("Annotation saved.");
            inv.annNote.value = "";
            if (inv.annAssignee) inv.annAssignee.value = "";
            await refreshAnnotationsList();
        } catch (error) {
            showInvToast(String(error.message || error));
        }
    }

    async function downloadBlobFrom(url, defaultName) {
        const response = await fetch(url);
        if (!response.ok) {
            let msg = "Export failed";
            try {
                const data = await response.json();
                msg = data.error || msg;
            } catch (_err) {}
            throw new Error(msg);
        }
        const blob = await response.blob();
        const objectUrl = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = objectUrl;
        a.download = defaultName;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(objectUrl);
    }

    async function exportIocs(format) {
        const params = new URLSearchParams({
            format: String(format || "json"),
            protocol_filter: (el.protocolFilter && el.protocolFilter.value || "").trim(),
            host_filter: (el.hostFilter && el.hostFilter.value || "").trim(),
        });
        const ext = String(format || "json").toLowerCase() === "csv" ? "csv" : "json";
        await downloadBlobFrom(`/api/iocs/export?${params.toString()}`, `kittyprotocol-iocs.${ext}`);
        showInvToast(`IOC ${ext.toUpperCase()} export ready.`);
    }

    async function exportCaseBundle() {
        const response = await fetch("/api/case-bundle");
        const data = await response.json();
        if (!response.ok || data.error) {
            throw new Error(data.error || "Case bundle export failed");
        }
        const sid = data.session_id || "session";
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
        const objectUrl = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = objectUrl;
        a.download = `kittyprotocol-case-bundle-${String(sid)}.json`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(objectUrl);
        showInvToast("Case bundle export ready.");
    }

    function refreshInvestigationPanel() {
        renderInvestigationProvenance();
        renderGlobalTimeline();
        refreshViewsList();
        refreshAnnotationsList();
    }

    function flowById(flowId) {
        return (currentAnalysis.flows || []).find((flow) => String(flow.id) === String(flowId)) || null;
    }

    function isPinned(flowId) {
        return pinnedFlowIds.includes(String(flowId));
    }

    function togglePinnedFlow(flowId) {
        const id = String(flowId || "");
        if (!id) return;
        if (isPinned(id)) {
            pinnedFlowIds = pinnedFlowIds.filter((item) => item !== id);
        } else {
            pinnedFlowIds = [id].concat(pinnedFlowIds.filter((item) => item !== id)).slice(0, 12);
        }
        writeJsonStore(STORE_KEYS.pinned, pinnedFlowIds);
        renderPinnedFlowsBar();
        renderFlows(currentAnalysis.flows || []);
        if (lastFlowDetail && lastFlowDetail.id === id) {
            renderInspector(lastFlowDetail, { keepPacketIndex: selectedFlowPacketIndex });
        }
    }

    function renderQuickFilters() {
        if (!el.quickFilterBar) return;
        const seen = new Set();
        const protocols = [];
        const preferred = ["TLS", "SSH", "DNS", "HTTP", "HTTP2", "QUIC"];
        for (const proto of preferred) {
            if (seen.has(proto)) continue;
            protocols.push(proto);
            seen.add(proto);
        }
        for (const item of (currentAnalysis.protocols || [])) {
            const proto = String(item.protocol || "").toUpperCase();
            if (!proto || seen.has(proto)) continue;
            protocols.push(proto);
            seen.add(proto);
            if (protocols.length >= 8) break;
        }
        const buttons = [
            { label: "Tous", type: "protocol", value: "" },
            ...protocols.slice(0, 8).map((proto) => ({ label: proto, type: "protocol", value: proto })),
            { label: "High risk", type: "risk", value: "5" },
            { label: "Pinned", type: "pinned", value: "1" },
        ];
        el.quickFilterBar.innerHTML = buttons.map((btn) => {
            const active =
                (btn.type === "protocol" && quickFilterState.protocol === btn.value) ||
                (btn.type === "risk" && quickFilterState.risk === btn.value) ||
                (btn.type === "pinned" && quickFilterState.pinnedOnly);
            return `<button type="button" class="quick-filter ${active ? "active" : ""}" data-qf-type="${escapeHtml(btn.type)}" data-qf-value="${escapeHtml(btn.value)}">${escapeHtml(btn.label)}</button>`;
        }).join("");
        el.quickFilterBar.querySelectorAll("[data-qf-type]").forEach((btn) => {
            btn.addEventListener("click", () => {
                const type = btn.getAttribute("data-qf-type");
                const value = btn.getAttribute("data-qf-value") || "";
                if (type === "protocol") quickFilterState.protocol = quickFilterState.protocol === value ? "" : value;
                if (type === "risk") quickFilterState.risk = quickFilterState.risk === value ? "all" : value;
                if (type === "pinned") quickFilterState.pinnedOnly = !quickFilterState.pinnedOnly;
                renderQuickFilters();
                renderFlows(currentAnalysis.flows || []);
            });
        });
    }

    function renderProfileBar() {
        if (!el.quickFilterBar) return;
        let bar = document.getElementById("profileBar");
        if (!bar) {
            bar = document.createElement("div");
            bar.id = "profileBar";
            bar.className = "profile-bar";
            el.quickFilterBar.parentElement.insertBefore(bar, el.quickFilterBar);
        }
        const profiles = [
            { id: "web_tls", label: "Profil Web/TLS", apply: () => ({ proto: "TLS,HTTP,HTTP2", risk: "all", search: "" }) },
            { id: "dns_hunt", label: "Profil DNS", apply: () => ({ proto: "DNS", risk: "all", search: "dns qname" }) },
            { id: "ssh", label: "Profil SSH", apply: () => ({ proto: "SSH", risk: "all", search: "ssh" }) },
            { id: "high_risk", label: "High-risk profile", apply: () => ({ proto: "", risk: "5", search: "" }) },
            { id: "volume", label: "Profil gros volume", apply: () => ({ proto: "", risk: "3", search: "bytes length" }) },
        ];
        bar.innerHTML = profiles.map((p) => `<button type="button" class="quick-filter" data-profile-id="${p.id}">${p.label}</button>`).join("");
        bar.querySelectorAll("[data-profile-id]").forEach((btn) => {
            btn.addEventListener("click", () => {
                const id = btn.getAttribute("data-profile-id");
                const profile = profiles.find((p) => p.id === id);
                if (!profile) return;
                const cfg = profile.apply();
                if (el.protocolFilter) el.protocolFilter.value = cfg.proto || "";
                if (el.search) el.search.value = cfg.search || "";
                if (el.flowsRiskMin) el.flowsRiskMin.value = cfg.risk || "all";
                quickFilterState.risk = cfg.risk || "all";
                quickFilterState.protocol = "";
                pagerState.flow_page = 1;
                pagerState.finding_page = 1;
                switchView("flows");
                renderQuickFilters();
                refreshQuery(isLiveActive());
            });
        });
    }

    function renderPinnedFlowsBar() {
        if (!el.pinnedFlowsBar) return;
        const pins = pinnedFlowIds.map(flowById).filter(Boolean);
        if (!pins.length) {
            el.pinnedFlowsBar.className = "pinned-flows-bar empty";
            el.pinnedFlowsBar.textContent = "No pinned flows.";
            return;
        }
        el.pinnedFlowsBar.className = "pinned-flows-bar";
        el.pinnedFlowsBar.innerHTML = pins.map((flow) => {
            const active = selectedFlowId === flow.id ? "active" : "";
            return `<button type="button" class="pin-chip ${active}" data-pin-open="${escapeHtml(flow.id)}">${escapeHtml(flow.protocol)} ${escapeHtml(flow.server || "")}</button>`;
        }).join("");
        el.pinnedFlowsBar.querySelectorAll("[data-pin-open]").forEach((btn) => {
            btn.addEventListener("click", () => {
                switchView("flows");
                selectFlow(btn.getAttribute("data-pin-open"));
            });
        });
    }

    async function setCompareSlot(slot, flowId) {
        if (!slot || !flowId) return;
        compareSlots[slot] = String(flowId);
        await renderCompareTray();
    }

    async function fetchFlowDetail(flowId) {
        if (lastFlowDetail && String(lastFlowDetail.id) === String(flowId)) {
            return lastFlowDetail;
        }
        const response = await fetch(`/api/flows/${encodeURIComponent(flowId)}`);
        const data = await response.json();
        if (!response.ok || data.error) {
            throw new Error(data.error || "Flows not found");
        }
        return data;
    }

    async function renderCompareTray() {
        if (!el.compareTray) return;
        const ids = [compareSlots.a, compareSlots.b].filter(Boolean);
        if (!ids.length) {
            el.compareTray.classList.add("hidden");
            el.compareTray.innerHTML = "";
            return;
        }
        el.compareTray.classList.remove("hidden");
        el.compareTray.innerHTML = "<div class='meta'>Comparison in progress...</div>";
        try {
            const details = await Promise.all(["a", "b"].map(async (slot) => {
                const id = compareSlots[slot];
                if (!id) return { slot, detail: null };
                return { slot, detail: await fetchFlowDetail(id) };
            }));
            el.compareTray.innerHTML = `
                <div class="sticky-row">
                    <strong>Flow comparison</strong>
                    <button type="button" class="tiny-action" id="compareClearBtn">Fermer</button>
                </div>
                <div class="compare-grid">
                    ${details.map(({ slot, detail }) => renderCompareCard(slot, detail)).join("")}
                </div>
            `;
            const clear = el.compareTray.querySelector("#compareClearBtn");
            if (clear) clear.addEventListener("click", () => {
                compareSlots = { a: null, b: null };
                renderCompareTray();
            });
            el.compareTray.querySelectorAll("[data-compare-open]").forEach((btn) => {
                btn.addEventListener("click", () => selectFlow(btn.getAttribute("data-compare-open")));
            });
        } catch (error) {
            el.compareTray.innerHTML = `<div class="meta">${escapeHtml(String(error.message || error))}</div>`;
        }
    }

    function renderCompareCard(slot, detail) {
        if (!detail) {
            return `<div class="compare-card"><strong>${slot.toUpperCase()}</strong><div class="meta">Choose a flow.</div></div>`;
        }
        const iocCount = Object.values(detail.iocs || {}).reduce((n, arr) => n + (arr || []).length, 0);
        return `<div class="compare-card">
            <div class="sticky-row">
                <strong>${slot.toUpperCase()} · ${escapeHtml(detail.protocol || "")}</strong>
                <button type="button" class="tiny-action" data-compare-open="${escapeHtml(detail.id)}">Ouvrir</button>
            </div>
            <div class="meta">${escapeHtml(detail.client || "")} → ${escapeHtml(detail.server || "")}</div>
            <div class="meta">Risk ${escapeHtml(detail.risk_score || 0)} · ${escapeHtml(detail.packet_count || 0)} packets · IOC ${iocCount}</div>
            <div class="meta">${escapeHtml(detail.narrative || "")}</div>
        </div>`;
    }

    function renderFlows(flows) {
        const listEl = el.flows;
        const savedTop = listEl.scrollTop;
        const savedLeft = listEl.scrollLeft;
        try {
            renderQuickFilters();
            renderPinnedFlowsBar();
            const allFlows = flows || [];
            const query = String(el.flowsQuickSearch && el.flowsQuickSearch.value || "").trim().toLowerCase();
            const minRiskRaw = String(el.flowsRiskMin && el.flowsRiskMin.value || "all");
            const mergedRisk = quickFilterState.risk !== "all" ? quickFilterState.risk : minRiskRaw;
            const minRisk = mergedRisk === "all" ? null : Number(mergedRisk || 0);
            const sortMode = String(el.flowsSort && el.flowsSort.value || "risk_desc");

            let prepared = allFlows.filter((flow) => {
                if (quickFilterState.protocol && String(flow.protocol || "").toUpperCase() !== quickFilterState.protocol.toUpperCase()) {
                    return false;
                }
                if (quickFilterState.pinnedOnly && !isPinned(flow.id)) {
                    return false;
                }
                if (minRisk != null && Number(flow.risk_score || 0) < minRisk) {
                    return false;
                }
                if (!query) {
                    return true;
                }
                const blob = [
                    flow.protocol,
                    flow.transport,
                    flow.client,
                    flow.server,
                    flow.request_preview,
                    flow.response_preview,
                ].join(" ").toLowerCase();
                return blob.includes(query);
            });

            prepared = prepared.slice().sort((a, b) => {
                if (sortMode === "packets_desc") {
                    return Number(b.packet_count || 0) - Number(a.packet_count || 0);
                }
                if (sortMode === "latest_desc") {
                    return String(b.last_seen || "").localeCompare(String(a.last_seen || ""));
                }
                if (sortMode === "protocol_asc") {
                    return String(a.protocol || "").localeCompare(String(b.protocol || ""));
                }
                const riskDelta = Number(b.risk_score || 0) - Number(a.risk_score || 0);
                if (riskDelta !== 0) {
                    return riskDelta;
                }
                return Number(b.packet_count || 0) - Number(a.packet_count || 0);
            });

            const dynamicFlowLimit = Math.max(LIMITS.flows, flowRenderLimit);
            const limited = limitWithMeta(prepared, dynamicFlowLimit);
            if (!limited.items.length) {
                listEl.className = "scroll-cards empty";
                listEl.textContent = allFlows.length
                    ? "No flows match the local filters (search/sort/risk)."
                    : "No flows found (filters may be too strict).";
                return;
            }
            listEl.className = "scroll-cards";
            const notice = limited.hidden > 0
                ? `<article class="card"><div class="meta">Showing ${limited.items.length} of ${limited.total} flows.</div></article>`
                : "";
            listEl.innerHTML = notice + limited.items.map((flow) => {
                const timeline = (flow.timeline || []).slice(0, LIMITS.timeline).map((entry) =>
                    "<li>" + escapeHtml(entry.request || "request") + (entry.response ? " → " + escapeHtml(entry.response) : "") + "</li>"
                ).join("");
                const risk = Number(flow.risk_score || 0);
                const riskClass = risk >= 5 ? "high" : risk >= 3 ? "medium" : "low";
                const pinned = isPinned(flow.id);
                const iocCount = Number(flow.ioc_count || 0);
                return `
                <article class="card selectable ${selectedFlowId === flow.id ? "active" : ""}" data-flow-id="${escapeHtml(flow.id)}">
                    <h3>${escapeHtml(flow.protocol)} <span class="pill">${escapeHtml(flow.transport)}</span> <span class="risk-pill ${riskClass}">risk ${escapeHtml(flow.risk_score || 0)}</span>${iocCount ? ` <span class="pill">IOC ${iocCount}</span>` : ""}</h3>
                    <div class="meta">Protocol confidence: ${escapeHtml(flow.protocol_confidence || 0)}%</div>
                    <div class="meta">${escapeHtml(flow.client)} → ${escapeHtml(flow.server)}</div>
                    <div class="meta">Packets ${escapeHtml(flow.packet_count)} · req ${escapeHtml(flow.request_count)} · resp ${escapeHtml(flow.response_count)} · avg ${escapeHtml(flow.avg_packet_size)} bytes</div>
                    <div class="meta">First / last: ${escapeHtml(flow.first_seen || "—")} → ${escapeHtml(flow.last_seen || "—")}</div>
                    <div class="meta">Request preview: ${escapeHtml(flow.request_preview || "n/a")}</div>
                    <div class="meta">Response preview: ${escapeHtml(flow.response_preview || "n/a")}</div>
                    <div class="meta">${escapeHtml(flow.narrative || "")}</div>
                    ${timeline ? `<ul class="list compact">${timeline}</ul>` : `<div class="meta">No synthesized HTTP timeline.</div>`}
                    <div class="flow-card-actions">
                        <button type="button" class="tiny-action" data-pin-flow="${escapeHtml(flow.id)}">${pinned ? "Unpin" : "Pin"}</button>
                        <button type="button" class="tiny-action" data-compare-a="${escapeHtml(flow.id)}">Compare A</button>
                        <button type="button" class="tiny-action" data-compare-b="${escapeHtml(flow.id)}">Compare B</button>
                        <button type="button" class="tiny-action" data-copy-text="${escapeHtml(flow.client || "")}">Copy client</button>
                        <button type="button" class="tiny-action" data-copy-text="${escapeHtml(flow.server || "")}">Copy server</button>
                        <button type="button" class="tiny-action" data-pivot-proto="${escapeHtml(flow.protocol || "")}">Filter proto</button>
                    </div>
                </article>
            `;
            }).join("");
            if (limited.hidden > 0) {
                listEl.insertAdjacentHTML("beforeend", `<article class="card"><button type="button" class="btn btn-secondary" id="loadMoreFlowsBtn">Load ${Math.min(limited.hidden, 80)} more flows</button></article>`);
            }
            listEl.querySelectorAll("[data-flow-id]").forEach((card) => {
                card.addEventListener("click", () => {
                    selectFlow(card.getAttribute("data-flow-id"));
                });
            });
            listEl.querySelectorAll("[data-pin-flow], [data-compare-a], [data-compare-b], [data-copy-text], [data-pivot-proto]").forEach((btn) => {
                btn.addEventListener("click", (event) => {
                    event.stopPropagation();
                    const pin = btn.getAttribute("data-pin-flow");
                    const a = btn.getAttribute("data-compare-a");
                    const b = btn.getAttribute("data-compare-b");
                    const copyTxt = btn.getAttribute("data-copy-text");
                    const pivotProto = btn.getAttribute("data-pivot-proto");
                    if (pin) togglePinnedFlow(pin);
                    if (a) setCompareSlot("a", a);
                    if (b) setCompareSlot("b", b);
                    if (copyTxt) copyText(copyTxt);
                    if (pivotProto && el.protocolFilter) {
                        el.protocolFilter.value = String(pivotProto || "").toLowerCase();
                        pagerState.flow_page = 1;
                        refreshQuery(isLiveActive());
                    }
                });
            });
            const more = listEl.querySelector("#loadMoreFlowsBtn");
            if (more) {
                more.addEventListener("click", () => {
                    flowRenderLimit += 80;
                    renderFlows(currentAnalysis.flows || []);
                });
            }
        } finally {
            scheduleScrollRestore(listEl, savedTop, savedLeft);
        }
    }

    function renderPatterns(patterns) {
        const suggestionMap = new Map();
        for (const s of (currentAnalysis.suggestions || [])) {
            const key = `${String(s.flow_id || "")}|${String(s.pattern || "")}`;
            if (!suggestionMap.has(key)) suggestionMap.set(key, s);
        }
        const deduped = uniqueBy(patterns, (pattern) => [
            pattern.flow_id || "",
            pattern.type || "",
            pattern.severity || "",
            pattern.message || "",
        ].join("|"));
        const dynamicFindingLimit = Math.max(LIMITS.patterns, findingRenderLimit);
        const limited = limitWithMeta(deduped, dynamicFindingLimit);
        if (!limited.items.length) {
            el.patterns.className = "scroll-cards empty";
            el.patterns.textContent = "No signal.";
            return;
        }
        el.patterns.className = "scroll-cards";
        const notice = limited.hidden > 0
            ? `<article class="card"><div class="meta">${limited.items.length} of ${limited.total} findings shown.</div></article>`
            : "";
        el.patterns.innerHTML = notice + limited.items.map((pattern) => {
            const sug = suggestionMap.get(`${String(pattern.flow_id || "")}|${String(pattern.type || "")}`) || {};
            const pb = sug.playbook || {};
            const checklist = (pb.checklist || []).map((line) => `<li>${escapeHtml(line)}</li>`).join("");
            const mods = (pb.modules_in_order || []).map((m) =>
                `<li><code>${escapeHtml(m.module || "")}</code> - ${escapeHtml(m.reason || "")}</li>`
            ).join("");
            return `
            <article class="card">
                <div class="pill ${escapeHtml(pattern.severity)}">${escapeHtml(pattern.severity)}</div>
                <h3>${escapeHtml(pattern.type)}</h3>
                <div class="meta">${escapeHtml(pattern.message)}</div>
                <div class="meta">Criticality score: ${escapeHtml(pattern.criticality_score || 0)}${pattern.occurrences ? ` · occurrences ${escapeHtml(pattern.occurrences)}` : ""}</div>
                <div class="flow-card-actions">
                    <button type="button" class="tiny-action" data-open-flow="${escapeHtml(pattern.flow_id || "")}">Open flow</button>
                    <button type="button" class="tiny-action" data-annotate-finding="${escapeHtml(utf8ToB64(JSON.stringify({
                        flow_id: pattern.flow_id || "",
                        type: pattern.type || "",
                        message: pattern.message || "",
                        severity: pattern.severity || "",
                    })))}">Create annotation draft</button>
                </div>
                ${renderList((pattern.evidence || []).slice(0, LIMITS.evidence))}
                ${((sug.possible_vulnerabilities || []).length || (sug.attack_ideas || []).length || (sug.next_steps || []).length) ? `
                    <div class="finding-actions">
                        ${(sug.possible_vulnerabilities || []).length ? `<div class="finding-action"><div class="meta finding-action-title">Possible vulnerabilities</div>${renderList((sug.possible_vulnerabilities || []).slice(0, LIMITS.evidence))}</div>` : ""}
                        ${(sug.attack_ideas || []).length ? `<div class="finding-action"><div class="meta finding-action-title">Attack ideas</div>${renderList((sug.attack_ideas || []).slice(0, LIMITS.evidence))}</div>` : ""}
                        ${(sug.next_steps || []).length ? `<div class="finding-action"><div class="meta finding-action-title">Next steps</div>${renderList((sug.next_steps || []).slice(0, LIMITS.evidence))}</div>` : ""}
                    </div>
                ` : ""}
                ${(checklist || mods) ? `<details class="playbook-box"><summary>Playbook: ${escapeHtml(pb.title || pattern.type || "details")}</summary><p class="meta">Checklist</p><ul class="list">${checklist || "<li>-</li>"}</ul><p class="meta">Suggested modules (order)</p><ul class="list">${mods || "<li>-</li>"}</ul></details>` : ""}
            </article>`;
        }).join("");
        el.patterns.querySelectorAll("[data-open-flow]").forEach((btn) => {
            btn.addEventListener("click", () => {
                const flowId = String(btn.getAttribute("data-open-flow") || "").trim();
                if (!flowId) return;
                switchView("flows");
                selectFlow(flowId);
            });
        });
        el.patterns.querySelectorAll("[data-annotate-finding]").forEach((btn) => {
            btn.addEventListener("click", () => {
                const payload = b64ToUtf8(String(btn.getAttribute("data-annotate-finding") || ""));
                if (!payload) return;
                try {
                    const finding = JSON.parse(payload);
                    if (inv.annFlow) inv.annFlow.value = String(finding.flow_id || "");
                    if (inv.annNote) {
                        const sev = String(finding.severity || "").toUpperCase();
                        inv.annNote.value = `[${sev}] ${finding.type || "Finding"} - ${finding.message || ""}`.trim();
                    }
                    if (inv.annStatus) inv.annStatus.value = "to verify";
                    switchView("investigation");
                    showInvToast("Annotation draft prepared from finding.");
                    markOnboardingStep("reviewed_finding");
                } catch (_err) {
                    showInvToast("Unable to prepare annotation draft.");
                }
            });
        });
        if (limited.hidden > 0) {
            el.patterns.insertAdjacentHTML("beforeend", `<article class="card"><button type="button" class="btn btn-secondary" id="loadMoreFindingsBtn">Load ${Math.min(limited.hidden, 80)} more findings</button></article>`);
            const more = el.patterns.querySelector("#loadMoreFindingsBtn");
            if (more) {
                more.addEventListener("click", () => {
                    findingRenderLimit += 80;
                    renderPatterns(deduped);
                });
            }
        }
    }

    function renderRecordings(items) {
        const recordings = items || [];
        if (!recordings.length) {
            el.recordings.className = "scroll-cards scroll-cards--compact empty";
            el.recordings.textContent = "No saved session.";
            el.replayRecordingSelect.innerHTML = "<option value=''>No session</option>";
            el.replayFlowSelect.innerHTML = "<option value=''>All flows</option>";
            return;
        }
        el.recordings.className = "scroll-cards scroll-cards--compact";
        el.recordings.innerHTML = recordings.map((item) => `
            <article class="card">
                <h3>${escapeHtml(item.name || item.recording_id)}</h3>
                <div class="meta">${escapeHtml(item.created_at || "")} | ${escapeHtml(item.source_type || "analysis")}</div>
                <div class="meta">Flows: ${escapeHtml(item.flow_count || 0)} | Packets: ${escapeHtml(item.processed_packets || 0)}</div>
                <div class="meta">${escapeHtml((item.protocols || []).join(", ") || "—")}</div>
                <div class="button-row button-row-split">
                    <button class="btn btn-secondary" type="button" data-load-recording="${escapeHtml(item.recording_id)}">Load</button>
                    <button class="btn btn-primary" type="button" data-pick-replay="${escapeHtml(item.recording_id)}">Replay</button>
                </div>
            </article>
        `).join("");
        el.replayRecordingSelect.innerHTML = recordings.map((item) =>
            `<option value="${escapeHtml(item.recording_id)}">${escapeHtml(item.name || item.recording_id)}</option>`
        ).join("");
        el.recordings.querySelectorAll("[data-load-recording]").forEach((button) => {
            button.addEventListener("click", () => loadRecording(button.getAttribute("data-load-recording")));
        });
        el.recordings.querySelectorAll("[data-pick-replay]").forEach((button) => {
            button.addEventListener("click", async () => {
                el.replayRecordingSelect.value = button.getAttribute("data-pick-replay");
                await loadReplayContext();
            });
        });
    }

    function renderReplayEvents(events) {
        if (events) {
            lastReplayEvents = events;
        }
        const direction = String(el.replayDirection && el.replayDirection.value || "");
        const source = events || lastReplayEvents || [];
        const items = direction ? source.filter((event) => String(event.direction || "") === direction) : source;
        if (!items.length) {
            el.replayEvents.className = "scroll-cards scroll-cards--compact empty";
            el.replayEvents.textContent = "No replay event.";
            return;
        }
        el.replayEvents.className = "scroll-cards scroll-cards--compact";
        el.replayEvents.innerHTML = items.map((event) => `
            <article class="card">
                <div class="meta">#${escapeHtml(event.index)} | ${escapeHtml(event.timestamp || "")} | ${escapeHtml(event.direction || "")}</div>
                <h3>${escapeHtml(event.protocol || "UNKNOWN")} ${escapeHtml(event.summary || "")}</h3>
                <div class="meta">${escapeHtml(event.src || "")} -> ${escapeHtml(event.dst || "")} | ${escapeHtml(event.length || 0)} bytes</div>
                ${event.payload_excerpt ? `<div class="payload-box">${escapeHtml(event.payload_excerpt)}</div>` : ""}
                ${renderKeyValues(event.fields || {})}
            </article>
        `).join("");
    }

    function renderDecryptionPanel() {
        if (!el.decItems || !el.decSummary) return;
        const cfg = decryptionState.config || {};
        const items = decryptionState.items || [];
        const keylog = String(cfg.tls_keylog_path || "");
        if (el.decTlsKeylog && document.activeElement !== el.decTlsKeylog) {
            el.decTlsKeylog.value = keylog;
        }
        if (el.decPersistSecrets) {
            el.decPersistSecrets.checked = Boolean(cfg.persist_secrets);
        }
        if (keylog) {
            setDecryptionStatus(cfg.tls_keylog_exists ? "success" : "error", cfg.tls_keylog_exists ? "Keylog path is configured." : "Keylog path does not exist.");
        } else {
            setDecryptionStatus("idle", "No TLS keylog configured.");
        }
        const notes = (decryptionState.notes || []).slice(0, 2).join(" ");
        const keylogChecks = decryptionState.keylog_checks || {};
        const keylogHint = keylogChecks.exists
            ? ` | keylog: ok (${keylogChecks.size_bytes || 0} bytes)`
            : " | keylog: missing/empty";
        el.decSummary.textContent = `Engine: ${decryptionState.engine || "scapy_only"} | Flows: ${decryptionState.total_flows || 0} | TLS-like: ${decryptionState.tls_like_flows || 0} | decryptable candidates: ${decryptionState.decryptable_candidates || 0} (${decryptionState.decryptable_coverage_pct || 0}%)${keylogHint}${notes ? " | " + notes : ""}`;
        if (!items.length) {
            el.decItems.className = "scroll-cards empty";
            el.decItems.textContent = "No TLS-like flows in current result.";
            return;
        }
        el.decItems.className = "scroll-cards";
        el.decItems.innerHTML = items.slice(0, 100).map((row) => `
            <article class="card selectable" data-dec-flow="${escapeHtml(row.flow_id || "")}">
                <h3>${escapeHtml(row.protocol || "")} ${escapeHtml(row.client || "")} -> ${escapeHtml(row.server || "")}</h3>
                <div class="meta">${escapeHtml(row.status || "")}</div>
                ${row.reason_code ? `<div class="meta">${escapeHtml(row.reason_code)}</div>` : ""}
                <div class="meta">${escapeHtml(row.reason || "")}</div>
                ${row.tls_sni ? `<div class="meta">SNI: ${escapeHtml(row.tls_sni)}</div>` : ""}
                ${row.tls_ja3 ? `<div class="meta">JA3: ${escapeHtml(row.tls_ja3)}</div>` : ""}
                ${row.tls_cert_subject ? `<div class="meta">Cert subject: ${escapeHtml(row.tls_cert_subject)}</div>` : ""}
                ${row.tls_cert_issuer ? `<div class="meta">Cert issuer: ${escapeHtml(row.tls_cert_issuer)}</div>` : ""}
                ${row.tls_cert_validity ? `<div class="meta">Cert validity: ${escapeHtml(row.tls_cert_validity)}</div>` : ""}
                ${row.next_action ? `<div class="meta"><strong>Next:</strong> ${escapeHtml(row.next_action)}</div>` : ""}
                ${(row.diagnostics || []).length ? `<ul class="list compact">${(row.diagnostics || []).slice(0, 5).map((d) => `<li>${escapeHtml(d)}</li>`).join("")}</ul>` : ""}
            </article>
        `).join("");
        el.decItems.querySelectorAll("[data-dec-flow]").forEach((card) => {
            card.addEventListener("click", () => {
                const fid = card.getAttribute("data-dec-flow");
                if (!fid) return;
                switchView("flows");
                selectFlow(fid);
            });
        });
    }

    async function fetchDecryptionConfig() {
        try {
            const response = await fetch("/api/decryption/config");
            const data = await response.json();
            if (!response.ok || data.error) throw new Error(data.error || "Failed to load decryption config");
            decryptionState.config = data || {};
            renderDecryptionPanel();
        } catch (error) {
            setDecryptionStatus("error", String(error.message || error));
        }
    }

    async function saveDecryptionConfig() {
        if (!el.decTlsKeylog) return;
        try {
            const response = await fetch("/api/decryption/config", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    tls_keylog_path: String(el.decTlsKeylog.value || "").trim(),
                    persist_secrets: Boolean(el.decPersistSecrets && el.decPersistSecrets.checked),
                }),
            });
            const data = await response.json();
            if (!response.ok || data.error) throw new Error(data.error || "Failed to save decryption config");
            decryptionState.config = data.config || {};
            renderDecryptionPanel();
        } catch (error) {
            setDecryptionStatus("error", String(error.message || error));
        }
    }

    async function clearDecryptionConfig() {
        try {
            const response = await fetch("/api/decryption/config", { method: "DELETE" });
            const data = await response.json();
            if (!response.ok || data.error) throw new Error(data.error || "Failed to clear decryption config");
            decryptionState.config = data.config || {};
            renderDecryptionPanel();
        } catch (error) {
            setDecryptionStatus("error", String(error.message || error));
        }
    }

    function globalSearchItems(query) {
        const q = String(query || "").trim().toLowerCase();
        if (!q) return [];
        const items = [];
        for (const flow of currentAnalysis.flows || []) {
            const blob = [
                flow.id,
                flow.protocol,
                flow.client,
                flow.server,
                flow.request_preview,
                flow.response_preview,
                flow.narrative,
                JSON.stringify(flow.iocs || {}),
            ].join(" ").toLowerCase();
            if (blob.includes(q)) {
                items.push({ kind: "Flows", title: `${flow.protocol} ${flow.client} -> ${flow.server}`, meta: flow.narrative || flow.id, flow_id: flow.id });
            }
        }
        for (const pattern of currentAnalysis.patterns || []) {
            const blob = [pattern.type, pattern.message, pattern.flow_id, (pattern.evidence || []).join(" ")].join(" ").toLowerCase();
            if (blob.includes(q)) {
                items.push({ kind: "Signal", title: `${pattern.severity || ""} ${pattern.type || ""}`, meta: pattern.message || "", flow_id: pattern.flow_id });
            }
        }
        const iocs = currentAnalysis.iocs || {};
        for (const [kind, values] of Object.entries(iocs)) {
            for (const value of values || []) {
                if (String(value).toLowerCase().includes(q)) {
                    items.push({ kind: "IOC", title: `${kind}: ${value}`, meta: "IOC extracted from current session", flow_id: "" });
                }
            }
        }
        return items.slice(0, 40);
    }

    function parseOmniboxQuery(query) {
        const tokens = String(query || "").trim().split(/\s+/).filter(Boolean);
        const out = { text: [], fields: {} };
        for (const tok of tokens) {
            const m = tok.match(/^([a-z_]+)\:(.+)$/i);
            if (!m) {
                out.text.push(tok);
                continue;
            }
            const key = String(m[1] || "").toLowerCase();
            const value = String(m[2] || "").trim();
            if (!value) continue;
            out.fields[key] = value;
        }
        return out;
    }

    function applyOmniboxQuery(rawQuery) {
        const parsed = parseOmniboxQuery(rawQuery);
        const f = parsed.fields || {};
        const free = parsed.text.join(" ").trim();
        const searchTerms = [];
        if (free) searchTerms.push(free);
        if (f.sni) searchTerms.push(`tls.sni ${f.sni}`);
        if (f.dns) searchTerms.push(`dns.qname ${f.dns}`);
        if (f.payload) searchTerms.push(f.payload);
        if (f.proto && el.protocolFilter) {
            el.protocolFilter.value = f.proto.toUpperCase();
        }
        if (f.risk && el.flowsRiskMin) {
            const rv = String(f.risk).replace(">=", "");
            el.flowsRiskMin.value = ["1", "3", "5"].includes(rv) ? rv : "all";
            quickFilterState.risk = ["1", "3", "5"].includes(rv) ? rv : "all";
        }
        if (f.ip && el.hostFilter) el.hostFilter.value = f.ip;
        if (f.port && el.portFilter) el.portFilter.value = f.port;
        if (el.search) el.search.value = searchTerms.join(" ").trim();
        pagerState.flow_page = 1;
        pagerState.finding_page = 1;
        const view = f.view || "flows";
        switchView(view);
        refreshQuery(isLiveActive());
        if (f.flow) {
            selectedFlowId = f.flow;
            selectFlow(f.flow, true);
        }
        if (f.frame && Number.isFinite(Number(f.frame))) {
            selectedFlowPacketIndex = Math.max(0, Number(f.frame) - 1);
            if (lastFlowDetail) refreshPacketTableUi(false);
        }
    }

    function renderGlobalSearchResults() {
        if (!el.globalSearch || !el.globalSearchResults) return;
        const q = el.globalSearch.value || "";
        const items = globalSearchItems(q);
        if (!String(q).trim()) {
            el.globalSearchResults.classList.add("hidden");
            el.globalSearchResults.innerHTML = "";
            return;
        }
        if (!items.length) {
            el.globalSearchResults.classList.remove("hidden");
            el.globalSearchResults.innerHTML = "<div class='meta' style='padding:8px;'>No results.</div>";
            return;
        }
        el.globalSearchResults.classList.remove("hidden");
        el.globalSearchResults.innerHTML = items.map((item) => `
            <button type="button" class="global-result" data-global-flow="${escapeHtml(item.flow_id || "")}">
                <strong>${escapeHtml(item.kind)}</strong> · ${escapeHtml(item.title)}
                <div class="meta">${escapeHtml(item.meta || "")}</div>
            </button>
        `).join("");
        el.globalSearchResults.querySelectorAll("[data-global-flow]").forEach((btn) => {
            btn.addEventListener("click", () => {
                const fid = btn.getAttribute("data-global-flow");
                el.globalSearchResults.classList.add("hidden");
                if (fid) {
                    switchView("flows");
                    selectFlow(fid);
                } else {
                    switchView("investigation");
                }
            });
        });
    }

    function hydrateHeavyStatsAsync() {
        const params = new URLSearchParams({
            protocol_filter: (el.protocolFilter && el.protocolFilter.value || "").trim(),
            host_filter: (el.hostFilter && el.hostFilter.value || "").trim(),
        });
        window.setTimeout(async () => {
            try {
                const response = await fetch(`/api/iocs?${params.toString()}`);
                const data = await response.json();
                if (!response.ok || data.error) return;
                if (data.iocs) currentAnalysis.iocs = data.iocs;
            } catch (_err) {
                /* silent background refresh */
            }
        }, 0);
    }

    function applyAnalysis(data) {
        if (!data || !data.local_demo) {
            demoFlowDetails = null;
        }
        currentAnalysis = {
            flows: data.flows || [],
            patterns: data.patterns || [],
            suggestions: data.suggestions || [],
            processed_packets: data.processed_packets,
            live_capture: data.live_capture,
            flow_count: data.flow_count,
            protocols: data.protocols || [],
            pagination: data.pagination || {},
            session_id: data.session_id || "",
            provenance: data.provenance || null,
            global_timeline: data.global_timeline || [],
            fts_indexed: Boolean(data.fts_indexed),
            local_demo: Boolean(data.local_demo),
            iocs: data.iocs || {},
            endpoint_map: data.endpoint_map || {},
            decryption: data.decryption || {},
            pcap: data.pcap || "",
            mode: data.mode || "",
        };
        decryptionState = {
            ...(data.decryption || {}),
            config: (data.decryption && data.decryption.config) || decryptionState.config || {},
            items: (data.decryption && data.decryption.items) || [],
        };
        const flowCount = Number(data.flow_count || 0);
        const uniquePatterns = uniqueBy(data.patterns || [], (pattern) => [
            pattern.flow_id || "",
            pattern.type || "",
            pattern.message || "",
        ].join("|"));
        el.flowCount.textContent = String(flowCount);
        el.patternCount.textContent = String(uniquePatterns.length);
        const navFc = document.getElementById("navFindingCount");
        if (navFc) navFc.textContent = String(uniquePatterns.length);
        el.packetCount.textContent = String(data.processed_packets || data.live_capture?.processed_packets || 0);
        renderProtocolStats(currentAnalysis.protocols);
        renderQuickFilters();
        renderProfileBar();
        renderPinnedFlowsBar();
        renderFlows(currentAnalysis.flows);
        renderPatterns(uniquePatterns);
        renderMissionControl();
        markOnboardingStep("loaded_data");
        renderOnboardingCard();
        const pg = currentAnalysis.pagination || {};
        const flowTotal = pg.flows && typeof pg.flows.total === "number" ? pg.flows.total : flowCount;
        el.datasetHint.textContent = flowTotal > LIMITS.flows
            ? `The list is truncated to ${LIMITS.flows} cards: use pagination to view more.`
            : "Summary aligned with filters and current page.";
        renderPager(pg);
        renderDecryptionPanel();
        renderGlobalSearchResults();
        const availableIds = new Set((data.flows || []).map((flow) => flow.id));
        if (selectedFlowId && !availableIds.has(selectedFlowId)) {
            selectedFlowId = null;
            renderInspectorEmpty();
        }
        if (!selectedFlowId && (data.flows || []).length) {
            selectFlow(data.flows[0].id);
        } else if (selectedFlowId) {
            const liveRunning = Boolean(data.live_capture && data.live_capture.running);
            /* In live mode, avoid reloading inspector automatically to preserve scroll. */
            if (!liveRunning) {
                selectFlow(selectedFlowId, true);
            }
        }
        const invPanel = document.querySelector('.view-panel[data-view-panel="investigation"]');
        if (invPanel && invPanel.classList.contains("active")) {
            refreshInvestigationPanel();
        }
        hydrateHeavyStatsAsync();
        persistInvestigationContext();
    }

    function renderPager(pagination) {
        const flows = pagination.flows || {};
        const findings = pagination.findings || {};
        el.flowPagerMeta.textContent = `Flows ${flows.page || 1} / ${flows.total_pages || 1} — ${flows.total ?? 0}`;
        el.findingPagerMeta.textContent = `Findings ${findings.page || 1} / ${findings.total_pages || 1} — ${findings.total ?? 0}`;
        el.flowPrev.disabled = flows.has_prev !== true;
        el.flowNext.disabled = flows.has_next !== true;
        el.findingPrev.disabled = findings.has_prev !== true;
        el.findingNext.disabled = findings.has_next !== true;
    }

    function currentFilters(isLive) {
        const liveMode = Boolean(isLive);
        return {
            protocol_filter: (liveMode ? el.liveProtocolFilter.value : el.protocolFilter.value).trim(),
            severity_filter: liveMode ? "" : el.severityFilter.value.trim(),
            host_filter: liveMode ? "" : el.hostFilter.value.trim(),
            port_filter: liveMode ? "" : el.portFilter.value.trim(),
            search: (liveMode ? el.liveSearch.value : el.search.value).trim(),
            flow_page: pagerState.flow_page,
            flow_per_page: pagerState.flow_per_page,
            finding_page: pagerState.finding_page,
            finding_per_page: pagerState.finding_per_page,
        };
    }

    function renderProtocolStats(protocols) {
        const items = protocols || [];
        if (!items.length) {
            el.protocolStats.textContent = "No protocol stats.";
            return;
        }
        el.protocolStats.innerHTML = items.slice(0, 8).map((item) => {
            return `<span class="protocol-chip">${escapeHtml(item.protocol)} · ${escapeHtml(item.flow_count)} flows · ${escapeHtml(item.packet_count)} pkt · risk ${escapeHtml(item.risk_score || 0)}</span>`;
        }).join("");
    }

    function renderMissionControl() {
        if (!el.missionScore || !el.missionHighlights) return;
        const flows = currentAnalysis.flows || [];
        const findings = uniqueBy(currentAnalysis.patterns || [], (pattern) => [
            pattern.flow_id || "",
            pattern.type || "",
            pattern.message || "",
        ].join("|"));
        if (!currentAnalysis.session_id || (!flows.length && !findings.length)) {
            el.missionScore.className = "mission-score";
            el.missionScore.textContent = "No active session.";
            el.missionHighlights.className = "mission-highlights empty";
            el.missionHighlights.textContent = "Run an analysis to generate a triage plan.";
            return;
        }
        const highRiskFlows = flows.filter((flow) => Number(flow.risk_score || 0) >= 5);
        const mediumRiskFlows = flows.filter((flow) => Number(flow.risk_score || 0) >= 3 && Number(flow.risk_score || 0) < 5);
        const criticalFindings = findings.filter((f) => String(f.severity || "").toLowerCase() === "high");
        const exposureScore = Math.max(0, 100 - (highRiskFlows.length * 9) - (criticalFindings.length * 6) - (mediumRiskFlows.length * 2));
        const scoreClass = exposureScore < 55 ? "high" : exposureScore < 75 ? "medium" : "low";
        el.missionScore.className = `mission-score ${scoreClass}`;
        el.missionScore.textContent = `Exposure ${exposureScore}/100`;
        const topFinding = findings.slice().sort((a, b) => Number(b.criticality_score || 0) - Number(a.criticality_score || 0))[0];
        const topFlow = flows.slice().sort((a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0))[0];
        const rows = [
            {
                title: "Priority 1 - Contain high-risk flows",
                detail: `${highRiskFlows.length} flows at risk >= 5 currently visible.`,
            },
            {
                title: "Priority 2 - Validate critical findings",
                detail: `${criticalFindings.length} high-severity findings require confirmation.`,
            },
            {
                title: "Priority 3 - Prepare analyst handoff",
                detail: `Session ${currentAnalysis.session_id} is ready for case export and annotation.`,
            },
        ];
        if (topFinding) {
            rows.unshift({
                title: `Top finding - ${String(topFinding.type || "Unknown finding")}`,
                detail: String(topFinding.message || "No detail available."),
            });
        }
        if (topFlow) {
            rows.push({
                title: "Top risky flow",
                detail: `${topFlow.protocol || "UNKNOWN"} ${topFlow.client || "?"} -> ${topFlow.server || "?"} (risk ${topFlow.risk_score || 0}).`,
            });
        }
        el.missionHighlights.className = "mission-highlights";
        el.missionHighlights.innerHTML = rows.slice(0, 4).map((row) => `
            <article class="mission-item">
                <strong>${escapeHtml(row.title)}</strong>
                <div class="meta">${escapeHtml(row.detail)}</div>
            </article>
        `).join("");
    }

    function renderInspectorEmpty() {
        lastFlowDetail = null;
        selectedFlowPacketIndex = null;
        el.inspector.className = "analyzer-body inspector-empty";
        el.inspector.textContent = "Select a flow from the left list.";
    }

    function renderKeyValues(entries) {
        const rows = Object.entries(entries || {});
        if (!rows.length) return "<div class='meta'>No extracted fields.</div>";
        return "<div class='kv-grid'>" + rows.map(([key, value]) =>
            `<div class="kv-key">${escapeHtml(key)}</div><div>${escapeHtml(value)}</div>`
        ).join("") + "</div>";
    }

    function renderPacketCards(packets, label) {
        if (!packets || !packets.length) return `<div class="meta">No data ${label === "Request" ? "request" : "response"}.</div>`;
        return packets.slice(0, 6).map((pkt) => `
            <article class="action-card">
                <h5>${escapeHtml(pkt.summary || label)}</h5>
                <div class="meta">${escapeHtml(pkt.src || "")} -> ${escapeHtml(pkt.dst || "")} | ${escapeHtml(pkt.timestamp || "")} | ${escapeHtml(pkt.length || 0)} bytes</div>
                ${pkt.payload_excerpt ? `<div class="payload-box">${escapeHtml(pkt.payload_excerpt)}</div>` : ""}
                ${renderKeyValues(pkt.fields || {})}
            </article>
        `).join("");
    }

    function utf8ToB64(str) {
        try {
            return btoa(unescape(encodeURIComponent(String(str || ""))));
        } catch (_e) {
            return "";
        }
    }

    function b64ToUtf8(b64) {
        try {
            return decodeURIComponent(escape(window.atob(String(b64 || ""))));
        } catch (_e) {
            return "";
        }
    }

    function renderFrameworkActions(actions) {
        if (!actions || !actions.length) return "<div class='meta'>No framework pivot suggested for this flow.</div>";
        return actions.map((action) => {
            const launch = action.launch || {};
            const prefill = launch.prefill || action.command || "";
            const b64 = prefill ? utf8ToB64(prefill) : "";
            return `
            <article class="action-card">
                <h5>${escapeHtml(action.title || action.module || "KittySploit Action")}</h5>
                <div class="meta">${escapeHtml(action.module || "")}</div>
                <div class="code-box">${escapeHtml(action.command || "")}</div>
                ${b64 ? `<button type="button" class="btn btn-secondary btn-copy-launch" data-copy-b64="${escapeHtml(b64)}">Copy console prefill</button>` : ""}
                ${launch.deeplink ? `<div class="meta">Lien interne</div><div class="code-box">${escapeHtml(launch.deeplink)}</div>` : ""}
            </article>`;
        }).join("");
    }

    function getSortedFlowPackets(detail) {
        const pkts = detail.replay_packets || detail.packet_preview || [];
        return pkts.slice().sort((a, b) => {
            const fa = Number(a.flow_packet_index);
            const fb = Number(b.flow_packet_index);
            if (Number.isFinite(fa) && Number.isFinite(fb) && fa !== fb) {
                return fa - fb;
            }
            const ta = Number(a.timestamp_epoch || 0);
            const tb = Number(b.timestamp_epoch || 0);
            if (ta !== tb) return ta - tb;
            return (Number(a.number) || 0) - (Number(b.number) || 0);
        });
    }

    function stableFlowPacketIndex(pkt, sortedAll) {
        if (!pkt || !sortedAll || !sortedAll.length) return -1;
        if (pkt.flow_packet_index != null && Number.isFinite(Number(pkt.flow_packet_index))) {
            return Number(pkt.flow_packet_index);
        }
        const pos = sortedAll.indexOf(pkt);
        return pos >= 0 ? pos : -1;
    }

    function inferFlowPacketIndex(detail, pkt) {
        if (!pkt) return -1;
        return stableFlowPacketIndex(pkt, getSortedFlowPackets(detail));
    }

    function buildConversationTurnsFromReplay(detail) {
        const all = getSortedFlowPackets(detail);
        const proto = String(detail.protocol || "").toUpperCase();
        if (proto.includes("HTTP")) {
            return all.filter((p) => {
                const d = String(p.direction || "").toLowerCase();
                if (d === "request" || d === "response") return true;
                const s = String(p.summary || "");
                return /^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT)\s/i.test(s) || /^HTTP\/\d/i.test(s);
            });
        }
        return all;
    }

    function renderConversationTimeline(detail) {
        const turns = buildConversationTurnsFromReplay(detail);
        const cap = 120;
        const shown = turns.slice(0, cap);
        const allSorted = getSortedFlowPackets(detail);
        const metaBits = [];
        const m = detail.conversation;
        if (m && m.request_methods && m.request_methods.length) {
            metaBits.push("Methods: " + m.request_methods.map((x) => `${x.name} ×${x.count}`).join(", "));
        }
        if (m && m.response_codes && m.response_codes.length) {
            metaBits.push("Codes: " + m.response_codes.map((x) => `${x.name} ×${x.count}`).join(", "));
        }
        const metaLine = metaBits.length ? `<p class="conv-intro">${escapeHtml(metaBits.join(" · "))}</p>` : "";
        if (!shown.length) {
            return `<div class="inspector-section">
                <h4>Conversation for this flow</h4>
                <p class="conv-intro">Vue chronologique type « Follow TCP stream ». Chargez plus de frames si besoin (bouton sous le tableau).</p>
                ${metaLine}
                <div class="meta">No frame dans la vue courante.</div>
            </div>`;
        }
        const rows = shown
            .map((pkt) => {
                const si = stableFlowPacketIndex(pkt, allSorted);
                const dir = escapeHtml(String(pkt.direction || "").toUpperCase() || "—");
                const disp = si >= 0 ? si + 1 : "—";
                return `<li class="conv-row" data-flow-pkt-idx="${si}" role="button" tabindex="0">
                    <span class="conv-dir">${dir}</span>
                    <span class="conv-time">#${disp}</span>
                    <span class="conv-sum">${escapeHtml(pkt.summary || "—")}</span>
                </li>`;
            })
            .join("");
        const more =
            turns.length > cap
                ? `<p class="conv-intro">${turns.length - cap} autre(s) ligne(s) — parcourir aussi le tableau des frames.</p>`
                : "";
        return `<div class="inspector-section">
            <h4>Conversation for this flow</h4>
            <p class="conv-intro">Chronological order, one line per message (click opens details under the table).</p>
            ${metaLine}
            <ul class="conv-list" id="convTimelineList">${rows}</ul>
            ${more}
        </div>`;
    }

    function wireConversationTimeline(detail) {
        const list = el.inspector.querySelector("#convTimelineList");
        if (!list) return;
        const mount = el.inspector.querySelector("#pktFrameMount");
        list.querySelectorAll(".conv-row").forEach((row) => {
            const go = () => {
                const idx = Number(row.getAttribute("data-flow-pkt-idx"));
                if (!Number.isFinite(idx) || idx < 0) return;
                selectedFlowPacketIndex = idx;
                refreshPacketTableUi(false);
                if (mount) mount.scrollIntoView({ behavior: "smooth", block: "nearest" });
            };
            row.addEventListener("click", go);
            row.addEventListener("keydown", (ev) => {
                if (ev.key === "Enter" || ev.key === " ") {
                    ev.preventDefault();
                    go();
                }
            });
        });
    }

    function hexStringToUint8(hex) {
        const s = String(hex || "").replace(/\s/g, "");
        if (!s.length || s.length % 2) {
            return new Uint8Array();
        }
        const out = new Uint8Array(s.length / 2);
        for (let i = 0; i < out.length; i++) {
            out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    function uint8ToHexDump(u8, maxBytes) {
        const cap = Math.min(u8.length, maxBytes || 65536);
        const lines = [];
        for (let i = 0; i < cap; i += 16) {
            const chunk = u8.slice(i, i + 16);
            const hex = Array.from(chunk)
                .map((b) => b.toString(16).padStart(2, "0"))
                .join(" ");
            const ascii = Array.from(chunk)
                .map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : "."))
                .join("");
            lines.push(`${i.toString(16).padStart(4, "0")}  ${hex.padEnd(47, " ")}  ${ascii}`);
        }
        if (u8.length > cap) {
            lines.push("... (truncated in display)");
        }
        return lines.join("\n");
    }

    async function loadPcapHexForPacket(flowId, flowPacketIndex, maxBytes) {
        const u = new URLSearchParams({
            flow_packet_index: String(flowPacketIndex),
            max_bytes: String(maxBytes || 8192),
        });
        const res = await fetch(`/api/flows/${encodeURIComponent(flowId)}/packet/hex?${u.toString()}`);
        const data = await res.json();
        if (!res.ok || data.error) {
            throw new Error(data.error || res.statusText || "hex");
        }
        return data;
    }

    async function appendFlowPacketsPage(flowId) {
        const detail = lastFlowDetail;
        if (!detail || !flowId) return;
        const loaded = (detail.replay_packets || []).length;
        const total = Number(detail.replay_packets_total != null ? detail.replay_packets_total : loaded);
        if (loaded >= total) return;
        const res = await fetch(
            `/api/flows/${encodeURIComponent(flowId)}/packets?offset=${encodeURIComponent(String(loaded))}&limit=200`
        );
        const data = await res.json();
        if (!res.ok || data.error) {
            throw new Error(data.error || "pagination packets");
        }
        const chunk = data.packets || [];
        detail.replay_packets = (detail.replay_packets || []).concat(chunk);
        if (data.total != null) {
            detail.replay_packets_total = data.total;
        }
    }

    function packetSearchBlob(pkt) {
        const f = pkt.fields || {};
        const fieldStr = Object.entries(f).map(([k, v]) => `${k}=${v}`).join(" ");
        const idx = pkt.flow_packet_index != null ? String(pkt.flow_packet_index) : "";
        return [pkt.summary, pkt.src, pkt.dst, pkt.direction, pkt.timestamp, idx, fieldStr].join(" ").toLowerCase();
    }

    function textToHexDump(text, maxBytes) {
        const raw = String(text || "");
        if (!raw) return "";
        const bytes = new TextEncoder().encode(raw.length > maxBytes ? raw.slice(0, maxBytes) : raw);
        const lines = [];
        for (let i = 0; i < bytes.length; i += 16) {
            const chunk = bytes.slice(i, i + 16);
            const hex = Array.from(chunk).map((b) => b.toString(16).padStart(2, "0")).join(" ");
            const ascii = Array.from(chunk).map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : ".")).join("");
            lines.push(`${i.toString(16).padStart(4, "0")}  ${hex.padEnd(47, " ")}  ${ascii}`);
        }
        if (bytes.length >= maxBytes) {
            lines.push("... (truncated)");
        }
        return lines.join("\n");
    }

    function renderFlowFindingsBlock(detail) {
        const fid = detail.id;
        const hits = (currentAnalysis.patterns || []).filter((p) => p.flow_id === fid);
        if (!hits.length) {
            return "<div class='meta'>No signal for this flow (current page).</div>";
        }
        const cards = hits.slice(0, 24).map((p) => `
            <article class="action-card">
                <span class="pill ${escapeHtml(p.severity)}">${escapeHtml(p.severity)}</span>
                <strong>${escapeHtml(p.type)}</strong>
                <div class="meta">${escapeHtml(p.message || "")}</div>
            </article>`).join("");
        return `<div class="inspector-scroll-list">${cards}</div>`;
    }

    function riskClass(score) {
        const n = Number(score || 0);
        return n >= 5 ? "high" : n >= 3 ? "medium" : "low";
    }

    function flowSummaryText(detail) {
        return [
            detail.narrative || "",
            `Client: ${detail.client || ""}`,
            `Server: ${detail.server || ""}`,
            `Transport: ${detail.transport || ""}`,
            `Packets: ${detail.packet_count || 0}`,
            `Risk: ${detail.risk_score || 0}`,
        ].filter(Boolean).join("\n");
    }

    function tsharkCommandForFlow(detail) {
        const client = String(detail.client || "").split(":");
        const server = String(detail.server || "").split(":");
        const cHost = client.slice(0, -1).join(":") || client[0] || "";
        const sHost = server.slice(0, -1).join(":") || server[0] || "";
        const cPort = client[client.length - 1] || "";
        const sPort = server[server.length - 1] || "";
        const pcap = currentAnalysis.pcap || "capture.pcapng";
        const terms = [];
        if (cHost && sHost) terms.push(`(ip.addr == ${cHost} && ip.addr == ${sHost})`);
        if (cPort && sPort) terms.push(`(tcp.port == ${cPort} || tcp.port == ${sPort} || udp.port == ${cPort} || udp.port == ${sPort})`);
        return `tshark -r "${pcap}" -Y "${terms.join(" && ")}"`;
    }

    function renderTimelineViz(detail) {
        const pkts = getSortedFlowPackets(detail).slice(0, 80);
        if (!pkts.length) return "<div class='meta'>No frames for timeline.</div>";
        const maxLen = Math.max(...pkts.map((p) => Number(p.length || 0)), 1);
        const bars = pkts.map((pkt) => {
            const h = Math.max(7, Math.round((Number(pkt.length || 0) / maxLen) * 34));
            const cls = `${String(pkt.direction || "").toLowerCase()} ${Number(pkt.length || 0) > maxLen * 0.8 ? "alert" : ""}`;
            return `<span class="timeline-bar ${escapeHtml(cls)}" style="height:${h}px" title="#${escapeHtml(pkt.flow_packet_index != null ? Number(pkt.flow_packet_index) + 1 : "")} ${escapeHtml(pkt.summary || "")}"></span>`;
        }).join("");
        return `<div class="timeline-viz" style="--timeline-count:${pkts.length}">${bars}</div>`;
    }

    function renderIocGrid(iocs) {
        const entries = Object.entries(iocs || {}).filter(([, values]) => (values || []).length);
        if (!entries.length) return "<div class='meta'>No IOC extracted for this flow.</div>";
        return `<div class="ioc-grid">${entries.map(([kind, values]) => `
            <div class="ioc-cell">
                <strong>${escapeHtml(kind)}</strong>
                <ul class="ioc-list">${(values || []).slice(0, 10).map((v) => `<li>${escapeHtml(v)}</li>`).join("")}</ul>
            </div>
        `).join("")}</div>`;
    }

    function renderRiskReasons(reasons) {
        const rows = reasons || [];
        if (!rows.length) return "<div class='meta'>Score is 0: no weighted findings.</div>";
        const cards = rows.map((r) => `
            <article class="action-card">
                <span class="pill ${escapeHtml(r.severity || "")}">+${escapeHtml(r.points || 0)} ${escapeHtml(r.severity || "")}</span>
                <strong>${escapeHtml(r.type || "")}</strong>
                <div class="meta">${escapeHtml(r.message || "")}</div>
                ${renderList((r.evidence || []).slice(0, 3))}
            </article>
        `).join("");
        return `<div class="inspector-scroll-list">${cards}</div>`;
    }

    function renderProtocolViews(detail) {
        const views = detail.protocol_views || {};
        const http = views.http || {};
        const dns = views.dns || {};
        const tls = views.tls || {};
        const topSni = (tls.sni || [])[0] && (tls.sni || [])[0].name || "";
        const topJa3 = (tls.ja3 || [])[0] && (tls.ja3 || [])[0].hash || "";
        const httpReq = (http.requests || []).slice(0, 8).map((r) => `<li>${escapeHtml(r.method || "")} ${escapeHtml(r.host || "")}${escapeHtml(r.uri || "")}</li>`).join("");
        const httpResp = (http.responses || []).slice(0, 8).map((r) => `<li>${escapeHtml(r.code || "")} ${escapeHtml(r.phrase || "")}</li>`).join("");
        const dnsRows = (dns.queries || []).slice(0, 12).map((r) => `<li>${escapeHtml(r.name)} ×${escapeHtml(r.count)}</li>`).join("");
        const tlsRows = (tls.sni || []).slice(0, 12).map((r) => `<li>${escapeHtml(r.name)} ×${escapeHtml(r.count)}</li>`).join("");
        const ja3Rows = (tls.ja3 || []).slice(0, 6).map((r) => `<li>${escapeHtml(r.hash)} ×${escapeHtml(r.count)}</li>`).join("");
        const certIssuerRows = (tls.cert_issuer || []).slice(0, 6).map((r) => `<li>${escapeHtml(r.name)} ×${escapeHtml(r.count)}</li>`).join("");
        const certSubjectRows = (tls.cert_subject || []).slice(0, 6).map((r) => `<li>${escapeHtml(r.name)} ×${escapeHtml(r.count)}</li>`).join("");
        return `<div class="protocol-view">
            <div class="control-grid">
                <div>
                    <strong>HTTP</strong>
                    <ul class="list">${httpReq || httpResp || "<li>—</li>"}</ul>
                    ${httpResp ? `<div class="meta">Responses</div><ul class="list">${httpResp}</ul>` : ""}
                </div>
                <div>
                    <strong>DNS</strong>
                    <ul class="list">${dnsRows || "<li>—</li>"}</ul>
                </div>
                <div>
                    <strong>TLS</strong>
                    <div class="flow-card-actions">
                        ${topSni ? `<button type="button" class="tiny-action" data-copy-text="${escapeHtml(topSni)}">Copy SNI</button><button type="button" class="tiny-action" data-filter-search="sni:${escapeHtml(topSni)}">Filter SNI</button>` : ""}
                        ${topJa3 ? `<button type="button" class="tiny-action" data-copy-text="${escapeHtml(topJa3)}">Copy JA3</button><button type="button" class="tiny-action" data-filter-search="ja3:${escapeHtml(topJa3)}">Filter JA3</button>` : ""}
                    </div>
                    <ul class="list">${tlsRows || "<li>—</li>"}</ul>
                    ${ja3Rows ? `<div class="meta">JA3</div><ul class="list">${ja3Rows}</ul>` : ""}
                    ${certIssuerRows ? `<div class="meta">Certificate issuers</div><ul class="list">${certIssuerRows}</ul>` : ""}
                    ${certSubjectRows ? `<div class="meta">Certificate subjects</div><ul class="list">${certSubjectRows}</ul>` : ""}
                </div>
            </div>
        </div>`;
    }

    function renderEndpointMap(detail) {
        const map = detail.endpoint_map || {};
        const nodes = map.nodes || [];
        const edges = map.edges || [];
        if (!nodes.length) return "<div class='meta'>No endpoint map available.</div>";
        return `<div class="endpoint-map">
            ${nodes.slice(0, 6).map((n) => `<span class="endpoint-node ${n.internal ? "internal" : ""}">${escapeHtml(n.id)}</span>`).join("")}
            ${edges.slice(0, 5).map((e) => `<span class="endpoint-edge">${escapeHtml(e.source)} → ${escapeHtml(e.target)} · ${escapeHtml((e.protocols || []).join(","))} · ${escapeHtml(e.packets)} pkt</span>`).join("")}
        </div>`;
    }

    function getSelectedPacketObject(detail) {
        const all = getSortedFlowPackets(detail);
        if (selectedFlowPacketIndex == null || selectedFlowPacketIndex < 0) return null;
        return all.find((p) => stableFlowPacketIndex(p, all) === selectedFlowPacketIndex) || null;
    }

    function renderFrameDetail(detail, pkt) {
        const mount = el.inspector.querySelector("#pktFrameMount");
        if (!mount) return;
        if (!pkt) {
            mount.innerHTML = "<div class='meta'>Select a row in the packet table.</div>";
            return;
        }
        const blob = JSON.stringify(pkt, null, 2);
        const excerpt = pkt.payload_excerpt || "";
        const flowIdx = inferFlowPacketIndex(detail, pkt);
        const allP = getSortedFlowPackets(detail);
        const si = stableFlowPacketIndex(pkt, allP);
        const frameLabel = si >= 0 ? String(si + 1) : "—";
        const capNo = Number(pkt.number) > 0 ? String(pkt.number) : "—";
        const isLocalDemo = Boolean(currentAnalysis.local_demo);
        mount.innerHTML = `
            <div class="frame-actions">
                <button type="button" class="btn btn-secondary btn-compact" id="pktCopyJsonBtn">Copy JSON frame</button>
                <button type="button" class="btn btn-secondary btn-compact" id="pktBookmarkBtn">${isFrameBookmarked(detail.id, si) ? "Remove bookmark" : "Bookmark frame"}</button>
                <span class="meta">Frame ${escapeHtml(frameLabel)} / flows · capture #${escapeHtml(capNo)} · ${escapeHtml(pkt.timestamp || "")} · ${escapeHtml(pkt.direction || "")}</span>
            </div>
            <div class="kv-grid">
                <div class="kv-key">Summary</div><div>${escapeHtml(pkt.summary || "")}</div>
                <div class="kv-key">Src → Dst</div><div>${escapeHtml(pkt.src || "")} → ${escapeHtml(pkt.dst || "")}</div>
                <div class="kv-key">Size</div><div>${escapeHtml(pkt.length)} bytes</div>
            </div>
            <h4 style="margin:14px 0 6px;font-size:13px;">Extracted fields</h4>
            ${renderKeyValues(pkt.fields || {})}
            <h4 style="margin:14px 0 6px;font-size:13px;">Full frame (PCAP)</h4>
            <div class="frame-actions" style="margin-bottom:6px;">
                <button type="button" class="btn btn-secondary btn-compact" id="pktLoadHexBtn" ${isLocalDemo ? "disabled" : ""}>Load hex from PCAP</button>
                <span class="meta">${flowIdx >= 0 ? "flow_packet_index=" + escapeHtml(String(flowIdx)) : ""}</span>
            </div>
            <div id="pktHexErr" class="meta" style="color:#b42318;"></div>
            <div id="pktHexDump" class="hex-preview"><span class='meta'>${isLocalDemo ? "Unavailable in local demo mode (no backend PCAP source)." : "Not loaded — use the button above (requires the same PCAP as the analysis run)."}</span></div>
            <h4 style="margin:14px 0 6px;font-size:13px;">Text excerpt (analysis)</h4>
            <div class="hex-preview">${excerpt ? escapeHtml(textToHexDump(excerpt, 512)) : "<span class='meta'>No excerpt - enable \"Include raw excerpts\" then re-run analysis.</span>"}</div>
            <details class="filter-details" style="margin-top:10px;"><summary>Raw JSON</summary>
                <pre class="code-box" style="max-height:220px;">${escapeHtml(blob)}</pre>
            </details>
        `;
        const copyBtn = mount.querySelector("#pktCopyJsonBtn");
        if (copyBtn) copyBtn.addEventListener("click", () => copyText(blob));
        const markBtn = mount.querySelector("#pktBookmarkBtn");
        if (markBtn) {
            markBtn.addEventListener("click", () => {
                toggleFrameBookmark(detail.id, si);
                refreshPacketTableUi(false);
            });
        }
        const hexBtn = mount.querySelector("#pktLoadHexBtn");
        const hexErr = mount.querySelector("#pktHexErr");
        const hexOut = mount.querySelector("#pktHexDump");
        if (hexBtn && detail && detail.id) {
            hexBtn.addEventListener("click", async () => {
                if (Boolean(currentAnalysis.local_demo)) {
                    if (hexErr) hexErr.textContent = "Hex loading is disabled in local demo mode.";
                    return;
                }
                const idx = inferFlowPacketIndex(detail, pkt);
                if (idx < 0) {
                    if (hexErr) hexErr.textContent = "Unable to determine frame index for this PCAP.";
                    return;
                }
                hexBtn.disabled = true;
                if (hexErr) hexErr.textContent = "";
                if (hexOut) hexOut.textContent = "Loading...";
                try {
                    const data = await loadPcapHexForPacket(detail.id, idx, 65536);
                    const u8 = hexStringToUint8(data.hex);
                    const note =
                        data.truncated || (data.returned_length || 0) < (data.total_length || 0)
                            ? ` (${data.returned_length || u8.length} / ${data.total_length || "?"} bytes returned)`
                            : ` (${data.total_length || u8.length} bytes)`;
                    if (hexOut) {
                        hexOut.textContent = uint8ToHexDump(u8, 65536) + note;
                    }
                } catch (err) {
                    if (hexErr) hexErr.textContent = String(err.message || err);
                    if (hexOut) hexOut.textContent = "—";
                } finally {
                    hexBtn.disabled = false;
                }
            });
        }
    }

    function getBookmarkedFrames(flowId) {
        return (frameBookmarks[flowBookmarkKey(flowId)] || []).map((v) => Number(v)).filter((n) => Number.isFinite(n) && n >= 0);
    }

    function isFrameBookmarked(flowId, frameIdx) {
        return getBookmarkedFrames(flowId).includes(Number(frameIdx));
    }

    function toggleFrameBookmark(flowId, frameIdx) {
        const key = flowBookmarkKey(flowId);
        if (!key || frameIdx == null || frameIdx < 0) return;
        const cur = getBookmarkedFrames(flowId);
        const n = Number(frameIdx);
        const next = cur.includes(n) ? cur.filter((x) => x !== n) : cur.concat([n]).sort((a, b) => a - b).slice(0, 80);
        frameBookmarks[key] = next;
        writeJsonStore(STORE_KEYS.frameBookmarks, frameBookmarks);
        renderFrameBookmarks(flowId);
    }

    function renderFrameBookmarks(flowId) {
        const bar = el.inspector.querySelector("#frameBookmarksBar");
        if (!bar) return;
        const marks = getBookmarkedFrames(flowId);
        if (!marks.length) {
            bar.innerHTML = "<span class='meta'>No frame bookmark.</span>";
            return;
        }
        bar.innerHTML = marks.map((idx) => {
            const active = Number(selectedFlowPacketIndex) === idx ? "active" : "";
            return `<button type="button" class="bookmark-chip ${active}" data-frame-mark="${idx}">#${idx + 1}</button>`;
        }).join("");
        bar.querySelectorAll("[data-frame-mark]").forEach((btn) => {
            btn.addEventListener("click", () => {
                const idx = Number(btn.getAttribute("data-frame-mark"));
                if (!Number.isFinite(idx)) return;
                selectedFlowPacketIndex = idx;
                refreshPacketTableUi(false);
            });
        });
    }

    function hidePacketContextMenu() {
        const menu = document.getElementById("pktContextMenu");
        if (menu && menu.parentElement) menu.parentElement.removeChild(menu);
    }

    function showPacketContextMenu(evt, detail, pkt, frameIdx) {
        hidePacketContextMenu();
        const menu = document.createElement("div");
        menu.id = "pktContextMenu";
        menu.className = "pkt-context-menu";
        const src = String(pkt.src || "");
        const dst = String(pkt.dst || "");
        const flowFilter = `ip.addr == ${src.split(":")[0]} && ip.addr == ${dst.split(":")[0]}`;
        menu.innerHTML = `
            <button type="button" data-act="bookmark">${isFrameBookmarked(detail.id, frameIdx) ? "Remove frame bookmark" : "Bookmark frame"}</button>
            <button type="button" data-act="copy_tuple">Copy src/dst/dir</button>
            <button type="button" data-act="copy_filter">Copy filtre Wireshark</button>
            <button type="button" data-act="host_filter">Filter by source host</button>
            <button type="button" data-act="compare_a">Set flow as A</button>
            <button type="button" data-act="compare_b">Set flow as B</button>
        `;
        menu.style.left = `${Math.min(evt.clientX, window.innerWidth - 240)}px`;
        menu.style.top = `${Math.min(evt.clientY, window.innerHeight - 220)}px`;
        document.body.appendChild(menu);
        menu.querySelectorAll("button[data-act]").forEach((btn) => {
            btn.addEventListener("click", async () => {
                const act = btn.getAttribute("data-act");
                hidePacketContextMenu();
                if (act === "bookmark") {
                    toggleFrameBookmark(detail.id, frameIdx);
                    refreshPacketTableUi(false);
                    return;
                }
                if (act === "copy_tuple") {
                    await copyText(`${pkt.src || ""} -> ${pkt.dst || ""} ${pkt.direction || ""}`);
                    return;
                }
                if (act === "copy_filter") {
                    await copyText(flowFilter);
                    return;
                }
                if (act === "host_filter") {
                    if (el.hostFilter) el.hostFilter.value = src.split(":")[0] || "";
                    pagerState.flow_page = 1;
                    switchView("flows");
                    refreshQuery(isLiveActive());
                    return;
                }
                if (act === "compare_a") {
                    pickCompareSlot("a", detail.id);
                    return;
                }
                if (act === "compare_b") {
                    pickCompareSlot("b", detail.id);
                }
            });
        });
    }

    function applyPacketColumnState() {
        const table = el.inspector.querySelector(".packet-table");
        if (!table) return;
        ["time", "src", "dst", "len"].forEach((col) => {
            table.classList.toggle(`hide-${col}`, Boolean(packetColumnState[col]));
        });
    }

    function refreshPacketTableUi(resetSelection) {
        const detail = lastFlowDetail;
        if (!detail) return;
        const tbody = el.inspector.querySelector("#pktTbody");
        const meta = el.inspector.querySelector("#pktTableMeta");
        const filterInput = el.inspector.querySelector("#pktFilterInput");
        if (!tbody || !meta) return;
        const q = String(filterInput && filterInput.value || "").trim().toLowerCase();
        const all = getSortedFlowPackets(detail);
        const filtered = q ? all.filter((p) => packetSearchBlob(p).includes(q)) : all;
        const total = filtered.length;
        const shown = filtered.slice(0, PACKET_TABLE_CAP);
        const totalKnown = Number(detail.replay_packets_total != null ? detail.replay_packets_total : all.length);
        const loaded = all.length;
        let metaText = total > PACKET_TABLE_CAP
            ? `Affichage ${shown.length} / ${total} packets (filtre). Limite affichage ${PACKET_TABLE_CAP} — affine le filtre.`
            : `${total} packet(s)` + (q ? " (filtered)" : "");
        if (totalKnown > loaded) {
            metaText += ` — ${loaded} / ${totalKnown} frames loaded (server)`;
        }
        meta.textContent = metaText;
        const moreBtn = el.inspector.querySelector("#pktLoadMoreBtn");
        if (moreBtn) {
            moreBtn.classList.toggle("hidden", totalKnown <= loaded);
        }

        if (resetSelection || selectedFlowPacketIndex == null) {
            selectedFlowPacketIndex = shown.length ? stableFlowPacketIndex(shown[0], all) : null;
        } else if (!filtered.some((p) => stableFlowPacketIndex(p, all) === selectedFlowPacketIndex)) {
            selectedFlowPacketIndex = shown.length ? stableFlowPacketIndex(shown[0], all) : null;
        }

        tbody.innerHTML = shown.map((pkt) => {
            const si = stableFlowPacketIndex(pkt, all);
            const active = si === selectedFlowPacketIndex ? "selected" : "";
            const dir = escapeHtml(pkt.direction || "");
            const capNo = Number(pkt.number) > 0 ? String(pkt.number) : "—";
            const disp = si >= 0 ? String(si + 1) : "—";
            return `<tr class="${active}" data-flow-pkt-idx="${si}">
                <td title="Position in this flow">${escapeHtml(disp)}</td>
                <td title="N° dans la capture (si disponible)">${escapeHtml(capNo)}</td>
                <td class="col-time">${escapeHtml(pkt.timestamp || "")}</td>
                <td><span class="packet-dir">${dir}</span></td>
                <td class="col-src">${escapeHtml(pkt.src || "")}</td>
                <td class="col-dst">${escapeHtml(pkt.dst || "")}</td>
                <td class="col-len">${escapeHtml(String(pkt.length || ""))}</td>
                <td>${escapeHtml(detail.protocol || "")}</td>
                <td>${escapeHtml(pkt.summary || "")}</td>
            </tr>`;
        }).join("");

        tbody.querySelectorAll("tr[data-flow-pkt-idx]").forEach((row) => {
            row.addEventListener("click", () => {
                selectedFlowPacketIndex = Number(row.getAttribute("data-flow-pkt-idx"));
                tbody.querySelectorAll("tr").forEach((r) => r.classList.remove("selected"));
                row.classList.add("selected");
                renderFrameDetail(detail, getSelectedPacketObject(detail));
            });
            row.addEventListener("contextmenu", (event) => {
                event.preventDefault();
                const idx = Number(row.getAttribute("data-flow-pkt-idx"));
                const pkt = shown.find((p) => stableFlowPacketIndex(p, all) === idx);
                if (!pkt) return;
                showPacketContextMenu(event, detail, pkt, idx);
            });
        });

        const sel = getSelectedPacketObject(detail);
        if (sel) {
            const si = stableFlowPacketIndex(sel, all);
            const tr = tbody.querySelector(`tr[data-flow-pkt-idx="${String(si)}"]`);
            if (tr) {
                tbody.querySelectorAll("tr").forEach((r) => r.classList.remove("selected"));
                tr.classList.add("selected");
            }
        }
        renderFrameDetail(detail, getSelectedPacketObject(detail));
        renderFrameBookmarks(detail.id);
        syncUrlState();
    }

    function wirePacketInspectorControls() {
        const filterInput = el.inspector.querySelector("#pktFilterInput");
        if (filterInput) {
            filterInput.addEventListener("input", () => {
                refreshPacketTableUi(true);
            });
        }
        const jumpBtn = el.inspector.querySelector("#pktJumpBtn");
        const jumpIn = el.inspector.querySelector("#pktJumpInput");
        if (jumpBtn && jumpIn) {
            jumpBtn.addEventListener("click", () => {
                const n = Number(String(jumpIn.value || "").trim());
                if (!Number.isFinite(n) || n < 1) return;
                const detail = lastFlowDetail;
                if (!detail) return;
                const all = getSortedFlowPackets(detail);
                selectedFlowPacketIndex = Math.min(Math.max(0, Math.floor(n) - 1), Math.max(0, all.length - 1));
                refreshPacketTableUi(false);
            });
        }
        const prev = el.inspector.querySelector("#pktPrevBtn");
        const next = el.inspector.querySelector("#pktNextBtn");
        const step = (delta) => {
            const detail = lastFlowDetail;
            if (!detail) return;
            const all = getSortedFlowPackets(detail);
            if (!all.length) return;
            let pos = all.findIndex((p) => stableFlowPacketIndex(p, all) === selectedFlowPacketIndex);
            if (pos < 0) pos = 0;
            pos = Math.max(0, Math.min(all.length - 1, pos + delta));
            selectedFlowPacketIndex = stableFlowPacketIndex(all[pos], all);
            refreshPacketTableUi(false);
        };
        if (prev) prev.addEventListener("click", () => step(-1));
        if (next) next.addEventListener("click", () => step(1));
        const more = el.inspector.querySelector("#pktLoadMoreBtn");
        if (more) {
            more.addEventListener("click", async () => {
                const fid = lastFlowDetail && lastFlowDetail.id;
                if (!fid) return;
                more.disabled = true;
                try {
                    await appendFlowPacketsPage(fid);
                    refreshPacketTableUi(false);
                } catch (err) {
                    setStatus("error", String(err.message || err));
                } finally {
                    more.disabled = false;
                }
            });
        }
    }

    function renderInspector(detail, opts) {
        opts = opts || {};
        if (!detail || detail.error) {
            renderInspectorEmpty();
            return;
        }
        lastFlowDetail = detail;
        const totalPk = Number(
            detail.replay_packets_total != null ? detail.replay_packets_total : (detail.replay_packets || []).length || 0
        );
        if (opts.keepPacketIndex != null && Number.isFinite(Number(opts.keepPacketIndex))) {
            const k = Math.floor(Number(opts.keepPacketIndex));
            selectedFlowPacketIndex = Math.min(Math.max(0, k), Math.max(0, totalPk - 1));
        } else {
            selectedFlowPacketIndex = null;
        }
        el.inspector.className = "analyzer-body";
        const exportPcap = `/api/export/flow/${encodeURIComponent(detail.id)}.pcap`;
        const exportJson = `/api/export/flow/${encodeURIComponent(detail.id)}.json`;
        const pinned = isPinned(detail.id);
        const rClass = riskClass(detail.risk_score);
        el.inspector.innerHTML = `
            <div class="inspector-sticky">
                <div class="sticky-row">
                    <div>
                        <h4>${escapeHtml(detail.protocol)} · ${escapeHtml(detail.client)} → ${escapeHtml(detail.server)}</h4>
                        <div class="meta">${escapeHtml(detail.narrative || "")}</div>
                    </div>
                    <div class="sticky-actions">
                        <span class="risk-pill ${rClass}">risk ${escapeHtml(detail.risk_score || 0)}</span>
                        <button type="button" class="tiny-action" id="flowPinBtn">${pinned ? "Unpin" : "Pin"}</button>
                        <button type="button" class="tiny-action" id="flowCopySummaryBtn">Copy summary</button>
                        <button type="button" class="tiny-action" id="flowCopyEndpointsBtn">Copy endpoints</button>
                        <button type="button" class="tiny-action" id="flowCopyTsharkBtn">Copy tshark</button>
                        <button type="button" class="tiny-action" id="flowCompareABtn">A</button>
                        <button type="button" class="tiny-action" id="flowCompareBBtn">B</button>
                        <button type="button" class="tiny-action" id="flowFilterThisProtoBtn">Filter this proto</button>
                    </div>
                </div>
            </div>
            <details class="inspector-section inspector-section--first" open>
                <summary><h4>Flow summary · ${escapeHtml(detail.protocol)}</h4></summary>
                <div class="inspector-export-row">
                    <a href="${exportPcap}" target="_blank" rel="noopener">PCAP (flow)</a>
                    <a href="${exportJson}" target="_blank" rel="noopener">JSON (flow)</a>
                </div>
                <div class="flow-summary-box">${escapeHtml(detail.narrative || "")}</div>
                <div class="kv-grid">
                    <div class="kv-key">Client</div><div>${escapeHtml(detail.client)}</div>
                    <div class="kv-key">Server</div><div>${escapeHtml(detail.server)}</div>
                    <div class="kv-key">Transport</div><div>${escapeHtml(detail.transport)}</div>
                    <div class="kv-key">Packets</div><div>${escapeHtml(detail.packet_count)}</div>
                    <div class="kv-key">Risk score</div><div>${escapeHtml(detail.risk_score || 0)}</div>
                    <div class="kv-key">Protocol confidence</div><div>${escapeHtml(detail.protocol_confidence || 0)}%</div>
                    <div class="kv-key">Window</div><div>${escapeHtml(detail.first_seen || "")} → ${escapeHtml(detail.last_seen || "")}</div>
                    <div class="kv-key">Duration</div><div>${escapeHtml(detail.duration_seconds || 0)} s</div>
                </div>
            </details>
            <details class="inspector-section" open>
                <summary><h4>Why this protocol?</h4></summary>
                <div class="protocol-view">
                    ${(detail.protocol_why || []).length
                        ? `<ul class="list">${(detail.protocol_why || []).map((row) => `<li>${escapeHtml(row.reason || "")} (${escapeHtml(row.count || 0)} packets)</li>`).join("")}</ul>`
                        : "<div class='meta'>No protocol evidence captured.</div>"}
                </div>
            </details>
            <details class="inspector-section" open>
                <summary><h4>Visual timeline</h4></summary>
                ${renderTimelineViz(detail)}
            </details>
            <details class="inspector-section" open>
                <summary><h4>Protocol view</h4></summary>
                ${renderProtocolViews(detail)}
            </details>
            <details class="inspector-section" open>
                <summary><h4>Extracted IOC</h4></summary>
                ${renderIocGrid(detail.iocs || {})}
            </details>
            <details class="inspector-section" open>
                <summary><h4>Endpoint map</h4></summary>
                ${renderEndpointMap(detail)}
            </details>
            <details class="inspector-section">
                <summary><h4>Why this score?</h4></summary>
                ${renderRiskReasons(detail.risk_reasons || [])}
            </details>
            ${renderConversationTimeline(detail)}
            <div class="inspector-section">
                <h4>Frame table (chronological)</h4>
                <p class="conv-intro">Frame is the stable index inside this flow (1..N). Capture is the global packet number when available.</p>
                <div class="packet-column-toggles">
                    <button type="button" class="tiny-action" data-pkt-col="time">Time</button>
                    <button type="button" class="tiny-action" data-pkt-col="src">Src</button>
                    <button type="button" class="tiny-action" data-pkt-col="dst">Dst</button>
                    <button type="button" class="tiny-action" data-pkt-col="len">Octets</button>
                </div>
                <div class="packet-toolbar">
                    <div class="field field-grow">
                        <label for="pktFilterInput">Filter packets</label>
                        <input id="pktFilterInput" type="text" placeholder="sni, dns, src, summary..." autocomplete="off">
                    </div>
                    <div class="field field-narrow">
                        <label for="pktJumpInput">Go to frame</label>
                        <input id="pktJumpInput" type="number" min="1" placeholder="1…N">
                    </div>
                    <div class="field field-actions">
                        <span class="field-spacer-label" aria-hidden="true">&nbsp;</span>
                        <button type="button" class="btn btn-secondary btn-compact" id="pktJumpBtn">OK</button>
                    </div>
                    <div class="field field-actions">
                        <span class="field-spacer-label" aria-hidden="true">&nbsp;</span>
                        <button type="button" class="btn btn-secondary btn-compact" id="pktPrevBtn">← Frame</button>
                    </div>
                    <div class="field field-actions">
                        <span class="field-spacer-label" aria-hidden="true">&nbsp;</span>
                        <button type="button" class="btn btn-secondary btn-compact" id="pktNextBtn">Frame →</button>
                    </div>
                    <div class="field field-actions">
                        <span class="field-spacer-label" aria-hidden="true">&nbsp;</span>
                        <button type="button" class="btn btn-secondary btn-compact hidden" id="pktLoadMoreBtn">Load more frames</button>
                    </div>
                </div>
                <div id="pktTableMeta" class="packet-meta">—</div>
                <div id="frameBookmarksBar" class="bookmark-bar"></div>
                <div class="packet-table-wrap">
                    <table class="packet-table" aria-label="Flow packets">
                        <thead><tr><th>Frame</th><th>Capture</th><th class="col-time">Time</th><th>Dir</th><th class="col-src">Src</th><th class="col-dst">Dst</th><th class="col-len">Bytes</th><th>Proto</th><th>Info</th></tr></thead>
                        <tbody id="pktTbody"></tbody>
                    </table>
                </div>
                <div id="pktFrameMount" class="frame-panel"></div>
            </div>
            <div class="inspector-section">
                <h4>Findings linked to this flow</h4>
                ${renderFlowFindingsBlock(detail)}
            </div>
            <details class="filter-details">
                <summary>Field summary (aggregate)</summary>
                <div class="inspector-section" style="border:none;padding-top:8px;">
                    ${renderKeyValues(detail.field_summary || {})}
                </div>
            </details>
            <details class="filter-details">
                <summary>Legacy request/response preview (max 6)</summary>
                <div class="inspector-section" style="border:none;padding-top:8px;">
                    <h4>Requests</h4>${renderPacketCards(detail.requests || [], "Request")}
                </div>
                <div class="inspector-section" style="border:none;">
                    <h4>Responses</h4>${renderPacketCards(detail.responses || [], "Response")}
                </div>
            </details>
            <div class="inspector-section">
                <h4>KittySploit actions</h4>
                ${renderFrameworkActions(detail.framework_actions || [])}
            </div>
        `;
        attachPivotActions(el.inspector);
        el.inspector.querySelectorAll("[data-copy-b64]").forEach((btn) => {
            btn.addEventListener("click", () => copyText(b64ToUtf8(btn.getAttribute("data-copy-b64"))));
        });
        const pinBtn = el.inspector.querySelector("#flowPinBtn");
        if (pinBtn) pinBtn.addEventListener("click", () => togglePinnedFlow(detail.id));
        const sumBtn = el.inspector.querySelector("#flowCopySummaryBtn");
        if (sumBtn) sumBtn.addEventListener("click", () => copyText(flowSummaryText(detail)));
        const epBtn = el.inspector.querySelector("#flowCopyEndpointsBtn");
        if (epBtn) epBtn.addEventListener("click", () => copyText(`${detail.client || ""} -> ${detail.server || ""}`));
        const tsharkBtn = el.inspector.querySelector("#flowCopyTsharkBtn");
        if (tsharkBtn) tsharkBtn.addEventListener("click", () => copyText(tsharkCommandForFlow(detail)));
        const ca = el.inspector.querySelector("#flowCompareABtn");
        const cb = el.inspector.querySelector("#flowCompareBBtn");
        if (ca) ca.addEventListener("click", () => setCompareSlot("a", detail.id));
        if (cb) cb.addEventListener("click", () => setCompareSlot("b", detail.id));
        const pbtn = el.inspector.querySelector("#flowFilterThisProtoBtn");
        if (pbtn) {
            pbtn.addEventListener("click", () => {
                if (!el.protocolFilter) return;
                el.protocolFilter.value = String(detail.protocol || "").toLowerCase();
                pagerState.flow_page = 1;
                refreshQuery(isLiveActive());
            });
        }
        el.inspector.querySelectorAll("[data-pkt-col]").forEach((btn) => {
            const col = btn.getAttribute("data-pkt-col");
            btn.classList.toggle("active", !packetColumnState[col]);
            btn.addEventListener("click", () => {
                packetColumnState[col] = !packetColumnState[col];
                writeJsonStore(STORE_KEYS.packetCols, packetColumnState);
                applyPacketColumnState();
                btn.classList.toggle("active", !packetColumnState[col]);
            });
        });
        wireConversationTimeline(detail);
        wirePacketInspectorControls();
        applyPacketColumnState();
        refreshPacketTableUi(opts.keepPacketIndex == null);
    }

    async function selectFlow(flowId, silent) {
        if (!flowId) return;
        selectedFlowId = flowId;
        if (!silent) {
            renderFlows(currentAnalysis.flows || []);
        }
        const insp = el.inspector;
        const sameFlowQuiet = Boolean(silent && lastFlowDetail && String(lastFlowDetail.id) === String(flowId));
        const savedTop = sameFlowQuiet ? insp.scrollTop : 0;
        const savedLeft = sameFlowQuiet ? insp.scrollLeft : 0;
        const savedPkt = sameFlowQuiet ? selectedFlowPacketIndex : pendingDeepFrameIndex;
        pendingDeepFrameIndex = null;
        if (demoFlowDetails && demoFlowDetails[flowId]) {
            renderInspector(demoFlowDetails[flowId], { keepPacketIndex: savedPkt });
            markOnboardingStep("reviewed_flow");
            if (inv.annFlow) inv.annFlow.value = flowId;
            scheduleScrollRestore(insp, savedTop, savedLeft);
            syncUrlState();
            return;
        }
        try {
            const response = await fetch(`/api/flows/${encodeURIComponent(flowId)}`);
            const data = await response.json();
            if (!response.ok || data.error) {
                throw new Error(data.error || "Unable to load flow details");
            }
            renderInspector(data, { keepPacketIndex: savedPkt });
            markOnboardingStep("reviewed_flow");
            if (inv.annFlow) inv.annFlow.value = flowId;
            const currentCards = el.flows.querySelectorAll("[data-flow-id]");
            currentCards.forEach((card) => {
                card.classList.toggle("active", card.getAttribute("data-flow-id") === flowId);
            });
        } catch (error) {
            el.inspector.innerHTML = `<div class="inspector-empty">${escapeHtml(String(error.message || error))}</div>`;
        }
        scheduleScrollRestore(insp, savedTop, savedLeft);
        syncUrlState();
    }

    async function loadInterfaces() {
        try {
            const response = await fetch("/api/interfaces");
            const data = await response.json();
            if (!response.ok || data.error) {
                throw new Error(data.error || "Unable to list interfaces");
            }
            const interfaces = data.interfaces || [];
            el.interfaceSelect.innerHTML = interfaces.map((name) => `<option value="${escapeHtml(name)}">${escapeHtml(name)}</option>`).join("");
            if (!interfaces.length) {
                el.interfaceSelect.innerHTML = "<option value=''>No interface</option>";
            }
        } catch (error) {
            setLiveStatus("error", String(error.message || error));
        }
    }

    async function pollLiveSnapshot() {
        try {
            const params = new URLSearchParams(currentFilters(true));
            const response = await fetch(`/api/live/snapshot?${params.toString()}`);
            const data = await response.json();
            applyAnalysis(data);
            const live = data.live_capture || {};
            if (live.running) {
                const observed = Number(live.observed_packets || 0);
                const processed = Number(live.processed_packets || 0);
                const nic = live.sniff_interface && live.interface && live.sniff_interface !== live.interface
                    ? `${live.interface} -> ${live.sniff_interface}`
                    : (live.interface || live.sniff_interface || "?");
                const note = live.capture_note ? ` | ${live.capture_note}` : "";
                const hint = live.warning ? ` | ${live.warning}` : "";
                setLiveStatus("loading", `${nic} | seen: ${observed} | classified: ${processed}${note}${hint}`);
            } else if (live.error) {
                setLiveStatus("error", live.error);
            } else if (live.warning) {
                setLiveStatus("loading", live.warning);
            } else {
                setLiveStatus("idle", "Idle");
            }
        } catch (error) {
            setLiveStatus("error", String(error.message || error));
        }
    }

    async function runAnalysis() {
        queryCache.clear();
        pagerState.flow_page = 1;
        pagerState.finding_page = 1;
        const file = el.pcap && el.pcap.files && el.pcap.files[0];
        if (!file) {
            setStatus("error", "Select a PCAP/PCAPNG file to upload.");
            return;
        }
        const payload = new FormData();
        payload.set("pcap_file", file);
        payload.set("display_filter", el.filter.value.trim());
        payload.set("protocol_filter", (el.protocolFilter && el.protocolFilter.value.trim()) || "");
        payload.set("severity_filter", (el.severityFilter && el.severityFilter.value.trim()) || "");
        payload.set("host_filter", (el.hostFilter && el.hostFilter.value.trim()) || "");
        payload.set("port_filter", (el.portFilter && el.portFilter.value.trim()) || "");
        payload.set("search", (el.search && el.search.value.trim()) || "");
        payload.set("flow_page", String(pagerState.flow_page));
        payload.set("flow_per_page", String(pagerState.flow_per_page));
        payload.set("finding_page", String(pagerState.finding_page));
        payload.set("finding_per_page", String(pagerState.finding_per_page));
        payload.set("max_packets", String(Number(el.maxPackets.value || 2000)));
        payload.set("include_raw", String(Boolean(el.includeRaw.checked)));
        payload.set("bpf_filter", (el.bpf && el.bpf.value.trim()) || "");
        payload.set("enable_fts", String(Boolean(el.ftsIndex && el.ftsIndex.checked)));

        setStatus("loading", "Analysis in progress...");
        el.error.classList.add("hidden");
        el.error.textContent = "";

        try {
            const response = await fetch("/api/analyze", {
                method: "POST",
                body: payload,
            });
            const data = await response.json();
            if (!response.ok || data.error) {
                throw new Error(data.error || "Analysis failed");
            }
            applyAnalysis(data);
            await loadRecordings();
            setStatus("success", "Analysis completed.");
        } catch (error) {
            setStatus("error", "Analysis failed.");
            el.error.textContent = String(error.message || error);
            el.error.classList.remove("hidden");
        }
    }

    async function startLiveCapture() {
        queryCache.clear();
        pagerState.flow_page = 1;
        pagerState.finding_page = 1;
        const payload = {
            interface: el.interfaceSelect.value,
            display_filter: el.liveFilter.value.trim(),
            protocol_filter: el.liveProtocolFilter.value.trim(),
            max_packets: Number(el.liveMaxPackets.value || 0),
            include_raw: Boolean(el.includeRaw.checked),
            bpf_filter: (el.liveBpf && el.liveBpf.value.trim()) || undefined,
        };
        if (!payload.interface) {
            setLiveStatus("error", "Choose a network interface.");
            return;
        }
        try {
            const response = await fetch("/api/live/start", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload),
            });
            const data = await response.json();
            if (!response.ok || data.error) {
                const prefix = data.error_code ? `[${data.error_code}] ` : "";
                throw new Error(prefix + (data.error || "Unable to start capture"));
            }
            setLiveStatus("loading", `Capture sur ${payload.interface}…`);
            setupRealtime();
            if (livePollTimer) {
                window.clearInterval(livePollTimer);
            }
            livePollTimer = window.setInterval(pollLiveSnapshot, 1500);
            await pollLiveSnapshot();
        } catch (error) {
            setLiveStatus("error", String(error.message || error));
        }
    }

    async function stopLiveCapture() {
        try {
            const response = await fetch("/api/live/stop", { method: "POST" });
            const data = await response.json();
            if (!response.ok || data.error) {
                throw new Error(data.error || "Unable to stop capture");
            }
            if (livePollTimer) {
                window.clearInterval(livePollTimer);
                livePollTimer = null;
            }
            teardownRealtime();
            queryCache.clear();
            if (data.analysis) {
                applyAnalysis(data.analysis);
            }
            await loadRecordings();
            setLiveStatus("idle", "Stopped");
        } catch (error) {
            setLiveStatus("error", String(error.message || error));
        }
    }

    async function refreshQuery(isLive) {
        try {
            const cacheKey = queryCacheKey(Boolean(isLive));
            const cached = queryCache.get(cacheKey);
            if (cached) {
                applyAnalysis(cached);
                return;
            }
            const response = await fetch("/api/query", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(currentFilters(Boolean(isLive))),
            });
            const data = await response.json();
            if (!response.ok || data.error) {
                throw new Error(data.error || "Unable to refresh results");
            }
            queryCache.set(cacheKey, data);
            applyAnalysis(data);
        } catch (error) {
            setStatus("error", String(error.message || error));
        }
    }

    async function exportReport(format) {
        try {
            const response = await fetch("/api/export", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ ...currentFilters(false), format }),
            });
            if (!response.ok) {
                let message = "Export failed";
                try {
                    const data = await response.json();
                    message = data.error || message;
                } catch (_err) {}
                throw new Error(message);
            }
            const blob = await response.blob();
            const url = URL.createObjectURL(blob);
            const link = document.createElement("a");
            link.href = url;
            link.download = format === "html" ? "kittyprotocol-report.html" : "kittyprotocol-report.json";
            document.body.appendChild(link);
            link.click();
            link.remove();
            URL.revokeObjectURL(url);
            setStatus("success", `${format.toUpperCase()} export ready.`);
        } catch (error) {
            setStatus("error", String(error.message || error));
        }
    }

    async function loadRecordings() {
        try {
            const response = await fetch("/api/recordings");
            const data = await response.json();
            if (!response.ok || data.error) {
                throw new Error(data.error || "Unable to list recordings");
            }
            currentRecordings = data.recordings || [];
            renderRecordings(currentRecordings);
            if (!el.replayRecordingSelect.value && currentRecordings.length) {
                el.replayRecordingSelect.value = currentRecordings[0].recording_id;
            }
        } catch (error) {
            setStatus("error", String(error.message || error));
        }
    }

    async function saveRecording() {
        try {
            const response = await fetch("/api/recordings/save", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ name: el.recordingName.value.trim() }),
            });
            const data = await response.json();
            if (!response.ok || data.error) {
                throw new Error(data.error || "Unable to save recording");
            }
            setStatus("success", `Session saved: ${data.recording_id}.`);
            await loadRecordings();
        } catch (error) {
            setStatus("error", String(error.message || error));
        }
    }

    async function loadRecording(recordingId) {
        try {
            queryCache.clear();
            const response = await fetch(`/api/recordings/${encodeURIComponent(recordingId)}/load`, { method: "POST" });
            const data = await response.json();
            if (!response.ok || data.error) {
                throw new Error(data.error || "Unable to load recording");
            }
            applyAnalysis(data.result || {});
            setStatus("success", `Session loaded: ${recordingId}.`);
            await populateReplayFlowSelect();
        } catch (error) {
            setStatus("error", String(error.message || error));
        }
    }

    async function populateReplayFlowSelect() {
        const flows = currentAnalysis.flows || [];
        const options = [`<option value="">All flows</option>`].concat(
            flows.map((flow) => `<option value="${escapeHtml(flow.id)}">${escapeHtml(flow.protocol)} ${escapeHtml(flow.client)} -> ${escapeHtml(flow.server)}</option>`)
        );
        el.replayFlowSelect.innerHTML = options.join("");
    }

    async function loadReplayContext() {
        replayState.recordingId = el.replayRecordingSelect.value;
        replayState.flowId = "";
        replayState.cursor = 0;
        replayState.total = 0;
        renderReplayEvents([]);
        if (!replayState.recordingId) {
            setReplayStatus("idle", "Idle");
            return;
        }
        await loadRecording(replayState.recordingId);
        replayState.flowId = el.replayFlowSelect.value;
        setReplayStatus("loading", `Replay ready: ${replayState.recordingId}.`);
    }

    async function replayNextEvents() {
        const recordingId = el.replayRecordingSelect.value;
        if (!recordingId) {
            setReplayStatus("error", "Pick a session first.");
            return;
        }
        replayState.recordingId = recordingId;
        replayState.flowId = el.replayFlowSelect.value;
        try {
            const params = new URLSearchParams({
                cursor: String(replayState.cursor || 0),
                limit: "12",
            });
            if (replayState.flowId) {
                params.set("flow_id", replayState.flowId);
            }
            const response = await fetch(`/api/recordings/${encodeURIComponent(recordingId)}/replay?${params.toString()}`);
            const data = await response.json();
            if (!response.ok || data.error) {
                throw new Error(data.error || "Unable to replay recording");
            }
            replayState.cursor = Number(data.next_cursor || 0);
            replayState.total = Number(data.total || 0);
            renderReplayEvents(data.events || []);
            setReplayStatus(data.has_more ? "loading" : "success", `Replay ${replayState.cursor} / ${replayState.total}`);
        } catch (error) {
            setReplayStatus("error", String(error.message || error));
        }
    }

    function startReplayAutoplay() {
        if (replayTimer) window.clearInterval(replayTimer);
        const speed = Math.max(0.25, Math.min(Number(el.replaySpeed && el.replaySpeed.value || 1), 5));
        const interval = Math.round(1500 / speed);
        replayTimer = window.setInterval(async () => {
            await replayNextEvents();
            if (replayState.total && replayState.cursor >= replayState.total) {
                pauseReplayAutoplay();
            }
        }, interval);
        setReplayStatus("loading", `Autoplay ×${speed}`);
    }

    function pauseReplayAutoplay() {
        if (replayTimer) {
            window.clearInterval(replayTimer);
            replayTimer = null;
        }
        setReplayStatus("idle", "Play en pause");
    }

    function teardownRealtime() {
        if (!wsClient) {
            return;
        }
        try {
            wsClient.removeAllListeners();
            wsClient.disconnect();
        } catch (_err) {
            /* ignore */
        }
        wsClient = null;
    }

    function setupRealtime() {
        if (typeof window.io !== "function") {
            return;
        }
        teardownRealtime();
        try {
            wsClient = window.io("/ws", { transports: ["polling"], upgrade: false });
            wsClient.on("connect", () => setLiveStatus("loading", "Realtime flow feed connected"));
            wsClient.on("disconnect", () => setLiveStatus("loading", "Realtime flow feed disconnected (polling active)"));
            wsClient.on("live_snapshot", (snapshot) => {
                if (!snapshot || typeof snapshot !== "object") {
                    return;
                }
                applyAnalysis(snapshot);
                if (snapshot.live_capture && snapshot.live_capture.running) {
                    const observed = Number(snapshot.live_capture.observed_packets || 0);
                    const processed = Number(snapshot.live_capture.processed_packets || 0);
                    const liveCap = snapshot.live_capture;
                    const nic = liveCap.sniff_interface && liveCap.interface && liveCap.sniff_interface !== liveCap.interface
                        ? `${liveCap.interface} -> ${liveCap.sniff_interface}`
                        : (liveCap.interface || liveCap.sniff_interface || "?");
                    const note = liveCap.capture_note ? ` | ${liveCap.capture_note}` : "";
                    const hint = liveCap.warning ? ` | ${liveCap.warning}` : "";
                    setLiveStatus(
                        "loading",
                        `${nic} | seen: ${observed} | classified: ${processed}${note}${hint}`
                    );
                }
            });
        } catch (_error) {
            wsClient = null;
        }
    }

    function setupGridResizer() {
        if (!el.gridHandle) return;
        let dragging = false;
        const grid = el.gridHandle.closest(".flows-analysis-grid");
        el.gridHandle.addEventListener("pointerdown", (event) => {
            dragging = true;
            el.gridHandle.setPointerCapture(event.pointerId);
        });
        el.gridHandle.addEventListener("pointermove", (event) => {
            if (!dragging || !grid) return;
            const rect = grid.getBoundingClientRect();
            const pct = Math.max(22, Math.min(55, ((event.clientX - rect.left) / rect.width) * 100));
            const value = `${pct.toFixed(1)}%`;
            document.documentElement.style.setProperty("--flows-list-width", value);
            window.localStorage.setItem(STORE_KEYS.listWidth, value);
        });
        const stop = () => { dragging = false; };
        el.gridHandle.addEventListener("pointerup", stop);
        el.gridHandle.addEventListener("pointercancel", stop);
    }

    function setupKeyboardShortcuts() {
        document.addEventListener("keydown", (event) => {
            const tag = String(event.target && event.target.tagName || "").toLowerCase();
            const editing = tag === "input" || tag === "textarea" || tag === "select";
            if (editing && event.key !== "Escape") return;
            if (event.key === "?") {
                event.preventDefault();
                showInvToast("Shortcuts: / search, f flows, j/k next/prev flow, Enter open flow, arrows frame nav, p pin, Esc close overlays.");
                return;
            }
            if (event.key === "/") {
                event.preventDefault();
                if (el.globalSearch) el.globalSearch.focus();
                return;
            }
            if (event.key === "Escape") {
                if (el.globalSearchResults) el.globalSearchResults.classList.add("hidden");
                hidePacketContextMenu();
                return;
            }
            if (event.key === "f") {
                switchView("flows");
                return;
            }
            if ((event.key === "j" || event.key === "k") && activeViewName === "flows") {
                const flows = currentAnalysis.flows || [];
                if (!flows.length) return;
                const idx = Math.max(0, flows.findIndex((flow) => flow.id === selectedFlowId));
                const nextIdx = event.key === "j" ? Math.min(flows.length - 1, idx + 1) : Math.max(0, idx - 1);
                event.preventDefault();
                selectFlow(flows[nextIdx].id);
                return;
            }
            if (event.key === "Enter" && activeViewName === "flows" && selectedFlowId) {
                event.preventDefault();
                selectFlow(selectedFlowId);
                return;
            }
            if (event.key === "p" && selectedFlowId) {
                togglePinnedFlow(selectedFlowId);
                return;
            }
            if ((event.key === "ArrowDown" || event.key === "ArrowUp") && activeViewName === "flows") {
                const flows = currentAnalysis.flows || [];
                if (!flows.length) return;
                const idx = Math.max(0, flows.findIndex((flow) => flow.id === selectedFlowId));
                const nextIdx = event.key === "ArrowDown" ? Math.min(flows.length - 1, idx + 1) : Math.max(0, idx - 1);
                event.preventDefault();
                selectFlow(flows[nextIdx].id);
                return;
            }
            if ((event.key === "ArrowRight" || event.key === "ArrowLeft") && activeViewName === "flows" && lastFlowDetail) {
                const all = getSortedFlowPackets(lastFlowDetail);
                if (!all.length) return;
                const current = selectedFlowPacketIndex == null ? 0 : Number(selectedFlowPacketIndex);
                const next = event.key === "ArrowRight" ? Math.min(all.length - 1, current + 1) : Math.max(0, current - 1);
                event.preventDefault();
                selectedFlowPacketIndex = next;
                refreshPacketTableUi(false);
            }
        });
    }

    function initFromUrl() {
        const params = new URLSearchParams(window.location.search);
        const view = params.get("view");
        const flow = params.get("flow");
        const frame = Number(params.get("frame") || 0);
        if (view) {
            activeViewName = view;
            switchView(view);
        }
        if (flow) {
            selectedFlowId = flow;
        }
        if (frame > 0) {
            pendingDeepFrameIndex = frame - 1;
            selectedFlowPacketIndex = frame - 1;
        }
    }

    el.analyze.addEventListener("click", runAnalysis);
    if (el.pcap) el.pcap.addEventListener("change", updateSelectedPcapName);
    el.saveRecording.addEventListener("click", saveRecording);
    el.refreshRecordings.addEventListener("click", loadRecordings);
    el.loadReplay.addEventListener("click", loadReplayContext);
    el.replayNext.addEventListener("click", replayNextEvents);
    if (el.replayPlay) el.replayPlay.addEventListener("click", startReplayAutoplay);
    if (el.replayPause) el.replayPause.addEventListener("click", pauseReplayAutoplay);
    if (el.replayDirection) el.replayDirection.addEventListener("change", () => renderReplayEvents(lastReplayEvents));
    el.replayRecordingSelect.addEventListener("change", populateReplayFlowSelect);
    el.exportJson.addEventListener("click", () => exportReport("json"));
    el.exportHtml.addEventListener("click", () => exportReport("html"));
    el.refreshInterfaces.addEventListener("click", loadInterfaces);
    el.startLive.addEventListener("click", startLiveCapture);
    el.stopLive.addEventListener("click", stopLiveCapture);
    el.flowPrev.addEventListener("click", () => {
        pagerState.flow_page = Math.max(1, pagerState.flow_page - 1);
        refreshQuery(isLiveActive());
    });
    el.flowNext.addEventListener("click", () => {
        pagerState.flow_page += 1;
        refreshQuery(isLiveActive());
    });
    el.findingPrev.addEventListener("click", () => {
        pagerState.finding_page = Math.max(1, pagerState.finding_page - 1);
        refreshQuery(isLiveActive());
    });
    el.findingNext.addEventListener("click", () => {
        pagerState.finding_page += 1;
        refreshQuery(isLiveActive());
    });
    if (el.flowsQuickSearch) {
        el.flowsQuickSearch.addEventListener("input", () => {
            persistInvestigationContext();
            renderFlows(currentAnalysis.flows || []);
        });
    }
    if (el.flowsSort) {
        el.flowsSort.addEventListener("change", () => {
            persistInvestigationContext();
            renderFlows(currentAnalysis.flows || []);
        });
    }
    if (el.flowsRiskMin) {
        el.flowsRiskMin.addEventListener("change", () => {
            persistInvestigationContext();
            renderFlows(currentAnalysis.flows || []);
        });
    }
    if (el.globalSearch) {
        el.globalSearch.addEventListener("input", renderGlobalSearchResults);
        el.globalSearch.addEventListener("focus", renderGlobalSearchResults);
        el.globalSearch.addEventListener("keydown", (event) => {
            if (event.key !== "Enter") return;
            const q = el.globalSearch.value.trim();
            if (!q) return;
            event.preventDefault();
            applyOmniboxQuery(q);
        });
    }
    if (el.decSave) el.decSave.addEventListener("click", saveDecryptionConfig);
    if (el.decClear) el.decClear.addEventListener("click", clearDecryptionConfig);
    if (el.sidebarToggle) el.sidebarToggle.addEventListener("click", toggleSidebar);
    el.navItems.forEach((item) => {
        item.addEventListener("click", () => switchView(item.dataset.view));
        item.addEventListener("keydown", (event) => {
            if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                switchView(item.dataset.view);
            }
        });
    });
    if (inv.refreshViews) inv.refreshViews.addEventListener("click", () => refreshViewsList());
    if (inv.saveView) inv.saveView.addEventListener("click", () => saveCurrentView());
    if (inv.compareRun) inv.compareRun.addEventListener("click", () => runCompareCaptures());
    if (inv.ftsRun) inv.ftsRun.addEventListener("click", () => runFtsSearch());
    if (inv.annSave) inv.annSave.addEventListener("click", () => saveAnnotation());
    if (inv.annRefresh) inv.annRefresh.addEventListener("click", () => refreshAnnotationsList());
    if (inv.exportIocJson) {
        inv.exportIocJson.addEventListener("click", async () => {
            try {
                await exportIocs("json");
            } catch (error) {
                showInvToast(String(error.message || error));
            }
        });
    }
    if (inv.exportIocCsv) {
        inv.exportIocCsv.addEventListener("click", async () => {
            try {
                await exportIocs("csv");
            } catch (error) {
                showInvToast(String(error.message || error));
            }
        });
    }
    if (inv.exportCaseBundle) {
        inv.exportCaseBundle.addEventListener("click", async () => {
            try {
                await exportCaseBundle();
            } catch (error) {
                showInvToast(String(error.message || error));
            }
        });
    }
    if (inv.copySession) inv.copySession.addEventListener("click", () => copyText(currentAnalysis.session_id || ""));
    if (inv.copyProv) inv.copyProv.addEventListener("click", () => copyText(inv.provenancePre ? inv.provenancePre.textContent : ""));
    if (el.missionFocusHighRisk) {
        el.missionFocusHighRisk.addEventListener("click", () => {
            quickFilterState.risk = "5";
            switchView("flows");
            renderQuickFilters();
            renderFlows(currentAnalysis.flows || []);
            persistInvestigationContext();
            setStatus("success", "Flow view focused on risk >= 5.");
        });
    }
    if (el.missionOpenTopFinding) {
        el.missionOpenTopFinding.addEventListener("click", () => {
            const findings = (currentAnalysis.patterns || []).slice().sort(
                (a, b) => Number(b.criticality_score || 0) - Number(a.criticality_score || 0)
            );
            const top = findings[0];
            if (!top) {
                setStatus("idle", "No findings in current scope.");
                return;
            }
            switchView("findings");
            if (top.flow_id) selectedFlowId = String(top.flow_id);
            setStatus("success", `Top finding: ${top.type || "finding"}.`);
        });
    }
    if (el.missionJumpInvestigation) {
        el.missionJumpInvestigation.addEventListener("click", () => {
            switchView("investigation");
            refreshInvestigationPanel();
        });
    }
    if (el.missionExportCase) {
        el.missionExportCase.addEventListener("click", async () => {
            try {
                await exportCaseBundle();
                markOnboardingStep("exported_bundle");
            } catch (error) {
                showInvToast(String(error.message || error));
            }
        });
    }
    if (el.missionCopyExec) {
        el.missionCopyExec.addEventListener("click", async () => {
            try {
                await copyExecutiveSummary();
                markOnboardingStep("exported_bundle");
            } catch (error) {
                setStatus("error", String(error.message || error));
            }
        });
    }
    if (el.missionExportExec) {
        el.missionExportExec.addEventListener("click", async () => {
            try {
                await exportExecutiveSummaryHtml();
                markOnboardingStep("exported_bundle");
            } catch (error) {
                setStatus("error", String(error.message || error));
            }
        });
    }
    if (el.onboardingStart) {
        el.onboardingStart.addEventListener("click", async () => {
            await startGuidedMode();
        });
    }
    if (el.onboardingDemo) {
        el.onboardingDemo.addEventListener("click", async () => {
            await loadDemoContext();
        });
    }
    if (el.onboardingInstantDemo) {
        el.onboardingInstantDemo.addEventListener("click", async () => {
            await runInstantDemo();
        });
    }

    applyUiPreferences();
    setupGridResizer();
    setupKeyboardShortcuts();
    document.addEventListener("click", (event) => {
        const menu = document.getElementById("pktContextMenu");
        if (!menu) return;
        if (!menu.contains(event.target)) hidePacketContextMenu();
    });
    document.addEventListener("scroll", hidePacketContextMenu, true);
    renderProfileBar();
    renderMissionControl();
    renderOnboardingCard();
    renderInspectorEmpty();
    fetchDecryptionConfig();
    restoreInvestigationContext();
    initFromUrl();
    if (!new URLSearchParams(window.location.search).get("view")) {
        switchView(activeViewName || "overview");
    }
    loadInterfaces();
    loadRecordings();
    populateReplayFlowSelect();
    setReplayStatus("idle", "Idle");
    updateSelectedPcapName();
})();
