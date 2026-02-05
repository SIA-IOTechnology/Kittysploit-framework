const API_BASE = 'http://127.0.0.1:8443/api';
let currentFlowId = null;
let currentTab = 'request';
let flowsData = [];
let sharedFlows = new Set(); // IDs des flows partagés en collaboration

// Interception state
let interceptEnabled = false;
let pendingInterceptsData = [];
let selectedInterceptId = null;
let autoResumeEnabled = false; // Mode auto-resume : reprend automatiquement toutes les requêtes

// Search
let searchTerm = '';

// Modules
let modulesData = [];
let selectedModuleId = null;
let moduleSearchTerm = '';

// Pagination
const PAGE_SIZE = 50;
let currentPage = 1;
let totalPages = 1;

// Flow polling optimization
const FLOW_POLL_SIZE = 300; // Reduced from 10000 to limit backend load
let flowsHash = ''; // Lightweight hash to detect changes

// Sorting
let sortColumn = null; // 'method', 'status', 'time', or null
let sortOrder = 'asc'; // 'asc' or 'desc'

// DOM Elements
const flowListEl = document.getElementById('flow-list');
const detailContentEl = document.getElementById('detail-content');
const clearBtn = document.getElementById('clear-btn');
const tabs = document.querySelectorAll('.tab');
const navItems = document.querySelectorAll('.nav-item');
const viewSections = document.querySelectorAll('.view-section');
const currentViewTitle = document.getElementById('current-view-title');
const viewActionsContainer = document.getElementById('view-actions-container');
const collabLiveIndicator = document.getElementById('collab-live-indicator');
const toastContainerId = 'toast-container';

// Simple toast notification
function showToast(message, type = 'info') {
    let container = document.getElementById(toastContainerId);
    if (!container) {
        container = document.createElement('div');
        container.id = toastContainerId;
        container.style.cssText = 'position: fixed; top: 16px; right: 16px; display: flex; flex-direction: column; gap: 8px; z-index: 2000; pointer-events: none;';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    const bg = type === 'error' ? '#f44336' : type === 'success' ? '#4caf50' : '#333';
    toast.style.cssText = `min-width: 220px; max-width: 320px; padding: 10px 12px; border-radius: 8px; color: #fff; background: ${bg}; box-shadow: 0 8px 20px rgba(0,0,0,0.2); font-size: 13px; display: flex; align-items: center; gap: 8px; pointer-events: auto;`;
    toast.textContent = message;

    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transition = 'opacity 0.2s ease';
        setTimeout(() => toast.remove(), 200);
    }, 2600);
}

async function copyToClipboard(text) {
    try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(text);
            return true;
        }
        // Fallback: temporary textarea
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.top = '-9999px';
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        textarea.remove();
        return true;
    } catch (err) {
        console.error('Clipboard copy failed', err);
        return false;
    }
}

function debounce(fn, delay = 200) {
    let timeoutId;
    return (...args) => {
        clearTimeout(timeoutId);
        timeoutId = setTimeout(() => fn.apply(null, args), delay);
    };
}

const debouncedSidechannelSearch = debounce(() => renderSidechannelFlows(), 150);

// Browser Launch
const launchBtn = document.getElementById('launch-browser-btn');
const launchStatus = document.getElementById('launch-status');

// Workspace Management
const workspaceSelect = document.getElementById('workspace-select');
const workspaceRefreshBtn = document.getElementById('workspace-refresh-btn');
const workspaceCreateBtn = document.getElementById('workspace-create-btn');
const workspaceDeleteBtn = document.getElementById('workspace-delete-btn');
const workspaceSaveDataCheck = document.getElementById('workspace-save-data');
const workspaceInfo = document.getElementById('workspace-info');
const workspaceDescription = document.getElementById('workspace-description');
let workspaceSaveEnabled = true; // Par défaut, on enregistre dans le workspace
let currentWorkspaceName = null;

// Interception
const interceptToggleBtn = document.getElementById('intercept-toggle-btn');
const interceptStatusText = document.getElementById('intercept-status-text');
const pendingCountText = document.getElementById('pending-count-text');
const pendingListEl = document.getElementById('pending-list');
const interceptEditorEl = document.getElementById('intercept-editor');
const resumeAllBtn = document.getElementById('resume-all-btn');
const dropAllBtn = document.getElementById('drop-all-btn');

// Modules
const moduleSearchInput = document.getElementById('module-search');
const refreshModulesBtn = document.getElementById('refresh-modules-btn');
const moduleListEl = document.getElementById('module-list');
const moduleConfigEl = document.getElementById('module-config');
const moduleCountText = document.getElementById('module-count-text');
const runModuleBtn = document.getElementById('run-module-btn');
let moduleOutputCache = {}; // Preserve output when switching modules

// Repeater - Système d'onglets
let repeaterTabs = [];
let activeRepeaterTabId = null;
const repeaterTabsContainer = document.getElementById('repeater-tabs-container');
const repeaterContentContainer = document.getElementById('repeater-content-container');
const repeaterNewTabBtn = document.getElementById('repeater-new-tab-btn');

// Intruder - Système d'onglets
let intruderTabs = [];
let activeIntruderTabId = null;
const intruderTabsContainer = document.getElementById('intruder-tabs-container');
const intruderContentContainer = document.getElementById('intruder-content-container');
const intruderNewTabBtn = document.getElementById('intruder-new-tab-btn');

// Replay
const replayBtn = document.getElementById('replay-btn');
const sendToRepeaterBtn = document.getElementById('send-to-repeater-btn');
const sendToIntruderBtn = document.getElementById('send-to-intruder-btn');

// Search
const searchInput = document.getElementById('flow-search');

// Pagination
const pageFirstBtn = document.getElementById('page-first');
const pagePrevBtn = document.getElementById('page-prev');
const pageNextBtn = document.getElementById('page-next');
const pageLastBtn = document.getElementById('page-last');
const pageCurrentEl = document.getElementById('page-current');
const paginationInfoEl = document.getElementById('pagination-info');

// Statistics
const statTotalEl = document.getElementById('stat-total');
const statAvgTimeEl = document.getElementById('stat-avg-time');
const statSuccessRateEl = document.getElementById('stat-success-rate');
const statErrorsEl = document.getElementById('stat-errors');

// Export
const exportHarBtn = document.getElementById('export-har-btn');
const exportJsonBtn = document.getElementById('export-json-btn');

// Encoder / Decoder
const encoderModeSelect = document.getElementById('encoder-mode');
const encoderInputEl = document.getElementById('encoder-input');
const encoderOutputEl = document.getElementById('encoder-output');
const encoderEncodeBtn = document.getElementById('encoder-encode-btn');
const encoderDecodeBtn = document.getElementById('encoder-decode-btn');
const encoderSwapBtn = document.getElementById('encoder-swap-btn');
const encoderClearBtn = document.getElementById('encoder-clear-btn');
const encoderCopyInputBtn = document.getElementById('encoder-copy-input-btn');
const encoderCopyOutputBtn = document.getElementById('encoder-copy-output-btn');

// SideChannel
let sidechannelTabManual = null;
let sidechannelTabUrls = null;
let sidechannelTabResults = null;
let sidechannelResultsBadge = null;
let sidechannelManualMode = null;
let sidechannelUrlsMode = null;
let sidechannelResultsMode = null;
let sidechannelUrlsList = null;
let sidechannelAttackTypeSelect = null;
let sidechannelManualAttackTypeSelect = null;
let sidechannelGenerateUrlBtn = null;
let sidechannelTestBtn = null;
let sidechannelFlowsList = null;
let sidechannelFlowSearch = null;
let sidechannelResultsList = null;
let sidechannelGeneratedUrlInput = null;
let sidechannelCopyUrlBtn = null;
let sidechannelExportResultsBtn = null;
let sidechannelClearResultsBtn = null;
let selectedSidechannelFlowId = null;
let sidechannelApiKeyValid = false;
let sidechannelTests = []; // Liste des tests en cours
let sidechannelDetections = []; // Liste des détections (résultats)
let sidechannelPollInterval = null;
let currentGeneratedUrl = null; // URL générée pour injection manuelle
let currentSidechannelMode = 'manual'; // 'manual', 'urls', or 'results'
let sidechannelGeneratedUrls = []; // Liste des URLs générées
let sidechannelFlowCache = [];
let sidechannelFlowsSignature = '';
let sidechannelLastFlowFetchTs = 0;
let sidechannelFlowsFetchInFlight = false;
const SIDECHANNEL_MIN_FLOW_FETCH_INTERVAL = 900;

// === NAVIGATION ===
function switchView(viewId, navItem = null) {
    currentViewId = viewId;
    navItems.forEach(nav => nav.classList.remove('active'));
    if (navItem) {
        navItem.classList.add('active');
    }

    // Hide all view sections (including dynamically added UI extension views)
    document.querySelectorAll('.view-section').forEach(section => {
        section.style.display = 'none';
        section.classList.remove('active');
    });

    const activeSection = document.getElementById(`${viewId}-view`);
    if (activeSection) {
        activeSection.style.display = 'flex';
        activeSection.classList.add('active');
    }

    updateTopBarForView(viewId);

    if (viewId === 'api') {
        newReactApisCount = 0;
        updateApiTabBadge(0);
    }

    // WebSocket tab: load connections
    if (viewId === 'websocket') {
        loadWebSocketConnections();
    }

    // Collaboration tab: validate auth; otherwise remove overlay
    if (viewId === 'collaborate') {
        ensureCollabAuth();
        // Synchroniser l'état visuel (no-session vs active-session)
        if (currentSessionId) {
            showCollaborationSession();
        } else {
            hideCollaborationSession();
        }
    } else {
        removeCollabApiOverlay();
    }

    // SideChannel tab: validate auth; otherwise remove overlay
    if (viewId === 'sidechannel') {
        checkSidechannelApiKey();
        restoreSidechannelData();
    } else {
        removeSidechannelApiOverlay();
    }

    // Notify extension iframes whether they are visible (so they can pause/resume timers)
    document.querySelectorAll('iframe[id^="ext-frame-"]').forEach(iframe => {
        try {
            const section = iframe.closest('.view-section');
            const visible = section && section.id === `${viewId}-view`;
            iframe.contentWindow && iframe.contentWindow.postMessage(
                { type: 'kittyproxy-visible', visible: !!visible },
                window.location.origin
            );
        } catch (e) { /* cross-origin or not loaded */ }
    });
}

// Logo icon click handler - navigate to browser (home)
const logoIcon = document.getElementById('logo-icon');
if (logoIcon) {
    logoIcon.addEventListener('click', () => switchView('browser'));
}

// Use delegation so dynamically added nav items (e.g. UI extensions) also work
const mainNav = document.querySelector('.main-nav');
if (mainNav) {
    mainNav.addEventListener('click', (e) => {
        const item = e.target.closest('.nav-item');
        if (!item || !item.dataset.view) return;
        e.preventDefault();
        switchView(item.dataset.view, item);
    });
}

// UI extension tab labels (filled when extensions are loaded)
window.uiExtensionTitles = window.uiExtensionTitles || {};

// Update top bar title and actions based on current view
function updateTopBarForView(viewId) {
    const titleEl = document.getElementById('current-view-title');
    const actionsContainer = document.getElementById('view-actions-container');

    // View titles mapping
    const viewTitles = {
        'browser': 'Browser',
        'analyze': 'Analyze',
        'intercept': 'Intercept',
        'modules': 'Kittysploit Modules',
        'plugins': 'Interception Plugins',
        'visualize': 'Visualization',
        'collaborate': 'Collaboration & IA',
        'monitor': 'Performance Monitor',
        'replay': 'Repeater',
        'intruder': 'Intruder',
        'api': 'API Tester',
        'encoder': 'Encoder / Decoder',
        'websocket': 'WebSocket',
        'sidechannel': 'Side Channel'
    };

    // Update title (use UI extension title for ext-* views)
    if (titleEl) {
        titleEl.textContent = window.uiExtensionTitles[viewId] || viewTitles[viewId] || viewId.charAt(0).toUpperCase() + viewId.slice(1);
    }

    // Update actions - move the actions bar content to the top bar
    if (actionsContainer) {
        actionsContainer.innerHTML = '';

        // Find the actions bar for this view
        const actionsBar = document.getElementById(`${viewId}-actions`);
        if (actionsBar && actionsBar.children.length > 0) {
            // Move all children from the actions bar to the top bar
            while (actionsBar.firstChild) {
                actionsContainer.appendChild(actionsBar.firstChild);
            }
        }
    }
}

// Initialize top bar on page load
// Load UI extensions (custom tabs with their own interface, like Burp Suite extensions)
async function loadUiExtensions() {
    const mainNav = document.querySelector('.main-nav');
    const contentWrapper = document.querySelector('.content-wrapper');
    if (!mainNav || !contentWrapper) return;
    try {
        const res = await fetch(`${API_BASE}/ui-extensions`);
        if (!res.ok) return;
        const list = await res.json();
        if (!Array.isArray(list) || list.length === 0) return;
        list.forEach(ext => {
            const viewId = 'ext-' + ext.id;
            window.uiExtensionTitles[viewId] = ext.tabLabel || ext.name;
            const navItem = document.createElement('div');
            navItem.className = 'nav-item';
            navItem.dataset.view = viewId;
            navItem.dataset.label = ext.tabLabel || ext.name;
            navItem.title = ext.description || ext.tabLabel || ext.name;
            navItem.innerHTML = `<span class="material-symbols-outlined">${ext.icon || 'extension'}</span>`;
            mainNav.appendChild(navItem);
            const section = document.createElement('div');
            section.id = viewId + '-view';
            section.className = 'view-section';
            section.style.display = 'none';
            section.style.flexDirection = 'column';
            section.style.flex = '1';
            section.style.overflow = 'hidden';
            section.innerHTML = `
                <div class="top-bar"><h2>${escapeHtml(ext.tabLabel || ext.name)}</h2></div>
                <iframe id="ext-frame-${escapeAttr(ext.id)}" src="${escapeAttr(ext.entryUrl)}" title="${escapeAttr(ext.tabLabel)}" style="flex: 1; width: 100%; border: none; background: #fff;"></iframe>
            `;
            contentWrapper.appendChild(section);
        });
        applyTabsVisibility();
    } catch (e) {
        console.warn('[UI Extensions] Failed to load:', e);
    }
}
function escapeHtml(s) { const div = document.createElement('div'); div.textContent = s; return div.innerHTML; }
function escapeAttr(s) { return String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/'/g, '&#39;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

// Tab visibility (global so loadUiExtensions can call applyTabsVisibility after async load)
const TABS_VISIBLE_KEY = 'kittyproxy-tabs-visible';
function getTabsVisible() {
    try {
        const s = localStorage.getItem(TABS_VISIBLE_KEY);
        return s ? JSON.parse(s) : {};
    } catch (e) { return {}; }
}
function setTabsVisible(obj) {
    try {
        localStorage.setItem(TABS_VISIBLE_KEY, JSON.stringify(obj));
    } catch (e) {}
}
function applyTabsVisibility() {
    const visible = getTabsVisible();
    const mainNav = document.querySelector('.main-nav');
    if (!mainNav) return;
    const activeViewId = document.querySelector('.nav-item.active[data-view]')?.dataset?.view || currentViewId;
    mainNav.querySelectorAll('.nav-item[data-view]').forEach(item => {
        const viewId = item.dataset.view;
        const show = visible[viewId] !== false;
        item.style.display = show ? '' : 'none';
    });
    document.querySelectorAll('.view-section').forEach(section => {
        const id = section.id;
        if (!id || !id.endsWith('-view')) return;
        const viewId = id.slice(0, -5);
        if (visible[viewId] === false) {
            section.style.display = 'none';
        } else {
            section.style.display = (activeViewId === viewId) ? 'flex' : 'none';
        }
    });
    if (activeViewId && visible[activeViewId] === false) {
        const firstVisible = Array.from(mainNav.querySelectorAll('.nav-item[data-view]')).find(item => visible[item.dataset.view] !== false);
        if (firstVisible) firstVisible.click();
    }
}

document.addEventListener('DOMContentLoaded', () => {
    loadUiExtensions();
    // Load fast mode settings on startup
    loadFastModeSettings();

    // S'assurer que le body et le sidebar commencent en haut
    window.scrollTo(0, 0);
    document.body.scrollTop = 0;
    document.documentElement.scrollTop = 0;

    const sidebar = document.querySelector('.sidebar');
    if (sidebar) {
        sidebar.scrollTop = 0;
    }
    const mainNav = document.querySelector('.main-nav');
    if (mainNav) {
        mainNav.scrollTop = 0;
    }

    updateCollabLiveIndicator(false);

    // Restaurer l'état de la collaboration au chargement
    const savedState = restoreCollaborationState();
    if (savedState && savedState.sessionId) {
        console.log('[Collaboration] Restoring session on page load:', savedState);
        currentSessionId = savedState.sessionId;
        currentUserId = savedState.userId;
        currentUsername = savedState.username || currentUsername;

        // Rejoindre la session automatiquement
        joinCollaborationSession(savedState.sessionId);
    }

    // Restaurer les données SideChannel au chargement
    restoreSidechannelData();

    // Apply tab visibility from localStorage first (before choosing active view)
    applyTabsVisibility();

    // Find the active view (only visible tabs are shown; active may have been set by applyTabsVisibility)
    const visibleForNav = getTabsVisible();
    const activeNavItem = document.querySelector('.nav-item.active[data-view]');
    const activeIsVisible = activeNavItem && visibleForNav[activeNavItem.dataset.view] !== false;
    if (activeNavItem && activeNavItem.dataset.view && activeIsVisible) {
        switchView(activeNavItem.dataset.view, activeNavItem);
    } else {
        const firstVisible = Array.from(document.querySelectorAll('.main-nav .nav-item[data-view]')).find(item => visibleForNav[item.dataset.view] !== false);
        if (firstVisible) {
            switchView(firstVisible.dataset.view, firstVisible);
        } else {
            switchView('browser');
        }
    }

    // Sidebar toggle functionality

    // Fonction pour créer et ajouter le bouton toggle à une top-bar
    function addToggleButtonToTopBar(topBar) {
        // Vérifier si le bouton existe déjà
        if (topBar.querySelector('#sidebar-toggle-btn')) {
            return;
        }

        const toggleBtn = document.createElement('button');
        toggleBtn.id = 'sidebar-toggle-btn';
        toggleBtn.className = 'btn btn-secondary';
        toggleBtn.title = 'Toggle Sidebar';
        toggleBtn.style.cssText = 'padding: 8px 12px; min-width: auto;';
        toggleBtn.innerHTML = '<span class="material-symbols-outlined" id="sidebar-toggle-icon">menu</span>';

        // Insérer le bouton au début de la top-bar
        const firstChild = topBar.firstElementChild;

        // Vérifier si le premier enfant est déjà un conteneur flex
        const isFlexContainer = firstChild &&
            firstChild.style &&
            firstChild.style.display === 'flex' &&
            firstChild.style.alignItems === 'center';

        if (isFlexContainer) {
            // Si le premier élément est déjà un conteneur flex, ajouter le bouton dedans au début
            firstChild.insertBefore(toggleBtn, firstChild.firstChild);
        } else {
            // Sinon, créer un nouveau conteneur flex
            const container = document.createElement('div');
            container.style.cssText = 'display: flex; align-items: center; gap: 12px;';
            container.appendChild(toggleBtn);

            // Déplacer tous les enfants existants dans le nouveau container
            const existingChildren = Array.from(topBar.childNodes);
            existingChildren.forEach(child => {
                if (child.nodeType === 1) { // Element node only
                    container.appendChild(child);
                }
            });

            // Ajouter le container à la top-bar
            topBar.appendChild(container);
        }
    }

    // Bouton engrenage (cog) en haut à droite : afficher/masquer les onglets (getTabsVisible, setTabsVisible, applyTabsVisibility définis plus haut au chargement)
    function addTabsSettingsButtonToTopBar(topBar) {
        if (topBar.querySelector('.tabs-settings-btn')) return;
        topBar.style.position = 'relative';
        topBar.style.paddingRight = '72px';
        const wrap = document.createElement('div');
        wrap.style.cssText = 'position: absolute; right: 16px; top: 50%; transform: translateY(-50%); flex-shrink: 0; display: flex; align-items: center;';
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'btn btn-secondary tabs-settings-btn';
        btn.title = 'Tab visibility';
        btn.style.cssText = 'padding: 5px 7px; min-width: auto;';
        btn.innerHTML = '<span class="material-symbols-outlined" style="font-size: 18px;">settings</span>';
        btn.addEventListener('click', openTabsSettingsModal);
        wrap.appendChild(btn);
        topBar.appendChild(wrap);
    }
    function openTabsSettingsModal() {
        const modal = document.getElementById('tabs-settings-modal');
        const listEl = document.getElementById('tabs-settings-list');
        if (!modal || !listEl) return;
        const visible = getTabsVisible();
        const items = [];
        document.querySelectorAll('.main-nav .nav-item[data-view]').forEach(item => {
            const viewId = item.dataset.view;
            const label = item.dataset.label || item.title || viewId;
            items.push({ viewId, label, checked: visible[viewId] !== false });
        });
        listEl.innerHTML = items.map(({ viewId, label, checked }) =>
            `<label style="display: flex; align-items: center; gap: 10px; padding: 8px 0; cursor: pointer;">
                <input type="checkbox" data-tabs-view="${viewId}" ${checked ? 'checked' : ''}>
                <span>${escapeHtml(label)}</span>
            </label>`
        ).join('');
        modal.style.display = 'flex';
        modal.setAttribute('aria-hidden', 'false');
    }
    function closeTabsSettingsModal() {
        const modal = document.getElementById('tabs-settings-modal');
        if (modal) {
            modal.style.display = 'none';
            modal.setAttribute('aria-hidden', 'true');
        }
    }
    function applyTabsSettingsFromModal() {
        const listEl = document.getElementById('tabs-settings-list');
        if (!listEl) return;
        const visible = {};
        listEl.querySelectorAll('input[type="checkbox"][data-tabs-view]').forEach(cb => {
            visible[cb.dataset.tabsView] = cb.checked;
        });
        setTabsVisible(visible);
        applyTabsVisibility();
        closeTabsSettingsModal();
    }
    document.getElementById('tabs-settings-modal-close')?.addEventListener('click', closeTabsSettingsModal);
    document.getElementById('tabs-settings-apply')?.addEventListener('click', applyTabsSettingsFromModal);
    document.getElementById('tabs-settings-modal')?.addEventListener('click', function (e) {
        if (e.target === this) closeTabsSettingsModal();
    });
    document.getElementById('tabs-settings-select-all')?.addEventListener('click', function () {
        document.querySelectorAll('#tabs-settings-list input[type="checkbox"]').forEach(cb => { cb.checked = true; });
    });
    document.getElementById('tabs-settings-select-none')?.addEventListener('click', function () {
        document.querySelectorAll('#tabs-settings-list input[type="checkbox"]').forEach(cb => { cb.checked = false; });
    });

    // Ajouter le bouton toggle et le bouton cog à toutes les top-bar
    const allTopBars = document.querySelectorAll('.top-bar');
    allTopBars.forEach(topBar => {
        addToggleButtonToTopBar(topBar);
        addTabsSettingsButtonToTopBar(topBar);
    });
    applyTabsVisibility();

    // Observer pour ajouter le bouton aux top-bar créées dynamiquement
    const topBarObserver = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
            mutation.addedNodes.forEach((node) => {
                if (node.nodeType === 1) { // Element node
                    if (node.classList && node.classList.contains('top-bar')) {
                        addToggleButtonToTopBar(node);
                        addTabsSettingsButtonToTopBar(node);
                    }
                    // Vérifier aussi les enfants
                    const topBars = node.querySelectorAll && node.querySelectorAll('.top-bar');
                    if (topBars) {
                        topBars.forEach(topBar => {
                            addToggleButtonToTopBar(topBar);
                            addTabsSettingsButtonToTopBar(topBar);
                        });
                    }
                }
            });
        });
    });

    topBarObserver.observe(document.body, {
        childList: true,
        subtree: true
    });

    if (sidebar) {
        // Restaurer l'état du sidebar depuis localStorage
        const sidebarExpanded = localStorage.getItem('sidebarExpanded') === 'true';
        if (sidebarExpanded) {
            sidebar.classList.add('expanded');
            updateToggleIcon();
        }

        // Gérer le clic sur le bouton toggle (délégation d'événements)
        document.addEventListener('click', (e) => {
            if (e.target.closest('#sidebar-toggle-btn')) {
                e.stopPropagation();
                sidebar.classList.toggle('expanded');
                const isExpanded = sidebar.classList.contains('expanded');
                localStorage.setItem('sidebarExpanded', isExpanded);
                updateToggleIcon();
            }
        });

        // Fonction pour mettre à jour l'icône
        function updateToggleIcon() {
            const icons = document.querySelectorAll('#sidebar-toggle-icon');
            const isExpanded = sidebar.classList.contains('expanded');
            icons.forEach(icon => {
                icon.textContent = isExpanded ? 'chevron_left' : 'menu';
            });
        }

        // Observer les changements de classe pour mettre à jour l'icône
        const sidebarObserver = new MutationObserver(() => {
            updateToggleIcon();
        });
        sidebarObserver.observe(sidebar, {
            attributes: true,
            attributeFilter: ['class']
        });
    }
});

// === ENCODER / DECODER ===
function encodeBase64(text) {
    const bytes = new TextEncoder().encode(text);
    let binary = '';
    bytes.forEach(b => binary += String.fromCharCode(b));
    return btoa(binary);
}

function decodeBase64(text) {
    const binary = atob(text);
    const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
    return new TextDecoder().decode(bytes);
}

function encodeHex(text) {
    return Array.from(text).map(ch => ch.charCodeAt(0).toString(16).padStart(2, '0')).join('');
}

function decodeHex(text) {
    const cleaned = text.replace(/\s+/g, '');
    if (cleaned.length % 2 !== 0) {
        throw new Error('Invalid hex length');
    }
    if (!cleaned) return '';
    const bytes = cleaned.match(/.{1,2}/g).map(byte => parseInt(byte, 16));
    return String.fromCharCode(...bytes);
}

function encodeHtmlEntities(text) {
    return text.replace(/[\u00A0-\u9999<>&'"]/gim, i => '&#' + i.charCodeAt(0) + ';');
}

function decodeHtmlEntities(text) {
    const txt = document.createElement('textarea');
    txt.innerHTML = text;
    return txt.value;
}

function runEncoder(action) {
    if (!encoderInputEl || !encoderOutputEl) return;
    const mode = encoderModeSelect ? encoderModeSelect.value : 'base64';
    const source = encoderInputEl.value || '';

    try {
        let result = source;
        switch (mode) {
            case 'base64':
                result = action === 'encode' ? encodeBase64(source) : decodeBase64(source);
                break;
            case 'url':
                result = action === 'encode' ? encodeURIComponent(source) : decodeURIComponent(source);
                break;
            case 'html':
                result = action === 'encode' ? encodeHtmlEntities(source) : decodeHtmlEntities(source);
                break;
            case 'hex':
                result = action === 'encode' ? encodeHex(source) : decodeHex(source);
                break;
        }
        encoderOutputEl.value = result;
        showToast(`Texte ${action === 'encode' ? 'encodé' : 'décodé'} (${mode})`, 'success');
    } catch (err) {
        console.error('[Encoder] error', err);
        showToast(`Erreur lors du ${action === 'encode' ? 'codage' : 'décodage'} (${mode})`, 'error');
    }
}

function copyEncoderText(targetEl) {
    if (!targetEl) return;
    copyToClipboard(targetEl.value || '').then(ok => {
        if (ok) {
            showToast('Copié dans le presse-papiers', 'success');
        } else {
            showToast('Impossible de copier le texte', 'error');
        }
    });
}

if (encoderEncodeBtn && encoderDecodeBtn) {
    encoderEncodeBtn.addEventListener('click', () => runEncoder('encode'));
    encoderDecodeBtn.addEventListener('click', () => runEncoder('decode'));
}

if (encoderSwapBtn && encoderInputEl && encoderOutputEl) {
    encoderSwapBtn.addEventListener('click', () => {
        [encoderInputEl.value, encoderOutputEl.value] = [encoderOutputEl.value, encoderInputEl.value];
        showToast('Champs échangés', 'info');
    });
}

if (encoderClearBtn && encoderInputEl && encoderOutputEl) {
    encoderClearBtn.addEventListener('click', () => {
        encoderInputEl.value = '';
        encoderOutputEl.value = '';
    });
}

if (encoderCopyInputBtn) {
    encoderCopyInputBtn.addEventListener('click', () => copyEncoderText(encoderInputEl));
}

if (encoderCopyOutputBtn) {
    encoderCopyOutputBtn.addEventListener('click', () => copyEncoderText(encoderOutputEl));
}

// === SIDECHANNEL ===
let sidechannelContentDefaultHTML = null;

// Sauvegarder les données SideChannel dans localStorage
function saveSidechannelData() {
    try {
        const dataToSave = {
            generatedUrls: sidechannelGeneratedUrls.map(url => ({
                ...url,
                generated_at: url.generated_at instanceof Date ? url.generated_at.toISOString() : url.generated_at
            })),
            tests: sidechannelTests.map(test => ({
                ...test,
                timestamp: test.timestamp instanceof Date ? test.timestamp.toISOString() : test.timestamp
            })),
            detections: sidechannelDetections.map(detection => ({
                ...detection,
                detected_at: detection.detected_at instanceof Date ? detection.detected_at.toISOString() : detection.detected_at
            }))
        };
        localStorage.setItem('sidechannelData', JSON.stringify(dataToSave));
    } catch (err) {
        console.error('Error saving SideChannel data:', err);
    }
}

// Restaurer les données SideChannel depuis localStorage
function restoreSidechannelData() {
    try {
        const savedData = localStorage.getItem('sidechannelData');
        if (savedData) {
            const data = JSON.parse(savedData);

            // Restaurer les URLs générées
            if (data.generatedUrls && Array.isArray(data.generatedUrls)) {
                sidechannelGeneratedUrls = data.generatedUrls.map(url => ({
                    ...url,
                    generated_at: url.generated_at ? new Date(url.generated_at) : new Date()
                }));
            }

            // Restaurer les tests
            if (data.tests && Array.isArray(data.tests)) {
                sidechannelTests = data.tests.map(test => ({
                    ...test,
                    timestamp: test.timestamp ? new Date(test.timestamp) : new Date()
                }));
            }

            // Restaurer les détections
            if (data.detections && Array.isArray(data.detections)) {
                sidechannelDetections = data.detections.map(detection => ({
                    ...detection,
                    detected_at: detection.detected_at ? new Date(detection.detected_at) : new Date()
                }));
            }

            // Mettre à jour l'affichage
            if (currentViewId === 'sidechannel') {
                renderSidechannelUrls();
                renderSidechannelResults();
                updateSidechannelResultsBadge();

                // Redémarrer le polling si nécessaire
                const hasPendingTests = sidechannelTests.some(t => t.status === 'pending');
                if (hasPendingTests) {
                    startSidechannelPolling();
                }
            }
        }
    } catch (err) {
        console.error('Error restoring SideChannel data:', err);
    }
}

function renderSidechannelApiKeyRequired(message) {
    if (currentViewId !== 'sidechannel') return;
    const content = document.getElementById('sidechannel-content');
    if (content) {
        if (!sidechannelContentDefaultHTML) {
            sidechannelContentDefaultHTML = content.innerHTML;
        }
        content.innerHTML = `
            <div style="width: 100%; display: flex; align-items: center; justify-content: center; padding: 20px 0;">
                <div style="max-width: 420px; width: 90%; padding: 22px; border: 1px solid rgba(0,255,255,0.25); border-radius: 12px; background: #181a23; color: #fff; font-family: 'Segoe UI', sans-serif; box-shadow: 0 10px 30px rgba(0,0,0,0.35); text-align: center;">
                    <h3 style="margin: 0 0 8px 0; color: #00ffff; font-size: 20px; text-align: center;">Pro feature – API key required</h3>
                    <p style="margin: 6px 0 12px 0; color: rgba(255,255,255,0.9); text-align: center;">${message || 'SideChannel requires a valid API key.'}</p>
                    <div style="padding: 12px; border: 1px dashed rgba(0,255,255,0.35); border-radius: 10px; background: rgba(0,255,255,0.06); color: rgba(255,255,255,0.95); font-size: 13px; text-align: center;">
                        <p style="margin: 0 0 6px 0; text-align: center;">Add your key in <code style="background: rgba(255,255,255,0.12); padding: 2px 6px; border-radius: 6px; color: #00ffff;">config.toml</code> :</p>
                        <p style="margin: 0; font-family: Consolas, monospace; text-align: center;">
                            [FRAMEWORK]<br>
                            api_key = "your_api_key"
                        </p>
                    </div>
                    <p style="margin: 14px 0 0 0; color: rgba(255,255,255,0.75); font-size: 12px; text-align: center;">Restart KittyProxy after updating.</p>
                </div>
            </div>
        `;
        content.style.display = 'flex';
        content.style.justifyContent = 'center';
        content.style.alignItems = 'center';
    }
    hydrateSidechannelDom();
    if (sidechannelTestBtn) sidechannelTestBtn.disabled = true;
}

function removeSidechannelApiOverlay() {
    if (currentViewId !== 'sidechannel') return;
    const content = document.getElementById('sidechannel-content');
    if (content && sidechannelContentDefaultHTML) {
        content.innerHTML = sidechannelContentDefaultHTML;
        // Restore default styles
        content.style.display = '';
        content.style.justifyContent = '';
        content.style.alignItems = '';
        hydrateSidechannelDom();
    }
}

// Load and check API key status from server (utilise le même endpoint que collaboration)
async function checkSidechannelApiKey() {
    if (currentViewId !== 'sidechannel') return;

    try {
        // Utilise le même endpoint que la collaboration
        const res = await fetch(`${API_BASE}/collab/auth`);
        if (!res.ok) {
            const data = await res.json().catch(() => ({}));
            renderSidechannelApiKeyRequired(data.detail || data.message || 'API key invalid or missing.');
            sidechannelApiKeyValid = false;
            return false;
        }
        const data = await res.json();
        sidechannelApiKeyValid = !!(data.valid && data.token);

        if (sidechannelApiKeyValid) {
            removeSidechannelApiOverlay();
            updateSidechannelTestButtonState();
            if (sidechannelGenerateUrlBtn) sidechannelGenerateUrlBtn.disabled = false;
            // Initialize the correct mode on first load (default to manual)
            switchSidechannelMode(currentSidechannelMode || 'manual');
        } else {
            renderSidechannelApiKeyRequired(data.detail || data.message || 'API key invalid or missing.');
            if (sidechannelTestBtn) sidechannelTestBtn.disabled = true;
            if (sidechannelGenerateUrlBtn) sidechannelGenerateUrlBtn.disabled = true;
        }
        return sidechannelApiKeyValid;
    } catch (err) {
        console.error('Error checking SideChannel API key:', err);
        renderSidechannelApiKeyRequired('Unable to validate API key.');
        sidechannelApiKeyValid = false;
        return false;
    }
}

function getMethodColor(method) {
    const colors = {
        'GET': '#4caf50',
        'POST': '#2196f3',
        'PUT': '#ff9800',
        'DELETE': '#f44336',
        'PATCH': '#9c27b0'
    };
    return colors[method] || '#666';
}

function getStatusColor(status) {
    if (status >= 200 && status < 300) return '#4caf50';
    if (status >= 300 && status < 400) return '#ff9800';
    if (status >= 400) return '#f44336';
    return '#666';
}

function escapeHtml(value) {
    if (value === null || value === undefined) return '';
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function formatDuration(ms) {
    if (ms === null || ms === undefined) return '--';
    if (ms >= 1000) {
        return `${(ms / 1000).toFixed(1)}s`;
    }
    return `${Math.max(1, Math.round(ms))} ms`;
}

function formatResponseSize(bytes) {
    if (bytes === null || bytes === undefined) return '--';
    if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes === 0) return '0 B';
    return `${bytes} B`;
}

function updateSidechannelTestButtonState() {
    if (!sidechannelTestBtn) return;
    if (sidechannelTestBtn.dataset.loading === '1') {
        return;
    }
    const shouldEnable = sidechannelApiKeyValid && !!selectedSidechannelFlowId;
    sidechannelTestBtn.disabled = !shouldEnable;
}

// Load flows for SideChannel
async function loadSidechannelFlows(options = {}) {
    if (!sidechannelFlowsList) return;
    const { forceNetwork = false } = options;
    const now = Date.now();
    if (!forceNetwork && sidechannelFlowsFetchInFlight) {
        return;
    }
    if (!forceNetwork && now - sidechannelLastFlowFetchTs < SIDECHANNEL_MIN_FLOW_FETCH_INTERVAL) {
        renderSidechannelFlows();
        return;
    }
    sidechannelFlowsFetchInFlight = true;
    if (sidechannelFlowCache.length === 0) {
        sidechannelFlowsList.innerHTML = '<div style="text-align: center; padding: 40px 20px; color: #888; font-size: 0.9rem;">Loading flows...</div>';
    }
    try {
        const res = await fetch(`${API_BASE}/flows?page=1&size=1000`);
        if (!res.ok) {
            throw new Error(`HTTP ${res.status}: ${res.statusText}`);
        }
        const data = await res.json();
        const flows = data.items || data.flows || [];
        const signature = flows.map(flow => {
            const flowId = flow.id || flow.flow_id || '';
            const status = flow.status_code || flow.response?.status_code || '';
            const method = flow.method || flow.request?.method || '';
            return `${flowId}:${status}:${method}:${flow.timestamp_start || ''}`;
        }).join('|');
        sidechannelLastFlowFetchTs = now;
        if (!forceNetwork && signature === sidechannelFlowsSignature && sidechannelFlowCache.length) {
            renderSidechannelFlows();
            return;
        }
        sidechannelFlowsSignature = signature;
        sidechannelFlowCache = flows;
        renderSidechannelFlows();
    } catch (err) {
        console.error('Error loading SideChannel flows:', err);
        if (sidechannelFlowsList) {
            sidechannelFlowsList.innerHTML = '<div style="text-align: center; padding: 50px 20px; color: #f44336; font-size: 0.9rem;">Error loading flows</div>';
        }
    } finally {
        sidechannelFlowsFetchInFlight = false;
    }
}

function renderSidechannelFlows() {
    if (!sidechannelFlowsList) return;
    const searchTerm = (sidechannelFlowSearch?.value || '').trim().toLowerCase();
    const hasFlows = sidechannelFlowCache.length > 0;
    const filteredFlows = hasFlows
        ? sidechannelFlowCache.filter(flow => {
            if (!searchTerm) return true;
            const url = (flow.request?.url || flow.url || flow.path || '').toLowerCase();
            const method = (flow.request?.method || flow.method || '').toLowerCase();
            const status = String(flow.status_code ?? flow.response?.status_code ?? '').toLowerCase();
            return url.includes(searchTerm) || method.includes(searchTerm) || status.includes(searchTerm);
        })
        : [];

    const selectionVisible = filteredFlows.some(flow => {
        const flowId = flow.id || flow.flow_id || flow.uuid;
        return flowId && flowId === selectedSidechannelFlowId;
    });
    if (!selectionVisible) {
        selectedSidechannelFlowId = null;
    }
    updateSidechannelTestButtonState();

    if (!hasFlows) {
        sidechannelFlowsList.innerHTML = '<div style="text-align: center; padding: 50px 20px; color: #888; font-size: 0.9rem;">No flows available. Make sure the proxy is running and capturing traffic.</div>';
        return;
    }

    if (filteredFlows.length === 0) {
        sidechannelFlowsList.innerHTML = '<div style="text-align: center; padding: 50px 20px; color: #888; font-size: 0.9rem;">No flows match your search</div>';
        return;
    }

    const fragment = document.createDocumentFragment();
    filteredFlows.forEach(flow => {
        const flowId = flow.id || flow.flow_id || flow.uuid;
        const method = (flow.request?.method || flow.method || 'GET').toUpperCase();
        const url = flow.request?.url || flow.url || flow.request?.path || flow.path || 'Unknown URL';
        const statusValue = flow.status_code ?? flow.response?.status_code ?? '-';
        const status = statusValue === null || statusValue === undefined || statusValue === '' ? '---' : statusValue;
        let host = flow.host || flow.request?.host || '';
        if (!host && url) {
            try {
                const parsed = new URL(url);
                host = parsed.host;
            } catch {
                // ignore parsing errors
            }
        }
        const durationLabel = formatDuration(flow.duration_ms);
        const sizeLabel = formatResponseSize(flow.response_size);
        const metaParts = [];
        if (durationLabel !== '--') metaParts.push(durationLabel);
        if (sizeLabel !== '--') metaParts.push(sizeLabel);
        const metaText = metaParts.length ? metaParts.join(' | ') : '--';
        const isSelected = flowId && flowId === selectedSidechannelFlowId;

        const item = document.createElement('div');
        item.className = 'sidechannel-flow-item' + (isSelected ? ' selected' : '');
        item.title = url;

        item.innerHTML = `
            <div class="sidechannel-flow-header">
                <div class="sidechannel-flow-badges">
                    <span style="padding: 4px 10px; background: ${getMethodColor(method)}; color: white; border-radius: 4px; font-size: 12px; font-weight: 600; font-family: 'Fira Code', monospace;">${escapeHtml(method)}</span>
                    <span style="padding: 4px 10px; background: ${getStatusColor(statusValue)}; color: white; border-radius: 4px; font-size: 12px; font-weight: 600;">${escapeHtml(status)}</span>
                </div>
                <div class="sidechannel-flow-url-container">
                    <div class="sidechannel-flow-url">${escapeHtml(url)}</div>
                    ${host ? `<div class="sidechannel-flow-host">${escapeHtml(host)}</div>` : ''}
                </div>
            </div>
            <div class="sidechannel-flow-meta">
                ${metaText !== '--' ? `<span>${escapeHtml(metaText)}</span>` : ''}
            </div>
        `;

        item.addEventListener('click', () => {
            selectedSidechannelFlowId = flowId;
            document.querySelectorAll('#sidechannel-flows-list .sidechannel-flow-item').forEach(el => {
                el.classList.remove('selected');
            });
            item.classList.add('selected');
            updateSidechannelTestButtonState();
        });

        fragment.appendChild(item);
    });

    sidechannelFlowsList.innerHTML = '';
    sidechannelFlowsList.appendChild(fragment);
}

async function handleSidechannelGenerateUrlClick() {
    if (!sidechannelApiKeyValid) {
        showToast('API key not configured or invalid. Please configure it in config.toml', 'error');
        return;
    }
    if (!sidechannelGenerateUrlBtn) return;
    const attackType = sidechannelManualAttackTypeSelect ? sidechannelManualAttackTypeSelect.value : 'xxe';
    sidechannelGenerateUrlBtn.disabled = true;
    sidechannelGenerateUrlBtn.innerHTML = '<span class="material-symbols-outlined" style="font-size: 18px;">hourglass_empty</span> Generating...';
    try {
        const res = await fetch(`${API_BASE}/sidechannel/generate-url`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ attack_type: attackType })
        });
        const data = await res.json();
        if (res.ok) {
            currentGeneratedUrl = data.sidechannel_url;
            const testId = data.test_id;
            if (sidechannelGeneratedUrlInput) {
                sidechannelGeneratedUrlInput.value = currentGeneratedUrl || '';
            }
            if (sidechannelCopyUrlBtn) {
                sidechannelCopyUrlBtn.disabled = !currentGeneratedUrl;
            }
            const urlEntry = {
                id: `url-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                test_id: testId,
                attack_type: attackType,
                sidechannel_url: currentGeneratedUrl,
                generated_at: new Date(),
                status: 'pending'
            };
            sidechannelGeneratedUrls.push(urlEntry);
            saveSidechannelData();
            if (currentSidechannelMode === 'urls') {
                renderSidechannelUrls();
            }
            const test = {
                id: testId,
                flow_id: 'manual',
                attack_type: attackType,
                sidechannel_url: currentGeneratedUrl,
                status: 'pending',
                detected: false,
                timestamp: new Date(),
                details: {},
                manual: true
            };
            sidechannelTests.push(test);
            saveSidechannelData();
            renderSidechannelTests();
            showToast('URL generated! Copy it and inject it manually in your payloads.', 'success');
            startSidechannelPolling();
        } else {
            showToast(data.detail || data.message || 'Failed to generate URL', 'error');
        }
    } catch (err) {
        console.error('SideChannel generate URL error:', err);
        showToast('Failed to generate URL', 'error');
    } finally {
        if (sidechannelGenerateUrlBtn) {
            sidechannelGenerateUrlBtn.disabled = !sidechannelApiKeyValid;
            sidechannelGenerateUrlBtn.innerHTML = '<span class="material-symbols-outlined" style="font-size: 18px;">link</span> Generate URL';
        }
    }
}

function handleSidechannelCopyUrlClick() {
    if (!currentGeneratedUrl) {
        showToast('No URL to copy yet', 'info');
        return;
    }
    copyToClipboard(currentGeneratedUrl).then(ok => {
        if (ok) {
            showToast('URL copied to clipboard', 'success');
        } else {
            showToast('Failed to copy URL', 'error');
        }
    });
}

async function handleSidechannelTestClick() {
    if (!selectedSidechannelFlowId) {
        showToast('Please select a flow to test', 'error');
        return;
    }
    if (!sidechannelApiKeyValid) {
        showToast('API key not configured or invalid. Please configure it in config.toml', 'error');
        return;
    }
    if (!sidechannelTestBtn) return;
    const attackType = sidechannelAttackTypeSelect ? sidechannelAttackTypeSelect.value : 'xxe';
    sidechannelTestBtn.dataset.loading = '1';
    sidechannelTestBtn.disabled = true;
    sidechannelTestBtn.innerHTML = '<span class="material-symbols-outlined" style="font-size: 18px;">hourglass_empty</span> Starting...';
    try {
        const res = await fetch(`${API_BASE}/sidechannel/test`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                flow_id: selectedSidechannelFlowId,
                attack_type: attackType
            })
        });
        const data = await res.json();
        if (res.ok) {
            const test = {
                id: data.test_id || `test-${Date.now()}`,
                flow_id: data.flow_id,
                attack_type: data.attack_type,
                sidechannel_url: data.sidechannel_url,
                status: 'pending',
                detected: data.detected || false,
                timestamp: new Date(),
                details: data.details || {},
                request_duration: data.request_duration,
                target_response_status: data.target_response_status
            };
            sidechannelTests.push(test);
            saveSidechannelData();
            showToast('Test started! Monitoring for requests...', 'success');
            startSidechannelPolling();
            checkSidechannelTest(test.id);
        } else {
            showToast(data.detail || data.message || 'Test failed', 'error');
        }
    } catch (err) {
        console.error('SideChannel test error:', err);
        showToast('Failed to start test', 'error');
    } finally {
        if (sidechannelTestBtn) {
            delete sidechannelTestBtn.dataset.loading;
            sidechannelTestBtn.innerHTML = '<span class="material-symbols-outlined" style="font-size: 18px;">bug_report</span> Test Attack';
        }
        updateSidechannelTestButtonState();
    }
}

function handleSidechannelExportResultsClick() {
    if (sidechannelDetections.length === 0) {
        showToast('No detections to export', 'info');
        return;
    }
    const exportData = {
        export_date: new Date().toISOString(),
        total_detections: sidechannelDetections.length,
        detections: sidechannelDetections.map(d => ({
            id: d.id,
            test_id: d.test_id,
            attack_type: d.attack_type,
            sidechannel_url: d.sidechannel_url,
            detected_at: d.detected_at.toISOString(),
            evidence: d.evidence,
            flow_id: d.flow_id,
            manual: d.manual
        }))
    };
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sidechannel-detections-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast('Results exported successfully', 'success');
}

function handleSidechannelClearResultsClick() {
    if (sidechannelDetections.length === 0) {
        showToast('No results to clear', 'info');
        return;
    }
    if (confirm('Clear all detection results? This cannot be undone.')) {
        sidechannelDetections = [];
        saveSidechannelData();
        updateSidechannelResultsBadge();
        renderSidechannelResults();
        showToast('All results cleared', 'info');
    }
}

function hydrateSidechannelDom() {
    sidechannelTabManual = document.getElementById('sidechannel-tab-manual');
    sidechannelTabUrls = document.getElementById('sidechannel-tab-urls');
    sidechannelTabResults = document.getElementById('sidechannel-tab-results');
    sidechannelResultsBadge = document.getElementById('sidechannel-results-badge');
    sidechannelManualMode = document.getElementById('sidechannel-manual-mode');
    sidechannelUrlsMode = document.getElementById('sidechannel-urls-mode');
    sidechannelResultsMode = document.getElementById('sidechannel-results-mode');
    sidechannelUrlsList = document.getElementById('sidechannel-urls-list');
    sidechannelManualAttackTypeSelect = document.getElementById('sidechannel-manual-attack-type');
    sidechannelGenerateUrlBtn = document.getElementById('sidechannel-generate-url-btn');
    sidechannelResultsList = document.getElementById('sidechannel-results-list');
    sidechannelGeneratedUrlInput = document.getElementById('sidechannel-generated-url');
    sidechannelCopyUrlBtn = document.getElementById('sidechannel-copy-url-btn');
    sidechannelExportResultsBtn = document.getElementById('sidechannel-export-results-btn');
    sidechannelClearResultsBtn = document.getElementById('sidechannel-clear-results-btn');

    if (sidechannelTabManual) sidechannelTabManual.onclick = () => switchSidechannelMode('manual');
    if (sidechannelTabUrls) sidechannelTabUrls.onclick = () => switchSidechannelMode('urls');
    if (sidechannelTabResults) sidechannelTabResults.onclick = () => switchSidechannelMode('results');
    if (sidechannelGenerateUrlBtn) {
        sidechannelGenerateUrlBtn.onclick = handleSidechannelGenerateUrlClick;
        sidechannelGenerateUrlBtn.disabled = !sidechannelApiKeyValid;
    }
    if (sidechannelCopyUrlBtn) {
        sidechannelCopyUrlBtn.onclick = handleSidechannelCopyUrlClick;
        sidechannelCopyUrlBtn.disabled = !currentGeneratedUrl;
    }
    if (sidechannelTestBtn) {
        sidechannelTestBtn.onclick = handleSidechannelTestClick;
        updateSidechannelTestButtonState();
    }
    if (sidechannelExportResultsBtn) {
        sidechannelExportResultsBtn.onclick = handleSidechannelExportResultsClick;
    }
    if (sidechannelClearResultsBtn) {
        sidechannelClearResultsBtn.onclick = handleSidechannelClearResultsClick;
    }

    if (currentSidechannelMode === 'urls') {
        renderSidechannelUrls();
    } else if (currentSidechannelMode === 'results') {
        renderSidechannelResults();
    }
    updateSidechannelResultsBadge();
}

hydrateSidechannelDom();

// Mode switching
function switchSidechannelMode(mode) {
    currentSidechannelMode = mode;

    // Update tabs
    const tabs = [sidechannelTabManual, sidechannelTabUrls, sidechannelTabResults];
    tabs.forEach(tab => {
        if (tab) {
            tab.classList.remove('active');
            tab.style.borderBottomColor = 'transparent';
            tab.style.color = '#666';
            tab.style.fontWeight = '500';
        }
    });

    if (mode === 'manual' && sidechannelTabManual) {
        sidechannelTabManual.classList.add('active');
        sidechannelTabManual.style.borderBottomColor = 'var(--primary-color, #6200ea)';
        sidechannelTabManual.style.color = 'var(--primary-color, #6200ea)';
        sidechannelTabManual.style.fontWeight = '600';
    } else if (mode === 'urls' && sidechannelTabUrls) {
        sidechannelTabUrls.classList.add('active');
        sidechannelTabUrls.style.borderBottomColor = 'var(--primary-color, #6200ea)';
        sidechannelTabUrls.style.color = 'var(--primary-color, #6200ea)';
        sidechannelTabUrls.style.fontWeight = '600';
    } else if (mode === 'results' && sidechannelTabResults) {
        sidechannelTabResults.classList.add('active');
        sidechannelTabResults.style.borderBottomColor = 'var(--primary-color, #6200ea)';
        sidechannelTabResults.style.color = 'var(--primary-color, #6200ea)';
        sidechannelTabResults.style.fontWeight = '600';
    }

    // Update panels
    if (sidechannelManualMode && sidechannelUrlsMode && sidechannelResultsMode) {
        // Hide all panels first
        sidechannelManualMode.style.display = 'none';
        sidechannelUrlsMode.style.display = 'none';
        sidechannelResultsMode.style.display = 'none';

        if (mode === 'manual') {
            sidechannelManualMode.style.display = 'block';
        } else if (mode === 'urls') {
            sidechannelUrlsMode.style.display = 'block';
            // Render URLs list
            renderSidechannelUrls();
        } else if (mode === 'results') {
            sidechannelResultsMode.style.display = 'flex';
            // Render results
            renderSidechannelResults();
        }
    }
}

// Rendre la liste des tests
// Function kept for compatibility but does nothing - tests panel has been removed
// Tests are still tracked in memory for polling and detection purposes
function renderSidechannelTests() {
    // No-op: tests panel removed, but tests are still tracked in memory
    return;
}

// Copier l'URL SideChannel
function copySidechannelUrl(url) {
    copyToClipboard(url).then(ok => {
        if (ok) {
            showToast('URL copied to clipboard', 'success');
        } else {
            showToast('Failed to copy URL', 'error');
        }
    });
}
window.copySidechannelUrl = copySidechannelUrl;

// Supprimer un test
function deleteSidechannelTest(testId) {
    sidechannelTests = sidechannelTests.filter(t => t.id !== testId);
    renderSidechannelTests();
    showToast('Test removed', 'info');
}
window.deleteSidechannelTest = deleteSidechannelTest;

// Vérifier le statut d'un test
async function checkSidechannelTest(testId) {
    const test = sidechannelTests.find(t => t.id === testId);
    if (!test) return;

    // Ne vérifier que les tests en attente
    if (test.status !== 'pending') return;

    try {
        const res = await fetch(`${API_BASE}/sidechannel/check/${testId}`, {
            method: 'GET',
            headers: { 'Content-Type': 'application/json' }
        });

        if (res.ok) {
            const data = await res.json();
            test.status = data.detected ? 'detected' : (data.message && data.message.includes('expired') ? 'error' : 'pending');
            test.detected = data.detected || false;
            if (data.details) {
                // Merger les détails, en préservant l'evidence existante
                test.details = {
                    ...test.details,
                    ...data.details,
                    evidence: data.details.evidence || test.details.evidence || data.details.request_details || test.details.evidence
                };
            }
            // Mettre à jour la liste des URLs si on est en mode URLs
            if (currentSidechannelMode === 'urls') {
                renderSidechannelUrls();
            }

            // Si une vulnérabilité est détectée, ajouter à la liste des détections
            if (data.detected) {
                // Vérifier si cette détection n'existe pas déjà
                const existingDetection = sidechannelDetections.find(d => d.test_id === test.id);
                if (!existingDetection) {
                    const detection = {
                        id: `detection-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                        test_id: test.id,
                        attack_type: test.attack_type,
                        sidechannel_url: test.sidechannel_url,
                        detected_at: new Date(),
                        evidence: test.details?.evidence || data.details?.evidence || {},
                        flow_id: test.flow_id,
                        manual: test.manual || false
                    };
                    sidechannelDetections.push(detection);
                    saveSidechannelData();
                    updateSidechannelResultsBadge();
                    // Si on est en mode results, re-render
                    if (currentSidechannelMode === 'results') {
                        renderSidechannelResults();
                    }
                }
                showToast(`⚠️ Vulnerability detected for ${test.attack_type.toUpperCase()}! Check Results tab.`, 'error');
            }
        } else if (res.status === 404) {
            // Test expiré ou non trouvé
            test.status = 'error';
            test.details = { ...test.details, message: 'Test expired or not found' };
        }
    } catch (err) {
        console.error('Error checking test:', err);
        // Ne pas changer le statut en cas d'erreur réseau
    }
}

// Démarrer le polling automatique
function startSidechannelPolling() {
    if (sidechannelPollInterval) return; // Déjà en cours

    sidechannelPollInterval = setInterval(() => {
        sidechannelTests.filter(t => t.status === 'pending').forEach(test => {
            checkSidechannelTest(test.id);
        });
    }, 5000); // Vérifier toutes les 5 secondes
}

// Arrêter le polling
function stopSidechannelPolling() {
    if (sidechannelPollInterval) {
        clearInterval(sidechannelPollInterval);
        sidechannelPollInterval = null;
    }
}

// Toggle auto-poll
// Auto-polling is now always enabled when there are active tests
// No manual controls needed since the tests panel has been removed

// Afficher les détails d'un test
function showSidechannelTestDetails(test) {
    const overlay = document.getElementById('sidechannel-details-overlay');
    const panel = document.getElementById('sidechannel-details-panel');
    const content = document.getElementById('sidechannel-details-content');

    if (!overlay || !panel || !content) return;

    // Construire le contenu de la modal
    let html = `
        <div style="display: flex; flex-direction: column; gap: 20px;">
            <!-- Test Information -->
            <div style="background: #f5f5f5; border-radius: 8px; padding: 16px;">
                <h3 style="margin: 0 0 12px 0; font-size: 16px; font-weight: 600; color: #333; display: flex; align-items: center; gap: 8px;">
                    <span class="material-symbols-outlined" style="font-size: 20px;">info</span>
                    Test Information
                </h3>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; font-size: 0.9rem;">
                    <div>
                        <div style="color: #666; margin-bottom: 4px;">Attack Type:</div>
                        <div style="font-weight: 600; color: #333;">${test.attack_type.toUpperCase()}</div>
                    </div>
                    <div>
                        <div style="color: #666; margin-bottom: 4px;">Status:</div>
                        <div style="font-weight: 600; color: ${test.status === 'detected' ? '#f44336' : test.status === 'not_detected' ? '#4caf50' : '#2196f3'};">
                            ${test.status === 'detected' ? 'Vulnerability Detected' : test.status === 'not_detected' ? 'No Vulnerability' : test.status === 'error' ? 'Error' : 'Monitoring...'}
                        </div>
                    </div>
                    <div>
                        <div style="color: #666; margin-bottom: 4px;">Timestamp:</div>
                        <div style="font-weight: 600; color: #333;">${test.timestamp.toLocaleString()}</div>
                    </div>
                    <div>
                        <div style="color: #666; margin-bottom: 4px;">Source:</div>
                        <div style="font-weight: 600; color: #333;">${test.manual ? 'Manual Injection' : `Flow: ${test.flow_id.substring(0, 12)}...`}</div>
                    </div>
                </div>
            </div>
            
            <!-- SideChannel URL -->
            <div style="background: #e3f2fd; border-left: 4px solid #2196f3; border-radius: 8px; padding: 16px;">
                <h3 style="margin: 0 0 12px 0; font-size: 16px; font-weight: 600; color: #1976d2; display: flex; align-items: center; gap: 8px;">
                    <span class="material-symbols-outlined" style="font-size: 20px;">link</span>
                    SideChannel URL
                </h3>
                <div style="display: flex; gap: 8px; align-items: center;">
                    <code style="flex: 1; padding: 10px; background: white; border-radius: 6px; font-family: 'Fira Code', monospace; font-size: 0.85rem; word-break: break-all; border: 1px solid #90caf9;">
                        ${test.sidechannel_url || 'N/A'}
                    </code>
                    <button onclick="copySidechannelUrl('${test.sidechannel_url}')" 
                        style="background: #2196f3; color: white; border: none; padding: 10px 16px; border-radius: 6px; cursor: pointer; font-size: 0.9rem; display: flex; align-items: center; gap: 6px; transition: background 0.2s;"
                        onmouseover="this.style.background='#1976d2'"
                        onmouseout="this.style.background='#2196f3'">
                        <span class="material-symbols-outlined" style="font-size: 18px;">content_copy</span>
                        Copy
                    </button>
                </div>
            </div>
    `;

    // Si une vulnérabilité a été détectée, afficher les détails de la requête
    if (test.status === 'detected' && test.details && test.details.evidence) {
        const evidence = test.details.evidence;
        html += `
            <div style="background: #ffebee; border-left: 4px solid #f44336; border-radius: 8px; padding: 16px;">
                <h3 style="margin: 0 0 12px 0; font-size: 16px; font-weight: 600; color: #c62828; display: flex; align-items: center; gap: 8px;">
                    <span class="material-symbols-outlined" style="font-size: 20px;">bug_report</span>
                    Request Details (Evidence)
                </h3>
                <div style="display: flex; flex-direction: column; gap: 16px;">
        `;

        // IP Source
        if (evidence.ip || evidence.remote_addr) {
            html += `
                <div>
                    <div style="color: #666; margin-bottom: 6px; font-size: 0.85rem; font-weight: 600;">Source IP:</div>
                    <div style="padding: 8px 12px; background: white; border-radius: 6px; font-family: 'Fira Code', monospace; font-size: 0.9rem;">
                        ${evidence.ip || evidence.remote_addr || 'N/A'}
                    </div>
                </div>
            `;
        }

        // Headers
        if (evidence.headers) {
            html += `
                <div>
                    <div style="color: #666; margin-bottom: 6px; font-size: 0.85rem; font-weight: 600;">Request Headers:</div>
                    <div style="padding: 12px; background: white; border-radius: 6px; max-height: 300px; overflow-y: auto;">
                        <pre style="margin: 0; font-family: 'Fira Code', monospace; font-size: 0.8rem; white-space: pre-wrap; word-break: break-word;">${JSON.stringify(evidence.headers, null, 2)}</pre>
                    </div>
                </div>
            `;
        }

        // User-Agent
        if (evidence.user_agent || (evidence.headers && evidence.headers['User-Agent'])) {
            html += `
                <div>
                    <div style="color: #666; margin-bottom: 6px; font-size: 0.85rem; font-weight: 600;">User-Agent:</div>
                    <div style="padding: 8px 12px; background: white; border-radius: 6px; font-family: 'Fira Code', monospace; font-size: 0.85rem; word-break: break-all;">
                        ${evidence.user_agent || evidence.headers['User-Agent'] || 'N/A'}
                    </div>
                </div>
            `;
        }

        // Method
        if (evidence.method) {
            html += `
                <div>
                    <div style="color: #666; margin-bottom: 6px; font-size: 0.85rem; font-weight: 600;">HTTP Method:</div>
                    <div style="padding: 8px 12px; background: white; border-radius: 6px; font-size: 0.9rem; font-weight: 600; display: inline-block;">
                        ${evidence.method}
                    </div>
                </div>
            `;
        }

        // Body
        if (evidence.body) {
            html += `
                <div>
                    <div style="color: #666; margin-bottom: 6px; font-size: 0.85rem; font-weight: 600;">Request Body:</div>
                    <div style="padding: 12px; background: white; border-radius: 6px; max-height: 200px; overflow-y: auto;">
                        <pre style="margin: 0; font-family: 'Fira Code', monospace; font-size: 0.8rem; white-space: pre-wrap; word-break: break-word;">${typeof evidence.body === 'string' ? evidence.body : JSON.stringify(evidence.body, null, 2)}</pre>
                    </div>
                </div>
            `;
        }

        // Timestamp de la requête
        if (evidence.timestamp || evidence.request_time) {
            html += `
                <div>
                    <div style="color: #666; margin-bottom: 6px; font-size: 0.85rem; font-weight: 600;">Request Timestamp:</div>
                    <div style="padding: 8px 12px; background: white; border-radius: 6px; font-size: 0.9rem;">
                        ${evidence.timestamp || evidence.request_time || 'N/A'}
                    </div>
                </div>
            `;
        }

        // Raw evidence (si disponible)
        if (Object.keys(evidence).length > 0) {
            html += `
                <div>
                    <div style="color: #666; margin-bottom: 6px; font-size: 0.85rem; font-weight: 600;">Raw Evidence (JSON):</div>
                    <div style="padding: 12px; background: white; border-radius: 6px; max-height: 300px; overflow-y: auto;">
                        <pre style="margin: 0; font-family: 'Fira Code', monospace; font-size: 0.75rem; white-space: pre-wrap; word-break: break-word;">${JSON.stringify(evidence, null, 2)}</pre>
                    </div>
                </div>
            `;
        }

        html += `
                </div>
            </div>
        `;
    } else if (test.status === 'pending') {
        html += `
            <div style="background: #e3f2fd; border-left: 4px solid #2196f3; border-radius: 8px; padding: 16px; text-align: center;">
                <span class="material-symbols-outlined" style="font-size: 48px; color: #2196f3; margin-bottom: 12px; display: block;">hourglass_empty</span>
                <div style="font-size: 1rem; color: #1976d2; font-weight: 600;">Monitoring for requests...</div>
                <div style="font-size: 0.85rem; color: #666; margin-top: 8px;">The system is waiting for a request on the SideChannel URL.</div>
            </div>
        `;
    } else if (test.status === 'not_detected') {
        html += `
            <div style="background: #e8f5e9; border-left: 4px solid #4caf50; border-radius: 8px; padding: 16px; text-align: center;">
                <span class="material-symbols-outlined" style="font-size: 48px; color: #4caf50; margin-bottom: 12px; display: block;">check_circle</span>
                <div style="font-size: 1rem; color: #2e7d32; font-weight: 600;">No Vulnerability Detected</div>
                <div style="font-size: 0.85rem; color: #666; margin-top: 8px;">No request was received on the SideChannel URL.</div>
            </div>
        `;
    }

    // Recommendations
    if (test.details && test.details.recommendations && test.details.recommendations.length > 0) {
        html += `
            <div style="background: #fff3cd; border-left: 4px solid #ff9800; border-radius: 8px; padding: 16px;">
                <h3 style="margin: 0 0 12px 0; font-size: 16px; font-weight: 600; color: #856404; display: flex; align-items: center; gap: 8px;">
                    <span class="material-symbols-outlined" style="font-size: 20px;">lightbulb</span>
                    Recommendations
                </h3>
                <ul style="margin: 0; padding-left: 20px; color: #856404; font-size: 0.9rem; line-height: 1.8;">
                    ${test.details.recommendations.map(rec => `<li>${rec}</li>`).join('')}
                </ul>
            </div>
        `;
    }

    html += `
        </div>
    `;

    content.innerHTML = html;
    overlay.style.display = 'block';
    panel.style.display = 'block';
}

// Fermer la modal de détails
function closeSidechannelDetails() {
    const overlay = document.getElementById('sidechannel-details-overlay');
    const panel = document.getElementById('sidechannel-details-panel');
    if (overlay) overlay.style.display = 'none';
    if (panel) panel.style.display = 'none';
}
window.closeSidechannelDetails = closeSidechannelDetails;

// Render generated URLs list
function renderSidechannelUrls() {
    if (!sidechannelUrlsList) return;

    if (sidechannelGeneratedUrls.length === 0) {
        sidechannelUrlsList.innerHTML = `
            <div style="text-align: center; padding: 40px 20px; color: #888; font-size: 0.9rem;">
                No URLs generated yet. Go to "Manual Mode" to generate your first URL.
            </div>
        `;
        return;
    }

    sidechannelUrlsList.innerHTML = '';

    // Trier par date (plus récent en premier)
    const sortedUrls = [...sidechannelGeneratedUrls].sort((a, b) => b.generated_at - a.generated_at);

    sortedUrls.forEach(urlEntry => {
        const item = document.createElement('div');
        item.className = 'sidechannel-url-item';
        item.style.cssText = 'background: #f5f5f5; border-radius: 6px; padding: 12px; margin-bottom: 8px; border-left: 3px solid #2196f3;';

        // Trouver le test correspondant pour le statut
        const test = sidechannelTests.find(t => t.id === urlEntry.test_id);
        const status = test ? test.status : urlEntry.status;
        const statusColor = status === 'detected' ? '#f44336' : status === 'not_detected' ? '#4caf50' : '#2196f3';
        const statusIcon = status === 'detected' ? 'warning' : status === 'not_detected' ? 'check_circle' : 'hourglass_empty';
        const statusText = status === 'detected' ? 'Vulnerability Detected' : status === 'not_detected' ? 'No Vulnerability' : 'Monitoring...';

        item.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
                <div style="flex: 1;">
                    <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 6px;">
                        <span style="padding: 4px 8px; background: #e3f2fd; border-radius: 4px; font-size: 11px; color: #1976d2; font-weight: 600;">${urlEntry.attack_type.toUpperCase()}</span>
                        <span style="padding: 4px 8px; background: ${statusColor}20; color: ${statusColor}; border-radius: 4px; font-size: 11px; font-weight: 600; display: flex; align-items: center; gap: 4px;">
                            <span class="material-symbols-outlined" style="font-size: 14px;">${statusIcon}</span>
                            ${statusText}
                        </span>
                    </div>
                    <div style="font-size: 0.85rem; color: #666; margin-bottom: 4px;">
                        <div style="display: flex; align-items: center; gap: 6px;">
                            <span class="material-symbols-outlined" style="font-size: 14px;">link</span>
                            <code style="font-family: 'Fira Code', monospace; word-break: break-all; font-size: 0.8rem; color: #333;">${urlEntry.sidechannel_url}</code>
                            <button onclick="event.stopPropagation(); copySidechannelUrl('${urlEntry.sidechannel_url}')" 
                                style="background: #f5f5f5; border: none; padding: 4px 8px; border-radius: 4px; cursor: pointer; font-size: 11px; margin-left: 8px;">
                                <span class="material-symbols-outlined" style="font-size: 14px; vertical-align: middle;">content_copy</span>
                            </button>
                        </div>
                    </div>
                    <div style="font-size: 0.75rem; color: #999;">
                        ${urlEntry.generated_at.toLocaleString()}
                    </div>
                </div>
                <button class="delete-url-btn" onclick="event.stopPropagation(); deleteSidechannelUrl('${urlEntry.id}')" 
                    style="background: transparent; border: none; padding: 4px; cursor: pointer; color: #999; border-radius: 4px;">
                    <span class="material-symbols-outlined" style="font-size: 18px;">close</span>
                </button>
            </div>
        `;

        sidechannelUrlsList.appendChild(item);
    });
}

// Supprimer une URL générée
function deleteSidechannelUrl(urlId) {
    sidechannelGeneratedUrls = sidechannelGeneratedUrls.filter(u => u.id !== urlId);
    saveSidechannelData();
    renderSidechannelUrls();
    showToast('URL removed', 'info');
}
window.deleteSidechannelUrl = deleteSidechannelUrl;

// Clear all tests
// Clear button removed - tests panel has been removed

// Render results (détections)
function renderSidechannelResults() {
    if (!sidechannelResultsList) return;

    if (sidechannelDetections.length === 0) {
        sidechannelResultsList.innerHTML = `
            <div style="text-align: center; padding: 80px 20px; color: var(--text-secondary);">
                <span class="material-symbols-outlined" style="font-size: 64px; color: #ddd; margin-bottom: 20px; display: block;">analytics</span>
                <p style="font-size: 1rem; margin: 0;">No detections yet. Results will appear here when vulnerabilities are detected.</p>
            </div>
        `;
        return;
    }

    sidechannelResultsList.innerHTML = '';

    // Trier par date (plus récent en premier)
    const sortedDetections = [...sidechannelDetections].sort((a, b) => b.detected_at - a.detected_at);

    sortedDetections.forEach(detection => {
        const item = document.createElement('div');
        item.className = 'sidechannel-detection-item';
        item.style.cssText = 'background: white; border-radius: 8px; padding: 16px; margin-bottom: 12px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-left: 4px solid #f44336;';

        const evidence = detection.evidence || {};
        const ip = evidence.ip || evidence.remote_addr || 'Unknown';
        const method = evidence.method || 'GET';
        const userAgent = evidence.user_agent || (evidence.headers && evidence.headers['User-Agent']) || 'Unknown';
        const body = evidence.body || '';
        const headers = evidence.headers || {};

        item.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px;">
                <div style="flex: 1;">
                    <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
                        <span class="material-symbols-outlined" style="font-size: 20px; color: #f44336;">warning</span>
                        <span style="font-weight: 600; color: #333; font-size: 14px;">Vulnerability Detected</span>
                        <span style="padding: 4px 8px; background: #f5f5f5; border-radius: 4px; font-size: 11px; color: #666; font-weight: 600;">${detection.attack_type.toUpperCase()}</span>
                    </div>
                    <div style="font-size: 0.85rem; color: #666; margin-bottom: 8px;">
                        <div style="display: flex; align-items: center; gap: 6px; margin-bottom: 4px;">
                            <span class="material-symbols-outlined" style="font-size: 14px;">link</span>
                            <span style="font-family: 'Fira Code', monospace; word-break: break-all; font-size: 0.8rem;">${detection.sidechannel_url || 'N/A'}</span>
                        </div>
                        <div style="font-size: 0.75rem; color: #999; margin-top: 4px;">
                            ${detection.detected_at.toLocaleString()} • ${detection.manual ? 'Manual injection' : `Flow: ${detection.flow_id ? detection.flow_id.substring(0, 8) : 'N/A'}...`}
                        </div>
                    </div>
                </div>
                <button class="delete-detection-btn" onclick="event.stopPropagation(); deleteSidechannelDetection('${detection.id}')" 
                    style="background: transparent; border: none; padding: 4px; cursor: pointer; color: #999; border-radius: 4px;">
                    <span class="material-symbols-outlined" style="font-size: 18px;">close</span>
                </button>
            </div>
            
            <!-- Request Details -->
            <div style="background: #f5f5f5; border-radius: 6px; padding: 12px; margin-top: 12px;">
                <div style="font-weight: 600; color: #333; margin-bottom: 8px; font-size: 0.9rem; display: flex; align-items: center; gap: 6px;">
                    <span class="material-symbols-outlined" style="font-size: 16px;">info</span>
                    Request Details
                </div>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; font-size: 0.8rem; margin-bottom: 8px;">
                    <div>
                        <span style="color: #666; font-weight: 600;">Source IP:</span>
                        <div style="font-family: 'Fira Code', monospace; color: #333; margin-top: 2px;">${ip}</div>
                    </div>
                    <div>
                        <span style="color: #666; font-weight: 600;">Method:</span>
                        <div style="color: #333; margin-top: 2px;">${method}</div>
                    </div>
                </div>
                ${userAgent !== 'Unknown' ? `
                    <div style="margin-bottom: 8px;">
                        <span style="color: #666; font-weight: 600; font-size: 0.8rem;">User-Agent:</span>
                        <div style="font-family: 'Fira Code', monospace; color: #333; margin-top: 2px; font-size: 0.75rem; word-break: break-all;">${userAgent}</div>
                    </div>
                ` : ''}
                ${Object.keys(headers).length > 0 ? `
                    <details style="margin-top: 8px;">
                        <summary style="cursor: pointer; color: #666; font-weight: 600; font-size: 0.8rem; margin-bottom: 4px;">Headers (${Object.keys(headers).length})</summary>
                        <pre style="background: white; padding: 8px; border-radius: 4px; margin-top: 4px; font-size: 0.7rem; overflow-x: auto; max-height: 200px; overflow-y: auto;">${JSON.stringify(headers, null, 2)}</pre>
                    </details>
                ` : ''}
                ${body ? `
                    <details style="margin-top: 8px;">
                        <summary style="cursor: pointer; color: #666; font-weight: 600; font-size: 0.8rem; margin-bottom: 4px;">Request Body</summary>
                        <pre style="background: white; padding: 8px; border-radius: 4px; margin-top: 4px; font-size: 0.7rem; overflow-x: auto; max-height: 300px; overflow-y: auto; white-space: pre-wrap; word-break: break-word;">${typeof body === 'string' ? body : JSON.stringify(body, null, 2)}</pre>
                    </details>
                ` : ''}
            </div>
            
            <!-- Raw Evidence -->
            <details style="margin-top: 8px;">
                <summary style="cursor: pointer; color: #666; font-weight: 600; font-size: 0.85rem; margin-bottom: 4px;">Raw Evidence (JSON)</summary>
                <pre style="background: #f5f5f5; padding: 12px; border-radius: 4px; margin-top: 4px; font-size: 0.7rem; overflow-x: auto; max-height: 400px; overflow-y: auto; font-family: 'Fira Code', monospace;">${JSON.stringify(evidence, null, 2)}</pre>
            </details>
        `;

        // Plus besoin d'ouvrir une modal, toutes les infos sont déjà affichées
        sidechannelResultsList.appendChild(item);
    });
}

// Supprimer une détection
function deleteSidechannelDetection(detectionId) {
    sidechannelDetections = sidechannelDetections.filter(d => d.id !== detectionId);
    updateSidechannelResultsBadge();
    renderSidechannelResults();
    showToast('Detection removed', 'info');
}
window.deleteSidechannelDetection = deleteSidechannelDetection;

// Mettre à jour le badge de résultats
function updateSidechannelResultsBadge() {
    if (sidechannelResultsBadge) {
        const count = sidechannelDetections.length;
        if (count > 0) {
            sidechannelResultsBadge.textContent = count;
            sidechannelResultsBadge.style.display = 'block';
        } else {
            sidechannelResultsBadge.style.display = 'none';
        }
    }
}

// Load flows when SideChannel view is opened
const originalSwitchView = switchView;
switchView = function (viewId, navItem = null) {
    originalSwitchView(viewId, navItem);
    if (viewId === 'sidechannel' && sidechannelApiKeyValid) {
        // Démarrer le polling si activé et qu'il y a des tests en cours
        if (sidechannelTests.length > 0) {
            startSidechannelPolling();
        }
    } else if (viewId !== 'sidechannel') {
        // Arrêter le polling quand on quitte la vue
        stopSidechannelPolling();
    }
};

// === WORKSPACE MANAGEMENT ===
async function loadWorkspaces() {
    try {
        const res = await fetch(`${API_BASE}/workspaces`);
        if (!res.ok) {
            console.error('[Workspace] Failed to load workspaces');
            return;
        }
        const data = await res.json();
        const workspaces = data.workspaces || [];
        const current = data.current || null;
        currentWorkspaceName = current;

        // Clear and populate select
        workspaceSelect.innerHTML = '';

        if (workspaces.length === 0) {
            const option = document.createElement('option');
            option.value = '';
            option.textContent = 'No workspaces';
            workspaceSelect.appendChild(option);
        } else {
            workspaces.forEach(ws => {
                const option = document.createElement('option');
                option.value = ws;
                option.textContent = ws;
                if (ws === current) {
                    option.selected = true;
                }
                workspaceSelect.appendChild(option);
            });
        }

        // Create custom workspace select (same style as browser select)
        if (workspaces.length > 0) {
            createCustomWorkspaceSelect(workspaces, current);
        }

        // Show/hide delete button
        workspaceDeleteBtn.style.display = current ? 'inline-flex' : 'none';

        // Update workspace indicator in all top bars
        updateWorkspaceIndicator(current);

        // Load current workspace info
        await loadCurrentWorkspaceInfo();
    } catch (err) {
        console.error('[Workspace] Error loading workspaces:', err);
    }
}

// Créer un select personnalisé pour les workspaces (même style que le browser select)
function createCustomWorkspaceSelect(workspaces, currentWorkspace) {
    const workspaceSelectEl = document.getElementById('workspace-select');
    if (!workspaceSelectEl) return;

    // Supprimer l'ancien select personnalisé s'il existe
    const existingContainer = document.getElementById('custom-workspace-select-container');
    if (existingContainer) {
        existingContainer.remove();
    }

    // Créer le conteneur du select personnalisé
    const customSelectContainer = document.createElement('div');
    customSelectContainer.id = 'custom-workspace-select-container';
    customSelectContainer.style.cssText = 'position: relative; width: 100%; flex: 1;';

    // Créer le bouton du select (affichage) - même style que browser select
    const customSelectButton = document.createElement('div');
    customSelectButton.id = 'custom-workspace-select-button';
    customSelectButton.style.cssText = 'width: 100%; padding: 12px; border: 1px solid var(--border-color); border-radius: 10px; font-size: 0.95rem; background: white; cursor: pointer; display: flex; align-items: center; gap: 10px; transition: border 0.2s, box-shadow 0.2s; box-sizing: border-box;';
    customSelectButton.setAttribute('tabindex', '0'); // Make it focusable

    // Créer la liste déroulante
    const customSelectDropdown = document.createElement('div');
    customSelectDropdown.id = 'custom-workspace-select-dropdown';
    customSelectDropdown.style.cssText = 'display: none; position: absolute; top: 100%; left: 0; right: 0; background: white; border: 1px solid var(--border-color); border-radius: 10px; margin-top: 4px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); z-index: 1000; max-height: 300px; overflow-y: auto;';

    let selectedWorkspace = currentWorkspace || workspaces[0];

    // Helper function to format workspace name with (temporary) for default
    function formatWorkspaceName(workspace) {
        if (workspace === 'default') {
            return 'default (temporary)';
        }
        return workspace;
    }

    // Fonction pour mettre à jour l'affichage
    function updateDisplay(workspace, skipEvent = false) {
        selectedWorkspace = workspace;
        const displayName = formatWorkspaceName(workspace);
        customSelectButton.innerHTML = `
            <span class="material-symbols-outlined" style="font-size: 20px; color: var(--primary-color);">folder</span>
            <span style="flex: 1;">${displayName}</span>
            <span class="material-symbols-outlined" style="font-size: 18px; color: #666;">arrow_drop_down</span>
        `;
        workspaceSelectEl.value = workspace;
        customSelectDropdown.style.display = 'none';

        // Only trigger change event if not skipping (to avoid double notification)
        if (!skipEvent) {
            workspaceSelectEl.dispatchEvent(new Event('change', { bubbles: true }));
        }
    }

    // Initialiser l'affichage
    if (selectedWorkspace) {
        updateDisplay(selectedWorkspace);
    } else {
        customSelectButton.innerHTML = `
            <span class="material-symbols-outlined" style="font-size: 20px; color: var(--primary-color);">folder</span>
            <span style="flex: 1;">Select workspace...</span>
            <span class="material-symbols-outlined" style="font-size: 18px; color: #666;">arrow_drop_down</span>
        `;
    }

    // Créer les options
    workspaces.forEach(workspace => {
        const option = document.createElement('div');
        option.style.cssText = 'padding: 12px; cursor: pointer; display: flex; align-items: center; gap: 10px; transition: background 0.2s;';
        option.onmouseover = () => option.style.background = '#f5f5f5';
        option.onmouseout = () => option.style.background = '';
        option.onclick = () => {
            if (workspace !== currentWorkspaceName) {
                // Update display without triggering change event (skipEvent = true)
                updateDisplay(workspace, true);
                // Then switch workspace (this will show the notification)
                switchWorkspace(workspace);
            } else {
                // Just close the dropdown if same workspace
                customSelectDropdown.style.display = 'none';
                const arrow = customSelectButton.querySelector('.material-symbols-outlined:last-child');
                if (arrow) {
                    arrow.style.transform = 'rotate(0deg)';
                }
            }
        };

        const displayName = formatWorkspaceName(workspace);
        option.innerHTML = `
            <span class="material-symbols-outlined" style="font-size: 20px; color: var(--primary-color);">folder</span>
            <span>${displayName}</span>
        `;

        customSelectDropdown.appendChild(option);
    });

    // Toggle dropdown
    customSelectButton.onclick = (e) => {
        e.stopPropagation();
        const isOpen = customSelectDropdown.style.display === 'block';
        customSelectDropdown.style.display = isOpen ? 'none' : 'block';

        // Update arrow rotation
        const arrow = customSelectButton.querySelector('.material-symbols-outlined:last-child');
        if (arrow) {
            arrow.style.transform = isOpen ? 'rotate(0deg)' : 'rotate(180deg)';
            arrow.style.transition = 'transform 0.2s';
        }
    };

    // Fermer quand on clique ailleurs
    document.addEventListener('click', (e) => {
        if (!customSelectContainer.contains(e.target)) {
            customSelectDropdown.style.display = 'none';
            const arrow = customSelectButton.querySelector('.material-symbols-outlined:last-child');
            if (arrow) {
                arrow.style.transform = 'rotate(0deg)';
            }
        }
    });

    // Hover effect
    customSelectButton.onmouseenter = () => {
        customSelectButton.style.borderColor = 'var(--primary-color)';
        customSelectButton.style.boxShadow = '0 0 0 3px rgba(98, 0, 234, 0.08)';
    };
    customSelectButton.onmouseleave = () => {
        if (document.activeElement !== customSelectButton) {
            customSelectButton.style.borderColor = 'var(--border-color)';
            customSelectButton.style.boxShadow = 'none';
        }
    };

    // Focus effect
    customSelectButton.onfocus = () => {
        customSelectButton.style.borderColor = 'var(--primary-color)';
        customSelectButton.style.boxShadow = '0 0 0 3px rgba(98, 0, 234, 0.1)';
    };
    customSelectButton.onblur = () => {
        customSelectButton.style.borderColor = 'var(--border-color)';
        customSelectButton.style.boxShadow = 'none';
    };

    // Assembler le select personnalisé
    customSelectContainer.appendChild(customSelectButton);
    customSelectContainer.appendChild(customSelectDropdown);

    // Remplacer le select natif dans le workspace-select-row
    const workspaceSelectRow = workspaceSelectEl.closest('.workspace-select-row');
    if (workspaceSelectRow) {
        workspaceSelectEl.style.display = 'none';
        workspaceSelectRow.insertBefore(customSelectContainer, workspaceSelectEl);
    }
}

async function loadCurrentWorkspaceInfo() {
    try {
        const res = await fetch(`${API_BASE}/workspaces/current`);
        if (!res.ok) {
            workspaceInfo.style.display = 'none';
            return;
        }
        const data = await res.json();
        if (data.name) {
            workspaceDescription.textContent = data.description || `Workspace: ${data.name}`;
            workspaceInfo.style.display = 'block';
        } else {
            workspaceInfo.style.display = 'none';
        }
    } catch (err) {
        console.error('[Workspace] Error loading current workspace info:', err);
        workspaceInfo.style.display = 'none';
    }
}

async function switchWorkspace(workspaceName) {
    if (!workspaceName) {
        console.warn('[Workspace] No workspace name provided');
        return;
    }

    try {
        const res = await fetch(`${API_BASE}/workspaces/${encodeURIComponent(workspaceName)}/switch`, {
            method: 'POST'
        });

        if (!res.ok) {
            const error = await res.json();
            showToast(`Failed to switch workspace: ${error.detail || 'Unknown error'}`, 'error');
            return;
        }

        const data = await res.json();
        currentWorkspaceName = data.workspace;
        showToast(`Switched to workspace: ${data.workspace}`, 'success');

        // Update workspace indicator
        updateWorkspaceIndicator(data.workspace);

        // Reload workspaces to update UI
        await loadWorkspaces();
    } catch (err) {
        console.error('[Workspace] Error switching workspace:', err);
        showToast(`Error switching workspace: ${err.message}`, 'error');
    }
}

function showCreateWorkspaceModal() {
    document.getElementById('modal-workspace-name').value = '';
    document.getElementById('modal-workspace-description').value = '';
    document.getElementById('modal-create-workspace').style.display = 'flex';
}

function showDeleteWorkspaceModal() {
    const workspaceName = workspaceSelect.value;
    if (!workspaceName) {
        showToast('No workspace selected', 'error');
        return;
    }

    const message = `Are you sure you want to delete workspace "${workspaceName}"? This action cannot be undone.`;
    document.getElementById('modal-delete-workspace-message').textContent = message;
    document.getElementById('modal-delete-workspace-force').checked = false;
    document.getElementById('modal-delete-workspace').style.display = 'flex';
}

async function confirmCreateWorkspace() {
    const name = document.getElementById('modal-workspace-name').value.trim();
    const description = document.getElementById('modal-workspace-description').value.trim();

    if (!name) {
        showToast('Workspace name is required', 'error');
        return;
    }

    // Validate workspace name (alphanumeric, hyphens, underscores)
    if (!/^[a-zA-Z0-9_-]+$/.test(name)) {
        showToast('Workspace name can only contain alphanumeric characters, hyphens, and underscores', 'error');
        return;
    }

    try {
        const res = await fetch(`${API_BASE}/workspaces`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                name: name,
                description: description
            })
        });

        if (!res.ok) {
            const error = await res.json();
            showToast(`Failed to create workspace: ${error.detail || 'Unknown error'}`, 'error');
            return;
        }

        const data = await res.json();
        showToast(`Workspace "${data.name}" created successfully`, 'success');
        closeModal('modal-create-workspace');

        // Reload workspaces and switch to the new one
        await loadWorkspaces();
        await switchWorkspace(data.name);
    } catch (err) {
        console.error('[Workspace] Error creating workspace:', err);
        showToast(`Error creating workspace: ${err.message}`, 'error');
    }
}

async function confirmDeleteWorkspace() {
    const workspaceName = workspaceSelect.value;
    if (!workspaceName) {
        showToast('No workspace selected', 'error');
        return;
    }

    const force = document.getElementById('modal-delete-workspace-force').checked;

    try {
        const url = `${API_BASE}/workspaces/${encodeURIComponent(workspaceName)}?force=${force}`;
        const res = await fetch(url, {
            method: 'DELETE'
        });

        if (!res.ok) {
            const error = await res.json();
            showToast(`Failed to delete workspace: ${error.detail || 'Unknown error'}`, 'error');
            return;
        }

        const data = await res.json();
        showToast(`Workspace "${data.name}" deleted successfully`, 'success');
        closeModal('modal-delete-workspace');

        // Reload workspaces
        await loadWorkspaces();
    } catch (err) {
        console.error('[Workspace] Error deleting workspace:', err);
        showToast(`Error deleting workspace: ${err.message}`, 'error');
    }
}

// Event listeners for workspace controls
if (workspaceSelect) {
    let isSwitchingWorkspace = false; // Flag to prevent double notifications
    workspaceSelect.addEventListener('change', async (e) => {
        const workspaceName = e.target.value;
        if (workspaceName && workspaceName !== currentWorkspaceName && !isSwitchingWorkspace) {
            isSwitchingWorkspace = true;
            await switchWorkspace(workspaceName);
            isSwitchingWorkspace = false;
        }
    });
}

if (workspaceRefreshBtn) {
    workspaceRefreshBtn.addEventListener('click', async () => {
        await loadWorkspaces();
        showToast('Workspaces refreshed', 'success');
    });
}

if (workspaceCreateBtn) {
    workspaceCreateBtn.addEventListener('click', () => {
        showCreateWorkspaceModal();
    });
}

if (workspaceDeleteBtn) {
    workspaceDeleteBtn.addEventListener('click', () => {
        showDeleteWorkspaceModal();
    });
}

if (workspaceSaveDataCheck) {
    workspaceSaveDataCheck.addEventListener('change', (e) => {
        workspaceSaveEnabled = e.target.checked;
        showToast(
            workspaceSaveEnabled
                ? 'Workspace saving enabled'
                : 'Workspace saving disabled - data will not be saved to workspace',
            workspaceSaveEnabled ? 'success' : 'warning'
        );
    });
}

// Function to update workspace indicator in all top bars
function updateWorkspaceIndicator(workspaceName) {
    const indicators = document.querySelectorAll('.workspace-indicator');
    const indicatorNames = document.querySelectorAll('#workspace-indicator-name');

    if (workspaceName) {
        // Format workspace name with (temporary) for default
        const displayName = workspaceName === 'default' ? 'default (temporary)' : workspaceName;

        // Show indicators and update text
        indicators.forEach(indicator => {
            indicator.style.display = 'flex';
        });
        indicatorNames.forEach(nameEl => {
            nameEl.textContent = displayName;
        });
    } else {
        // Hide indicators if no workspace
        indicators.forEach(indicator => {
            indicator.style.display = 'none';
        });
    }
}

// Function to add workspace indicator to all top bars
function addWorkspaceIndicatorToTopBars() {
    const topBars = document.querySelectorAll('.top-bar');

    topBars.forEach(topBar => {
        // Check if indicator already exists
        if (topBar.querySelector('.workspace-indicator')) {
            return;
        }

        // Create indicator element
        const indicator = document.createElement('div');
        indicator.className = 'workspace-indicator';
        indicator.id = 'workspace-indicator';
        indicator.style.display = 'none';
        indicator.innerHTML = `
            <span class="material-symbols-outlined" style="font-size: 18px;">folder</span>
            <span id="workspace-indicator-name">-</span>
        `;

        // Add to top bar (on the right side)
        topBar.appendChild(indicator);
    });
}

// Load workspaces on page load
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        addWorkspaceIndicatorToTopBars();
        loadWorkspaces();
    });
} else {
    addWorkspaceIndicatorToTopBars();
    loadWorkspaces();
}

// === BROWSER LAUNCH ===
// Mapping des navigateurs vers leurs icônes
const browserIconMap = {
    'auto': 'chrome', // Utiliser l'icône Chrome pour auto-detect
    'chrome': 'chrome',
    'chromium': 'chromium', // Utiliser l'icône Chromium pour Chromium
    'edge': 'edge',
    'firefox': 'firefox',
    'brave': 'brave',
    'opera': 'opera',
    'safari': 'safari'
};

// Charger les navigateurs détectés au chargement de la page
async function loadDetectedBrowsers() {
    try {
        const res = await fetch(`${API_BASE}/detected_browsers`);
        if (!res.ok) {
            console.warn('[Browser] Failed to load detected browsers, using defaults');
            return;
        }
        const data = await res.json();
        const browsers = data.browsers || [];

        const browserSelect = document.getElementById('browser-select');
        if (!browserSelect) return;

        // Vider la liste actuelle
        browserSelect.innerHTML = '';

        // Ajouter uniquement les navigateurs détectés avec icônes
        browsers.forEach(browser => {
            const option = document.createElement('option');
            option.value = browser.value;

            // Créer le contenu avec icône
            const iconName = browserIconMap[browser.value] || 'unknown';
            const iconUrl = `/browser-icons/${iconName}`;

            // Pour les selects HTML natifs, on ne peut pas mettre d'images directement
            // On va créer un select personnalisé à la place
            option.textContent = browser.label;
            // Sélectionner le premier navigateur par défaut
            if (browsers.indexOf(browser) === 0) {
                option.selected = true;
            }
            browserSelect.appendChild(option);
        });

        // Créer un select personnalisé avec icônes
        if (browsers.length > 0) {
            createCustomBrowserSelect(browsers);
        }
    } catch (err) {
        console.error('[Browser] Error loading detected browsers:', err);
    }
}

// Créer un select personnalisé avec icônes
function createCustomBrowserSelect(browsers) {
    const browserSelect = document.getElementById('browser-select');
    if (!browserSelect) return;

    // Créer le conteneur du select personnalisé
    const customSelectContainer = document.createElement('div');
    customSelectContainer.id = 'custom-browser-select-container';
    customSelectContainer.style.cssText = 'position: relative; width: 100%;';

    // Créer le bouton du select (affichage)
    const customSelectButton = document.createElement('div');
    customSelectButton.id = 'custom-browser-select-button';
    customSelectButton.style.cssText = 'width: 100%; padding: 10px 12px; border: 1px solid var(--border-color); border-radius: 6px; font-size: 0.95rem; background: white; cursor: pointer; display: flex; align-items: center; gap: 10px;';

    // Créer la liste déroulante
    const customSelectDropdown = document.createElement('div');
    customSelectDropdown.id = 'custom-browser-select-dropdown';
    customSelectDropdown.style.cssText = 'display: none; position: absolute; top: 100%; left: 0; right: 0; background: white; border: 1px solid var(--border-color); border-radius: 6px; margin-top: 4px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); z-index: 1000; max-height: 300px; overflow-y: auto;';

    let selectedBrowser = browsers[0];

    // Fonction pour mettre à jour l'affichage
    function updateDisplay(browser) {
        selectedBrowser = browser;
        const iconName = browserIconMap[browser.value] || 'unknown';
        const iconUrl = `/browser-icons/${iconName}`;
        customSelectButton.innerHTML = `
            <img src="${iconUrl}" alt="${browser.label}" style="width: 20px; height: 20px; object-fit: contain;" onerror="this.style.display='none';">
            <span style="flex: 1;">${browser.label}</span>
            <span class="material-symbols-outlined" style="font-size: 18px; color: #666;">arrow_drop_down</span>
        `;
        browserSelect.value = browser.value;
        customSelectDropdown.style.display = 'none';
    }

    // Initialiser l'affichage
    updateDisplay(selectedBrowser);

    // Créer les options
    browsers.forEach(browser => {
        const option = document.createElement('div');
        option.style.cssText = 'padding: 10px 12px; cursor: pointer; display: flex; align-items: center; gap: 10px; transition: background 0.2s;';
        option.onmouseover = () => option.style.background = '#f5f5f5';
        option.onmouseout = () => option.style.background = '';
        option.onclick = () => updateDisplay(browser);

        const iconName = browserIconMap[browser.value] || 'unknown';
        const iconUrl = `/browser-icons/${iconName}`;
        option.innerHTML = `
            <img src="${iconUrl}" alt="${browser.label}" style="width: 20px; height: 20px; object-fit: contain;" onerror="this.style.display='none';">
            <span>${browser.label}</span>
        `;

        customSelectDropdown.appendChild(option);
    });

    // Toggle dropdown
    customSelectButton.onclick = (e) => {
        e.stopPropagation();
        const isOpen = customSelectDropdown.style.display === 'block';
        customSelectDropdown.style.display = isOpen ? 'none' : 'block';
    };

    // Fermer quand on clique ailleurs
    document.addEventListener('click', (e) => {
        if (!customSelectContainer.contains(e.target)) {
            customSelectDropdown.style.display = 'none';
        }
    });

    // Assembler le select personnalisé
    customSelectContainer.appendChild(customSelectButton);
    customSelectContainer.appendChild(customSelectDropdown);

    // Remplacer le select natif
    browserSelect.style.display = 'none';
    browserSelect.parentNode.insertBefore(customSelectContainer, browserSelect);
}

// Charger les navigateurs au chargement de la page
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', loadDetectedBrowsers);
} else {
    loadDetectedBrowsers();
}

if (launchBtn) {
    launchBtn.addEventListener('click', async () => {
        launchBtn.disabled = true;
        launchStatus.className = 'launch-status info';
        launchStatus.textContent = 'Launching browser...';

        try {
            // Récupérer le navigateur sélectionné
            const browserSelect = document.getElementById('browser-select');
            const selectedBrowser = browserSelect ? browserSelect.value : 'auto';

            const res = await fetch(`${API_BASE}/launch_browser`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ browser: selectedBrowser })
            });
            const data = await res.json();

            if (res.ok) {
                launchStatus.className = 'launch-status success';
                launchStatus.textContent = `Browser launched successfully! (${data.browser_name || data.browser})`;
                setTimeout(() => {
                    launchStatus.textContent = '';
                    launchBtn.disabled = false;
                }, 5000);
            } else {
                throw new Error(data.detail || 'Launch failed');
            }
        } catch (err) {
            console.error("Launch error", err);
            launchStatus.className = 'launch-status error';
            launchStatus.textContent = `Error: ${err.message}`;
            launchBtn.disabled = false;
        }
    });
}

// === INTERCEPTION ===
if (interceptToggleBtn) {
    interceptToggleBtn.addEventListener('click', async () => {
        interceptEnabled = !interceptEnabled;
        updateInterceptUI();

        try {
            await fetch(`${API_BASE}/intercept/toggle`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ enabled: interceptEnabled })
            });
        } catch (err) {
            console.error("Failed to toggle interception", err);
            interceptEnabled = !interceptEnabled;
            updateInterceptUI();
        }
    });
}

if (resumeAllBtn) {
    resumeAllBtn.addEventListener('click', async () => {
        // Toggle auto-resume mode
        autoResumeEnabled = !autoResumeEnabled;
        updateResumeAllButton();

        if (autoResumeEnabled) {
            // Activer le mode auto-resume : reprendre toutes les requêtes actuelles
            const flowIds = [...pendingInterceptsData.map(f => f.id)];

            for (const flowId of flowIds) {
                try {
                    await fetch(`${API_BASE}/intercept/${flowId}/resume`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({}) // Objet vide = reprendre avec les valeurs originales
                    });
                } catch (err) {
                    console.error(`Failed to resume ${flowId}`, err);
                }
            }

            // Initialiser previousPendingIds avec les requêtes actuelles pour éviter de les reprendre
            previousPendingIds = new Set(flowIds);
            pendingInterceptsData = [];
            selectedInterceptId = null;
            renderPendingList();
            updateInterceptTabBadge();
            if (interceptEditorEl) {
                interceptEditorEl.innerHTML = '<p style="color: #888; text-align: center; margin-top: 50px;">Select a request to view/modify</p>';
            }
        } else {
            // Désactiver le mode auto-resume : réinitialiser previousPendingIds
            previousPendingIds = new Set();
            isFirstPoll = true;
        }
    });
}

function updateResumeAllButton() {
    if (resumeAllBtn) {
        if (autoResumeEnabled) {
            resumeAllBtn.style.background = '#ff9800'; // Orange pour indiquer que c'est actif
            resumeAllBtn.textContent = 'Stop Auto-Resume';
        } else {
            resumeAllBtn.style.background = ''; // Retour à la couleur par défaut (btn-success)
            resumeAllBtn.textContent = 'Resume All';
        }
    }
}

if (dropAllBtn) {
    dropAllBtn.addEventListener('click', async () => {
        const flowIds = [...pendingInterceptsData.map(f => f.id)];

        for (const flowId of flowIds) {
            try {
                await fetch(`${API_BASE}/intercept/${flowId}/resume`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({})
                });
            } catch (err) {
                console.error(`Failed to drop ${flowId}`, err);
            }
        }

        pendingInterceptsData = [];
        selectedInterceptId = null;
        renderPendingList();
        updateInterceptTabBadge();
        if (interceptEditorEl) {
            interceptEditorEl.innerHTML = '<p style="color: #888; text-align: center; margin-top: 50px;">Select a request to view/modify</p>';
        }
    });
}

function updateInterceptUI() {
    if (interceptToggleBtn && interceptStatusText) {
        if (interceptEnabled) {
            interceptToggleBtn.style.background = '#f44336';
            interceptStatusText.textContent = 'Disable Interception';
        } else {
            interceptToggleBtn.style.background = '#6200ea';
            interceptStatusText.textContent = 'Enable Interception';
        }
    }
}

function updateInterceptTabBadge() {
    const interceptNavItem = document.querySelector('[data-view="intercept"]');
    if (!interceptNavItem) return;

    // Supprimer le badge existant s'il y en a un
    const existingBadge = interceptNavItem.querySelector('.intercept-badge');
    if (existingBadge) {
        existingBadge.remove();
    }

    // Ajouter un badge si il y a des requêtes en attente
    if (pendingInterceptsData.length > 0) {
        const badge = document.createElement('span');
        badge.className = 'intercept-badge';
        badge.textContent = pendingInterceptsData.length > 99 ? '99+' : pendingInterceptsData.length.toString();
        interceptNavItem.appendChild(badge);
    }
}

function renderPendingList() {
    if (!pendingListEl) return;

    if (pendingCountText) {
        pendingCountText.textContent = `${pendingInterceptsData.length} request${pendingInterceptsData.length !== 1 ? 's' : ''} pending`;
    }

    // Mettre à jour le badge de l'onglet
    updateInterceptTabBadge();

    if (pendingInterceptsData.length === 0) {
        pendingListEl.innerHTML = '<div style="padding: 20px; text-align: center; color: #888;">No pending requests</div>';
        return;
    }

    // Auto-select first request if we're on intercept page and none is selected
    const interceptView = document.getElementById('intercept-view');
    const isInterceptViewActive = interceptView && interceptView.style.display !== 'none';

    if (isInterceptViewActive && !selectedInterceptId && pendingInterceptsData.length > 0) {
        selectedInterceptId = pendingInterceptsData[0].id;
        // Render the editor for the auto-selected request
        setTimeout(() => renderInterceptEditor(selectedInterceptId), 0);
    }

    pendingListEl.innerHTML = pendingInterceptsData.map(flow => `
        <div class="flow-item ${selectedInterceptId === flow.id ? 'active' : ''}" data-flow-id="${flow.id}" style="display: grid; grid-template-columns: 1fr; padding: 15px; border-bottom: 1px solid #f0f0f0; cursor: pointer;">
            <div style="font-weight: 600; color: #6200ea; margin-bottom: 5px;">${flow.method}</div>
            <div style="font-size: 0.85em; color: #666; word-break: break-all;">${flow.url}</div>
        </div>
    `).join('');

    document.querySelectorAll('#pending-list .flow-item').forEach(item => {
        item.addEventListener('click', (e) => {
            const flowId = e.currentTarget.dataset.flowId;
            selectedInterceptId = flowId;
            // Désactiver le mode auto-resume quand l'utilisateur sélectionne une requête pour modification manuelle
            if (autoResumeEnabled) {
                autoResumeEnabled = false;
                updateResumeAllButton();
            }
            renderPendingList();
            renderInterceptEditor(flowId);
        });
    });
}

function renderInterceptEditor(flowId) {
    const flow = pendingInterceptsData.find(f => f.id === flowId);
    if (!flow || !interceptEditorEl) return;

    const reqHeaders = JSON.stringify(flow.request.headers, null, 2);
    const reqBody = flow.request.content_bs64 ? atob(flow.request.content_bs64) : '';

    interceptEditorEl.innerHTML = `
        <div style="background: white; border: 1px solid #e0e0e0; border-radius: 8px; padding: 16px; box-sizing: border-box;">
            <label style="display: block; font-weight: 600; margin-bottom: 8px; color: #333; font-size: 0.9rem;">Method</label>
            <input type="text" id="intercept-method" value="${escapeHtml(flow.method)}" style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 6px; box-sizing: border-box; font-family: 'Fira Code', monospace; font-size: 0.9rem;">
        </div>
        <div style="background: white; border: 1px solid #e0e0e0; border-radius: 8px; padding: 16px; box-sizing: border-box;">
            <label style="display: block; font-weight: 600; margin-bottom: 8px; color: #333; font-size: 0.9rem;">URL</label>
            <input type="text" id="intercept-url" value="${escapeHtml(flow.url)}" style="width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 6px; box-sizing: border-box; font-family: 'Fira Code', monospace; font-size: 0.9rem; word-wrap: break-word; overflow-wrap: break-word;">
        </div>
        <div style="background: white; border: 1px solid #e0e0e0; border-radius: 8px; padding: 16px; box-sizing: border-box;">
            <label style="display: block; font-weight: 600; margin-bottom: 8px; color: #333; font-size: 0.9rem;">Headers (JSON)</label>
            <textarea id="intercept-headers" style="width: 100%; height: 150px; padding: 10px; border: 1px solid #ddd; border-radius: 6px; box-sizing: border-box; font-family: 'Fira Code', monospace; font-size: 0.85em; resize: vertical; overflow-x: hidden; word-wrap: break-word; overflow-wrap: break-word;">${escapeHtml(reqHeaders)}</textarea>
        </div>
        <div style="background: white; border: 1px solid #e0e0e0; border-radius: 8px; padding: 16px; box-sizing: border-box;">
            <label style="display: block; font-weight: 600; margin-bottom: 8px; color: #333; font-size: 0.9rem;">Body</label>
            <textarea id="intercept-body" style="width: 100%; height: 150px; padding: 10px; border: 1px solid #ddd; border-radius: 6px; box-sizing: border-box; font-family: 'Fira Code', monospace; font-size: 0.85em; resize: vertical; overflow-x: hidden; word-wrap: break-word; overflow-wrap: break-word;">${escapeHtml(reqBody)}</textarea>
        </div>
        <div style="display: flex; gap: 10px; margin-top: auto; padding-top: 10px; box-sizing: border-box;">
            <button id="resume-intercept-btn" style="flex: 1; padding: 12px; background: #4caf50; color: white; border: none; border-radius: 6px; cursor: pointer; font-weight: 600; font-size: 0.95rem; transition: background 0.2s;">Resume</button>
            <button id="drop-intercept-btn" style="flex: 1; padding: 12px; background: #f44336; color: white; border: none; border-radius: 6px; cursor: pointer; font-weight: 600; font-size: 0.95rem; transition: background 0.2s;">Drop</button>
        </div>
    `;

    document.getElementById('resume-intercept-btn').addEventListener('click', async () => {
        const method = document.getElementById('intercept-method').value;
        const url = document.getElementById('intercept-url').value;
        const headersStr = document.getElementById('intercept-headers').value;
        const bodyStr = document.getElementById('intercept-body').value;

        try {
            const headers = JSON.parse(headersStr);
            const payload = { method, url, headers, body_bs64: bodyStr ? btoa(bodyStr) : '' };

            await fetch(`${API_BASE}/intercept/${flowId}/resume`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            pendingInterceptsData = pendingInterceptsData.filter(f => f.id !== flowId);
            selectedInterceptId = null;
            renderPendingList();
            updateInterceptTabBadge();
            interceptEditorEl.innerHTML = '<p style="color: #888; text-align: center; margin-top: 50px;">Select a request to view/modify</p>';
        } catch (err) {
            alert('Error: Invalid JSON in headers or failed to resume');
            console.error(err);
        }
    });

    document.getElementById('drop-intercept-btn').addEventListener('click', async () => {
        try {
            await fetch(`${API_BASE}/intercept/${flowId}/resume`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({})
            });

            pendingInterceptsData = pendingInterceptsData.filter(f => f.id !== flowId);
            selectedInterceptId = null;
            renderPendingList();
            updateInterceptTabBadge();
            interceptEditorEl.innerHTML = '<p style="color: #888; text-align: center; margin-top: 50px;">Select a request to view/modify</p>';
        } catch (err) {
            console.error(err);
        }
    });
}

// Poll for pending intercepts
let previousPendingIds = new Set();
let isFirstPoll = true; // Pour initialiser previousPendingIds au premier poll
setInterval(async () => {
    if (!interceptEnabled) {
        // Réinitialiser quand l'interception est désactivée
        previousPendingIds = new Set();
        isFirstPoll = true;
        return;
    }

    try {
        const res = await fetch(`${API_BASE}/intercept/pending`);
        const pending = await res.json();

        // Initialiser previousPendingIds au premier poll ou quand le mode auto-resume est activé
        if (isFirstPoll) {
            previousPendingIds = new Set(pending.map(f => f.id));
            isFirstPoll = false;
        }

        // Si le mode auto-resume est activé, reprendre automatiquement toutes les nouvelles requêtes
        if (autoResumeEnabled && pending.length > 0) {
            const currentPendingIds = new Set(pending.map(f => f.id));
            const newFlowIds = [...currentPendingIds].filter(id => !previousPendingIds.has(id));

            // Reprendre toutes les nouvelles requêtes automatiquement
            for (const flowId of newFlowIds) {
                try {
                    await fetch(`${API_BASE}/intercept/${flowId}/resume`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({}) // Reprendre sans modifications
                    });
                } catch (err) {
                    console.error(`Failed to auto-resume ${flowId}`, err);
                }
            }
        }

        previousPendingIds = new Set(pending.map(f => f.id));
        pendingInterceptsData = pending;
        renderPendingList();
        updateInterceptTabBadge();
    } catch (err) {
        console.error("Failed to fetch pending intercepts", err);
    }
}, 1000);

// === MODULES ===
async function fetchModules() {
    try {
        const res = await fetch(`${API_BASE}/modules`);
        const data = await res.json();

        if (JSON.stringify(data) !== JSON.stringify(modulesData)) {
            modulesData = data;
            renderModuleList();
        }
    } catch (err) {
        console.error("Failed to fetch modules", err);
        modulesData = [];
        if (moduleListEl) {
            moduleListEl.innerHTML = '<div style="padding: 20px; text-align: center; color: #f44336;">Failed to connect to Kittysploit Framework</div>';
        }
    }
}

async function refreshModules() {
    if (!refreshModulesBtn) return;

    refreshModulesBtn.disabled = true;
    refreshModulesBtn.innerHTML = '<span class="material-symbols-outlined" style="font-size: 18px;">refresh</span> Refreshing...';

    try {
        const res = await fetch(`${API_BASE}/modules/refresh`, {
            method: 'POST'
        });
        const data = await res.json();

        if (res.ok) {
            // Reload modules after refresh
            await fetchModules();
            refreshModulesBtn.innerHTML = '<span class="material-symbols-outlined" style="font-size: 18px;">refresh</span> Refresh';
            refreshModulesBtn.disabled = false;
            alert(`Modules cache refreshed: ${data.count} modules loaded`);
        } else {
            alert(`Error: ${data.detail || 'Failed to refresh modules'}`);
            refreshModulesBtn.innerHTML = '<span class="material-symbols-outlined" style="font-size: 18px;">refresh</span> Refresh';
            refreshModulesBtn.disabled = false;
        }
    } catch (err) {
        console.error("Failed to refresh modules", err);
        alert(`Error: ${err.message}`);
        refreshModulesBtn.innerHTML = '<span class="material-symbols-outlined" style="font-size: 18px;">refresh</span> Refresh';
        refreshModulesBtn.disabled = false;
    }
}

function renderModuleList() {
    if (!moduleListEl) return;

    if (moduleCountText) {
        moduleCountText.textContent = `${modulesData.length} module${modulesData.length !== 1 ? 's' : ''} available`;
    }

    if (modulesData.length === 0) {
        moduleListEl.innerHTML = '<div style="padding: 20px; text-align: center; color: #888;">No modules found</div>';
        return;
    }

    const filteredModules = modulesData.filter(mod => {
        if (!moduleSearchTerm) return true;
        const name = (mod.name || '').toLowerCase();
        const description = (mod.description || '').toLowerCase();
        const category = (mod.category || '').toLowerCase();
        return name.includes(moduleSearchTerm) || description.includes(moduleSearchTerm) || category.includes(moduleSearchTerm);
    });

    moduleListEl.innerHTML = filteredModules.map(mod => `
        <div class="flow-item ${selectedModuleId === mod.name ? 'active' : ''}" data-module-id="${mod.name}" style="display: grid; grid-template-columns: 1fr; padding: 15px; border-bottom: 1px solid #f0f0f0; cursor: pointer;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 5px;">
                <div style="font-weight: 600; color: #6200ea;">${mod.name}</div>
                <div style="font-size: 0.75em; padding: 2px 8px; background: #e3f2fd; color: #1976d2; border-radius: 3px;">${mod.category || 'misc'}</div>
            </div>
            <div style="font-size: 0.85em; color: #666;">${mod.description || 'No description'}</div>
        </div>
    `).join('');

    document.querySelectorAll('#module-list .flow-item').forEach(item => {
        item.addEventListener('click', (e) => {
            // Save current module output before switching
            saveCurrentModuleOutput();
            const moduleId = e.currentTarget.dataset.moduleId;
            selectedModuleId = moduleId;
            renderModuleList();
            renderModuleConfig(moduleId);
        });
    });
}

function saveCurrentModuleOutput() {
    const moduleOutput = document.getElementById('module-output');
    if (moduleOutput && selectedModuleId) {
        moduleOutputCache[selectedModuleId] = {
            content: moduleOutput.textContent,
            visible: moduleOutput.style.display !== 'none',
            color: moduleOutput.style.color || '#d4d4d4'
        };
    }
}

function restoreModuleOutput(moduleId) {
    const cached = moduleOutputCache[moduleId];
    const moduleOutput = document.getElementById('module-output');
    if (moduleOutput && cached) {
        moduleOutput.textContent = cached.content || '';
        moduleOutput.style.display = cached.visible ? 'block' : 'none';
        moduleOutput.style.color = cached.color || '#d4d4d4';
    }
}

function updateModuleOutputCache(moduleOutput) {
    if (moduleOutput && selectedModuleId) {
        moduleOutputCache[selectedModuleId] = {
            content: moduleOutput.textContent,
            visible: moduleOutput.style.display !== 'none',
            color: moduleOutput.style.color || '#d4d4d4'
        };
    }
}

function renderModuleConfig(moduleId) {
    const module = modulesData.find(m => m.name === moduleId);
    if (!module || !moduleConfigEl) return;

    if (runModuleBtn) {
        runModuleBtn.disabled = false;
    }

    // Get recent unique URLs from flows (last 20)
    const recentUrls = [];
    if (flowsData && flowsData.length > 0) {
        const urlSet = new Set();
        for (let i = flowsData.length - 1; i >= 0 && recentUrls.length < 20; i--) {
            const flow = flowsData[i];
            if (flow.url && !urlSet.has(flow.url)) {
                urlSet.add(flow.url);
                recentUrls.push({
                    url: flow.url,
                    method: flow.method || 'GET',
                    status: flow.status_code || 0
                });
            }
        }
    }

    const recentUrlsHtml = recentUrls.map(f =>
        `<option value="${escapeHtml(f.url)}">${escapeHtml(f.method)} ${escapeHtml(f.url.length > 60 ? f.url.substring(0, 57) + '...' : f.url)}</option>`
    ).join('');

    const optionsHtml = module.options && module.options.length > 0 ?
        module.options.map(opt => `
            <div>
                <label style="display: block; font-weight: 600; margin-bottom: 5px;">
                    ${opt.name}${opt.required ? ' <span style="color: #f44336;">*</span>' : ''}
                </label>
                <input 
                    type="text" 
                    id="mod-opt-${opt.name}" 
                    value="${opt.default || ''}" 
                   placeholder="${opt.description || ''}"
                    style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                <div style="font-size: 0.8em; color: #666; margin-top: 3px;">${opt.description || ''}</div>
            </div>
        `).join('') :
        '<p style="color: #888;">This module has no configurable options</p>';

    moduleConfigEl.innerHTML = `
        <div style="background: #f5f5f5; padding: 15px; border-radius: 4px; margin-bottom: 15px;">
            <h4 style="margin: 0 0 10px 0;">${module.name}</h4>
            <p style="margin: 0; color: #666;">${module.description || 'No description available'}</p>
            ${module.author ? `<p style="margin: 5px 0 0 0; font-size: 0.85em; color: #888;">Author: ${module.author}</p>` : ''}
        </div>
        <div style="background: #e3f2fd; padding: 15px; border-radius: 4px; margin-bottom: 15px; border: 1px solid #90caf9;">
            <h4 style="margin: 0 0 10px 0; display: flex; align-items: center; gap: 8px; color: #1976d2;">
                <span class="material-symbols-outlined" style="font-size: 20px;">link</span>
                Target URL
            </h4>
            <div style="display: flex; gap: 10px; margin-bottom: 10px; flex-wrap: wrap;">
                <input 
                    type="text" 
                    id="module-target-url" 
                    placeholder="https://example.com:443/path"
                    style="flex: 1; min-width: 300px; padding: 8px 12px; border: 1px solid #90caf9; border-radius: 4px; font-family: 'Fira Code', monospace; font-size: 0.9em;">
                <select 
                    id="module-url-from-flows" 
                    style="width: 250px; padding: 8px 12px; border: 1px solid #90caf9; border-radius: 4px; background: white; cursor: pointer;"
                    onchange="document.getElementById('module-target-url').value = this.value;">
                    <option value="">Select from flows...</option>
                    ${recentUrlsHtml}
                </select>
            </div>
            <button 
                onclick="autoConfigureModuleFromUrl('${moduleId}')" 
                class="btn btn-secondary"
                style="display: flex; align-items: center; gap: 6px;">
                <span class="material-symbols-outlined" style="font-size: 18px;">auto_fix_high</span>
                Auto-configure from URL
            </button>
        </div>
        <div style="display: flex; flex-direction: column; gap: 15px; flex: 1; overflow-y: auto;">
            ${optionsHtml}
        </div>
        <div id="module-output" style="margin-top: 15px; padding: 15px; background: #1e1e1e; color: #d4d4d4; border-radius: 4px; font-family: 'Fira Code', monospace; font-size: 0.85em; height: 45vh; max-height: 50vh; min-height: 220px; overflow-y: auto; display: none; white-space: pre-wrap; line-height: 1.5;"></div>
    `;

    // Restore cached output if available
    restoreModuleOutput(moduleId);
}

if (moduleSearchInput) {
    moduleSearchInput.addEventListener('input', (e) => {
        moduleSearchTerm = e.target.value.toLowerCase();
        renderModuleList();
    });
}

if (refreshModulesBtn) {
    refreshModulesBtn.addEventListener('click', async () => {
        await refreshModules();
    });
}

if (runModuleBtn) {
    runModuleBtn.addEventListener('click', async () => {
        if (!selectedModuleId) return;

        const module = modulesData.find(m => m.name === selectedModuleId);
        if (!module) return;

        runModuleBtn.disabled = true;
        runModuleBtn.innerHTML = '<span class="material-symbols-outlined" style="font-size: 18px;">hourglass_empty</span> Running...';

        const moduleOutput = document.getElementById('module-output');
        if (moduleOutput) {
            moduleOutput.style.display = 'block';
            moduleOutput.textContent = 'Executing module...\n';
            updateModuleOutputCache(moduleOutput);
        }

        try {
            // Collect options
            const options = {};
            if (module.options) {
                module.options.forEach(opt => {
                    const input = document.getElementById(`mod-opt-${opt.name}`);
                    if (input) {
                        options[opt.name] = input.value;
                    }
                });
            }

            // Ensure target is sent even when the module options are not exposed in UI
            const targetInput = document.getElementById('module-target-url');
            const targetUrl = targetInput ? targetInput.value.trim() : '';
            if (!targetUrl) {
                showToast('Veuillez saisir une URL cible avant d\'exécuter le module', 'error');
                if (moduleOutput) {
                    moduleOutput.textContent += '\n✗ Module execution failed\n\nError:\nMissing target URL';
                    moduleOutput.style.color = '#f44336';
                }
                return;
            }

            // Normalize URL and map common option names
            let parsed;
            try {
                parsed = new URL(targetUrl);
            } catch (e) {
                showToast('URL cible invalide', 'error');
                if (moduleOutput) {
                    moduleOutput.textContent += `\n✗ Module execution failed\n\nError:\nInvalid target URL`;
                    moduleOutput.style.color = '#f44336';
                }
                return;
            }

            const isHttps = parsed.protocol === 'https:';
            const host = parsed.hostname;
            const inferredPort = parsed.port || (isHttps ? '443' : '80');
            const isDefaultPort = (!parsed.port && ((isHttps && inferredPort === '443') || (!isHttps && inferredPort === '80')));
            // target for kittysploit modules should be host only (protocol/port handled separately)
            const baseTargetHost = host;
            const portSuffix = isDefaultPort ? '' : `:${inferredPort}`;
            const baseTargetUrl = `${parsed.protocol}//${host}${portSuffix}`;
            const uri = `${parsed.pathname || '/'}${parsed.search || ''}`;

            // Add common target aliases when not already provided
            const hasTargetOpt = Object.keys(options).some(k => k.toLowerCase() === 'target');
            if (!hasTargetOpt) {
                options.target = baseTargetHost;
                options.TARGET = baseTargetHost;
            }

            // Some modules expect URL/RHOST(S)/RPORT/port instead of target
            options.URL = targetUrl; // keep full URL with path/query
            if (!options.RHOSTS) {
                options.RHOSTS = host;
            }
            if (!options.RHOST) {
                options.RHOST = host;
            }
            if (!options.RPORT) {
                options.RPORT = inferredPort;
            }
            if (!options.port) {
                options.port = inferredPort;
            }
            if (!options.TARGETURI) {
                options.TARGETURI = uri || '/';
            }
            if (!options.URI) {
                options.URI = uri || '/';
            }
            if (options.ssl === undefined) {
                options.ssl = isHttps;
            }
            if (options.SSL === undefined) {
                options.SSL = isHttps;
            }

            const res = await fetch(`${API_BASE}/modules/run`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    module_name: selectedModuleId,
                    options: options
                })
            });

            const data = await res.json();

            if (moduleOutput) {
                moduleOutput.style.color = '#d4d4d4';
                const resultVal = data.result;
                const isRunning = data.is_running;
                const baseOutput = data.output || '';
                const isExplicitFailure = resultVal === false;
                if (res.ok) {
                    moduleOutput.textContent += `\nOutput:\n${baseOutput || 'No output captured.'}`;
                    if (isRunning) {
                        moduleOutput.textContent += `\n\nStatus: still running...`;
                        moduleOutput.style.color = '#ffa000';
                    } else if (isExplicitFailure) {
                        moduleOutput.textContent += `\n\nResult: false`;
                        moduleOutput.style.color = '#f44336';
                    } else if (resultVal !== undefined && resultVal !== null) {
                        moduleOutput.textContent += `\n\nResult: ${resultVal}`;
                    }
                } else {
                    moduleOutput.textContent += `\n✗ Module execution failed\n\nError:\n${data.error || data.detail || 'Unknown error'}`;
                    moduleOutput.style.color = '#f44336';
                }
                updateModuleOutputCache(moduleOutput);
            }
        } catch (err) {
            console.error("Module execution error", err);
            if (moduleOutput) {
                moduleOutput.textContent += `\n✗ Connection error: ${err.message}`;
                moduleOutput.style.color = '#f44336';
                updateModuleOutputCache(moduleOutput);
            }
        } finally {
            runModuleBtn.disabled = false;
            runModuleBtn.innerHTML = '<span class="material-symbols-outlined" style="font-size: 18px;">play_arrow</span> Run Module';
        }
    });
}

// Auto-configure module from URL
async function autoConfigureModuleFromUrl(moduleId, silent = false) {
    const urlInput = document.getElementById('module-target-url');
    if (!urlInput) return;

    const url = urlInput.value.trim();
    if (!url) {
        if (!silent) {
            alert('Please enter a URL first');
        }
        return;
    }

    // Validate URL format
    try {
        new URL(url);
    } catch (e) {
        if (!silent) {
            alert('Invalid URL format. Please enter a valid URL (e.g., https://example.com:443/path)');
        }
        return;
    }

    // Show loading state (only if not silent)
    let btn = null;
    try {
        btn = (typeof event !== 'undefined' && event?.target) ? event.target.closest('button') : null;
    } catch (e) {
        // Ignore if event is not defined or other issues
    }
    const originalText = btn ? btn.innerHTML : '';
    if (btn && !silent) {
        btn.disabled = true;
        btn.innerHTML = '<span class="material-symbols-outlined" style="font-size: 18px; animation: spin 1s linear infinite;">refresh</span> Configuring...';
    }

    try {
        const res = await fetch(`${API_BASE}/auto_configure_module_from_url`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                module_name: moduleId,
                url: url
            })
        });

        const data = await res.json();

        if (res.ok && data.options) {
            // Fill option fields
            let filledCount = 0;
            Object.entries(data.options).forEach(([key, value]) => {
                const input = document.getElementById(`mod-opt-${key}`);
                if (input) {
                    input.value = String(value);
                    filledCount++;
                }
            });

            // Show success message (only if not silent)
            if (!silent) {
                if (filledCount > 0) {
                    const moduleOutput = document.getElementById('module-output');
                    if (moduleOutput) {
                        moduleOutput.style.display = 'block';
                        moduleOutput.style.color = '#4caf50';
                        moduleOutput.style.background = '#1e1e1e';
                        moduleOutput.style.border = 'none';
                        moduleOutput.textContent = `✓ Auto-configured ${filledCount} option(s) from URL:\n${url}\n\nConfigured options:\n${Object.entries(data.options).map(([k, v]) => `  ${k}: ${String(v).substring(0, 80)}${String(v).length > 80 ? '...' : ''}`).join('\n')}`;
                        moduleOutput.scrollTop = moduleOutput.scrollHeight;
                    }
                } else {
                    alert('No matching options found for this module. Please configure manually.');
                }
            }
        } else {
            if (!silent) {
                alert(`Error: ${data.detail || data.error || 'Failed to auto-configure'}`);
            }
        }
    } catch (err) {
        console.error('Auto-configure error:', err);
        if (!silent) {
            alert(`Connection error: ${err.message}`);
        }
    } finally {
        if (btn && !silent) {
            btn.disabled = false;
            btn.innerHTML = originalText;
        }
    }
}

// === API TESTER ===

let apiHistory = [];
let apiCollections = [];
let currentApiRequest = {
    id: null,
    method: 'GET',
    url: '',
    params: [],
    headers: [],
    bodyType: 'none',
    body: '',
    response: null
};

// Initialize API Tester
function initApiTester() {
    // Check if API Tester view exists
    const apiView = document.getElementById('api-view');
    if (!apiView) {
        console.warn('API Tester view not found, skipping initialization');
        return;
    }

    loadApiHistory();
    loadApiCollections();

    // If no current request, create a blank one or load last history
    if (!currentApiRequest.id) {
        if (apiHistory.length > 0) {
            loadApiRequest(apiHistory[0]);
        } else {
            createNewApiRequest();
        }
    }

    renderApiSidebar();
    renderApiRequest();
}

// Load/Save History
function loadApiHistory() {
    try {
        const saved = localStorage.getItem('kittyproxy_api_history');
        if (saved) apiHistory = JSON.parse(saved);
    } catch (e) { console.warn('Failed to load API history', e); }
}

function saveApiHistory() {
    localStorage.setItem('kittyproxy_api_history', JSON.stringify(apiHistory.slice(0, 50))); // Keep last 50
}

// Load/Save Collections
function loadApiCollections() {
    try {
        const saved = localStorage.getItem('kittyproxy_api_collections');
        if (saved) apiCollections = JSON.parse(saved);
    } catch (e) { console.warn('Failed to load API collections', e); }
}

function saveApiCollections() {
    localStorage.setItem('kittyproxy_api_collections', JSON.stringify(apiCollections));
}

// Render Sidebar
function renderApiSidebar() {
    const historyList = document.getElementById('api-history-list');
    const collectionsList = document.getElementById('api-collections-list');

    if (historyList) {
        if (apiHistory.length === 0) {
            historyList.innerHTML = '<div style="padding: 20px; text-align: center; color: #999; font-size: 13px;">No history yet</div>';
        } else {
            historyList.innerHTML = apiHistory.map(req => `
                <div class="api-history-item ${currentApiRequest.id === req.id ? 'active' : ''}" onclick="loadApiRequestById('${req.id}')">
                    <span class="method-badge method-${req.method}">${req.method}</span>
                    <span style="white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${escapeHtml(req.url || 'No URL')}</span>
                </div>
            `).join('');
        }
    }

    // TODO: Render collections
}

// Switch Sidebar Tab
function switchApiSidebarTab(tabName) {
    document.querySelectorAll('.api-sidebar-tab').forEach(t => t.classList.remove('active'));
    document.getElementById(`tab-${tabName}`).classList.add('active');

    document.getElementById('api-history-list').style.display = tabName === 'history' ? 'block' : 'none';
    document.getElementById('api-collections-list').style.display = tabName === 'collections' ? 'block' : 'none';
    document.getElementById('api-react-apis-list').style.display = tabName === 'react-apis' ? 'block' : 'none';

    // Charger les API React si on passe à cet onglet
    if (tabName === 'react-apis') {
        loadReactApis();
    }
}

// Store React APIs data globally for access from click handlers
let reactApisData = {
    apis: [],
    graphqlQueries: {}
};

// Track new React APIs for notification badge
let newReactApisCount = 0;
let lastReactApisCount = 0;

// Poll for new React APIs periodically (only if not on API view)
let reactApiPollInterval = null;

// Start polling for new React APIs
function startReactApiPolling() {
    // Poll every 5 seconds
    if (reactApiPollInterval) {
        clearInterval(reactApiPollInterval);
    }
    reactApiPollInterval = setInterval(async () => {
        // Only check if not on API view (to avoid unnecessary updates)
        const currentView = document.querySelector('.nav-item.active')?.dataset.view;
        if (currentView !== 'api') {
            try {
                const res = await fetch(`${API_BASE}/endpoints`);
                const data = await res.json();
                const reactApis = data.react_api_endpoints || [];

                // Check for new APIs and update notification badge
                if (reactApis.length > lastReactApisCount) {
                    newReactApisCount += (reactApis.length - lastReactApisCount);
                    updateApiTabBadge(newReactApisCount);
                    lastReactApisCount = reactApis.length;
                }
            } catch (err) {
                console.error('[REACT APIs] Error polling for new APIs:', err);
            }
        }
    }, 5000); // Poll every 5 seconds
}

// Initialize polling when page loads
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', startReactApiPolling);
} else {
    startReactApiPolling();
}

// Load and display React APIs
async function loadReactApis() {
    const reactApisList = document.getElementById('api-react-apis-list');
    if (!reactApisList) {
        console.warn('[REACT APIs] api-react-apis-list element not found');
        return;
    }

    console.log('[REACT APIs] Loading React APIs...');

    try {
        const res = await fetch(`${API_BASE}/endpoints`);
        const data = await res.json();

        console.log('[REACT APIs] Response received:', data);
        console.log('[REACT APIs] react_api_endpoints:', data.react_api_endpoints);

        const reactApis = data.react_api_endpoints || [];
        console.log(`[REACT APIs] Found ${reactApis.length} React API(s)`);

        // Check for new APIs and update notification badge
        if (reactApis.length > lastReactApisCount) {
            newReactApisCount += (reactApis.length - lastReactApisCount);
            updateApiTabBadge(newReactApisCount);
        }
        lastReactApisCount = reactApis.length;

        // Store globally
        reactApisData.apis = reactApis;
        reactApisData.graphqlQueries = data.graphql_queries || {};

        if (reactApis.length === 0) {
            console.log('[REACT APIs] No React APIs found, showing empty state');
            reactApisList.innerHTML = `
                <div style="padding: 20px; text-align: center; color: #999; font-size: 13px;">
                    <span class="material-symbols-outlined" style="font-size: 48px; display: block; margin-bottom: 10px; opacity: 0.5;">code_off</span>
                    No React APIs discovered yet.<br>
                    <small style="color: #777;">React APIs will appear here when detected in JavaScript files.</small>
                    <br><br>
                    <small style="color: #999;">Check the console for extraction logs.</small>
                </div>
            `;
            return;
        }

        const graphqlQueries = data.graphql_queries || {};

        reactApisList.innerHTML = reactApis.map((api, index) => {
            // Extraire le chemin de l'URL
            let path = api;
            try {
                const url = new URL(api);
                path = url.pathname + (url.search || '');
            } catch (e) {
                // Si ce n'est pas une URL complète, utiliser tel quel
            }

            // Vérifier si c'est un endpoint GraphQL avec des requêtes
            const isGraphQL = graphqlQueries[api] && graphqlQueries[api].length > 0;
            const queries = isGraphQL ? graphqlQueries[api] : [];

            // Déterminer la méthode HTTP probable (basé sur le chemin)
            let method = 'GET';
            if (isGraphQL || path.toLowerCase().includes('graphql')) {
                method = 'POST';  // GraphQL utilise généralement POST
            } else {
                const methodPatterns = {
                    'POST': ['/create', '/add', '/new', '/submit', '/save'],
                    'PUT': ['/update', '/edit', '/modify'],
                    'DELETE': ['/delete', '/remove', '/destroy'],
                    'PATCH': ['/patch', '/partial'],
                };
                for (const [m, patterns] of Object.entries(methodPatterns)) {
                    if (patterns.some(p => path.toLowerCase().includes(p))) {
                        method = m;
                        break;
                    }
                }
            }

            // Badge GraphQL si applicable
            const graphqlBadge = isGraphQL ? `<span style="background: #e10098; color: white; font-size: 9px; padding: 2px 4px; border-radius: 3px; margin-left: 4px;">GraphQL (${queries.length})</span>` : '';

            // Utiliser l'index pour récupérer les données depuis la variable globale
            return `
                <div class="api-react-api-item" 
                     data-api-index="${index}"
                     onclick="loadReactApiFromItem(${index}, '${api.replace(/'/g, "\\'")}', '${method}')" 
                     style="padding: 12px; border-bottom: 1px solid #e0e0e0; cursor: pointer; transition: background 0.2s;"
                     onmouseover="this.style.background='#f5f5f5'" 
                     onmouseout="this.style.background='transparent'">
                    <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
                        <span class="method-badge method-${method}" style="font-size: 11px; padding: 2px 6px;">${method}</span>
                        <span style="font-size: 12px; color: #666; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(api)}">${escapeHtml(path)}</span>
                        ${graphqlBadge}
                    </div>
                    <div style="font-size: 11px; color: #999; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(api)}">${escapeHtml(api)}</div>
                    ${isGraphQL ? `
                        <div style="margin-top: 8px; padding-top: 8px; border-top: 1px solid #eee;">
                            <div style="font-size: 10px; color: #666; font-weight: 600; margin-bottom: 4px; display: flex; align-items: center; justify-content: space-between;">
                                <span>GraphQL Queries (${queries.length}):</span>
                                <button onclick="event.stopPropagation(); showGraphQLQuerySelector('${api.replace(/'/g, "\\'")}', ${index})" 
                                        style="background: #e10098; color: white; border: none; padding: 2px 8px; border-radius: 3px; font-size: 9px; cursor: pointer; font-weight: 600;">
                                    Select Query
                                </button>
                            </div>
                            ${queries.slice(0, 3).map((q, qIdx) => `
                                <div onclick="event.stopPropagation(); loadGraphQLQuery('${api.replace(/'/g, "\\'")}', ${index}, ${qIdx})" 
                                     style="font-size: 10px; color: #888; margin: 2px 0; padding: 4px; background: #f9f9f9; border-radius: 3px; font-family: 'Fira Code', monospace; cursor: pointer; transition: background 0.2s;"
                                     onmouseover="this.style.background='#f0f0f0'" 
                                     onmouseout="this.style.background='#f9f9f9'">
                                    <span style="color: #e10098; font-weight: 600;">${q.type}</span> ${q.name ? q.name : ''} ${q.main_field ? `→ ${q.main_field}` : ''}
                                </div>
                            `).join('')}
                            ${queries.length > 3 ? `<div style="font-size: 9px; color: #999; margin-top: 4px; cursor: pointer; text-decoration: underline;" onclick="event.stopPropagation(); showGraphQLQuerySelector('${api.replace(/'/g, "\\'")}', ${index})">+ ${queries.length - 3} more...</div>` : ''}
                        </div>
                    ` : ''}
                </div>
            `;
        }).join('');

    } catch (err) {
        console.error('Error loading React APIs:', err);
        reactApisList.innerHTML = `
            <div style="padding: 20px; text-align: center; color: #f44336; font-size: 13px;">
                Error loading React APIs: ${err.message}
            </div>
        `;
    }
}

// Load a React API from a list item (with GraphQL data support)
function loadReactApiFromItem(index, url, method = 'GET') {
    // Récupérer les requêtes GraphQL depuis la variable globale
    let graphqlQueries = null;
    if (reactApisData.graphqlQueries[url] && reactApisData.graphqlQueries[url].length > 0) {
        graphqlQueries = reactApisData.graphqlQueries[url];
    }

    loadReactApiIntoRequest(url, method, graphqlQueries);
}

// Load a React API into the request builder
function loadReactApiIntoRequest(url, method = 'GET', graphqlQueries = null) {
    createNewApiRequest();

    // Mettre à jour l'objet currentApiRequest AVANT de rendre
    currentApiRequest.method = method;
    currentApiRequest.url = url;

    // Si c'est un endpoint GraphQL avec des requêtes, pré-remplir le body
    if (graphqlQueries && graphqlQueries.length > 0 && (method === 'POST' || url.toLowerCase().includes('graphql'))) {
        // Utiliser la première requête GraphQL
        const firstQuery = graphqlQueries[0];
        // Extraire la requête GraphQL (peut être une string ou déjà un objet)
        let queryString = firstQuery.full_content || firstQuery.content || '';

        // Si c'est déjà un objet JSON, le convertir en string formatée
        if (typeof queryString === 'object') {
            queryString = JSON.stringify(queryString, null, 2);
        }

        // Nettoyer et formater la requête GraphQL (préserver les retours à la ligne)
        queryString = queryString.trim();

        const graphqlBody = {
            query: queryString
        };

        // Ajouter les variables si présentes
        if (firstQuery.variables) {
            // Parser les variables depuis la string (ex: "$billingPlatform: BillingPlatform, $planGroup: String")
            const vars = {};
            const varMatches = firstQuery.variables.match(/\$(\w+):\s*(\w+)/g);
            if (varMatches) {
                varMatches.forEach(v => {
                    const match = v.match(/\$(\w+):\s*(\w+)/);
                    if (match) {
                        // Valeur par défaut basée sur le type
                        const varName = match[1];
                        const varType = match[2];
                        if (varType === 'String') {
                            vars[varName] = '';
                        } else if (varType === 'Int' || varType === 'Float') {
                            vars[varName] = 0;
                        } else if (varType === 'Boolean') {
                            vars[varName] = false;
                        } else if (varType === 'ID') {
                            vars[varName] = '';
                        } else {
                            vars[varName] = null;
                        }
                    }
                });
            }
            if (Object.keys(vars).length > 0) {
                graphqlBody.variables = vars;
            }
        }

        // Pré-remplir le body avec la requête GraphQL (formaté avec indentation)
        currentApiRequest.bodyType = 'json';
        // Utiliser JSON.stringify avec indentation pour un formatage propre
        currentApiRequest.body = JSON.stringify(graphqlBody, null, 2);

        // Ajouter le header Content-Type pour GraphQL
        const contentTypeHeader = currentApiRequest.headers.find(h => h.key.toLowerCase() === 'content-type');
        if (!contentTypeHeader) {
            currentApiRequest.headers.push({ key: 'Content-Type', value: 'application/json', active: true });
        } else {
            contentTypeHeader.value = 'application/json';
        }
    }

    renderApiRequest();

    // Si c'est GraphQL, basculer automatiquement sur l'onglet Body
    if (graphqlQueries && graphqlQueries.length > 0) {
        setTimeout(() => {
            switchApiReqTab('body');
            // Format and display JSON after switching to body tab
            setTimeout(() => {
                formatAndDisplayJson();
            }, 150);
        }, 100);
    }
}

// Update API tab badge notification
function updateApiTabBadge(count) {
    const apiNavItem = document.querySelector('[data-view="api"]');
    if (!apiNavItem) return;

    // Remove existing badge
    const existingBadge = apiNavItem.querySelector('.api-notification-badge');
    if (existingBadge) {
        existingBadge.remove();
    }

    // Add new badge if count > 0
    if (count > 0) {
        const badge = document.createElement('span');
        badge.className = 'api-notification-badge';
        badge.textContent = count > 99 ? '99+' : count.toString();
        badge.style.cssText = `
            position: absolute;
            top: 8px;
            right: 8px;
            background: #f44336;
            color: white;
            border-radius: 10px;
            padding: 2px 6px;
            font-size: 10px;
            font-weight: 600;
            min-width: 18px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.2);
            animation: pulse 2s infinite;
        `;
        apiNavItem.style.position = 'relative';
        apiNavItem.appendChild(badge);
    }
}

// Show GraphQL query selector modal
function showGraphQLQuerySelector(apiUrl, apiIndex) {
    const queries = reactApisData.graphqlQueries[apiUrl] || [];
    if (queries.length === 0) {
        alert('No GraphQL queries found for this endpoint');
        return;
    }

    // Create modal
    const modal = document.createElement('div');
    modal.id = 'graphql-query-selector-modal';
    modal.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0,0,0,0.5);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 10000;
    `;

    modal.innerHTML = `
        <div style="background: white; border-radius: 12px; padding: 24px; max-width: 600px; max-height: 80vh; overflow-y: auto; box-shadow: 0 8px 32px rgba(0,0,0,0.3);">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px;">
                <h2 style="margin: 0; color: #333; display: flex; align-items: center; gap: 8px;">
                    <span class="material-symbols-outlined" style="color: #e10098;">code</span>
                    Select GraphQL Query
                </h2>
                <button onclick="closeGraphQLQuerySelector()" style="background: transparent; border: none; cursor: pointer; padding: 4px;">
                    <span class="material-symbols-outlined">close</span>
                </button>
            </div>
            <div style="margin-bottom: 16px; padding: 12px; background: #f5f5f5; border-radius: 6px; font-size: 12px; color: #666;">
                <strong>Endpoint:</strong> ${escapeHtml(apiUrl)}
            </div>
            <div style="display: flex; flex-direction: column; gap: 8px;">
                ${queries.map((q, qIdx) => `
                    <div onclick="selectGraphQLQuery('${apiUrl.replace(/'/g, "\\'")}', ${apiIndex}, ${qIdx})" 
                         style="padding: 12px; border: 2px solid #e0e0e0; border-radius: 8px; cursor: pointer; transition: all 0.2s;"
                         onmouseover="this.style.borderColor='#e10098'; this.style.background='#fef5ff'" 
                         onmouseout="this.style.borderColor='#e0e0e0'; this.style.background='transparent'">
                        <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
                            <span style="background: #e10098; color: white; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 600;">${q.type.toUpperCase()}</span>
                            ${q.name ? `<span style="font-weight: 600; color: #333;">${escapeHtml(q.name)}</span>` : ''}
                            ${q.main_field ? `<span style="color: #666;">→ ${escapeHtml(q.main_field)}</span>` : ''}
                        </div>
                        ${q.variables ? `
                            <div style="font-size: 11px; color: #888; margin-bottom: 4px;">
                                <strong>Variables:</strong> ${escapeHtml(q.variables)}
                            </div>
                        ` : ''}
                        <pre style="margin: 0; padding: 8px; background: #f9f9f9; border-radius: 4px; font-size: 11px; font-family: 'Fira Code', monospace; overflow-x: auto; max-height: 150px; overflow-y: auto;">${escapeHtml(q.content)}</pre>
                    </div>
                `).join('')}
            </div>
        </div>
    `;

    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            closeGraphQLQuerySelector();
        }
    });

    document.body.appendChild(modal);
}

// Close GraphQL query selector modal
function closeGraphQLQuerySelector() {
    const modal = document.getElementById('graphql-query-selector-modal');
    if (modal) {
        modal.remove();
    }
}

// Select a GraphQL query
function selectGraphQLQuery(apiUrl, apiIndex, queryIndex) {
    closeGraphQLQuerySelector();
    loadGraphQLQuery(apiUrl, apiIndex, queryIndex);
}

// Load a specific GraphQL query into the request builder
function loadGraphQLQuery(apiUrl, apiIndex, queryIndex) {
    const queries = reactApisData.graphqlQueries[apiUrl] || [];
    if (queryIndex >= queries.length) {
        alert('Query not found');
        return;
    }

    const selectedQuery = queries[queryIndex];
    const isGraphQL = apiUrl.toLowerCase().includes('graphql') || apiUrl.toLowerCase().includes('gql');
    const method = isGraphQL ? 'POST' : 'GET';

    loadReactApiIntoRequest(apiUrl, method, [selectedQuery]);
}

// Create New Request
function createNewApiRequest() {
    currentApiRequest = {
        id: `req_${Date.now()}`,
        method: 'GET',
        url: '',
        params: [{ key: '', value: '', active: true }],
        headers: [{ key: 'User-Agent', value: 'KittyProxy/1.0', active: true }],
        bodyType: 'none',
        body: '',
        response: null
    };
    renderApiRequest();
}

// Load Request
function loadApiRequestById(id) {
    const req = apiHistory.find(r => r.id === id);
    if (req) {
        loadApiRequest(req);
    }
}

function loadApiRequest(req) {
    currentApiRequest = JSON.parse(JSON.stringify(req)); // Deep copy
    renderApiRequest();
}

// Render Request Editor
function renderApiRequest() {
    const methodEl = document.getElementById('api-method');
    const urlEl = document.getElementById('api-url');

    if (methodEl) {
        methodEl.value = currentApiRequest.method;
        // Déclencher l'événement change pour s'assurer que le select est mis à jour
        methodEl.dispatchEvent(new Event('change', { bubbles: true }));
    }
    if (urlEl) {
        urlEl.value = currentApiRequest.url;
        // Déclencher l'événement input pour s'assurer que l'input est mis à jour
        urlEl.dispatchEvent(new Event('input', { bubbles: true }));
    }

    // Render Params
    const paramsContainer = document.getElementById('api-params-container');
    if (paramsContainer) {
        paramsContainer.innerHTML = currentApiRequest.params.map((p, i) => `
            <div class="kv-editor-row">
                <input type="text" class="kv-key" placeholder="Key" value="${escapeHtml(p.key)}" oninput="updateKv('params', ${i}, 'key', this.value)">
                <input type="text" class="kv-value" placeholder="Value" value="${escapeHtml(p.value)}" oninput="updateKv('params', ${i}, 'value', this.value)">
                <button class="kv-remove" onclick="removeKv('params', ${i})"><span class="material-symbols-outlined" style="font-size: 16px;">close</span></button>
            </div>
        `).join('');
    }

    // Render Headers
    const headersContainer = document.getElementById('api-headers-container');
    if (headersContainer) {
        headersContainer.innerHTML = currentApiRequest.headers.map((p, i) => `
            <div class="kv-editor-row">
                <input type="text" class="kv-key" placeholder="Key" value="${escapeHtml(p.key)}" oninput="updateKv('headers', ${i}, 'key', this.value)">
                <input type="text" class="kv-value" placeholder="Value" value="${escapeHtml(p.value)}" oninput="updateKv('headers', ${i}, 'value', this.value)">
                <button class="kv-remove" onclick="removeKv('headers', ${i})"><span class="material-symbols-outlined" style="font-size: 16px;">close</span></button>
            </div>
        `).join('');
    }

    // Render Body
    const bodyTypeInput = document.querySelector(`input[name="body-type"][value="${currentApiRequest.bodyType}"]`);
    if (bodyTypeInput) bodyTypeInput.checked = true;

    const bodyEditor = document.getElementById('api-body-editor');
    if (bodyEditor) bodyEditor.value = currentApiRequest.body || '';

    toggleBodyType();

    // Render Response if exists
    const responseSection = document.getElementById('api-response-section');
    if (responseSection) {
        if (currentApiRequest.response) {
            renderApiResponse(currentApiRequest.response);
        } else {
            responseSection.style.display = 'none';
        }
    }

    renderApiSidebar(); // Update active state
}

// KV Helpers
function addKvRow(type) {
    const list = (type === 'api-params-container' || type === 'params') ? currentApiRequest.params : currentApiRequest.headers;
    list.push({ key: '', value: '', active: true });
    renderApiRequest();
}

function removeKv(type, index) {
    const list = type === 'params' ? currentApiRequest.params : currentApiRequest.headers;
    list.splice(index, 1);
    renderApiRequest();
}

function updateKv(type, index, field, value) {
    const list = type === 'params' ? currentApiRequest.params : currentApiRequest.headers;
    list[index][field] = value;

    // If updating params, sync with URL
    if (type === 'params') {
        syncParamsToUrl();
    }
}

function syncParamsToUrl() {
    try {
        const urlVal = document.getElementById('api-url').value;
        if (!urlVal) return;

        let urlObj;
        try {
            urlObj = new URL(urlVal);
        } catch {
            return;
        }

        const searchParams = new URLSearchParams();
        currentApiRequest.params.forEach(p => {
            if (p.key) searchParams.append(p.key, p.value);
        });

        // Preserve hash if any
        const hash = urlObj.hash;
        urlObj.search = searchParams.toString();
        urlObj.hash = hash;

        document.getElementById('api-url').value = urlObj.toString();
        currentApiRequest.url = urlObj.toString();
    } catch (e) { console.error(e); }
}

// Switch Request Tab
function switchApiReqTab(tabName) {
    document.querySelectorAll('.api-req-tab').forEach(t => t.classList.remove('active'));
    document.getElementById(`req-tab-${tabName}`).classList.add('active');

    document.querySelectorAll('.api-req-panel').forEach(p => p.classList.remove('active'));
    document.getElementById(`api-panel-${tabName}`).classList.add('active');
}

// Toggle Body Type
function toggleBodyType() {
    const typeInput = document.querySelector('input[name="body-type"]:checked');
    if (!typeInput) return;

    const type = typeInput.value;
    currentApiRequest.bodyType = type;

    const container = document.getElementById('api-body-editor-container');
    const msg = document.getElementById('api-body-none-msg');
    const jsonView = document.getElementById('api-body-json-view');
    const bodyEditor = document.getElementById('api-body-editor');
    const formatBtn = document.getElementById('api-body-format-btn');

    if (container && msg) {
        if (type === 'none') {
            container.style.display = 'none';
            msg.style.display = 'block';
        } else {
            container.style.display = 'flex';
            msg.style.display = 'none';

            // Show JSON formatted view for JSON type, textarea for raw
            if (type === 'json') {
                if (jsonView) jsonView.style.display = 'flex';
                if (bodyEditor) bodyEditor.style.display = 'none';
                if (formatBtn) formatBtn.style.display = 'none';
                formatAndDisplayJson();
            } else {
                if (jsonView) jsonView.style.display = 'none';
                if (bodyEditor) bodyEditor.style.display = 'block';
                if (formatBtn) formatBtn.style.display = type === 'raw' ? 'block' : 'none';
            }
        }
    }
}

// Format and display JSON with syntax highlighting
function formatAndDisplayJson() {
    const jsonView = document.getElementById('api-body-json-view');
    const jsonFormatted = document.getElementById('api-body-json-formatted');
    const bodyEditor = document.getElementById('api-body-editor');

    if (!jsonView || !jsonFormatted || !bodyEditor) return;

    const bodyText = bodyEditor.value || currentApiRequest.body || '';

    if (!bodyText.trim()) {
        jsonFormatted.textContent = '';
        return;
    }

    try {
        // Try to parse and format JSON
        let jsonObj;
        try {
            jsonObj = JSON.parse(bodyText);
        } catch (parseError) {
            // If parsing fails, try to clean up the string first
            // Remove any trailing commas and fix common issues
            let cleaned = bodyText.trim();
            // Try to fix common JSON issues
            cleaned = cleaned.replace(/,\s*}/g, '}').replace(/,\s*]/g, ']');
            jsonObj = JSON.parse(cleaned);
        }

        const formatted = JSON.stringify(jsonObj, null, 2);
        jsonFormatted.textContent = formatted;
        jsonFormatted.style.color = '#abb2bf';
        jsonFormatted.style.whiteSpace = 'pre';
        jsonFormatted.style.wordWrap = 'normal';
        jsonFormatted.style.overflowWrap = 'normal';

        // Apply syntax highlighting
        if (window.hljs) {
            jsonFormatted.className = 'language-json';
            hljs.highlightElement(jsonFormatted);
        }
    } catch (e) {
        // If not valid JSON, show error message with proper line breaks
        const errorMsg = `// Invalid JSON:\n${bodyText}`;
        jsonFormatted.textContent = errorMsg;
        jsonFormatted.style.color = '#e06c75';
        jsonFormatted.style.whiteSpace = 'pre-wrap';
    }
}

// Update body when editor changes (for JSON type, update formatted view)
function updateApiBody() {
    const bodyEditor = document.getElementById('api-body-editor');
    if (!bodyEditor) return;

    currentApiRequest.body = bodyEditor.value;

    // If JSON type is selected and we're in formatted view, update it
    if (currentApiRequest.bodyType === 'json') {
        const jsonView = document.getElementById('api-body-json-view');
        if (jsonView && jsonView.style.display !== 'none') {
            formatAndDisplayJson();
        }
    }
}

// Switch from JSON view to editor
function switchToJsonEditor() {
    const jsonView = document.getElementById('api-body-json-view');
    const bodyEditor = document.getElementById('api-body-editor');

    if (jsonView && bodyEditor) {
        jsonView.style.display = 'none';
        bodyEditor.style.display = 'block';
        bodyEditor.focus();
    }
}

// Format JSON body in editor
function formatJsonBody() {
    const bodyEditor = document.getElementById('api-body-editor');
    if (!bodyEditor) return;

    const bodyText = bodyEditor.value || '';
    if (!bodyText.trim()) return;

    try {
        const jsonObj = JSON.parse(bodyText);
        const formatted = JSON.stringify(jsonObj, null, 2);
        bodyEditor.value = formatted;
        currentApiRequest.body = formatted;

        // If JSON type is selected, update the formatted view
        if (currentApiRequest.bodyType === 'json') {
            formatAndDisplayJson();
        }
    } catch (e) {
        alert('Invalid JSON: ' + e.message);
    }
}

// Send Request
async function sendApiRequest() {
    // Update current request object from inputs
    const methodEl = document.getElementById('api-method');
    const urlEl = document.getElementById('api-url');
    const bodyEl = document.getElementById('api-body-editor');

    if (methodEl) currentApiRequest.method = methodEl.value;
    if (urlEl) currentApiRequest.url = urlEl.value;

    // Get body from editor (even if hidden, it still has the value)
    if (bodyEl) {
        currentApiRequest.body = bodyEl.value;
    }

    if (!currentApiRequest.url) {
        alert('Please enter a URL');
        return;
    }

    const sendBtn = document.getElementById('api-send-btn');
    const originalText = sendBtn ? sendBtn.innerHTML : 'Send';
    if (sendBtn) {
        sendBtn.innerHTML = '<span class="material-symbols-outlined" style="font-size: 18px; animation: spin 1s linear infinite;">refresh</span> Sending...';
        sendBtn.disabled = true;
    }

    try {
        // Prepare headers object
        const headers = {};
        currentApiRequest.headers.forEach(h => {
            if (h.key) headers[h.key] = h.value;
        });

        // Prepare body
        let bodyBs64 = '';
        if (currentApiRequest.bodyType !== 'none' && currentApiRequest.body) {
            bodyBs64 = btoa(currentApiRequest.body);
        }

        const payload = {
            method: currentApiRequest.method,
            url: currentApiRequest.url,
            headers: headers,
            body_bs64: bodyBs64
        };

        const startTime = Date.now();
        const res = await fetch(`${API_BASE}/send_custom`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const endTime = Date.now();
        const duration = endTime - startTime;

        let responseData;
        try {
            responseData = await res.json();
            // The endpoint returns { status: 'ok', status_code: ..., ... } or { status: 'error', ... }
            if (responseData.status === 'ok') {
                // Construct response object for UI
                const uiResponse = {
                    status: responseData.status_code,
                    statusText: responseData.reason || 'OK',
                    time: duration,
                    size: responseData.content_bs64 ? responseData.content_bs64.length : 0, // Approx
                    headers: responseData.headers || {},
                    body: responseData.content_bs64 ? atob(responseData.content_bs64) : ''
                };

                currentApiRequest.response = uiResponse;
                renderApiResponse(uiResponse);

                // Add to history if new or changed
                addToHistory(currentApiRequest);
            } else {
                throw new Error(responseData.message || responseData.detail || 'Unknown error');
            }
        } catch (e) {
            console.error('API Error:', e);
            alert('Error sending request: ' + e.message);
        }

    } catch (err) {
        console.error('Request Error:', err);
        alert('Error: ' + err.message);
    } finally {
        if (sendBtn) {
            sendBtn.innerHTML = originalText;
            sendBtn.disabled = false;
        }
    }
}

function renderApiResponse(resp) {
    const section = document.getElementById('api-response-section');
    if (!section) return;
    section.style.display = 'flex';

    const statusBadge = document.getElementById('api-resp-status');
    if (statusBadge) {
        statusBadge.textContent = `${resp.status} ${resp.statusText || ''}`;
        statusBadge.className = 'api-status-badge';
        if (resp.status >= 200 && resp.status < 300) statusBadge.classList.add('status-2xx');
        else if (resp.status >= 300 && resp.status < 400) statusBadge.classList.add('status-3xx');
        else if (resp.status >= 400 && resp.status < 500) statusBadge.classList.add('status-4xx');
        else statusBadge.classList.add('status-5xx');
    }

    const timeVal = document.getElementById('api-resp-time-val');
    if (timeVal) timeVal.textContent = `${resp.time}ms`;

    const sizeVal = document.getElementById('api-resp-size-val');
    if (sizeVal) sizeVal.textContent = formatBytes(resp.size);

    const contentCode = document.getElementById('api-resp-content');
    if (contentCode) {
        // Try to format JSON
        try {
            const json = JSON.parse(resp.body);
            contentCode.textContent = JSON.stringify(json, null, 2);
            if (window.hljs) hljs.highlightElement(contentCode);
        } catch {
            contentCode.textContent = resp.body;
        }
    }
}

function addToHistory(req) {
    // Remove if exists (move to top)
    apiHistory = apiHistory.filter(r => r.id !== req.id);
    apiHistory.unshift(JSON.parse(JSON.stringify(req)));
    if (apiHistory.length > 50) apiHistory.pop();
    saveApiHistory();
    renderApiSidebar();
}

function formatBytes(bytes, decimals = 2) {
    if (!+bytes) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

// Init API Tester on load
initApiTester();

// API Tester - New Request Button
const apiNewRequestBtn = document.getElementById('api-new-request-btn');
if (apiNewRequestBtn) {
    apiNewRequestBtn.addEventListener('click', () => {
        createNewApiRequest();
    });
}

// === SEARCH ===
if (searchInput) {
    searchInput.addEventListener('input', (e) => {
        searchTerm = e.target.value.toLowerCase();
        currentPage = 1; // Reset to first page
        renderFlowList();
    });
}

// === PAGINATION ===
if (pageFirstBtn) {
    pageFirstBtn.addEventListener('click', () => {
        currentPage = 1;
        renderFlowList();
    });
}

if (pagePrevBtn) {
    pagePrevBtn.addEventListener('click', () => {
        if (currentPage > 1) {
            currentPage--;
            renderFlowList();
        }
    });
}

if (pageNextBtn) {
    pageNextBtn.addEventListener('click', () => {
        if (currentPage < totalPages) {
            currentPage++;
            renderFlowList();
        }
    });
}

if (pageLastBtn) {
    pageLastBtn.addEventListener('click', () => {
        currentPage = totalPages;
        renderFlowList();
    });
}

// === EXPORT ===
if (exportJsonBtn) {
    exportJsonBtn.addEventListener('click', () => {
        const dataStr = JSON.stringify(flowsData, null, 2);
        const blob = new Blob([dataStr], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `kittyproxy-flows-${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
    });
}

if (exportHarBtn) {
    exportHarBtn.addEventListener('click', () => {
        const har = generateHAR(flowsData);
        const dataStr = JSON.stringify(har, null, 2);
        const blob = new Blob([dataStr], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `kittyproxy-${Date.now()}.har`;
        a.click();
        URL.revokeObjectURL(url);
    });
}

function generateHAR(flows) {
    return {
        log: {
            version: "1.2",
            creator: {
                name: "KittyProxy",
                version: "1.0"
            },
            entries: flows.map(flow => ({
                startedDateTime: new Date().toISOString(),
                time: flow.duration_ms || 0,
                request: {
                    method: flow.method,
                    url: flow.url,
                    httpVersion: "HTTP/1.1",
                    headers: Object.entries(flow.request?.headers || {}).map(([name, value]) => ({ name, value })),
                    queryString: [],
                    postData: flow.request?.content_bs64 ? {
                        mimeType: flow.request.headers?.['content-type'] || 'application/octet-stream',
                        text: atob(flow.request.content_bs64)
                    } : undefined
                },
                response: flow.response ? {
                    status: flow.status_code || 0,
                    statusText: flow.response.reason || '',
                    httpVersion: "HTTP/1.1",
                    headers: Object.entries(flow.response.headers || {}).map(([name, value]) => ({ name, value })),
                    content: {
                        size: flow.response.content_bs64 ? atob(flow.response.content_bs64).length : 0,
                        mimeType: flow.response.headers?.['content-type'] || 'application/octet-stream',
                        text: flow.response.content_bs64 ? atob(flow.response.content_bs64) : ''
                    }
                } : {
                    status: 0,
                    statusText: '',
                    httpVersion: "HTTP/1.1",
                    headers: [],
                    content: { size: 0, mimeType: 'text/plain', text: '' }
                },
                cache: {},
                timings: {
                    send: 0,
                    wait: flow.duration_ms || 0,
                    receive: 0
                }
            }))
        }
    };
}

// === ANALYZE ===
if (clearBtn) {
    clearBtn.addEventListener('click', async () => {
        await fetch(`${API_BASE}/clear`, { method: 'POST' });
        flowsData = [];
        renderFlowList();
        detailContentEl.innerHTML = '<div style="padding: 20px; color: #666; text-align: center;">Select a flow to view details</div>';
        currentFlowId = null;
        updateDetailButtons();

        // Clear all tab histories
        clearAllTabHistories();
    });
}

// === PCAP import (next to Scope) ===
const pcapUploadBtn = document.getElementById('pcap-upload-btn');
const pcapUploadInput = document.getElementById('pcap-upload-input');
if (pcapUploadBtn && pcapUploadInput) {
    pcapUploadBtn.addEventListener('click', () => pcapUploadInput.click());
    pcapUploadInput.addEventListener('change', async (e) => {
        const file = e.target.files?.[0];
        if (!file) return;
        const form = new FormData();
        form.append('file', file);
        pcapUploadInput.value = '';
        pcapUploadBtn.disabled = true;
        const origHtml = pcapUploadBtn.innerHTML;
        pcapUploadBtn.innerHTML = '<span class="material-symbols-outlined" style="font-size: 18px; animation: spin 1s linear infinite;">sync</span> Import...';
        try {
            const res = await fetch(`${API_BASE}/flows/import-pcap`, { method: 'POST', body: form });
            const data = await res.json();
            if (res.ok && data.imported != null) {
                await fetchFlows();
                renderFlowList();
                showToast(`PCAP importé: ${data.imported} flux HTTP/HTTPS affichés`, 'success');
            } else {
                showToast(data.detail || 'Import PCAP échoué', 'error');
            }
        } catch (err) {
            console.error('PCAP import error', err);
            showToast('Erreur lors de l\'import PCAP', 'error');
        } finally {
            pcapUploadBtn.disabled = false;
            pcapUploadBtn.innerHTML = origHtml;
        }
    });
}

// Function to clear all tab histories
function clearAllTabHistories() {
    // Clear API Tester history
    apiHistory = [];
    localStorage.removeItem('kittyproxy_api_history');
    renderApiSidebar();

    // Clear API Collections
    apiCollections = [];
    localStorage.removeItem('kittyproxy_api_collections');

    // Clear Repeater tabs
    repeaterTabs = [];
    activeRepeaterTabId = null;
    localStorage.removeItem('kittyproxy_repeater_tabs');
    localStorage.removeItem('kittyproxy_repeater_active_tab');
    if (typeof renderRepeaterTabs === 'function') {
        renderRepeaterTabs();
    }

    // Clear Intruder tabs
    intruderTabs = [];
    activeIntruderTabId = null;
    localStorage.removeItem('kittyproxy_intruder_tabs');
    localStorage.removeItem('kittyproxy_intruder_active_tab');
    if (typeof renderIntruderTabs === 'function') {
        renderIntruderTabs();
    }

    // Clear Collaboration state
    localStorage.removeItem('kittyproxy_collaboration_state');
    if (typeof clearCollaborationState === 'function') {
        clearCollaborationState();
    }

    console.log('All tab histories cleared');
}

if (replayBtn) {
    replayBtn.addEventListener('click', async () => {
        if (!currentFlowId) return;

        replayBtn.disabled = true;
        replayBtn.classList.add('spinning');

        try {
            const res = await fetch(`${API_BASE}/replay/${currentFlowId}`, { method: 'POST' });
            if (res.ok) {
                await fetchFlows();
            } else {
                const data = await res.json();
                alert(`Replay failed: ${data.detail}`);
            }
        } catch (err) {
            console.error("Replay error", err);
            alert("Replay failed to connect");
        } finally {
            replayBtn.disabled = false;
            replayBtn.classList.remove('spinning');
        }
    });
}

// === REPEATER - Système d'onglets ===

// Sauvegarder les onglets dans localStorage
function saveRepeaterTabs() {
    try {
        const tabsToSave = repeaterTabs.map(tab => ({
            id: tab.id,
            method: tab.method,
            url: tab.url,
            headers: tab.headers,
            body: tab.body,
            // Ne pas sauvegarder response et error pour économiser l'espace
        }));
        localStorage.setItem('kittyproxy_repeater_tabs', JSON.stringify(tabsToSave));
        localStorage.setItem('kittyproxy_repeater_active_tab', activeRepeaterTabId);
    } catch (e) {
        console.warn('Failed to save repeater tabs:', e);
    }
}

// Charger les onglets depuis localStorage
function loadRepeaterTabs() {
    try {
        const savedTabs = localStorage.getItem('kittyproxy_repeater_tabs');
        const savedActiveTab = localStorage.getItem('kittyproxy_repeater_active_tab');

        if (savedTabs) {
            const tabs = JSON.parse(savedTabs);
            repeaterTabs = tabs.map(tab => ({
                ...tab,
                response: null,
                error: null,
                title: generateRepeaterTabTitle(tab.method, tab.url)
            }));

            if (repeaterTabs.length > 0) {
                // Vérifier que l'onglet actif existe toujours
                if (savedActiveTab && repeaterTabs.find(t => t.id === savedActiveTab)) {
                    activeRepeaterTabId = savedActiveTab;
                } else {
                    activeRepeaterTabId = repeaterTabs[0].id;
                }
                renderRepeaterTabs();
                renderRepeaterContent();
                return true;
            }
        }
    } catch (e) {
        console.warn('Failed to load repeater tabs:', e);
    }
    return false;
}

// Générer un titre pour l'onglet basé sur l'URL et la méthode
function generateRepeaterTabTitle(method, url) {
    if (!url || url.trim() === '') {
        return `${method || 'GET'} (no URL)`;
    }

    try {
        const urlObj = new URL(url);
        // Afficher l'URL complète ou juste le pathname si c'est plus court
        let displayUrl = urlObj.pathname + (urlObj.search || '');
        if (displayUrl === '/') {
            displayUrl = urlObj.hostname;
        }

        // Limiter la longueur
        if (displayUrl.length > 35) {
            displayUrl = displayUrl.substring(0, 32) + '...';
        }

        return displayUrl;
    } catch {
        // Si l'URL n'est pas valide, afficher les premiers caractères
        const shortUrl = url.length > 35 ? url.substring(0, 32) + '...' : url;
        return shortUrl;
    }
}

// Créer le premier onglet par défaut
function initRepeater() {
    // Essayer de charger les onglets sauvegardés
    if (!loadRepeaterTabs()) {
        // Si aucun onglet sauvegardé, créer un onglet par défaut
        if (repeaterTabs.length === 0) {
            createRepeaterTab();
        }
    }
}

// Créer un nouvel onglet
function createRepeaterTab(tabData = null) {
    const tabId = `repeater-tab-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const method = tabData?.method || 'GET';
    const url = tabData?.url || '';
    const tab = {
        id: tabId,
        title: generateRepeaterTabTitle(method, url),
        method: method,
        url: url,
        headers: tabData?.headers || '{"User-Agent": "KittyProxy/1.0"}',
        body: tabData?.body || '',
        response: tabData?.response || null,
        error: tabData?.error || null
    };

    repeaterTabs.push(tab);
    activeRepeaterTabId = tabId;
    renderRepeaterTabs();
    renderRepeaterContent();
    saveRepeaterTabs();

    return tabId;
}

// Supprimer un onglet
function closeRepeaterTab(tabId) {
    const index = repeaterTabs.findIndex(t => t.id === tabId);
    if (index === -1) return;

    repeaterTabs.splice(index, 1);

    // Si l'onglet fermé était actif, activer un autre
    if (activeRepeaterTabId === tabId) {
        if (repeaterTabs.length > 0) {
            activeRepeaterTabId = repeaterTabs[repeaterTabs.length - 1].id;
        } else {
            activeRepeaterTabId = null;
            // Créer un nouvel onglet si plus aucun n'existe
            createRepeaterTab();
        }
    }

    renderRepeaterTabs();
    renderRepeaterContent();
    saveRepeaterTabs();
}

// Activer un onglet
function activateRepeaterTab(tabId) {
    activeRepeaterTabId = tabId;
    renderRepeaterTabs();
    renderRepeaterContent();
    saveRepeaterTabs();
}

// Rendre les onglets
function renderRepeaterTabs() {
    if (!repeaterTabsContainer) return;

    repeaterTabsContainer.innerHTML = '';

    repeaterTabs.forEach(tab => {
        const tabEl = document.createElement('div');
        tabEl.className = `repeater-tab ${activeRepeaterTabId === tab.id ? 'active' : ''}`;
        tabEl.dataset.tabId = tab.id;

        // Mettre à jour le titre avant de l'afficher
        tab.title = generateRepeaterTabTitle(tab.method, tab.url);

        const titleEl = document.createElement('span');
        titleEl.className = 'repeater-tab-title';
        titleEl.innerHTML = `
            <span class="repeater-tab-url">${escapeHtml(tab.title)}</span>
            <span class="repeater-tab-method">${escapeHtml(tab.method || 'GET')}</span>
        `;
        titleEl.addEventListener('click', () => activateRepeaterTab(tab.id));

        const closeBtn = document.createElement('button');
        closeBtn.className = 'repeater-tab-close';
        closeBtn.innerHTML = '<span class="material-symbols-outlined" style="font-size: 16px;">close</span>';
        closeBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            closeRepeaterTab(tab.id);
        });

        tabEl.appendChild(titleEl);
        tabEl.appendChild(closeBtn);
        repeaterTabsContainer.appendChild(tabEl);
    });
}

// Rendre le contenu de l'onglet actif
function renderRepeaterContent() {
    if (!repeaterContentContainer) return;

    const activeTab = repeaterTabs.find(t => t.id === activeRepeaterTabId);
    if (!activeTab) {
        repeaterContentContainer.innerHTML = '<div style="padding: 40px; text-align: center; color: #888;">No active tab</div>';
        return;
    }

    repeaterContentContainer.innerHTML = `
        <div class="repeater-tab-content">
            <div class="repeater-controls">
                <select id="repeater-method-${activeTab.id}" class="input-field" style="width: 100px;">
                    <option value="GET" ${activeTab.method === 'GET' ? 'selected' : ''}>GET</option>
                    <option value="POST" ${activeTab.method === 'POST' ? 'selected' : ''}>POST</option>
                    <option value="PUT" ${activeTab.method === 'PUT' ? 'selected' : ''}>PUT</option>
                    <option value="DELETE" ${activeTab.method === 'DELETE' ? 'selected' : ''}>DELETE</option>
                    <option value="PATCH" ${activeTab.method === 'PATCH' ? 'selected' : ''}>PATCH</option>
                </select>
                <input type="text" id="repeater-url-${activeTab.id}" class="input-field" placeholder="https://example.com/api"
                    style="flex: 1;" value="${escapeHtml(activeTab.url)}">
                <button id="repeater-send-${activeTab.id}" class="btn btn-primary">Send</button>
            </div>
            <div class="split-pane" style="flex: 1; border: 1px solid var(--border-color); border-radius: 4px; display: flex;">
                <div class="repeater-editor" id="repeater-editor-${activeTab.id}" style="width: 50%; min-width: 300px; flex-shrink: 0;">
                    <div class="section-title"
                        style="padding: 10px; background: #f5f5f5; margin: 0; border-bottom: 1px solid #eee;">
                        Request Headers (JSON)</div>
                    <textarea id="repeater-headers-${activeTab.id}"
                        spellcheck="false" autocapitalize="off" autocomplete="off"
                        style="flex: 1; border: none; padding: 10px; font-family: 'Fira Code', monospace; resize: none; border-bottom: 1px solid #eee; min-height: 150px;">${escapeHtml(activeTab.headers)}</textarea>
                    <div class="section-title"
                        style="padding: 10px; background: #f5f5f5; margin: 0; border-bottom: 1px solid #eee;">
                        Request Body</div>
                    <textarea id="repeater-body-${activeTab.id}"
                        spellcheck="false" autocapitalize="off" autocomplete="off"
                        style="flex: 1; border: none; padding: 10px; font-family: 'Fira Code', monospace; resize: none; min-height: 150px;">${escapeHtml(activeTab.body)}</textarea>
                </div>
                <div class="resize-handle" id="repeater-resize-handle-${activeTab.id}"></div>
                <div class="repeater-response" id="repeater-response-${activeTab.id}" style="flex: 1; min-width: 300px;">
                    ${activeTab.response ? displayRepeaterResponseHTML(activeTab.response) :
            activeTab.error ? displayRepeaterErrorHTML(activeTab.error) :
                '<div style="color: #888; text-align: center; margin-top: 20px;">Response will appear here</div>'}
                </div>
            </div>
        </div>
    `;

    // Attacher les event listeners
    const sendBtn = document.getElementById(`repeater-send-${activeTab.id}`);
    if (sendBtn) {
        sendBtn.addEventListener('click', () => sendRepeaterRequest(activeTab.id));
    }

    // Attacher les listeners pour sauvegarder les changements
    const methodEl = document.getElementById(`repeater-method-${activeTab.id}`);
    const urlEl = document.getElementById(`repeater-url-${activeTab.id}`);
    const headersEl = document.getElementById(`repeater-headers-${activeTab.id}`);
    const bodyEl = document.getElementById(`repeater-body-${activeTab.id}`);

    if (methodEl) {
        methodEl.addEventListener('change', () => {
            activeTab.method = methodEl.value;
            updateRepeaterTabTitle(activeTab.id);
            saveRepeaterTabs();
        });
    }
    if (urlEl) {
        urlEl.addEventListener('input', () => {
            activeTab.url = urlEl.value;
            updateRepeaterTabTitle(activeTab.id);
            saveRepeaterTabs();
        });
    }
    if (headersEl) {
        headersEl.addEventListener('input', () => {
            activeTab.headers = headersEl.value;
            saveRepeaterTabs();
        });
    }
    if (bodyEl) {
        bodyEl.addEventListener('input', () => {
            activeTab.body = bodyEl.value;
            saveRepeaterTabs();
        });
    }

    // Initialiser le resize handle pour cet onglet
    setupRepeaterResizeHandle(activeTab.id);
}

// Mettre à jour le titre de l'onglet
function updateRepeaterTabTitle(tabId) {
    const tab = repeaterTabs.find(t => t.id === tabId);
    if (!tab) return;

    tab.title = generateRepeaterTabTitle(tab.method, tab.url);
    renderRepeaterTabs();
}

// Envoyer une requête depuis un onglet
async function sendRepeaterRequest(tabId) {
    const tab = repeaterTabs.find(t => t.id === tabId);
    if (!tab) return;

    const sendBtn = document.getElementById(`repeater-send-${tabId}`);
    if (sendBtn) {
        sendBtn.disabled = true;
        sendBtn.textContent = 'Sending...';
    }

    try {
        const headersStr = tab.headers.trim();
        let headers = {};
        try {
            headers = headersStr ? JSON.parse(headersStr) : {};
        } catch (e) {
            tab.error = "Invalid JSON in Headers";
            renderRepeaterContent();
            if (sendBtn) {
                sendBtn.disabled = false;
                sendBtn.textContent = 'Send';
            }
            return;
        }

        const bodyBs64 = tab.body ? btoa(tab.body) : "";

        const payload = {
            method: tab.method,
            url: tab.url,
            headers: headers,
            body_bs64: bodyBs64
        };

        const res = await fetch(`${API_BASE}/send_custom`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        let responseData;
        try {
            responseData = await res.json();
        } catch (e) {
            let text = '';
            try {
                text = await res.text();
            } catch (textErr) {
                text = 'Could not read response';
            }
            const errorMsg = `Invalid response from server (${res.status} ${res.statusText}): ${text || 'Unknown error'}`;
            tab.error = errorMsg;
            tab.response = null;
            renderRepeaterContent();
            if (sendBtn) {
                sendBtn.disabled = false;
                sendBtn.textContent = 'Send';
            }
            saveRepeaterTabs();
            return;
        }

        if (!res.ok) {
            const errorDetail = responseData?.detail || responseData?.error || `API Error: ${res.status} ${res.statusText}`;
            tab.error = errorDetail;
            tab.response = null;
            renderRepeaterContent();
            saveRepeaterTabs();
        } else if (responseData && responseData.status === 'ok') {
            tab.response = responseData;
            tab.error = null;
            renderRepeaterContent();
            saveRepeaterTabs();
            setTimeout(fetchFlows, 500);
        } else {
            tab.error = responseData.detail || responseData.error || 'Request failed';
            tab.response = null;
            renderRepeaterContent();
            saveRepeaterTabs();
        }
    } catch (err) {
        console.error("Repeater error", err);
        tab.error = `Connection failed: ${err.message}`;
        tab.response = null;
        renderRepeaterContent();
        saveRepeaterTabs();
    } finally {
        if (sendBtn) {
            sendBtn.disabled = false;
            sendBtn.textContent = 'Send';
        }
    }
}

// Générer le HTML de la réponse
function displayRepeaterResponseHTML(responseData) {
    const statusCode = responseData.status_code || 0;
    const statusClass = statusCode >= 400 ? 'status-4xx' : statusCode >= 300 ? 'status-3xx' : 'status-2xx';
    const headers = responseData.headers || {};
    const bodyBs64 = responseData.content_bs64 || '';

    let bodyContent = '';
    let bodyPreview = '';

    if (bodyBs64) {
        try {
            bodyContent = atob(bodyBs64);
            try {
                const jsonContent = JSON.parse(bodyContent);
                bodyPreview = JSON.stringify(jsonContent, null, 2);
            } catch {
                bodyPreview = bodyContent;
            }
        } catch (e) {
            bodyPreview = '[Binary content]';
        }
    }

    let headersHtml = '';
    Object.entries(headers).forEach(([key, value]) => {
        headersHtml += `<div style="padding: 6px 12px; border-bottom: 1px solid #eee; display: flex; gap: 10px;">
            <span style="font-weight: 600; color: #6200ea; min-width: 150px;">${escapeHtml(key)}:</span>
            <span style="color: #333; font-family: 'Fira Code', monospace; font-size: 0.9em;">${escapeHtml(String(value))}</span>
        </div>`;
    });

    return `
        <div style="padding: 20px; height: 100%; overflow-y: auto;">
            <div style="margin-bottom: 20px;">
                <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 15px;">
                    <h3 style="margin: 0; color: #333; font-size: 1.2em;">Response</h3>
                    <span class="${statusClass}" style="padding: 4px 12px; border-radius: 12px; font-weight: 600; font-size: 0.85em; display: inline-block;">
                        ${statusCode} ${responseData.reason || ''}
                    </span>
                </div>
            </div>
            <div style="margin-bottom: 20px;">
                <h4 style="margin: 0 0 12px 0; color: #6200ea; font-size: 1em; font-weight: 600; display: flex; align-items: center; gap: 8px;">
                    <span class="material-symbols-outlined" style="font-size: 1.1em;">list</span>
                    Headers
                    <span style="font-size: 0.8em; font-weight: 400; color: #888; margin-left: auto;">
                        ${Object.keys(headers).length} header${Object.keys(headers).length !== 1 ? 's' : ''}
                    </span>
                </h4>
                <div style="border: 1px solid #e0e0e0; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.05); background: white;">
                    ${headersHtml || '<p style="padding: 20px; color: #888; text-align: center; margin: 0;">No headers</p>'}
                </div>
            </div>
            <div>
                <h4 style="margin: 0 0 12px 0; color: #6200ea; font-size: 1em; font-weight: 600; display: flex; align-items: center; gap: 8px;">
                    <span class="material-symbols-outlined" style="font-size: 1.1em;">description</span>
                    Body
                    ${bodyBs64 ? `<span style="font-size: 0.8em; font-weight: 400; color: #888; margin-left: auto;">${bodyContent.length} bytes</span>` : ''}
                </h4>
                <pre style="background: #1e1e1e; color: #d4d4d4; padding: 15px; border-radius: 8px; overflow-x: auto; font-size: 0.85em; font-family: 'Fira Code', 'Consolas', monospace; margin: 0; max-height: 400px; overflow-y: auto;">${escapeHtml(bodyPreview || '[No body]')}</pre>
            </div>
        </div>
    `;
}

// Générer le HTML d'erreur
function displayRepeaterErrorHTML(errorMessage) {
    let suggestion = '';
    if (errorMessage && errorMessage.toLowerCase().includes('proxy')) {
        suggestion = '<p style="margin-top: 15px; padding: 10px; background: #fff3cd; border-radius: 4px; color: #856404; font-size: 0.9em;"><strong>Tip:</strong> Make sure the proxy is running on port 8080.</p>';
    } else if (errorMessage && errorMessage.toLowerCase().includes('timeout')) {
        suggestion = '<p style="margin-top: 15px; padding: 10px; background: #fff3cd; border-radius: 4px; color: #856404; font-size: 0.9em;"><strong>Tip:</strong> The request took too long. Check your network connection or increase the timeout.</p>';
    } else if (errorMessage && errorMessage.toLowerCase().includes('connection')) {
        suggestion = '<p style="margin-top: 15px; padding: 10px; background: #fff3cd; border-radius: 4px; color: #856404; font-size: 0.9em;"><strong>Tip:</strong> Unable to connect to server. Check the URL and your network connection.</p>';
    }

    return `
        <div style="padding: 40px; text-align: center; color: #f44336;">
            <span class="material-symbols-outlined" style="font-size: 48px; margin-bottom: 15px; display: block;">error</span>
            <h3 style="margin: 0 0 10px 0; color: #d32f2f;">Request Failed</h3>
            <p style="margin: 0 0 10px 0; color: #666; word-break: break-word; max-width: 600px; margin-left: auto; margin-right: auto;">${escapeHtml(errorMessage)}</p>
            ${suggestion}
        </div>
    `;
}

// Initialiser le Repeater
if (repeaterNewTabBtn) {
    repeaterNewTabBtn.addEventListener('click', () => {
        createRepeaterTab();
    });
}

// Initialiser au chargement
initRepeater();

// Initialiser l'état des boutons au chargement
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', updateDetailButtons);
} else {
    updateDetailButtons();
}

// === INTRUDER - Système d'onglets avec payloads ===

// Sauvegarder les onglets Intruder dans localStorage
function saveIntruderTabs() {
    try {
        const tabsToSave = intruderTabs.map(tab => ({
            id: tab.id,
            method: tab.method,
            url: tab.url,
            headers: tab.headers,
            body: tab.body,
            payloads: tab.payloads,
            marker: tab.marker || '§payload§',
            attackType: tab.attackType || 'url', // 'url', 'params', 'body', 'headers'
            results: [] // Ne pas sauvegarder les résultats pour économiser l'espace
        }));
        localStorage.setItem('kittyproxy_intruder_tabs', JSON.stringify(tabsToSave));
        localStorage.setItem('kittyproxy_intruder_active_tab', activeIntruderTabId);
    } catch (e) {
        console.warn('Failed to save intruder tabs:', e);
    }
}

// Charger les onglets Intruder depuis localStorage
function loadIntruderTabs() {
    try {
        const savedTabs = localStorage.getItem('kittyproxy_intruder_tabs');
        const savedActiveTab = localStorage.getItem('kittyproxy_intruder_active_tab');

        if (savedTabs) {
            const tabs = JSON.parse(savedTabs);
            intruderTabs = tabs.map(tab => ({
                ...tab,
                results: [],
                title: generateIntruderTabTitle(tab.method, tab.url)
            }));

            if (intruderTabs.length > 0) {
                if (savedActiveTab && intruderTabs.find(t => t.id === savedActiveTab)) {
                    activeIntruderTabId = savedActiveTab;
                } else {
                    activeIntruderTabId = intruderTabs[0].id;
                }
                renderIntruderTabs();
                renderIntruderContent();
                return true;
            }
        }
    } catch (e) {
        console.warn('Failed to load intruder tabs:', e);
    }
    return false;
}

// Générer un titre pour l'onglet Intruder
function generateIntruderTabTitle(method, url) {
    if (!url || url.trim() === '') {
        return `${method || 'GET'} (no URL)`;
    }

    try {
        const urlObj = new URL(url);
        let displayUrl = urlObj.pathname + (urlObj.search || '');
        if (displayUrl === '/') {
            displayUrl = urlObj.hostname;
        }

        if (displayUrl.length > 35) {
            displayUrl = displayUrl.substring(0, 32) + '...';
        }

        return displayUrl;
    } catch {
        const shortUrl = url.length > 35 ? url.substring(0, 32) + '...' : url;
        return shortUrl;
    }
}

// Créer le premier onglet par défaut
function initIntruder() {
    if (!loadIntruderTabs()) {
        if (intruderTabs.length === 0) {
            createIntruderTab();
        }
    }
}

// Créer un nouvel onglet Intruder
function createIntruderTab(tabData = null) {
    const tabId = `intruder-tab-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const method = tabData?.method || 'GET';
    const url = tabData?.url || '';
    const tab = {
        id: tabId,
        title: generateIntruderTabTitle(method, url),
        method: method,
        url: url,
        headers: tabData?.headers || '{"User-Agent": "KittyProxy/1.0"}',
        body: tabData?.body || '',
        payloads: tabData?.payloads || [],
        marker: tabData?.marker || '§payload§',
        attackType: tabData?.attackType || 'url', // 'url', 'params', 'body', 'headers'
        results: [],
        isRunning: false
    };

    intruderTabs.push(tab);
    activeIntruderTabId = tabId;
    renderIntruderTabs();
    renderIntruderContent();
    saveIntruderTabs();

    return tabId;
}

// Supprimer un onglet Intruder
function closeIntruderTab(tabId) {
    const index = intruderTabs.findIndex(t => t.id === tabId);
    if (index === -1) return;

    intruderTabs.splice(index, 1);

    if (activeIntruderTabId === tabId) {
        if (intruderTabs.length > 0) {
            activeIntruderTabId = intruderTabs[intruderTabs.length - 1].id;
        } else {
            activeIntruderTabId = null;
            createIntruderTab();
        }
    }

    renderIntruderTabs();
    renderIntruderContent();
    saveIntruderTabs();
}

// Activer un onglet Intruder
function activateIntruderTab(tabId) {
    activeIntruderTabId = tabId;
    renderIntruderTabs();
    renderIntruderContent();
    saveIntruderTabs();
}

// Rendre les onglets Intruder
function renderIntruderTabs() {
    if (!intruderTabsContainer) return;

    intruderTabsContainer.innerHTML = '';

    intruderTabs.forEach(tab => {
        const tabEl = document.createElement('div');
        tabEl.className = `intruder-tab ${activeIntruderTabId === tab.id ? 'active' : ''}`;
        tabEl.dataset.tabId = tab.id;

        tab.title = generateIntruderTabTitle(tab.method, tab.url);

        const titleEl = document.createElement('span');
        titleEl.className = 'intruder-tab-title';
        titleEl.innerHTML = `
            <span class="intruder-tab-url">${escapeHtml(tab.title)}</span>
            <span class="intruder-tab-method">${escapeHtml(tab.method || 'GET')}</span>
            ${tab.isRunning ? '<span class="intruder-tab-running" style="color: #4caf50;">●</span>' : ''}
        `;
        titleEl.addEventListener('click', () => activateIntruderTab(tab.id));

        const closeBtn = document.createElement('button');
        closeBtn.className = 'intruder-tab-close';
        closeBtn.innerHTML = '<span class="material-symbols-outlined" style="font-size: 16px;">close</span>';
        closeBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            closeIntruderTab(tab.id);
        });

        tabEl.appendChild(titleEl);
        tabEl.appendChild(closeBtn);
        intruderTabsContainer.appendChild(tabEl);
    });
}

// Rendre le contenu de l'onglet Intruder actif
function renderIntruderContent() {
    if (!intruderContentContainer) return;

    const activeTab = intruderTabs.find(t => t.id === activeIntruderTabId);
    if (!activeTab) {
        intruderContentContainer.innerHTML = '<div style="padding: 40px; text-align: center; color: #888;">No active tab</div>';
        return;
    }

    const payloadsText = activeTab.payloads.join('\n');
    const resultsHtml = renderIntruderResults(activeTab.results);

    intruderContentContainer.innerHTML = `
        <div class="intruder-tab-content" style="display: flex; height: 100%; overflow: hidden; position: relative;">
            <!-- Left Panel: Request Configuration & Payloads -->
            <div id="intruder-left-panel-${activeTab.id}" style="width: 50%; border-right: 1px solid var(--border-color); display: flex; flex-direction: column; overflow: hidden; min-height: 0; padding: 15px; gap: 15px; flex-shrink: 0;">
                <!-- Configuration Section -->
                <div style="background: white; border: 1px solid var(--border-color); border-radius: 8px; padding: 15px; flex-shrink: 0;">
                    <h3 style="margin: 0 0 15px 0; font-size: 1.1em; color: #333;">Request Configuration</h3>
                    <div style="display: flex; gap: 10px; margin-bottom: 15px; align-items: center;">
                        <select id="intruder-method-${activeTab.id}" class="input-field" style="width: 100px;">
                            <option value="GET" ${activeTab.method === 'GET' ? 'selected' : ''}>GET</option>
                            <option value="POST" ${activeTab.method === 'POST' ? 'selected' : ''}>POST</option>
                            <option value="PUT" ${activeTab.method === 'PUT' ? 'selected' : ''}>PUT</option>
                            <option value="DELETE" ${activeTab.method === 'DELETE' ? 'selected' : ''}>DELETE</option>
                            <option value="PATCH" ${activeTab.method === 'PATCH' ? 'selected' : ''}>PATCH</option>
                        </select>
                        <input type="text" id="intruder-url-${activeTab.id}" class="input-field" placeholder="https://example.com/api/endpoint"
                            style="flex: 1;" value="${escapeHtml(activeTab.url)}">
                    </div>
                    <!-- Attack Type removed -->
                    <div style="display: flex; gap: 10px; margin-bottom: 15px; align-items: center;">
                        <label style="min-width: 120px; font-weight: 600; font-size: 0.9em;">Marker:</label>
                        <input type="text" id="intruder-marker-${activeTab.id}" class="input-field" placeholder="§payload§"
                            style="flex: 1;" value="${escapeHtml(activeTab.marker)}">
                    </div>
                    <div style="margin-bottom: 10px; font-size: 0.85em; color: #666; padding-left: 130px;">
                        Use this marker in URL/params/body/headers
                    </div>
                    <div style="margin-bottom: 15px; overflow: hidden;">
                        <label style="display: block; font-weight: 600; margin-bottom: 8px; font-size: 0.9em;">Request Headers (JSON)</label>
                        <textarea id="intruder-headers-${activeTab.id}"
                            style="width: 100%; min-height: 80px; max-height: 150px; padding: 10px; font-family: 'Fira Code', monospace; border: 1px solid var(--border-color); border-radius: 4px; resize: vertical; font-size: 0.85em; box-sizing: border-box; overflow-y: auto;">${escapeHtml(activeTab.headers)}</textarea>
                    </div>
                    <div style="overflow: hidden;">
                        <label style="display: block; font-weight: 600; margin-bottom: 8px; font-size: 0.9em;">Request Body</label>
                        <textarea id="intruder-body-${activeTab.id}"
                            style="width: 100%; min-height: 80px; max-height: 150px; padding: 10px; font-family: 'Fira Code', monospace; border: 1px solid var(--border-color); border-radius: 4px; resize: vertical; font-size: 0.85em; box-sizing: border-box; overflow-y: auto;">${escapeHtml(activeTab.body)}</textarea>
                    </div>
                </div>

                <!-- Payloads Section -->
                <div style="background: white; border: 1px solid var(--border-color); border-radius: 8px; padding: 15px; flex: 1; display: flex; flex-direction: column; min-height: 0; overflow: hidden;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; flex-shrink: 0;">
                        <h3 style="margin: 0; font-size: 1.1em; color: #333;">Payloads</h3>
                        <div style="display: flex; gap: 10px;">
                            <button id="intruder-load-payloads-${activeTab.id}" class="btn btn-secondary" style="font-size: 0.85em; padding: 6px 12px;">
                                <span class="material-symbols-outlined" style="font-size: 14px;">upload_file</span>
                                Load
                            </button>
                            <button id="intruder-start-${activeTab.id}" class="btn btn-primary" ${activeTab.isRunning ? 'disabled' : ''} style="font-size: 0.85em; padding: 6px 12px;">
                                <span class="material-symbols-outlined" style="font-size: 14px;">play_arrow</span>
                                ${activeTab.isRunning ? 'Running...' : 'Start'}
                            </button>
                            <button id="intruder-stop-${activeTab.id}" class="btn btn-danger" ${!activeTab.isRunning ? 'disabled' : ''} style="display: ${activeTab.isRunning ? 'block' : 'none'}; font-size: 0.85em; padding: 6px 12px;">
                                <span class="material-symbols-outlined" style="font-size: 14px;">stop</span>
                                Stop
                            </button>
                        </div>
                    </div>
                    <textarea id="intruder-payloads-${activeTab.id}"
                        style="flex: 1; width: 100%; padding: 10px; font-family: 'Fira Code', monospace; border: 1px solid var(--border-color); border-radius: 4px; resize: none; min-height: 0; font-size: 0.85em; box-sizing: border-box; overflow-y: auto; overflow-x: hidden;"
                        placeholder="Enter payloads, one per line...">${escapeHtml(payloadsText)}</textarea>
                    <div style="margin-top: 10px; font-size: 0.85em; color: #666; flex-shrink: 0;">
                        ${activeTab.payloads.length} payload${activeTab.payloads.length !== 1 ? 's' : ''} loaded
                    </div>
                </div>
            </div>

            <!-- Resize Handle -->
            <div class="intruder-resize-handle" id="intruder-resize-handle-${activeTab.id}" 
                style="width: 4px; background: var(--border-color); cursor: col-resize; flex-shrink: 0; position: relative; z-index: 10;"
                onmousedown="startIntruderResize(event, '${activeTab.id}')">
            </div>

            <!-- Right Panel: Results -->
            <div id="intruder-right-panel-${activeTab.id}" style="flex: 1; min-width: 300px; display: flex; flex-direction: column; overflow: hidden; min-height: 0; padding: 15px;">
                <div style="background: white; border: 1px solid var(--border-color); border-radius: 8px; padding: 15px; flex: 1; display: flex; flex-direction: column; min-height: 0; overflow: hidden;">
                    <h3 style="margin: 0 0 15px 0; font-size: 1.1em; color: #333; flex-shrink: 0;">Results</h3>
                    <div id="intruder-results-${activeTab.id}" style="flex: 1; overflow-y: auto; overflow-x: auto; border: 1px solid var(--border-color); border-radius: 4px; background: #fafafa; min-height: 0;">
                        ${resultsHtml}
                    </div>
                </div>
            </div>
        </div>
    `;

    // Attacher les event listeners
    attachIntruderEventListeners(activeTab);
}

// Attacher les event listeners pour un onglet Intruder
function attachIntruderEventListeners(tab) {
    const methodEl = document.getElementById(`intruder-method-${tab.id}`);
    const urlEl = document.getElementById(`intruder-url-${tab.id}`);
    const headersEl = document.getElementById(`intruder-headers-${tab.id}`);
    const bodyEl = document.getElementById(`intruder-body-${tab.id}`);
    const payloadsEl = document.getElementById(`intruder-payloads-${tab.id}`);
    const markerEl = document.getElementById(`intruder-marker-${tab.id}`);
    const startBtn = document.getElementById(`intruder-start-${tab.id}`);
    const stopBtn = document.getElementById(`intruder-stop-${tab.id}`);
    const loadPayloadsBtn = document.getElementById(`intruder-load-payloads-${tab.id}`);

    if (methodEl) {
        methodEl.addEventListener('change', () => {
            tab.method = methodEl.value;
            updateIntruderTabTitle(tab.id);
            saveIntruderTabs();
        });
    }

    if (urlEl) {
        urlEl.addEventListener('input', () => {
            tab.url = urlEl.value;
            updateIntruderTabTitle(tab.id);
            saveIntruderTabs();
        });
    }

    if (headersEl) {
        headersEl.addEventListener('input', () => {
            tab.headers = headersEl.value;
            saveIntruderTabs();
        });
    }

    if (bodyEl) {
        bodyEl.addEventListener('input', () => {
            tab.body = bodyEl.value;
            saveIntruderTabs();
        });
    }

    if (payloadsEl) {
        payloadsEl.addEventListener('input', () => {
            const payloadsText = payloadsEl.value.trim();
            tab.payloads = payloadsText ? payloadsText.split('\n').filter(p => p.trim()) : [];
            saveIntruderTabs();
        });
    }

    if (markerEl) {
        markerEl.addEventListener('input', () => {
            tab.marker = markerEl.value;
            saveIntruderTabs();
        });
    }

    if (startBtn) {
        startBtn.addEventListener('click', () => startIntruderAttack(tab.id));
    }

    if (stopBtn) {
        stopBtn.addEventListener('click', () => stopIntruderAttack(tab.id));
    }

    if (loadPayloadsBtn) {
        loadPayloadsBtn.addEventListener('click', () => {
            const input = document.createElement('input');
            input.type = 'file';
            input.accept = '.txt';
            input.onchange = (e) => {
                const file = e.target.files[0];
                if (file) {
                    const reader = new FileReader();
                    reader.onload = (event) => {
                        const content = event.target.result;
                        tab.payloads = content.split('\n').filter(p => p.trim());
                        const payloadsEl = document.getElementById(`intruder-payloads-${tab.id}`);
                        if (payloadsEl) {
                            payloadsEl.value = tab.payloads.join('\n');
                        }
                        saveIntruderTabs();
                        renderIntruderContent();
                    };
                    reader.readAsText(file);
                }
            };
            input.click();
        });
    }
}

// Rendre les résultats de l'attaque
function renderIntruderResults(results) {
    if (!results || results.length === 0) {
        return '<div style="padding: 40px; text-align: center; color: #888;">No results yet. Start an attack to see results here.</div>';
    }

    let html = '<div style="display: table; width: 100%; min-width: 800px; border-collapse: collapse;">';
    // Header
    html += '<div style="display: table-row; background: #f5f5f5; position: sticky; top: 0; z-index: 5;">';
    html += '<div style="display: table-cell; padding: 10px; font-weight: 600; border-bottom: 2px solid var(--border-color); width: 50px; text-align: center;">#</div>';
    html += '<div style="display: table-cell; padding: 10px; font-weight: 600; border-bottom: 2px solid var(--border-color);">URL</div>';
    html += '<div style="display: table-cell; padding: 10px; font-weight: 600; border-bottom: 2px solid var(--border-color); width: 80px; text-align: center;">Status</div>';
    html += '<div style="display: table-cell; padding: 10px; font-weight: 600; border-bottom: 2px solid var(--border-color); width: 80px; text-align: center;">Time</div>';
    html += '<div style="display: table-cell; padding: 10px; font-weight: 600; border-bottom: 2px solid var(--border-color); width: 100px; text-align: center;">Length</div>';
    html += '<div style="display: table-cell; padding: 10px; font-weight: 600; border-bottom: 2px solid var(--border-color); width: 100px; text-align: center;">Actions</div>';
    html += '</div>';

    // Rows
    results.forEach((result, index) => {
        const statusClass = result.status >= 400 ? 'status-4xx' : result.status >= 300 ? 'status-3xx' : 'status-2xx';
        const rowBg = index % 2 === 0 ? '#ffffff' : '#fafafa';
        const url = result.url || '';
        html += `
            <div style="display: table-row; background: ${rowBg}; transition: background 0.2s;" onmouseover="this.style.background='#f0f0f0'" onmouseout="this.style.background='${rowBg}'">
                <div style="display: table-cell; padding: 8px 10px; border-bottom: 1px solid #eee; color: #666; font-size: 0.9em; text-align: center;">${index + 1}</div>
                <div style="display: table-cell; padding: 8px 10px; border-bottom: 1px solid #eee; font-family: 'Fira Code', monospace; font-size: 0.85em; word-break: break-all; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(url)}">${escapeHtml(url)}</div>
                <div style="display: table-cell; padding: 8px 10px; border-bottom: 1px solid #eee; text-align: center;">
                    <span class="${statusClass}" style="padding: 2px 8px; border-radius: 4px; font-weight: 600; font-size: 0.85em; display: inline-block;">${result.status}</span>
                </div>
                <div style="display: table-cell; padding: 8px 10px; border-bottom: 1px solid #eee; font-size: 0.85em; color: #666; text-align: center;">${result.time}ms</div>
                <div style="display: table-cell; padding: 8px 10px; border-bottom: 1px solid #eee; font-size: 0.85em; color: #666; text-align: center;">${result.length} bytes</div>
                <div style="display: table-cell; padding: 8px 10px; border-bottom: 1px solid #eee; text-align: center;">
                    <button onclick="viewIntruderResult(${index})" class="btn btn-secondary" style="padding: 4px 8px; font-size: 0.75em;">
                        <span class="material-symbols-outlined" style="font-size: 14px; vertical-align: middle;">visibility</span>
                    </button>
                </div>
            </div>
        `;
    });

    html += '</div>';
    return html;
}

// Gérer le redimensionnement des panneaux Intruder
let intruderResizeData = null;

window.startIntruderResize = function (e, tabId) {
    e.preventDefault();
    const leftPanel = document.getElementById(`intruder-left-panel-${tabId}`);
    const rightPanel = document.getElementById(`intruder-right-panel-${tabId}`);

    if (!leftPanel || !rightPanel) return;

    const startX = e.clientX;
    const startWidth = leftPanel.offsetWidth;
    const containerWidth = leftPanel.parentElement.offsetWidth;

    intruderResizeData = {
        tabId,
        startX,
        startWidth,
        containerWidth
    };

    document.addEventListener('mousemove', handleIntruderResize);
    document.addEventListener('mouseup', stopIntruderResize);
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
};

function handleIntruderResize(e) {
    if (!intruderResizeData) return;

    const { tabId, startX, startWidth, containerWidth } = intruderResizeData;
    const leftPanel = document.getElementById(`intruder-left-panel-${tabId}`);
    const rightPanel = document.getElementById(`intruder-right-panel-${tabId}`);

    if (!leftPanel || !rightPanel) return;

    const diff = e.clientX - startX;
    const newWidth = Math.max(300, Math.min(containerWidth - 300, startWidth + diff));

    leftPanel.style.width = `${newWidth}px`;
    leftPanel.style.flexShrink = '0';
    rightPanel.style.flex = '1';
}

function stopIntruderResize() {
    if (intruderResizeData) {
        document.removeEventListener('mousemove', handleIntruderResize);
        document.removeEventListener('mouseup', stopIntruderResize);
        document.body.style.cursor = '';
        document.body.style.userSelect = '';
        intruderResizeData = null;
    }
}

// Démarrer une attaque Intruder
async function startIntruderAttack(tabId) {
    const tab = intruderTabs.find(t => t.id === tabId);
    if (!tab) return;

    if (tab.payloads.length === 0) {
        alert('Please add at least one payload');
        return;
    }

    if (!tab.marker || tab.marker.trim() === '') {
        alert('Please set a marker (e.g., §payload§)');
        return;
    }

    tab.isRunning = true;
    tab.results = [];
    renderIntruderTabs();
    renderIntruderContent();

    const startBtn = document.getElementById(`intruder-start-${tabId}`);
    const stopBtn = document.getElementById(`intruder-stop-${tabId}`);

    // Fonction pour traiter une requête de manière asynchrone
    const processRequest = async (index) => {
        if (!tab.isRunning) return;

        const payload = tab.payloads[index].trim();
        if (!payload) return;

        try {
            const result = await sendIntruderRequest(tab, payload, index);
            tab.results.push(result);
        } catch (error) {
            tab.results.push({
                payload: payload,
                url: tab.url, // Utiliser l'URL de base si l'erreur se produit avant l'injection
                status: 0,
                time: 0,
                length: 0,
                error: error.message,
                response: null
            });
        }

        // Mettre à jour l'interface de manière asynchrone pour ne pas bloquer
        // Utiliser setTimeout(0) pour forcer le navigateur à traiter les événements en attente
        await new Promise(resolve => {
            setTimeout(() => {
                requestAnimationFrame(() => {
                    renderIntruderContent();
                    resolve();
                });
            }, 0);
        });
    };

    // Traiter les requêtes une par une avec des pauses pour permettre au navigateur de traiter les événements
    for (let i = 0; i < tab.payloads.length; i++) {
        if (!tab.isRunning) break;

        await processRequest(i);

        // Délai entre les requêtes pour éviter de surcharger
        // Utiliser setTimeout pour permettre au navigateur de traiter les événements utilisateur
        await new Promise(resolve => setTimeout(resolve, 100));

        // Forcer le navigateur à traiter les événements en attente (scroll, resize, etc.)
        await new Promise(resolve => setTimeout(resolve, 0));
    }

    tab.isRunning = false;
    renderIntruderTabs();
    renderIntruderContent();
    saveIntruderTabs();
}

// Arrêter une attaque Intruder
function stopIntruderAttack(tabId) {
    const tab = intruderTabs.find(t => t.id === tabId);
    if (!tab) return;

    tab.isRunning = false;
    renderIntruderTabs();
    renderIntruderContent();
}

// Envoyer une requête Intruder avec un payload
async function sendIntruderRequest(tab, payload, index) {
    const startTime = Date.now();

    // Préparer la requête avec le payload injecté
    let url = tab.url;
    let headersStr = tab.headers;
    let body = tab.body;

    // Injecter le payload selon le type d'attaque
    if (tab.attackType === 'url') {
        // Vérifier que l'URL contient le marqueur avant de remplacer
        if (url.includes(tab.marker)) {
            url = url.replace(new RegExp(escapeRegex(tab.marker), 'g'), payload);
        } else {
            // Si le marqueur n'est pas dans l'URL, l'ajouter à la fin du path
            try {
                const urlObj = new URL(url);
                urlObj.pathname = urlObj.pathname + (urlObj.pathname.endsWith('/') ? '' : '/') + payload;
                url = urlObj.toString();
            } catch (e) {
                // Si l'URL n'est pas valide, simplement concaténer
                url = url + (url.endsWith('/') ? '' : '/') + payload;
            }
        }
    } else if (tab.attackType === 'params') {
        // Injecter dans les paramètres de l'URL
        try {
            const urlObj = new URL(url);
            const params = new URLSearchParams(urlObj.search);
            let foundMarker = false;
            for (const [key, value] of params.entries()) {
                if (value.includes(tab.marker)) {
                    params.set(key, value.replace(new RegExp(escapeRegex(tab.marker), 'g'), payload));
                    foundMarker = true;
                }
            }
            // Si aucun paramètre ne contient le marqueur, ajouter un nouveau paramètre
            if (!foundMarker) {
                params.append('payload', payload);
            }
            urlObj.search = params.toString();
            url = urlObj.toString();
        } catch (e) {
            // Si l'URL n'est pas valide, ajouter le payload comme paramètre
            url = url + (url.includes('?') ? '&' : '?') + 'payload=' + encodeURIComponent(payload);
        }
    } else if (tab.attackType === 'body') {
        body = body.replace(new RegExp(escapeRegex(tab.marker), 'g'), payload);
    } else if (tab.attackType === 'headers') {
        // Injecter dans les headers
        try {
            const headers = JSON.parse(headersStr);
            for (const key in headers) {
                if (String(headers[key]).includes(tab.marker)) {
                    headers[key] = String(headers[key]).replace(new RegExp(escapeRegex(tab.marker), 'g'), payload);
                }
            }
            headersStr = JSON.stringify(headers);
        } catch (e) {
            // Si les headers ne sont pas du JSON valide, essayer de remplacer directement
            headersStr = headersStr.replace(new RegExp(escapeRegex(tab.marker), 'g'), payload);
        }
    }

    // Parser les headers
    let headers = {};
    try {
        headers = headersStr.trim() ? JSON.parse(headersStr) : {};
    } catch (e) {
        headers = {};
    }

    // Ajouter un header spécial pour marquer les requêtes de l'Intruder
    // Cela permettra de les filtrer pour qu'elles n'apparaissent pas dans les autres vues
    headers['X-KittyProxy-Source'] = 'intruder';

    const bodyBs64 = body ? btoa(body) : "";

    const requestPayload = {
        method: tab.method,
        url: url,
        headers: headers,
        body_bs64: bodyBs64
    };

    try {
        const res = await fetch(`${API_BASE}/send_custom`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(requestPayload)
        });

        const endTime = Date.now();
        const time = endTime - startTime;

        let responseData;
        try {
            responseData = await res.json();
        } catch (e) {
            const text = await res.text().catch(() => '');
            return {
                payload: payload,
                url: url,
                status: res.status,
                time: time,
                length: text.length,
                error: `Invalid response: ${text.substring(0, 100)}`,
                response: null
            };
        }

        if (responseData && responseData.status === 'ok') {
            const contentLength = responseData.content_bs64 ? atob(responseData.content_bs64 || '').length : 0;
            return {
                payload: payload,
                url: url,
                status: responseData.status_code || res.status,
                time: time,
                length: contentLength,
                error: null,
                response: responseData
            };
        } else {
            return {
                payload: payload,
                url: url,
                status: res.status,
                time: time,
                length: 0,
                error: responseData?.detail || responseData?.error || 'Request failed',
                response: null
            };
        }
    } catch (err) {
        const endTime = Date.now();
        const time = endTime - startTime;
        return {
            payload: payload,
            url: url,
            status: 0,
            time: time,
            length: 0,
            error: `Connection failed: ${err.message}`,
            response: null
        };
    }
}

// Échapper les caractères spéciaux pour regex
function escapeRegex(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Afficher les détails d'un résultat Intruder (fonction globale)
window.viewIntruderResult = function (resultIndex) {
    const activeTab = intruderTabs.find(t => t.id === activeIntruderTabId);
    if (!activeTab || !activeTab.results || !activeTab.results[resultIndex]) {
        alert('Result not found');
        return;
    }

    const result = activeTab.results[resultIndex];
    let responseHtml = '';

    if (result.response) {
        responseHtml = displayRepeaterResponseHTML(result.response);
    } else if (result.error) {
        responseHtml = displayRepeaterErrorHTML(result.error);
    } else {
        responseHtml = '<div style="padding: 40px; text-align: center; color: #888;">No response data available</div>';
    }

    // Créer une modale pour afficher les détails
    const modal = document.createElement('div');
    modal.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 10000; display: flex; align-items: center; justify-content: center;';
    modal.innerHTML = `
        <div style="background: white; border-radius: 12px; width: 90%; max-width: 1200px; max-height: 90vh; display: flex; flex-direction: column; box-shadow: 0 8px 32px rgba(0,0,0,0.2);">
            <div style="padding: 20px; border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between; align-items: center;">
                <h2 style="margin: 0; font-size: 1.2em; color: #333;">Result #${resultIndex + 1} - Payload: ${escapeHtml(result.payload)}</h2>
                <button onclick="this.closest('[style*=\\'position: fixed\\']').remove()" style="background: #f5f5f5; border: none; width: 32px; height: 32px; border-radius: 6px; cursor: pointer; display: flex; align-items: center; justify-content: center;">
                    <span class="material-symbols-outlined" style="font-size: 18px;">close</span>
                </button>
            </div>
            <div style="flex: 1; overflow-y: auto; padding: 20px;">
                ${responseHtml}
            </div>
        </div>
    `;
    document.body.appendChild(modal);
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.remove();
        }
    });
}

// Mettre à jour le titre de l'onglet Intruder
function updateIntruderTabTitle(tabId) {
    const tab = intruderTabs.find(t => t.id === tabId);
    if (!tab) return;

    tab.title = generateIntruderTabTitle(tab.method, tab.url);
    renderIntruderTabs();
}

// Initialiser l'Intruder
if (intruderNewTabBtn) {
    intruderNewTabBtn.addEventListener('click', () => {
        createIntruderTab();
    });
}

// Initialiser au chargement
if (intruderTabsContainer && intruderContentContainer) {
    initIntruder();
}

// Send to Repeater
if (sendToRepeaterBtn) {
    sendToRepeaterBtn.addEventListener('click', async () => {
        if (!currentFlowId) return;

        try {
            // Récupérer les détails complets de la requête
            const res = await fetch(`${API_BASE}/flows/${currentFlowId}`);
            if (!res.ok) {
                alert('Failed to load flow details');
                return;
            }

            const flow = await res.json();

            if (!flow.request) {
                alert('Request details not available');
                return;
            }

            // Préparer les données pour le nouvel onglet
            const headers = flow.request.headers || {};
            let bodyContent = '';
            if (flow.request.content_bs64) {
                try {
                    bodyContent = atob(flow.request.content_bs64);
                } catch (e) {
                    bodyContent = '';
                }
            }

            // Créer un nouvel onglet avec les données de la requête
            // Le titre sera généré automatiquement par generateRepeaterTabTitle
            createRepeaterTab({
                method: flow.method || 'GET',
                url: flow.url || '',
                headers: JSON.stringify(headers, null, 2),
                body: bodyContent
            });

            // Basculer vers l'onglet Repeater
            const replayNavItem = document.querySelector('[data-view="replay"]');
            if (replayNavItem) {
                replayNavItem.click();
            }
        } catch (err) {
            console.error("Send to repeater error", err);
            alert("Failed to load request into repeater");
        }
    });
}

// Send to Intruder
if (sendToIntruderBtn) {
    sendToIntruderBtn.addEventListener('click', async () => {
        if (!currentFlowId) return;

        try {
            // Récupérer les détails complets de la requête
            const res = await fetch(`${API_BASE}/flows/${currentFlowId}`);
            if (!res.ok) {
                alert('Failed to load flow details');
                return;
            }

            const flow = await res.json();

            if (!flow.request) {
                alert('Request details not available');
                return;
            }

            // Préparer les données pour le nouvel onglet
            const headers = flow.request.headers || {};
            let bodyContent = '';
            if (flow.request.content_bs64) {
                try {
                    bodyContent = atob(flow.request.content_bs64);
                } catch (e) {
                    bodyContent = '';
                }
            }

            // Créer un nouvel onglet Intruder avec les données de la requête
            createIntruderTab({
                method: flow.method || 'GET',
                url: flow.url || '',
                headers: JSON.stringify(headers, null, 2),
                body: bodyContent,
                payloads: [],
                marker: '§payload§',
                attackType: 'url'
            });

            // Basculer vers l'onglet Intruder
            const intruderNavItem = document.querySelector('[data-view="intruder"]');
            if (intruderNavItem) {
                intruderNavItem.click();
            }
        } catch (err) {
            console.error("Send to intruder error", err);
            alert("Failed to load request into intruder");
        }
    });
}

tabs.forEach(tab => {
    tab.addEventListener('click', () => {
        tabs.forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        currentTab = tab.dataset.tab;
        renderDetail();
    });
});

// Lightweight hash function for flow changes detection
function computeFlowsHash(flows) {
    if (!flows || flows.length === 0) return '';
    // Create a lightweight hash from flow IDs, status codes, and timestamps
    // Only use first 50 flows for hash to keep it fast
    const sampleSize = Math.min(50, flows.length);
    const hashParts = flows.slice(0, sampleSize).map(flow => {
        const id = flow.id || '';
        const status = flow.status_code || '';
        const timestamp = flow.timestamp_start || '';
        return `${id}:${status}:${timestamp}`;
    });
    // Add total count and latest flow ID
    const latestFlow = flows[0];
    const latestId = latestFlow ? (latestFlow.id || '') : '';
    return `${flows.length}:${latestId}:${hashParts.join('|')}`;
}

async function fetchFlows() {
    try {
        // Récupérer les flows avec pagination côté serveur (réduit de 10000 à 300)
        const res = await fetch(`${API_BASE}/flows?page=1&size=${FLOW_POLL_SIZE}`);

        if (!res.ok) {
            throw new Error(`HTTP ${res.status}: ${res.statusText}`);
        }

        const data = await res.json();

        // L'API retourne maintenant une structure paginée
        const allFlows = data.items || data; // Support ancien format si nécessaire

        // Filtrer les flows provenant de l'Intruder pour qu'ils n'apparaissent pas dans Analyze/API
        // Les flows de l'Intruder ont le header X-KittyProxy-Source: intruder
        const flows = allFlows.filter(flow => {
            if (flow.request && flow.request.headers) {
                // Vérifier les headers (peuvent être un objet, dict, ou Headers)
                let sourceHeader = null;
                const headers = flow.request.headers;

                // Essayer différentes façons d'accéder aux headers
                if (typeof headers === 'object') {
                    if (headers.get && typeof headers.get === 'function') {
                        // Headers object avec méthode get()
                        sourceHeader = headers.get('X-KittyProxy-Source') || headers.get('x-kittyproxy-source');
                    } else {
                        // Objet simple
                        sourceHeader = headers['X-KittyProxy-Source'] ||
                            headers['x-kittyproxy-source'] ||
                            headers.get?.('X-KittyProxy-Source') ||
                            headers.get?.('x-kittyproxy-source');
                    }
                }

                // Exclure les flows provenant de l'Intruder
                if (sourceHeader === 'intruder') {
                    return false;
                }
            }
            return true; // Garder les flows sans header source ou avec un autre source
        });

        // Compute lightweight hash to detect changes
        const newHash = computeFlowsHash(flows);

        // Only update if hash changed (much faster than JSON.stringify comparison)
        if (newHash !== flowsHash) {
            flowsHash = newHash;
            flowsData = flows;
            renderFlowList();
            loadWebSocketConnections();

            // Update domains list if visualization view is visible
            const visualizeView = document.getElementById('visualize-view');
            if (visualizeView && visualizeView.style.display !== 'none') {
                extractAndDisplayDomains();
            }

            // Synchroniser avec la collaboration si une session est active
            if (currentSessionId && collaborationWebSocket) {
                syncFlowsToCollaboration();
            }
        }
    } catch (err) {
        console.warn("Failed to fetch flows from API:", err.message);
        // Ne pas bloquer l'application si l'API n'est pas accessible
        // Les flows peuvent toujours être ajoutés via WebSocket dans la collaboration
    }
}

function renderFlowList() {
    if (!flowListEl) return;
    flowListEl.innerHTML = '';

    // Filter flows
    let filteredFlows = flowsData.filter(flow => {
        if (!searchTerm) return true;
        const url = flow.url.toLowerCase();
        const method = flow.method.toLowerCase();
        const status = (flow.status_code || '').toString();
        return url.includes(searchTerm) || method.includes(searchTerm) || status.includes(searchTerm);
    });

    // Sort flows
    if (sortColumn) {
        filteredFlows = [...filteredFlows].sort((a, b) => {
            let aVal, bVal;

            switch (sortColumn) {
                case 'method':
                    aVal = (a.method || '').toUpperCase();
                    bVal = (b.method || '').toUpperCase();
                    break;
                case 'status':
                    aVal = a.status_code !== null && a.status_code !== undefined ? a.status_code : -1;
                    bVal = b.status_code !== null && b.status_code !== undefined ? b.status_code : -1;
                    break;
                case 'size':
                    aVal = a.response?.content_length !== null && a.response?.content_length !== undefined
                        ? a.response.content_length
                        : (a.response_size !== null && a.response_size !== undefined ? a.response_size : -1);
                    bVal = b.response?.content_length !== null && b.response?.content_length !== undefined
                        ? b.response.content_length
                        : (b.response_size !== null && b.response_size !== undefined ? b.response_size : -1);
                    break;
                case 'time':
                    aVal = a.duration_ms !== null && a.duration_ms !== undefined ? a.duration_ms :
                        (a.duration !== null && a.duration !== undefined ? a.duration * 1000 : -1);
                    bVal = b.duration_ms !== null && b.duration_ms !== undefined ? b.duration_ms :
                        (b.duration !== null && b.duration !== undefined ? b.duration * 1000 : -1);
                    break;
                default:
                    return 0;
            }

            if (aVal < bVal) return sortOrder === 'asc' ? -1 : 1;
            if (aVal > bVal) return sortOrder === 'asc' ? 1 : -1;
            return 0;
        });
    }

    // Calculate statistics
    updateStatistics(filteredFlows);

    // Calculate pagination
    totalPages = Math.max(1, Math.ceil(filteredFlows.length / PAGE_SIZE));
    if (currentPage > totalPages) currentPage = totalPages;

    const startIdx = (currentPage - 1) * PAGE_SIZE;
    const endIdx = Math.min(startIdx + PAGE_SIZE, filteredFlows.length);
    const paginatedFlows = filteredFlows.slice(startIdx, endIdx);

    // Update pagination UI
    updatePaginationUI(filteredFlows.length, startIdx, endIdx);

    // Render flows
    paginatedFlows.forEach(flow => {
        // Status code avec classe appropriée
        const statusCode = flow.status_code;
        let statusClass = '';
        let statusText = '-';
        if (statusCode !== null && statusCode !== undefined) {
            statusText = statusCode.toString();
            if (statusCode >= 500) {
                statusClass = 'status-5xx';
            } else if (statusCode >= 400) {
                statusClass = 'status-4xx';
            } else if (statusCode >= 300) {
                statusClass = 'status-3xx';
            } else if (statusCode >= 200) {
                statusClass = 'status-2xx';
            }
        }

        // Durée en millisecondes
        let timeText = '-';
        if (flow.duration_ms !== null && flow.duration_ms !== undefined) {
            timeText = `${Math.round(flow.duration_ms)}ms`;
        } else if (flow.duration !== null && flow.duration !== undefined) {
            timeText = `${Math.round(flow.duration * 1000)}ms`;
        }

        // Technologies détectées
        const techs = flow.technologies || {};
        const allTechs = [
            ...(techs.frameworks || []),
            ...(techs.cms || []),
            ...(techs.servers || []),
            ...(techs.languages || []),
        ];
        const techBadges = allTechs.slice(0, 3).map(tech =>
            `<span style="background: #e3f2fd; color: #1976d2; padding: 2px 6px; border-radius: 3px; font-size: 0.7em; margin-left: 4px;">${tech}</span>`
        ).join('');

        const flowItem = document.createElement('div');
        flowItem.className = `flow-item ${currentFlowId === flow.id ? 'active' : ''}`;
        flowItem.dataset.flowId = flow.id;

        // Méthode HTTP - style simple et professionnel
        const methodEl = document.createElement('div');
        methodEl.className = `flow-method method-${flow.method?.toUpperCase() || 'UNKNOWN'}`;
        methodEl.textContent = flow.method || '-';

        // Statut HTTP - style simple et professionnel
        const statusEl = document.createElement('div');
        statusEl.className = `flow-status status-${statusCode !== null && statusCode !== undefined ? Math.floor(statusCode / 100) + 'xx' : 'unknown'}`;
        statusEl.textContent = statusText;

        const urlEl = document.createElement('div');
        urlEl.className = 'flow-url';
        urlEl.style.overflow = 'hidden';
        urlEl.style.textOverflow = 'ellipsis';
        urlEl.style.whiteSpace = 'nowrap';
        urlEl.style.display = 'flex';
        urlEl.style.alignItems = 'center';
        urlEl.style.gap = '6px';

        // Add source indicators (API Tester, PCAP import)
        let sourceIndicator = '';
        if (flow.source === 'api_tester')
            sourceIndicator = '<span class="material-symbols-outlined" style="font-size: 16px; color: #6200ea; flex-shrink: 0;" title="Sent from API Tester">api</span>';
        else if (flow.source === 'pcap')
            sourceIndicator = '<span class="material-symbols-outlined" style="font-size: 16px; color: #ff9800; flex-shrink: 0;" title="Imported from PCAP">upload_file</span>';

        urlEl.innerHTML = `${sourceIndicator}<span style="flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${flow.url || '-'}</span>${techBadges}`;
        const sourceNote = flow.source === 'api_tester' ? '\nSource: API Tester' : (flow.source === 'pcap' ? '\nSource: PCAP import' : '');
        urlEl.title = flow.url + (allTechs.length > 0 ? `\nTechnologies: ${allTechs.join(', ')}` : '') + sourceNote;

        // Size - calculate from response_size (always available) or response.content_length (detail view)
        let sizeText = '-';
        let responseSize = null;
        // Prefer response_size (always available in list view)
        if (flow.response_size !== null && flow.response_size !== undefined && flow.response_size >= 0) {
            responseSize = flow.response_size;
        } else if (flow.response && flow.response.content_length !== null && flow.response.content_length !== undefined) {
            responseSize = flow.response.content_length;
        }
        if (responseSize !== null && responseSize !== undefined && responseSize >= 0) {
            sizeText = formatBytes(responseSize);
        }

        const sizeEl = document.createElement('div');
        sizeEl.className = 'flow-size';
        sizeEl.textContent = sizeText;
        sizeEl.style.fontFamily = 'monospace';
        sizeEl.style.fontSize = '0.9em';
        sizeEl.style.color = '#666';
        sizeEl.style.textAlign = 'right';

        const timeEl = document.createElement('div');
        timeEl.className = 'flow-time';
        timeEl.textContent = timeText;
        timeEl.style.fontFamily = 'monospace';
        timeEl.style.fontSize = '0.9em';

        flowItem.appendChild(methodEl);
        flowItem.appendChild(statusEl);
        flowItem.appendChild(urlEl);
        flowItem.appendChild(sizeEl);
        flowItem.appendChild(timeEl);

        // Ajouter une colonne "Share" pour la collaboration
        const shareCol = document.createElement('div');
        shareCol.className = 'flow-share';

        // Vérifier si connecté à un espace de collaboration
        const isConnected = currentSessionId && collaborationWebSocket && collaborationWebSocket.readyState === WebSocket.OPEN;

        if (isConnected) {
            const isShared = sharedFlows.has(flow.id);
            shareCol.innerHTML = isShared
                ? '<span class="material-symbols-outlined" style="font-size: 18px; color: #4caf50;">check_circle</span>'
                : '<span class="material-symbols-outlined" style="font-size: 18px; color: #666;">group</span>';
            shareCol.title = isShared ? 'Click to unshare' : 'Share in collaboration';
            shareCol.style.cursor = 'pointer';
            shareCol.onclick = (e) => {
                e.stopPropagation();
                toggleShareFlow(flow);
            };
            shareCol.style.opacity = '1';
        } else {
            shareCol.innerHTML = '<span class="material-symbols-outlined" style="font-size: 18px; color: #ccc;">group</span>';
            shareCol.title = 'Connect to collaboration first...';
            shareCol.style.opacity = '0.5';
            shareCol.style.cursor = 'not-allowed';
            shareCol.onclick = (e) => {
                e.stopPropagation();
            };
        }

        flowItem.appendChild(shareCol);

        // Add context menu (right-click) for "Run module on this URL"
        flowItem.addEventListener('contextmenu', (e) => {
            e.preventDefault();
            e.stopPropagation();
            showFlowContextMenu(e, flow);
        });

        flowItem.addEventListener('click', () => {
            currentFlowId = flow.id;
            renderFlowList();
            updateDetailButtons();
            renderDetail();
        });

        flowListEl.appendChild(flowItem);
    });
}

function updateStatistics(flows) {
    if (!statTotalEl) return;

    const total = flows.length;
    statTotalEl.textContent = total;

    // Average response time
    const withTime = flows.filter(f => f.duration_ms);
    const avgTime = withTime.length > 0
        ? Math.round(withTime.reduce((sum, f) => sum + f.duration_ms, 0) / withTime.length)
        : 0;
    statAvgTimeEl.textContent = `${avgTime}ms`;

    // Success rate (2xx and 3xx)
    const successCount = flows.filter(f => f.status_code && f.status_code < 400).length;
    const successRate = total > 0 ? Math.round((successCount / total) * 100) : 0;
    statSuccessRateEl.textContent = `${successRate}%`;

    // Errors (4xx and 5xx)
    const errorCount = flows.filter(f => f.status_code && f.status_code >= 400).length;
    statErrorsEl.textContent = errorCount;
}

function updatePaginationUI(total, start, end) {
    if (!paginationInfoEl) return;

    paginationInfoEl.textContent = total > 0 ? `Showing ${start + 1}-${end} of ${total}` : 'Showing 0-0 of 0';

    if (pageCurrentEl) pageCurrentEl.textContent = currentPage;

    if (pageFirstBtn) pageFirstBtn.disabled = currentPage === 1;
    if (pagePrevBtn) pagePrevBtn.disabled = currentPage === 1;
    if (pageNextBtn) pageNextBtn.disabled = currentPage === totalPages;
    if (pageLastBtn) pageLastBtn.disabled = currentPage === totalPages;
}

// Mettre à jour l'état des boutons selon la sélection
function updateDetailButtons() {
    const replayBtn = document.getElementById('replay-btn');
    const sendToRepeaterBtn = document.getElementById('send-to-repeater-btn');
    const sendToIntruderBtn = document.getElementById('send-to-intruder-btn');

    const hasSelection = currentFlowId !== null;

    if (replayBtn) {
        replayBtn.disabled = !hasSelection;
        replayBtn.style.opacity = hasSelection ? '1' : '0.5';
        replayBtn.style.cursor = hasSelection ? 'pointer' : 'not-allowed';
    }

    if (sendToRepeaterBtn) {
        sendToRepeaterBtn.disabled = !hasSelection;
        sendToRepeaterBtn.style.opacity = hasSelection ? '1' : '0.5';
        sendToRepeaterBtn.style.cursor = hasSelection ? 'pointer' : 'not-allowed';
    }

    if (sendToIntruderBtn) {
        sendToIntruderBtn.disabled = !hasSelection;
        sendToIntruderBtn.style.opacity = hasSelection ? '1' : '0.5';
        sendToIntruderBtn.style.cursor = hasSelection ? 'pointer' : 'not-allowed';
    }
}

async function renderDetail() {
    // Mettre à jour les boutons même si aucun flow n'est sélectionné
    updateDetailButtons();

    if (!currentFlowId || !detailContentEl) {
        // Afficher un message si aucun flow n'est sélectionné
        if (detailContentEl) {
            detailContentEl.innerHTML = '<div style="padding: 40px; text-align: center; color: #888;">Select a flow to view details</div>';
        }
        return;
    }

    // Show loading indicator
    detailContentEl.innerHTML = '<div style="padding: 20px; color: #666; text-align: center;">Loading flow details...</div>';

    // First try to find in cached flowsData
    let flow = flowsData.find(f => f.id === currentFlowId);

    // If flow doesn't have request/response details, fetch them
    if (!flow || !flow.request) {
        try {
            const res = await fetch(`${API_BASE}/flows/${currentFlowId}`);
            if (res.ok) {
                flow = await res.json();
                // Update the flow in flowsData cache
                const index = flowsData.findIndex(f => f.id === currentFlowId);
                if (index !== -1) {
                    flowsData[index] = flow;
                }
            } else {
                const errorData = await res.json().catch(() => ({}));
                detailContentEl.innerHTML = `<div style="padding: 20px; color: #f44336; text-align: center;">Failed to load flow details: ${errorData.detail || res.statusText}</div>`;
                return;
            }
        } catch (err) {
            console.error("Failed to fetch flow details", err);
            detailContentEl.innerHTML = `<div style="padding: 20px; color: #f44336; text-align: center;">Error loading flow details: ${err.message}</div>`;
            return;
        }
    }

    if (!flow) {
        detailContentEl.innerHTML = '<div style="padding: 20px; color: #666; text-align: center;">Flow not found</div>';
        return;
    }

    // Render the appropriate tab
    if (currentTab === 'request') {
        renderRequestTab(flow);
    } else if (currentTab === 'response') {
        renderResponseTab(flow);
    } else if (currentTab === 'tech') {
        renderTechTab(flow);
    } else if (currentTab === 'endpoints') {
        await renderEndpointsTab(flow);
    } else if (currentTab === 'hexdump') {
        renderHexdumpTab(flow);
    }
}

function renderRequestTab(flow) {
    if (!flow || !flow.request) {
        detailContentEl.innerHTML = '<div style="padding: 20px; color: #666; text-align: center;">Request details not available</div>';
        return;
    }

    // Helper function to get header icon/color based on header name
    const getHeaderStyle = (headerName) => {
        const name = headerName.toLowerCase();
        if (name.includes('authorization') || name.includes('cookie') || name.includes('token')) {
            return { icon: 'lock', color: '#333', bg: '#f5f5f5' };
        } else if (name.includes('content-type')) {
            return { icon: 'description', color: '#333', bg: '#f5f5f5' };
        } else if (name.includes('user-agent')) {
            return { icon: 'language', color: '#333', bg: '#f5f5f5' };
        } else if (name.includes('accept')) {
            return { icon: 'check_circle', color: '#333', bg: '#f5f5f5' };
        } else if (name.includes('referer') || name.includes('referrer')) {
            return { icon: 'link', color: '#333', bg: '#f5f5f5' };
        } else if (name.includes('host')) {
            return { icon: 'home', color: '#333', bg: '#f5f5f5' };
        }
        return { icon: 'list', color: '#333', bg: '#f5f5f5' };
    };

    const headersHtml = Object.entries(flow.request.headers || {}).map(([k, v], index) => {
        const style = getHeaderStyle(k);
        const isEven = index % 2 === 0;
        return `
            <div class="header-row" style="
                display: grid; 
                grid-template-columns: 30px 220px 1fr; 
                padding: 12px 15px; 
                border-bottom: 1px solid #e8e8e8;
                background: ${isEven ? '#ffffff' : '#fafafa'};
                transition: all 0.2s ease;
                align-items: center;
            " onmouseover="this.style.background='#f0f0f0'; this.style.paddingLeft='18px';" 
               onmouseout="this.style.background='${isEven ? '#ffffff' : '#fafafa'}'; this.style.paddingLeft='15px';">
                <span class="material-symbols-outlined" style="font-size: 18px; color: #666; text-align: center;">${style.icon}</span>
                <strong style="
                    color: #333; 
                    font-weight: 600; 
                    font-size: 0.9em;
                    text-transform: capitalize;
                    letter-spacing: 0.3px;
                ">${escapeHtml(k)}:</strong>
                <span style="
                    color: #333; 
                    font-family: 'Fira Code', monospace;
                    font-size: 0.9em;
                    word-break: break-all;
                    padding-left: 10px;
                ">${escapeHtml(String(v))}</span>
            </div>
        `;
    }).join('');

    // Récupérer le body depuis content_bs64 ou content directement
    let bodyContent = '';
    if (flow.request.content_bs64) {
        try {
            bodyContent = atob(flow.request.content_bs64);
        } catch (e) {
            console.warn('Error decoding base64 content:', e);
        }
    } else if (flow.request.content) {
        bodyContent = typeof flow.request.content === 'string' ? flow.request.content : String(flow.request.content);
    }

    let bodyHtml = '';
    if (bodyContent && bodyContent.trim()) {
        try {
            // Try to detect content type and format accordingly
            const contentType = flow.request.headers?.['content-type'] || '';
            if (contentType.includes('json') || bodyContent.trim().startsWith('{') || bodyContent.trim().startsWith('[')) {
                try {
                    const json = JSON.parse(bodyContent);
                    bodyHtml = `<pre style="margin: 0; padding: 20px; background: #282c34; color: #abb2bf; overflow-x: auto; border-radius: 8px; font-family: 'Fira Code', monospace; font-size: 0.9em; line-height: 1.6; box-shadow: 0 2px 8px rgba(0,0,0,0.1);"><code>${escapeHtml(JSON.stringify(json, null, 2))}</code></pre>`;
                } catch {
                    bodyHtml = `<pre style="margin: 0; padding: 20px; background: #282c34; color: #abb2bf; overflow-x: auto; border-radius: 8px; font-family: 'Fira Code', monospace; font-size: 0.9em; line-height: 1.6; box-shadow: 0 2px 8px rgba(0,0,0,0.1);"><code>${escapeHtml(bodyContent)}</code></pre>`;
                }
            } else {
                bodyHtml = `<pre style="margin: 0; padding: 20px; background: #282c34; color: #abb2bf; overflow-x: auto; border-radius: 8px; font-family: 'Fira Code', monospace; font-size: 0.9em; line-height: 1.6; box-shadow: 0 2px 8px rgba(0,0,0,0.1);"><code>${escapeHtml(bodyContent)}</code></pre>`;
            }
        } catch (e) {
            bodyHtml = `<pre style="margin: 0; padding: 20px; background: #282c34; color: #abb2bf; overflow-x: auto; border-radius: 8px; font-family: 'Fira Code', monospace; font-size: 0.9em; line-height: 1.6; box-shadow: 0 2px 8px rgba(0,0,0,0.1);"><code>${escapeHtml(bodyContent)}</code></pre>`;
        }
    } else {
        bodyHtml = '<div style="padding: 20px; color: #888; text-align: center; background: #f5f5f5; border-radius: 8px; border: 1px dashed #ddd;">No request body</div>';
    }

    detailContentEl.innerHTML = `
        <div style="padding: 20px; max-width: 100%;">
            <div style="margin-bottom: 25px;">
                <h4 style="margin: 0 0 12px 0; color: #333; font-size: 1.1em; font-weight: 600; display: flex; align-items: center; gap: 8px;">
                    <span class="material-symbols-outlined" style="font-size: 1.2em; color: #666;">send</span>
                    Request Line
                </h4>
                <div style="
                    background: #1e1e1e;
                    color: #e0e0e0;
                    padding: 12px 16px;
                    border-radius: 6px;
                    font-family: 'Fira Code', monospace;
                    font-size: 0.95em;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                    word-break: break-all;
                    border: 1px solid #2d2d2d;
                ">
                    <span style="font-weight: 600; margin-right: 10px; color: ${getMethodColor(flow.method || 'GET')};">${escapeHtml(flow.method || 'GET')}</span>
                    <span style="color: #e0e0e0;">${escapeHtml(flow.url || '')}</span>
                </div>
            </div>
            
            <div style="margin-bottom: 25px;">
                <h4 style="margin: 0 0 12px 0; color: #333; font-size: 1.1em; font-weight: 600; display: flex; align-items: center; gap: 8px;">
                    <span class="material-symbols-outlined" style="font-size: 1.2em; color: #666;">list</span>
                    Headers
                    <span style="font-size: 0.8em; font-weight: 400; color: #888; margin-left: auto;">
                        ${Object.keys(flow.request.headers || {}).length} header${Object.keys(flow.request.headers || {}).length !== 1 ? 's' : ''}
                    </span>
                </h4>
                <div style="
                    border: 1px solid #e0e0e0; 
                    border-radius: 8px; 
                    overflow: hidden;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.05);
                    background: white;
                ">${headersHtml || '<p style="padding: 20px; color: #888; text-align: center; margin: 0;">No headers</p>'}</div>
            </div>
            
            <div>
                <h4 style="margin: 0 0 12px 0; color: #333; font-size: 1.1em; font-weight: 600; display: flex; align-items: center; gap: 8px;">
                    <span class="material-symbols-outlined" style="font-size: 1.2em; color: #666;">description</span>
                    Body
                </h4>
            ${bodyHtml}
            </div>
        </div>
    `;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function renderWebSocketTab(flow) {
    if (!flow) {
        detailContentEl.innerHTML = '<div style="padding: 20px; color: #666; text-align: center;">No flow selected</div>';
        return;
    }

    const messages = getWebSocketMessages(flow);
    const hasWebSocket = isWebSocketFlow(flow);

    if (!hasWebSocket) {
        detailContentEl.innerHTML = `
            <div style="padding: 40px; text-align: center; color: #888;">
                <span class="material-symbols-outlined" style="font-size: 64px; color: #ddd; margin-bottom: 20px; display: block;">hub</span>
                <p style="font-size: 1rem; margin: 0;">This flow does not contain WebSocket data</p>
                <p style="font-size: 0.85rem; margin: 10px 0 0 0; color: #aaa;">WebSocket connections will appear here when captured</p>
            </div>
        `;
        return;
    }

    const statusCode = flow.status_code ?? flow.response?.status_code ?? 'N/A';
    let html = '<div style="padding: 20px;">';

    // Overview section
    html += '<div style="background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">';
    html += '<h3 style="margin: 0 0 15px 0; color: #333;">WebSocket Connection</h3>';
    html += `<div style="display: grid; grid-template-columns: auto 1fr; gap: 10px 20px; font-size: 0.9em;">`;
    html += `<div style="color: #666;">URL:</div><div style="font-family: monospace; word-break: break-all;">${flow.url || 'N/A'}</div>`;
    html += `<div style="color: #666;">Messages:</div><div>${messages.length}</div>`;
    html += `<div style="color: #666;">Status:</div><div>${statusCode}</div>`;
    html += `</div>`;
    html += '</div>';

    // Messages section
    if (messages.length > 0) {
        html += '<div style="background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">';
        html += '<h3 style="margin: 0 0 15px 0; color: #333;">Messages (' + messages.length + ')</h3>';
        html += '<div style="display: flex; flex-direction: column; gap: 12px;">';

        messages.forEach((msg, idx) => {
            const isClient = msg.from_client !== false && msg.direction !== 'server';
            const direction = isClient ? 'Client → Server' : 'Server → Client';
            const directionColor = isClient ? '#2196f3' : '#4caf50';
            const content = msg.content || msg.text || msg.data || '';
            const isText = msg.type === 'text' || typeof content === 'string';
            const timestamp = msg.timestamp || (flow.timestamp_start || 0) + (idx * 0.001);
            const date = new Date(timestamp * 1000);
            const size = typeof content === 'string' ? content.length : (content.byteLength || 0);

            // Try to parse JSON if it's text
            let parsedContent = null;
            let isJson = false;
            if (isText && typeof content === 'string' && content.trim()) {
                const trimmed = content.trim();
                if ((trimmed.startsWith('{') && trimmed.endsWith('}')) ||
                    (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
                    try {
                        parsedContent = JSON.parse(content);
                        isJson = true;
                    } catch (e) {
                        // Not valid JSON
                    }
                }
            }

            html += `<div style="background: white; border-radius: 8px; padding: 16px; border: 1px solid var(--border-color); border-left: 4px solid ${directionColor};">`;
            html += `<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">`;
            html += `<div>`;
            html += `<span style="color: ${directionColor}; font-weight: 600; font-size: 13px;">${direction}</span>`;
            html += `<span style="margin-left: 12px; font-size: 11px; color: #666;">${date.toLocaleTimeString()}</span>`;
            html += `</div>`;
            html += `<div style="font-size: 11px; color: #666;">`;
            html += `${isText ? 'Text' : 'Binary'} • ${size} bytes`;
            if (isJson) {
                html += ` • <span style="color: #4caf50; font-weight: 600;">JSON</span>`;
            }
            html += `</div>`;
            html += `</div>`;

            // Content display
            html += `<div style="background: #f5f5f5; border-radius: 4px; padding: 12px; font-family: 'Fira Code', monospace; font-size: 12px; max-height: 400px; overflow-y: auto; word-break: break-all; position: relative;">`;

            if (isJson && parsedContent) {
                // Pretty print JSON
                html += `<pre style="margin: 0; white-space: pre-wrap; word-wrap: break-word; color: #333;">${escapeHtml(JSON.stringify(parsedContent, null, 2))}</pre>`;
            } else if (isText) {
                html += `<pre style="margin: 0; white-space: pre-wrap; word-wrap: break-word; color: #333;">${escapeHtml(String(content))}</pre>`;
            } else {
                // Binary data
                html += `<pre style="margin: 0; white-space: pre-wrap; word-wrap: break-word; color: #666;">Binary data (${size} bytes)</pre>`;
                if (size < 1024) {
                    // Show hex dump for small binary data
                    const hex = Array.from(new Uint8Array(content)).map(b => b.toString(16).padStart(2, '0')).join(' ');
                    html += `<pre style="margin: 8px 0 0 0; font-size: 11px; color: #888;">${hex}</pre>`;
                }
            }

            html += `</div>`;
            html += `</div>`;
        });

        html += '</div>';
        html += '</div>';
    }

    html += '</div>';
    detailContentEl.innerHTML = html;
}

function renderResponseTab(flow) {
    if (!flow || !flow.response) {
        detailContentEl.innerHTML = '<div style="padding: 20px; color: #666; text-align: center;">No response yet</div>';
        return;
    }

    // Helper function to get header icon/color based on header name
    const getHeaderStyle = (headerName) => {
        const name = headerName.toLowerCase();
        if (name.includes('set-cookie')) {
            return { icon: 'cookie', color: '#333', bg: '#f5f5f5' };
        } else if (name.includes('content-type')) {
            return { icon: 'description', color: '#333', bg: '#f5f5f5' };
        } else if (name.includes('content-length')) {
            return { icon: 'straighten', color: '#333', bg: '#f5f5f5' };
        } else if (name.includes('location')) {
            return { icon: 'place', color: '#333', bg: '#f5f5f5' };
        } else if (name.includes('cache-control')) {
            return { icon: 'storage', color: '#333', bg: '#f5f5f5' };
        } else if (name.includes('server')) {
            return { icon: 'dns', color: '#333', bg: '#f5f5f5' };
        } else if (name.includes('date')) {
            return { icon: 'calendar_today', color: '#333', bg: '#f5f5f5' };
        }
        return { icon: 'list', color: '#333', bg: '#f5f5f5' };
    };

    const headersHtml = Object.entries(flow.response.headers || {}).map(([k, v], index) => {
        const style = getHeaderStyle(k);
        const isEven = index % 2 === 0;
        return `
            <div class="header-row" style="
                display: grid; 
                grid-template-columns: 30px 220px 1fr; 
                padding: 12px 15px; 
                border-bottom: 1px solid #e8e8e8;
                background: ${isEven ? '#ffffff' : '#fafafa'};
                transition: all 0.2s ease;
                align-items: center;
            " onmouseover="this.style.background='#f0f0f0'; this.style.paddingLeft='18px';" 
               onmouseout="this.style.background='${isEven ? '#ffffff' : '#fafafa'}'; this.style.paddingLeft='15px';">
                <span class="material-symbols-outlined" style="font-size: 18px; color: #666; text-align: center;">${style.icon}</span>
                <strong style="
                    color: #333; 
                    font-weight: 600; 
                    font-size: 0.9em;
                    text-transform: capitalize;
                    letter-spacing: 0.3px;
                ">${escapeHtml(k)}:</strong>
                <span style="
                    color: #333; 
                    font-family: 'Fira Code', monospace;
                    font-size: 0.9em;
                    word-break: break-all;
                    padding-left: 10px;
                ">${escapeHtml(String(v))}</span>
            </div>
        `;
    }).join('');

    // Récupérer le body depuis content_bs64 ou content directement
    let bodyContent = '';
    if (flow.response.content_bs64) {
        try {
            bodyContent = atob(flow.response.content_bs64);
        } catch (e) {
            console.warn('Error decoding base64 content:', e);
        }
    } else if (flow.response.content) {
        bodyContent = typeof flow.response.content === 'string' ? flow.response.content : String(flow.response.content);
    }

    let bodyHtml = '';
    if (bodyContent && bodyContent.trim()) {
        try {
            // Try to detect content type and format accordingly
            const contentType = flow.response.headers?.['content-type'] || '';
            if (contentType.includes('json') || bodyContent.trim().startsWith('{') || bodyContent.trim().startsWith('[')) {
                try {
                    const json = JSON.parse(bodyContent);
                    bodyHtml = `<pre style="margin: 0; padding: 20px; background: #282c34; color: #abb2bf; overflow-x: auto; border-radius: 8px; font-family: 'Fira Code', monospace; font-size: 0.9em; line-height: 1.6; box-shadow: 0 2px 8px rgba(0,0,0,0.1);"><code>${escapeHtml(JSON.stringify(json, null, 2))}</code></pre>`;
                } catch {
                    bodyHtml = `<pre style="margin: 0; padding: 20px; background: #282c34; color: #abb2bf; overflow-x: auto; border-radius: 8px; font-family: 'Fira Code', monospace; font-size: 0.9em; line-height: 1.6; box-shadow: 0 2px 8px rgba(0,0,0,0.1);"><code>${escapeHtml(bodyContent)}</code></pre>`;
                }
            } else if (contentType.includes('html')) {
                bodyHtml = `<pre style="margin: 0; padding: 20px; background: #282c34; color: #abb2bf; overflow-x: auto; border-radius: 8px; font-family: 'Fira Code', monospace; font-size: 0.9em; line-height: 1.6; box-shadow: 0 2px 8px rgba(0,0,0,0.1);"><code>${escapeHtml(bodyContent)}</code></pre>`;
            } else {
                bodyHtml = `<pre style="margin: 0; padding: 20px; background: #282c34; color: #abb2bf; overflow-x: auto; border-radius: 8px; font-family: 'Fira Code', monospace; font-size: 0.9em; line-height: 1.6; box-shadow: 0 2px 8px rgba(0,0,0,0.1);"><code>${escapeHtml(bodyContent)}</code></pre>`;
            }
        } catch (e) {
            bodyHtml = `<pre style="margin: 0; padding: 20px; background: #282c34; color: #abb2bf; overflow-x: auto; border-radius: 8px; font-family: 'Fira Code', monospace; font-size: 0.9em; line-height: 1.6; box-shadow: 0 2px 8px rgba(0,0,0,0.1);"><code>${escapeHtml(bodyContent)}</code></pre>`;
        }
    } else {
        bodyHtml = '<div style="padding: 20px; color: #888; text-align: center; background: #f5f5f5; border-radius: 8px; border: 1px dashed #ddd;">No response body</div>';
    }

    // Determine status color
    const statusCode = flow.status_code || 0;
    let statusColor = '#4caf50'; // Green for 2xx
    let statusBg = '#e8f5e9';
    if (statusCode >= 300 && statusCode < 400) {
        statusColor = '#ff9800'; // Orange for 3xx
        statusBg = '#fff3e0';
    } else if (statusCode >= 400 && statusCode < 500) {
        statusColor = '#f44336'; // Red for 4xx
        statusBg = '#ffebee';
    } else if (statusCode >= 500) {
        statusColor = '#d32f2f'; // Dark red for 5xx
        statusBg = '#ffebee';
    }

    detailContentEl.innerHTML = `
        <div style="padding: 20px; max-width: 100%;">
            <div style="margin-bottom: 25px;">
                <h4 style="margin: 0 0 12px 0; color: #333; font-size: 1.1em; font-weight: 600; display: flex; align-items: center; gap: 8px;">
                    <span class="material-symbols-outlined" style="font-size: 1.2em; color: #666;">check_circle</span>
                    Status
                </h4>
                <div style="
                    background: ${statusBg};
                    color: ${statusColor};
                    padding: 12px 16px;
                    border-radius: 8px;
                    font-family: 'Fira Code', monospace;
                    font-size: 0.95em;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                    border-left: 4px solid ${statusColor};
                ">
                    <span style="font-weight: 700; margin-right: 10px; font-size: 1.1em;">${escapeHtml(String(statusCode))}</span>
                    ${escapeHtml(flow.response.reason || '')}
                </div>
            </div>
            
            <div style="margin-bottom: 25px;">
                <h4 style="margin: 0 0 12px 0; color: #333; font-size: 1.1em; font-weight: 600; display: flex; align-items: center; gap: 8px;">
                    <span class="material-symbols-outlined" style="font-size: 1.2em; color: #666;">list</span>
                    Headers
                    <span style="font-size: 0.8em; font-weight: 400; color: #888; margin-left: auto;">
                        ${Object.keys(flow.response.headers || {}).length} header${Object.keys(flow.response.headers || {}).length !== 1 ? 's' : ''}
                    </span>
                </h4>
                <div style="
                    border: 1px solid #e0e0e0; 
                    border-radius: 8px; 
                    overflow: hidden;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.05);
                    background: white;
                ">${headersHtml || '<p style="padding: 20px; color: #888; text-align: center; margin: 0;">No headers</p>'}</div>
            </div>
            
            <div>
                <h4 style="margin: 0 0 12px 0; color: #333; font-size: 1.1em; font-weight: 600; display: flex; align-items: center; gap: 8px;">
                    <span class="material-symbols-outlined" style="font-size: 1.2em; color: #666;">description</span>
                    Body
                </h4>
            ${bodyHtml}
            </div>
        </div>
    `;
}

function renderHexdumpTab(flow) {
    // Récupérer le contenu depuis content_bs64 ou content directement
    let reqContent = '';
    if (flow.request && flow.request.content_bs64) {
        try {
            reqContent = atob(flow.request.content_bs64);
        } catch (e) {
            console.warn('Error decoding request base64:', e);
        }
    } else if (flow.request && flow.request.content) {
        reqContent = typeof flow.request.content === 'string' ? flow.request.content : String(flow.request.content);
    }

    let resContent = '';
    if (flow.response && flow.response.content_bs64) {
        try {
            resContent = atob(flow.response.content_bs64);
        } catch (e) {
            console.warn('Error decoding response base64:', e);
        }
    } else if (flow.response && flow.response.content) {
        resContent = typeof flow.response.content === 'string' ? flow.response.content : String(flow.response.content);
    }

    const reqHex = generateHexdump(reqContent);
    const resHex = generateHexdump(resContent);

    // Créer les éléments DOM directement pour éviter les problèmes d'échappement
    detailContentEl.innerHTML = `
        <div style="padding: 20px; max-width: 100%;">
            <div style="margin-bottom: 25px;">
                <h4 style="margin: 0 0 12px 0; color: #333; font-size: 1.1em; font-weight: 600; display: flex; align-items: center; gap: 8px;">
                    <span class="material-symbols-outlined" style="font-size: 1.2em; color: #666;">code</span>
                    Request Body Hexdump
                </h4>
                <pre id="hexdump-request" style="background: #1e1e1e; color: #d4d4d4; padding: 15px; overflow-x: auto; font-size: 0.85em; font-family: 'Fira Code', 'Consolas', monospace; white-space: pre-wrap; word-break: break-all; border-radius: 6px; border: 1px solid #2d2d2d;"></pre>
            </div>
            
            <div>
                <h4 style="margin: 0 0 12px 0; color: #333; font-size: 1.1em; font-weight: 600; display: flex; align-items: center; gap: 8px;">
                    <span class="material-symbols-outlined" style="font-size: 1.2em; color: #666;">code</span>
                    Response Body Hexdump
                </h4>
                <pre id="hexdump-response" style="background: #1e1e1e; color: #d4d4d4; padding: 15px; overflow-x: auto; font-size: 0.85em; font-family: 'Fira Code', 'Consolas', monospace; white-space: pre-wrap; word-break: break-all; border-radius: 6px; border: 1px solid #2d2d2d;"></pre>
            </div>
        </div>
    `;

    // Utiliser textContent pour éviter les problèmes d'interprétation
    const reqPre = document.getElementById('hexdump-request');
    const resPre = document.getElementById('hexdump-response');

    if (reqPre) {
        reqPre.textContent = reqHex || 'No request body';
    }

    if (resPre) {
        resPre.textContent = resHex || 'No response body';
    }
}

function generateHexdump(str) {
    if (!str) return '';

    const bytes = new TextEncoder().encode(str);
    let result = '';

    for (let i = 0; i < bytes.length; i += 16) {
        const offset = i.toString(16).padStart(8, '0');
        const chunk = bytes.slice(i, i + 16);

        let hex = '';
        let ascii = '';

        for (let j = 0; j < 16; j++) {
            if (j < chunk.length) {
                hex += chunk[j].toString(16).padStart(2, '0') + ' ';
                ascii += (chunk[j] >= 32 && chunk[j] <= 126) ? String.fromCharCode(chunk[j]) : '.';
            } else {
                hex += '   ';
                ascii += ' ';
            }

            if (j === 7) hex += ' ';
        }

        result += `${offset}  ${hex} |${ascii}|\n`;
    }

    return result;
}

function renderTechTab(flow) {
    if (!flow) {
        detailContentEl.innerHTML = '<div style="padding: 20px; color: #666; text-align: center;">Flow not found</div>';
        return;
    }

    const techs = flow.technologies || {};
    const fingerprint = flow.fingerprint || {};
    const moduleSuggestions = flow.module_suggestions || [];

    let html = '<div style="padding: 20px; max-width: 1200px;">';

    // Technologies détectées
    html += '<div style="background: white; border-radius: 12px; padding: 24px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">';
    html += '<h3 style="margin-top: 0; color: #333; display: flex; align-items: center; gap: 8px;">';
    html += '<span class="material-symbols-outlined" style="font-size: 24px; color: #666;">apps</span>';
    html += 'Detected Technologies</h3>';

    const hasTechs = Object.values(techs).some(arr => arr && arr.length > 0);
    if (hasTechs) {
        Object.keys(techs).forEach(category => {
            const items = techs[category] || [];
            if (items.length > 0) {
                // Get category icon
                let categoryIcon = 'inventory_2';
                if (category === 'servers') categoryIcon = 'dns';
                else if (category === 'frameworks') categoryIcon = 'settings';
                else if (category === 'cms') categoryIcon = 'description';
                else if (category === 'databases') categoryIcon = 'storage';
                else if (category === 'languages') categoryIcon = 'code';

                html += `<div style="margin-bottom: 20px;">`;
                html += `<h4 style="color: #333; text-transform: capitalize; margin-bottom: 12px; font-size: 15px; font-weight: 600; display: flex; align-items: center; gap: 6px;">`;
                html += `<span class="material-symbols-outlined" style="font-size: 18px; color: #666;">${categoryIcon}</span> ${category}`;
                html += `</h4>`;
                html += '<div style="display: flex; flex-wrap: wrap; gap: 10px;">';
                items.forEach(tech => {
                    html += `<span style="
                        background: #f5f5f5; 
                        color: #333; 
                        padding: 10px 16px; 
                        border-radius: 6px; 
                        font-weight: 500; 
                        font-size: 14px;
                        border: 1px solid #e0e0e0;
                        transition: all 0.2s ease;
                    ">${tech}</span>`;
                });
                html += '</div></div>';
            }
        });
    } else {
        html += '<p style="color: #888; text-align: center; padding: 30px; background: #f8f9fa; border-radius: 8px; margin: 0;">No technology detected for this request</p>';
    }
    html += '</div>';

    // Versions détectées avec déduplication
    if (fingerprint.versions && Object.keys(fingerprint.versions).length > 0) {
        html += '<div style="background: white; border-radius: 12px; padding: 24px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">';
        html += '<h3 style="margin-top: 0; color: #333; display: flex; align-items: center; gap: 8px;">';
        html += '<span class="material-symbols-outlined" style="font-size: 24px; color: #ff9800;">tag</span>';
        html += 'Detected Versions</h3>';
        html += '<div style="display: flex; flex-wrap: wrap; gap: 10px;">';

        // Use a Set to track unique version strings
        const displayedVersions = new Set();

        Object.entries(fingerprint.versions).forEach(([tech, vers]) => {
            (vers || []).forEach(v => {
                const versionStr = `${tech} ${v.version || ''}`;
                // Only add if not already displayed
                if (!displayedVersions.has(versionStr)) {
                    displayedVersions.add(versionStr);
                    html += `<span style="
                        background: linear-gradient(135deg, #fff3e0 0%, #ffe0b2 100%); 
                        color: #e65100; 
                        padding: 10px 16px; 
                        border-radius: 8px; 
                        font-weight: 600;
                        font-size: 14px;
                        font-family: 'Fira Code', monospace;
                        box-shadow: 0 2px 6px rgba(230, 81, 0, 0.15);
                        border: 1px solid rgba(230, 81, 0, 0.1);
                    ">${versionStr}</span>`;
                }
            });
        });
        html += '</div></div>';
    }

    // Configurations détectées
    if (fingerprint.configurations && fingerprint.configurations.length > 0) {
        html += '<div style="background: white; border-radius: 12px; padding: 24px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">';
        html += '<h3 style="margin-top: 0; color: #333; display: flex; align-items: center; gap: 8px;">';
        html += '<span class="material-symbols-outlined" style="font-size: 24px; color: #666;">settings</span>';
        html += 'Detected Configurations</h3>';
        html += '<div style="display: flex; flex-wrap: wrap; gap: 10px;">';
        fingerprint.configurations.forEach(cfg => {
            html += `<span style="
                background: #f5f5f5; 
                color: #333; 
                padding: 10px 16px; 
                border-radius: 6px; 
                font-weight: 500;
                font-size: 14px;
                border: 1px solid #e0e0e0;
            ">${cfg.description || cfg}</span>`;
        });
        html += '</div></div>';
    }

    // Fonctionnalités de sécurité
    if (fingerprint.security_features && fingerprint.security_features.length > 0) {
        html += '<div style="background: white; border-radius: 12px; padding: 24px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">';
        html += '<h3 style="margin-top: 0; color: #333; display: flex; align-items: center; gap: 8px;">';
        html += '<span class="material-symbols-outlined" style="font-size: 20px;">security</span>';
        html += 'Security Features</h3>';
        html += '<div style="display: flex; flex-wrap: wrap; gap: 8px;">';
        fingerprint.security_features.forEach(feat => {
            html += `<span style="background: linear-gradient(135deg, #e8f5e9 0%, #c8e6c9 100%); color: #2e7d32; padding: 8px 12px; border-radius: 6px; font-weight: 500; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">${feat.description || feat}</span>`;
        });
        html += '</div></div>';
    }

    // Vulnérabilités détectées
    if (fingerprint.vulnerabilities && fingerprint.vulnerabilities.length > 0) {
        html += '<div style="background: linear-gradient(135deg, #ffebee 0%, #ffcdd2 100%); border-radius: 12px; padding: 24px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); border-left: 4px solid #f44336;">';
        html += '<h3 style="margin-top: 0; color: #c62828; display: flex; align-items: center; gap: 8px;">';
        html += '<span class="material-symbols-outlined" style="font-size: 20px;">warning</span>';
        html += 'Potential Vulnerabilities</h3>';
        fingerprint.vulnerabilities.forEach(vuln => {
            const severityColor = vuln.severity === 'high' ? '#d32f2f' : '#f57c00';
            html += `<div style="background: white; padding: 12px; border-radius: 8px; margin-bottom: 8px; border-left: 3px solid ${severityColor};">`;
            html += `<div style="font-weight: 600; color: #333; margin-bottom: 4px;">${vuln.technology} ${vuln.version || ''}</div>`;
            html += `<div style="color: #666; font-size: 14px;">${vuln.description}</div>`;
            html += `<div style="margin-top: 4px;"><span style="background: ${severityColor}; color: white; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 500;">${vuln.severity.toUpperCase()}</span></div>`;
            html += `</div>`;
        });
        html += '</div>';
    }

    // Suggestions de modules
    if (moduleSuggestions.length > 0) {
        html += '<div style="background: white; border-radius: 12px; padding: 24px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">';
        html += '<h3 style="margin-top: 0; color: #333; display: flex; align-items: center; gap: 8px;">';
        html += '<span class="material-symbols-outlined" style="font-size: 24px; color: #fbc02d;">lightbulb</span>';
        html += `Suggestions de Modules (${moduleSuggestions.length})</h3>`;
        moduleSuggestions.slice(0, 5).forEach((sugg, index) => {
            const priorityColor = sugg.priority === 'high' ? '#f44336' : sugg.priority === 'medium' ? '#ff9800' : '#4caf50';
            html += `<div style="background: #f8f9fa; padding: 16px; border-radius: 8px; margin-bottom: 12px; border-left: 4px solid ${priorityColor}; display: flex; justify-content: space-between; align-items: flex-start; gap: 16px;">`;

            html += `<div style="flex: 1; cursor: pointer;" onclick="openModuleSuggestion('${sugg.module}', '${flow.id}')" onmouseover="this.style.opacity='0.8'" onmouseout="this.style.opacity='1'">`;
            html += `<div style="font-weight: 600; color: #333; margin-bottom: 6px; font-size: 15px;">${sugg.module}</div>`;
            html += `<div style="font-size: 13px; color: #666; margin-bottom: 8px;">Score: ${sugg.score || 0} | Priorité: <span style="color: ${priorityColor}; font-weight: 600;">${(sugg.priority || 'low').toUpperCase()}</span></div>`;
            if (sugg.reasons && sugg.reasons.length > 0) {
                html += `<div style="display: flex; flex-wrap: wrap; gap: 6px;">`;
                sugg.reasons.slice(0, 3).forEach(reason => {
                    html += `<span style="background: #e3f2fd; color: #1976d2; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: 500;">${reason}</span>`;
                });
                html += '</div>';
            }
            html += `</div>`;

            // Execute Button
            html += `<button onclick="event.stopPropagation(); executeModuleFromFlow('${sugg.module}', '${flow.id}')" class="execute-btn" style="
                background: #6200ea; 
                color: white; 
                border: none; 
                border-radius: 6px; 
                padding: 8px 16px; 
                cursor: pointer; 
                display: flex; 
                align-items: center; 
                gap: 6px; 
                font-weight: 600; 
                font-size: 13px;
                transition: all 0.2s;
                box-shadow: 0 2px 4px rgba(98, 0, 234, 0.2);
            " onmouseover="this.style.background='#5000d6'; this.style.transform='translateY(-1px)';" onmouseout="this.style.background='#6200ea'; this.style.transform='translateY(0)';">
                <span class="material-symbols-outlined" style="font-size: 18px;">play_arrow</span>
                Execute
            </button>`;

            html += `</div>`;
        });
        html += '</div>';
    }

    html += '</div>';
    detailContentEl.innerHTML = html;
}

// Show context menu for flow (right-click)
function showFlowContextMenu(event, flow) {
    // Remove existing context menu if any
    const existingMenu = document.getElementById('flow-context-menu');
    if (existingMenu) {
        existingMenu.remove();
    }

    // Create context menu
    const menu = document.createElement('div');
    menu.id = 'flow-context-menu';
    menu.style.cssText = `
        position: fixed;
        top: ${event.clientY}px;
        left: ${event.clientX}px;
        background: white;
        border: 1px solid var(--border-color);
        border-radius: 6px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        z-index: 10000;
        min-width: 200px;
        padding: 4px 0;
    `;

    menu.innerHTML = `
        <div 
            class="context-menu-item"
            onclick="openModuleSelectorFromFlow('${flow.id}')"
            style="padding: 10px 16px; cursor: pointer; display: flex; align-items: center; gap: 10px; transition: background 0.2s;"
            onmouseover="this.style.background='#f5f5f5'"
            onmouseout="this.style.background='white'">
            <span class="material-symbols-outlined" style="font-size: 18px; color: var(--primary-color);">play_arrow</span>
            <span style="font-weight: 500;">Run module on this URL</span>
        </div>
    `;

    document.body.appendChild(menu);

    // Close menu when clicking outside
    const closeMenu = (e) => {
        if (!menu.contains(e.target)) {
            menu.remove();
            document.removeEventListener('click', closeMenu);
            document.removeEventListener('contextmenu', closeMenu);
        }
    };

    setTimeout(() => {
        document.addEventListener('click', closeMenu);
        document.addEventListener('contextmenu', closeMenu);
    }, 100);
}

// Open module selector modal from flow
function openModuleSelectorFromFlow(flowId) {
    const flow = flowsData.find(f => f.id === flowId);
    if (!flow) {
        alert('Flow not found');
        return;
    }

    // Remove existing context menu
    const existingMenu = document.getElementById('flow-context-menu');
    if (existingMenu) {
        existingMenu.remove();
    }

    // Create modal
    let modal = document.getElementById('module-selector-modal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'module-selector-modal';
        modal.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
            z-index: 10001;
            display: flex;
            justify-content: center;
            align-items: center;
        `;
        document.body.appendChild(modal);
    }

    // Filter modules (prefer HTTP/web-related modules)
    const filteredModules = modulesData.filter(mod => {
        const name = (mod.name || '').toLowerCase();
        const desc = (mod.description || '').toLowerCase();
        const category = (mod.category || '').toLowerCase();
        return name.includes('http') || name.includes('web') || name.includes('scanner') ||
            desc.includes('http') || desc.includes('web') || category.includes('web') ||
            category.includes('scanner') || category.includes('auxiliary');
    });

    // Sort: HTTP/web modules first, then others
    const sortedModules = [
        ...filteredModules.filter(m => (m.name || '').toLowerCase().includes('http')),
        ...filteredModules.filter(m => !(m.name || '').toLowerCase().includes('http'))
    ];

    const modulesHtml = sortedModules.length > 0
        ? sortedModules.map(mod => `
            <div 
                class="module-selector-item"
                onclick="selectModuleFromFlow('${escapeHtml(mod.name)}', '${flowId}')"
                style="padding: 12px 16px; cursor: pointer; border-bottom: 1px solid #f0f0f0; transition: background 0.2s; display: flex; justify-content: space-between; align-items: center;"
                onmouseover="this.style.background='#f5f5f5'"
                onmouseout="this.style.background='white'">
                <div style="flex: 1;">
                    <div style="font-weight: 600; color: #333; margin-bottom: 4px;">${escapeHtml(mod.name)}</div>
                    <div style="font-size: 0.85em; color: #666;">${escapeHtml(mod.description || 'No description')}</div>
                </div>
                <span class="material-symbols-outlined" style="color: var(--primary-color);">play_arrow</span>
            </div>
        `).join('')
        : '<div style="padding: 20px; text-align: center; color: #888;">No suitable modules found</div>';

    modal.innerHTML = `
        <div style="background: white; border-radius: 12px; width: 90%; max-width: 600px; max-height: 80vh; display: flex; flex-direction: column; box-shadow: 0 8px 32px rgba(0,0,0,0.2);">
            <div style="padding: 20px 24px; border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <h3 style="margin: 0 0 4px 0; color: var(--primary-color); display: flex; align-items: center; gap: 10px;">
                        <span class="material-symbols-outlined" style="font-size: 24px;">play_arrow</span>
                        Run Module on URL
                    </h3>
                    <p style="margin: 0; color: #666; font-size: 0.9em; font-family: 'Fira Code', monospace;">${escapeHtml(flow.url || 'N/A')}</p>
                </div>
                <button 
                    onclick="closeModuleSelectorModal()"
                    style="background: #f5f5f5; border: none; width: 32px; height: 32px; border-radius: 6px; cursor: pointer; display: flex; align-items: center; justify-content: center; transition: all 0.2s;"
                    onmouseover="this.style.background='#e0e0e0'"
                    onmouseout="this.style.background='#f5f5f5'">
                    <span class="material-symbols-outlined" style="font-size: 18px;">close</span>
                </button>
            </div>
            <div style="flex: 1; overflow-y: auto; padding: 8px 0;">
                ${modulesHtml}
            </div>
            <div style="padding: 16px 24px; border-top: 1px solid var(--border-color); background: #fafafa; display: flex; justify-content: space-between; align-items: center;">
                <span style="color: #666; font-size: 0.9em;">${sortedModules.length} module(s) available</span>
                <button 
                    onclick="closeModuleSelectorModal()"
                    class="btn btn-secondary">
                    Cancel
                </button>
            </div>
        </div>
    `;

    modal.style.display = 'flex';
}

// Close module selector modal
function closeModuleSelectorModal() {
    const modal = document.getElementById('module-selector-modal');
    if (modal) {
        modal.style.display = 'none';
    }
}

// Select and configure module from flow (without executing)
async function selectModuleFromFlow(moduleName, flowId) {
    closeModuleSelectorModal();

    const flow = flowsData.find(f => f.id === flowId);
    if (!flow) {
        alert('Flow not found');
        return;
    }

    // Switch to modules view
    const modulesView = document.getElementById('modules-view');
    const modulesNavItem = document.querySelector('[data-view="modules"]');
    if (modulesView && modulesNavItem) {
        modulesNavItem.click();

        // Wait for the view to render, then select the module
        setTimeout(() => {
            // Select the module in the list
            selectedModuleId = moduleName;
            renderModuleList();
            renderModuleConfig(moduleName);

            // Wait a bit more for the config to render, then pre-fill URL and auto-configure
            setTimeout(async () => {
                // Pre-fill the URL from the flow
                const urlInput = document.getElementById('module-target-url');
                if (urlInput && flow.url) {
                    urlInput.value = flow.url;
                }

                // Auto-configure the options
                if (flow.url) {
                    await autoConfigureModuleFromUrl(moduleName, true);

                    // Show a notification about which flow was used
                    const moduleOutput = document.getElementById('module-output');
                    if (moduleOutput) {
                        moduleOutput.style.display = 'block';
                        moduleOutput.style.color = '#2196f3';
                        moduleOutput.style.background = '#e3f2fd';
                        moduleOutput.style.border = '1px solid #90caf9';
                        moduleOutput.style.borderRadius = '4px';
                        moduleOutput.style.padding = '12px';
                        moduleOutput.textContent = `✓ Module configured from flow:\n  URL: ${flow.url}\n  Method: ${flow.method || 'N/A'}\n  Status: ${flow.status_code || 'N/A'}\n\nOptions have been auto-configured. Review and click "Run Module" when ready.`;
                        moduleOutput.scrollTop = moduleOutput.scrollHeight;
                    }
                }
            }, 200);
        }, 100);
    }
}

// Styled confirmation modal (instead of window.confirm)
function showModuleConfirmation(moduleName, message) {
    return new Promise((resolve) => {
        const existing = document.getElementById('module-confirm-overlay');
        if (existing) existing.remove();

        const overlay = document.createElement('div');
        overlay.id = 'module-confirm-overlay';
        overlay.style.cssText = `
            position: fixed;
            inset: 0;
            background: rgba(0,0,0,0.4);
            backdrop-filter: blur(4px);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 3000;
        `;

        const modal = document.createElement('div');
        modal.style.cssText = `
            background: #ffffff;
            border-radius: 12px;
            box-shadow: 0 12px 40px rgba(0,0,0,0.18);
            width: min(460px, 90vw);
            padding: 22px 24px;
            display: flex;
            flex-direction: column;
            gap: 16px;
            border: 1px solid #e5e7eb;
        `;

        modal.innerHTML = `
            <div style="display:flex; align-items:center; gap:10px;">
                <div style="width:36px; height:36px; border-radius:10px; background: linear-gradient(135deg, #7e22ce, #2563eb); display:flex; align-items:center; justify-content:center; color:white; font-size:20px;">
                    <span class="material-symbols-outlined" style="font-size:20px;">play_arrow</span>
                </div>
                <div style="flex:1; min-width:0;">
                    <div style="font-weight:700; font-size:16px; color:#1f2937;">Execute module</div>
                    <div style="color:#6b7280; font-size:13px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">
                        ${escapeHtml(moduleName)}
                    </div>
                </div>
            </div>
            <div style="color:#374151; font-size:14px; line-height:1.5;">${message || 'Confirm the execution of the module.'}</div>
            <div style="display:flex; justify-content:flex-end; gap:10px; margin-top:4px;">
                <button id="module-confirm-cancel" class="btn btn-secondary" style="min-width:90px;">Cancel</button>
                <button id="module-confirm-ok" class="btn btn-primary" style="min-width:120px; display:flex; align-items:center; gap:6px;">
                    <span class="material-symbols-outlined" style="font-size:18px;">play_arrow</span>
                    Execute
                </button>
            </div>
        `;

        overlay.appendChild(modal);
        document.body.appendChild(overlay);

        const cleanup = () => {
            overlay.remove();
            document.removeEventListener('keydown', onKey);
        };

        const onKey = (e) => {
            if (e.key === 'Escape') {
                cleanup();
                resolve(false);
            }
        };
        document.addEventListener('keydown', onKey);

        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) {
                cleanup();
                resolve(false);
            }
        });

        modal.querySelector('#module-confirm-cancel').addEventListener('click', () => {
            cleanup();
            resolve(false);
        });

        modal.querySelector('#module-confirm-ok').addEventListener('click', () => {
            cleanup();
            resolve(true);
        });
    });
}

// Function to execute module from flow
async function executeModuleFromFlow(moduleName, flowId) {
    const proceed = await showModuleConfirmation(
        moduleName,
        'The options will be automatically configured from the request. Continue?'
    );
    if (!proceed) return;

    // Show loading state
    const btn = event.currentTarget;
    const originalText = btn.innerHTML;
    btn.innerHTML = '<span class="material-symbols-outlined" style="font-size: 18px; animation: spin 1s linear infinite;">refresh</span> Running...';
    btn.disabled = true;
    btn.style.opacity = '0.7';

    // Switch to modules view and show terminal
    const modulesView = document.getElementById('modules-view');
    const modulesNavItem = document.querySelector('[data-view="modules"]');
    if (modulesView && modulesNavItem) {
        // Switch to modules view
        modulesNavItem.click();

        // Wait a bit for the view to render
        setTimeout(() => {
            const moduleOutput = document.getElementById('module-output');
            if (moduleOutput) {
                moduleOutput.style.display = 'block';
                moduleOutput.textContent = `[${new Date().toLocaleTimeString()}] Executing module: ${moduleName}\n`;
                moduleOutput.style.color = '#d4d4d4';
                // Scroll to bottom
                moduleOutput.scrollTop = moduleOutput.scrollHeight;
            }
        }, 100);
    }

    try {
        const res = await fetch(`${API_BASE}/execute_module_from_flow`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                module_name: moduleName,
                flow_id: flowId
            })
        });

        const data = await res.json();

        // Get terminal element
        const moduleOutput = document.getElementById('module-output');

        if (res.ok) {
            if (moduleOutput) {
                // Show auto-configured options
                const optionsText = Object.entries(data.configured_options || {})
                    .map(([k, v]) => `  ${k}: ${String(v).substring(0, 80)}${String(v).length > 80 ? '...' : ''}`)
                    .join('\n');

                moduleOutput.textContent += `\n[${new Date().toLocaleTimeString()}] Auto-configured options:\n${optionsText}\n`;

                // If module is still running, poll for output
                if (data.is_running && data.execution_id) {
                    moduleOutput.textContent += `\n[${new Date().toLocaleTimeString()}] Module is running...\n`;
                    moduleOutput.textContent += `[${new Date().toLocaleTimeString()}] Output so far:\n${data.output || 'No output yet'}\n`;

                    // Poll for updates
                    const pollInterval = setInterval(async () => {
                        try {
                            const pollRes = await fetch(`${API_BASE}/module-output/${data.execution_id}`);
                            const pollData = await pollRes.json();

                            if (pollData.output) {
                                // Update output, but remove the [MODULE_COMPLETED] marker if present
                                let cleanOutput = pollData.output.replace(/\n\[MODULE_COMPLETED\]/g, '');
                                moduleOutput.textContent = moduleOutput.textContent.split('\n[')[0] + '\n' + cleanOutput;
                                moduleOutput.scrollTop = moduleOutput.scrollHeight;

                                // Check if module is completed (has Result: True/False or [MODULE_COMPLETED] marker)
                                if (pollData.output.includes('[MODULE_COMPLETED]') ||
                                    pollData.output.includes('Result: True') ||
                                    pollData.output.includes('Result: False') ||
                                    pollData.output.includes('Error executing module')) {
                                    clearInterval(pollInterval);
                                    moduleOutput.textContent += `\n[${new Date().toLocaleTimeString()}] ✓ Module execution completed\n`;
                                    moduleOutput.style.color = '#4caf50';
                                }
                            }
                        } catch (err) {
                            console.error("Polling error:", err);
                            clearInterval(pollInterval);
                        }
                    }, 1000); // Poll every second
                } else {
                    // Module completed
                    moduleOutput.textContent += `\n[${new Date().toLocaleTimeString()}] Output:\n${data.output || 'No output'}\n`;
                    moduleOutput.textContent += `\n[${new Date().toLocaleTimeString()}] ✓ Module execution completed\n`;
                    moduleOutput.style.color = '#4caf50';
                }

                // Scroll to bottom
                moduleOutput.scrollTop = moduleOutput.scrollHeight;
            }
        } else {
            if (moduleOutput) {
                moduleOutput.textContent += `\n[${new Date().toLocaleTimeString()}] ✗ Module execution failed\n`;
                moduleOutput.textContent += `Error: ${data.detail || 'Erreur inconnue'}\n`;
                moduleOutput.style.color = '#f44336';
                // Scroll to bottom
                moduleOutput.scrollTop = moduleOutput.scrollHeight;
            } else {
                alert(`Error during execution: ${data.detail || 'Unknown error'}`);
            }
        }
    } catch (err) {
        console.error("Execution error:", err);
        const moduleOutput = document.getElementById('module-output');
        if (moduleOutput) {
            moduleOutput.textContent += `\n[${new Date().toLocaleTimeString()}] ✗ Connection error: ${err.message}\n`;
            moduleOutput.style.color = '#f44336';
            // Scroll to bottom
            moduleOutput.scrollTop = moduleOutput.scrollHeight;
        } else {
            alert(`Connection error: ${err.message}`);
        }
    } finally {
        // Restore button
        btn.innerHTML = originalText;
        btn.disabled = false;
        btn.style.opacity = '1';
    }
}

function showModuleResultModal(moduleName, data) {
    // Create modal if not exists
    let modal = document.getElementById('module-result-modal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'module-result-modal';
        modal.style.cssText = `
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0,0,0,0.5); z-index: 10000;
            display: flex; justify-content: center; align-items: center;
        `;
        document.body.appendChild(modal);
    }

    const optionsHtml = Object.entries(data.configured_options || {}).map(([k, v]) =>
        `<div style="display: flex; justify-content: space-between; border-bottom: 1px solid #eee; padding: 4px 0;">
            <span style="font-weight: 600; color: #555;">${k}:</span>
            <span style="font-family: monospace; color: #2196f3;">${String(v).substring(0, 50)}${String(v).length > 50 ? '...' : ''}</span>
        </div>`
    ).join('');

    modal.innerHTML = `
        <div style="background: white; width: 800px; max-width: 90%; max-height: 90vh; border-radius: 12px; display: flex; flex-direction: column; box-shadow: 0 10px 25px rgba(0,0,0,0.2);">
            <div style="padding: 20px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; align-items: center;">
                <h3 style="margin: 0; color: #6200ea; display: flex; align-items: center; gap: 10px;">
                    <span class="material-symbols-outlined">terminal</span>
                    Execution Result: ${moduleName}
                </h3>
                <button onclick="document.getElementById('module-result-modal').style.display='none'" style="background: none; border: none; cursor: pointer; color: #666;">
                    <span class="material-symbols-outlined">close</span>
                </button>
            </div>
            <div style="padding: 20px; overflow-y: auto;">
                <div style="margin-bottom: 20px;">
                    <h4 style="margin: 0 0 10px 0; color: #333;">Auto-Configured Options</h4>
                    <div style="background: #f9f9f9; padding: 15px; border-radius: 8px; font-size: 13px;">
                        ${optionsHtml}
                    </div>
                </div>
                <div>
                    <h4 style="margin: 0 0 10px 0; color: #333;">Output</h4>
                    <pre style="background: #1e1e1e; color: #d4d4d4; padding: 15px; border-radius: 8px; font-family: 'Fira Code', monospace; font-size: 13px; white-space: pre-wrap; max-height: 400px; overflow-y: auto;">${data.output || 'No output'}</pre>
                </div>
            </div>
            <div style="padding: 15px 20px; border-top: 1px solid #eee; text-align: right;">
                <button onclick="document.getElementById('module-result-modal').style.display='none'" style="background: #6200ea; color: white; border: none; padding: 8px 20px; border-radius: 6px; cursor: pointer; font-weight: 600;">Close</button>
            </div>
        </div>
    `;
    modal.style.display = 'flex';
}

async function renderEndpointsTab(flow) {
    if (!flow) {
        detailContentEl.innerHTML = '<div style="padding: 20px; color: #666; text-align: center;">Flow not found</div>';
        return;
    }

    // Récupérer le domaine du flow actuel
    let flowDomain = null;
    let flowUrlNormalized = null;
    try {
        if (flow.url) {
            const url = new URL(flow.url);
            flowDomain = url.hostname;
            // Normaliser l'URL (sans query params et hash) pour la comparaison
            flowUrlNormalized = `${url.origin}${url.pathname}`;
        }
    } catch (e) {
        // Ignorer
    }

    // Récupérer tous les endpoints découverts depuis ce flow spécifique
    // Vérifier flow.discovered_endpoints (liste aplatie) et flow.endpoints (dictionnaire catégorisé)
    let discoveredEndpoints = flow.discovered_endpoints || [];

    // Si flow.endpoints existe, extraire tous les endpoints depuis toutes les catégories
    if (flow.endpoints && typeof flow.endpoints === 'object') {
        const endpointsFromDict = [];
        Object.values(flow.endpoints).forEach(categoryEndpoints => {
            if (Array.isArray(categoryEndpoints)) {
                endpointsFromDict.push(...categoryEndpoints);
            }
        });
        // Combiner avec discovered_endpoints et dédupliquer
        discoveredEndpoints = [...new Set([...discoveredEndpoints, ...endpointsFromDict])];
    }

    // Debug: log pour comprendre ce qui se passe
    console.log('[Endpoints Tab] Flow endpoints:', {
        discovered_endpoints: flow.discovered_endpoints?.length || 0,
        endpoints_dict: flow.endpoints ? Object.keys(flow.endpoints) : null,
        total_after_merge: discoveredEndpoints.length
    });

    // Créer un Set des URLs réellement appelées (dans flowsData)
    // Pour identifier les endpoints appelés depuis cette page, on regarde tous les flows
    const calledUrls = new Set();
    flowsData.forEach(f => {
        if (f.url) {
            try {
                const url = new URL(f.url);
                // Normaliser l'URL (sans query params et hash)
                const normalized = `${url.origin}${url.pathname}`;
                calledUrls.add(normalized);
                // Aussi ajouter l'URL complète
                calledUrls.add(f.url);
            } catch (e) {
                // Ignorer
            }
        }
    });

    // Séparer les endpoints appelés des endpoints découverts (non-appelés)
    const calledEndpoints = [];
    const discoveredNotCalled = [];

    discoveredEndpoints.forEach(endpoint => {
        try {
            // Normaliser l'endpoint (gérer les URLs relatives et absolues)
            let endpointUrl;
            if (endpoint.startsWith('http://') || endpoint.startsWith('https://')) {
                endpointUrl = new URL(endpoint);
            } else if (endpoint.startsWith('/')) {
                // URL relative, utiliser le domaine du flow actuel
                if (flow.url) {
                    const baseUrl = new URL(flow.url);
                    endpointUrl = new URL(endpoint, baseUrl.origin);
                } else {
                    endpointUrl = new URL(endpoint, 'http://localhost');
                }
            } else {
                // URL relative sans slash, essayer de la résoudre
                if (flow.url) {
                    const baseUrl = new URL(flow.url);
                    endpointUrl = new URL(endpoint, baseUrl);
                } else {
                    endpointUrl = new URL(endpoint, 'http://localhost');
                }
            }

            const normalized = `${endpointUrl.origin}${endpointUrl.pathname}`;
            const normalizedWithQuery = endpointUrl.href.split('#')[0]; // Sans hash

            // Vérifier si cet endpoint a été réellement appelé
            // Comparer avec différentes variantes
            if (calledUrls.has(normalized) ||
                calledUrls.has(normalizedWithQuery) ||
                calledUrls.has(endpointUrl.href) ||
                calledUrls.has(endpoint)) {
                calledEndpoints.push(endpointUrl.href);
            } else {
                discoveredNotCalled.push(endpointUrl.href);
            }
        } catch (e) {
            // Si l'URL est invalide, la considérer comme découverte mais non-appelée
            discoveredNotCalled.push(endpoint);
        }
    });

    // Organiser par domaine
    const organizeByDomain = (endpoints) => {
        const byDomain = new Map();
        endpoints.forEach(endpoint => {
            try {
                const url = new URL(endpoint);
                const domain = url.hostname;
                if (!byDomain.has(domain)) {
                    byDomain.set(domain, []);
                }
                if (!byDomain.get(domain).includes(endpoint)) {
                    byDomain.get(domain).push(endpoint);
                }
            } catch (e) {
                // Ignorer les URLs invalides
            }
        });
        return byDomain;
    };

    const calledByDomain = organizeByDomain(calledEndpoints);
    const discoveredByDomain = organizeByDomain(discoveredNotCalled);

    let html = '<div style="padding: 20px; max-width: 1200px;">';
    html += '<h2 style="margin-top: 0; color: #333; display: flex; align-items: center; gap: 10px;">';
    html += '<span class="material-symbols-outlined" style="font-size: 28px; color: #666;">link</span>';
    html += 'Endpoints</h2>';

    // Afficher les endpoints appelés
    if (calledEndpoints.length > 0) {
        html += '<div style="background: white; border-radius: 12px; padding: 24px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">';
        html += '<h3 style="margin-top: 0; color: #333; display: flex; align-items: center; gap: 8px;">';
        html += '<span class="material-symbols-outlined" style="font-size: 20px; color: #4caf50;">check_circle</span>';
        html += `Called Endpoints <span style="font-size: 0.85em; color: #666; font-weight: normal;">(${calledEndpoints.length})</span>`;
        html += `</h3>`;
        html += '<p style="color: #666; font-size: 0.9em; margin-top: -8px; margin-bottom: 16px;">Endpoints that were actually requested</p>';

        // Afficher par domaine
        const sortedCalledDomains = Array.from(calledByDomain.keys()).sort((a, b) => {
            if (flowDomain) {
                if (a === flowDomain) return -1;
                if (b === flowDomain) return 1;
            }
            return a.localeCompare(b);
        });

        sortedCalledDomains.forEach(domain => {
            const domainEndpoints = calledByDomain.get(domain);
            if (domainEndpoints && domainEndpoints.length > 0) {
                html += `<div style="margin-bottom: 16px;">`;
                html += `<h4 style="color: #666; font-size: 0.9em; margin-bottom: 8px; font-weight: 600;">${domain}</h4>`;
                html += '<div style="max-height: 400px; overflow-y: auto; border: 1px solid #e0e0e0; border-radius: 8px;">';
                domainEndpoints.forEach((endpoint, index) => {
                    html += `<div style="padding: 8px 15px; border-bottom: 1px solid #eee; ${index % 2 === 0 ? 'background: #fafafa;' : ''}">`;
                    html += `<a href="${endpoint}" target="_blank" style="color: #4caf50; text-decoration: none; font-family: \'Fira Code\', monospace; font-size: 0.9em; font-weight: 500;">${endpoint}</a>`;
                    html += `</div>`;
                });
                html += '</div></div>';
            }
        });

        html += '</div>';
    }

    // Afficher les endpoints découverts mais non-appelés
    if (discoveredNotCalled.length > 0) {
        html += '<div style="background: white; border-radius: 12px; padding: 24px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">';
        html += '<h3 style="margin-top: 0; color: #333; display: flex; align-items: center; gap: 8px;">';
        html += '<span class="material-symbols-outlined" style="font-size: 20px; color: #ff9800;">explore</span>';
        html += `Discovered Endpoints (Not Called) <span style="font-size: 0.85em; color: #666; font-weight: normal;">(${discoveredNotCalled.length})</span>`;
        html += `</h3>`;
        html += '<p style="color: #666; font-size: 0.9em; margin-top: -8px; margin-bottom: 16px;">Endpoints found in the response content but not yet requested</p>';

        // Afficher par domaine
        const sortedDiscoveredDomains = Array.from(discoveredByDomain.keys()).sort((a, b) => {
            if (flowDomain) {
                if (a === flowDomain) return -1;
                if (b === flowDomain) return 1;
            }
            return a.localeCompare(b);
        });

        sortedDiscoveredDomains.forEach(domain => {
            const domainEndpoints = discoveredByDomain.get(domain);
            if (domainEndpoints && domainEndpoints.length > 0) {
                html += `<div style="margin-bottom: 16px;">`;
                html += `<h4 style="color: #666; font-size: 0.9em; margin-bottom: 8px; font-weight: 600;">${domain}</h4>`;
                html += '<div style="max-height: 400px; overflow-y: auto; border: 1px solid #e0e0e0; border-radius: 8px;">';
                domainEndpoints.forEach((endpoint, index) => {
                    html += `<div style="padding: 8px 15px; border-bottom: 1px solid #eee; ${index % 2 === 0 ? 'background: #fafafa;' : ''}">`;
                    html += `<a href="${endpoint}" target="_blank" style="color: #ff9800; text-decoration: none; font-family: \'Fira Code\', monospace; font-size: 0.9em;">${endpoint}</a>`;
                    html += `</div>`;
                });
                html += '</div></div>';
            }
        });

        html += '</div>';
    }

    // Si aucun endpoint
    if (calledEndpoints.length === 0 && discoveredNotCalled.length === 0) {
        html += '<div style="text-align: center; padding: 40px; color: #888;">';
        html += '<p>No endpoints discovered for this request.</p>';
        if (discoveredEndpoints.length === 0) {
            html += '<p style="font-size: 0.85em; color: #999; margin-top: 10px;">';
            html += 'The response may not contain extractable endpoints, or endpoint extraction may not have run yet.';
            html += '</p>';
        }
        html += '</div>';
    }

    html += '</div>';
    detailContentEl.innerHTML = html;
}

// === INTERCEPTION PLUGINS ===
let pluginsData = [];
let selectedPluginName = null;

// DOM Elements for plugins
const pluginListEl = document.getElementById('plugin-list');
const pluginConfigEl = document.getElementById('plugin-config');
const pluginCountText = document.getElementById('plugin-count-text');
const refreshPluginsBtn = document.getElementById('refresh-plugins-btn');

async function fetchPlugins() {
    try {
        const res = await fetch(`${API_BASE}/plugins`);
        const data = await res.json();

        if (JSON.stringify(data) !== JSON.stringify(pluginsData)) {
            pluginsData = data;
            renderPluginList();
        }
    } catch (err) {
        console.error("Failed to fetch plugins", err);
        pluginsData = [];
        if (pluginListEl) {
            pluginListEl.innerHTML = '<div style="padding: 20px; text-align: center; color: #f44336;">Failed to load plugins</div>';
        }
    }
}

function renderPluginList() {
    if (!pluginListEl) return;

    if (pluginCountText) {
        pluginCountText.textContent = `${pluginsData.length} plugin${pluginsData.length !== 1 ? 's' : ''} available`;
    }

    if (pluginsData.length === 0) {
        pluginListEl.innerHTML = '<div style="padding: 20px; text-align: center; color: #888;">No plugins found</div>';
        return;
    }

    pluginListEl.innerHTML = pluginsData.map(plugin => `
        <div class="flow-item ${selectedPluginName === plugin.name ? 'active' : ''}" data-plugin-name="${plugin.name}" style="display: grid; grid-template-columns: 1fr auto; padding: 15px; border-bottom: 1px solid #f0f0f0; cursor: pointer; align-items: center;">
            <div>
                <div style="font-weight: 600; color: #6200ea; margin-bottom: 5px;">${plugin.name}</div>
                <div style="font-size: 0.85em; color: #666;">${plugin.description || 'No description'}</div>
            </div>
            <div style="display: flex; align-items: center; gap: 10px;">
                <label style="display: flex; align-items: center; gap: 5px; cursor: pointer;" onclick="event.stopPropagation();">
                    <input type="checkbox" ${plugin.enabled ? 'checked' : ''} 
                           onchange="togglePlugin('${plugin.name}', this.checked)"
                           style="cursor: pointer;">
                    <span style="font-size: 0.85em; color: ${plugin.enabled ? '#4caf50' : '#888'};">
                        ${plugin.enabled ? 'Enabled' : 'Disabled'}
                    </span>
                </label>
            </div>
        </div>
    `).join('');

    document.querySelectorAll('#plugin-list .flow-item').forEach(item => {
        item.addEventListener('click', (e) => {
            const pluginName = e.currentTarget.dataset.pluginName;
            selectedPluginName = pluginName;
            renderPluginList();
            renderPluginConfig(pluginName);
        });
    });
}

function renderPluginConfig(pluginName) {
    const plugin = pluginsData.find(p => p.name === pluginName);
    if (!plugin || !pluginConfigEl) return;

    let configHtml = '';

    // Header Modifier Plugin
    if (pluginName === 'Header Modifier') {
        configHtml = `
            <div style="background: #f5f5f5; padding: 15px; border-radius: 4px; margin-bottom: 15px;">
                <h4 style="margin: 0 0 10px 0;">${plugin.name}</h4>
                <p style="margin: 0; color: #666;">${plugin.description || 'No description available'}</p>
            </div>
            <div style="display: flex; flex-direction: column; gap: 15px;">
                <div>
                    <label style="display: block; font-weight: 600; margin-bottom: 5px;">Add Headers (JSON)</label>
                    <textarea id="plugin-add-headers" style="width: 100%; height: 100px; padding: 8px; border: 1px solid #ddd; border-radius: 4px; font-family: 'Fira Code', monospace; font-size: 0.85em;">${JSON.stringify(plugin.config.add_headers || {}, null, 2)}</textarea>
                </div>
                <div>
                    <label style="display: block; font-weight: 600; margin-bottom: 5px;">Remove Headers (one per line)</label>
                    <textarea id="plugin-remove-headers" style="width: 100%; height: 80px; padding: 8px; border: 1px solid #ddd; border-radius: 4px; font-family: 'Fira Code', monospace; font-size: 0.85em;">${(plugin.config.remove_headers || []).join('\n')}</textarea>
                </div>
                <div>
                    <label style="display: block; font-weight: 600; margin-bottom: 5px;">Modify Headers (JSON)</label>
                    <textarea id="plugin-modify-headers" style="width: 100%; height: 100px; padding: 8px; border: 1px solid #ddd; border-radius: 4px; font-family: 'Fira Code', monospace; font-size: 0.85em;">${JSON.stringify(plugin.config.modify_headers || {}, null, 2)}</textarea>
                </div>
                <button onclick="savePluginConfig('${pluginName}')" class="btn btn-success" style="width: 100%; justify-content: center; margin-top: 10px;">
                    Save Configuration
                </button>
            </div>
        `;
    }
    // URL Blocklist Plugin
    else if (pluginName === 'URL Blocklist') {
        configHtml = `
            <div style="background: #f5f5f5; padding: 15px; border-radius: 4px; margin-bottom: 15px;">
                <h4 style="margin: 0 0 10px 0;">${plugin.name}</h4>
                <p style="margin: 0; color: #666;">${plugin.description || 'No description available'}</p>
            </div>
            <div style="display: flex; flex-direction: column; gap: 15px;">
                <div>
                    <label style="display: block; font-weight: 600; margin-bottom: 5px;">Block Patterns (regex, one per line)</label>
                    <textarea id="plugin-block-patterns" style="width: 100%; height: 120px; padding: 8px; border: 1px solid #ddd; border-radius: 4px; font-family: 'Fira Code', monospace; font-size: 0.85em;">${(plugin.config.block_patterns || []).join('\n')}</textarea>
                    <div style="font-size: 0.8em; color: #666; margin-top: 5px;">URLs matching these patterns will be blocked</div>
                </div>
                <div>
                    <label style="display: block; font-weight: 600; margin-bottom: 5px;">Allow Patterns (regex, one per line)</label>
                    <textarea id="plugin-allow-patterns" style="width: 100%; height: 120px; padding: 8px; border: 1px solid #ddd; border-radius: 4px; font-family: 'Fira Code', monospace; font-size: 0.85em;">${(plugin.config.allow_patterns || []).join('\n')}</textarea>
                    <div style="font-size: 0.8em; color: #666; margin-top: 5px;">URLs matching these patterns will always be allowed (whitelist)</div>
                </div>
                <button onclick="savePluginConfig('${pluginName}')" class="btn btn-success" style="width: 100%; justify-content: center; margin-top: 10px;">
                    Save Configuration
                </button>
            </div>
        `;
    }
    // Payload Injector Plugin
    else if (pluginName === 'Payload Injector') {
        configHtml = `
            <div style="background: #f5f5f5; padding: 15px; border-radius: 4px; margin-bottom: 15px;">
                <h4 style="margin: 0 0 10px 0;">${plugin.name}</h4>
                <p style="margin: 0; color: #666;">${plugin.description || 'No description available'}</p>
            </div>
            <div style="display: flex; flex-direction: column; gap: 15px;">
                <div>
                    <label style="display: block; font-weight: 600; margin-bottom: 5px;">Injection Points (parameter names, one per line)</label>
                    <textarea id="plugin-injection-points" style="width: 100%; height: 80px; padding: 8px; border: 1px solid #ddd; border-radius: 4px; font-family: 'Fira Code', monospace; font-size: 0.85em;">${(plugin.config.injection_points || []).join('\n')}</textarea>
                </div>
                <div>
                    <label style="display: block; font-weight: 600; margin-bottom: 5px;">Payloads (one per line)</label>
                    <textarea id="plugin-payloads" style="width: 100%; height: 120px; padding: 8px; border: 1px solid #ddd; border-radius: 4px; font-family: 'Fira Code', monospace; font-size: 0.85em;">${(plugin.config.payloads || []).join('\n')}</textarea>
                </div>
                <button onclick="savePluginConfig('${pluginName}')" class="btn btn-success" style="width: 100%; justify-content: center; margin-top: 10px;">
                    Save Configuration
                </button>
            </div>
        `;
    }
    else {
        configHtml = `
            <div style="background: #f5f5f5; padding: 15px; border-radius: 4px; margin-bottom: 15px;">
                <h4 style="margin: 0 0 10px 0;">${plugin.name}</h4>
                <p style="margin: 0; color: #666;">${plugin.description || 'No description available'}</p>
            </div>
            <div style="display: flex; flex-direction: column; gap: 15px;">
                <p style="color: #888;">Configuration interface not available for this plugin</p>
            </div>
        `;
    }

    pluginConfigEl.innerHTML = configHtml;
}

async function togglePlugin(pluginName, enabled) {
    try {
        const endpoint = enabled ? 'enable' : 'disable';
        const res = await fetch(`${API_BASE}/plugins/${encodeURIComponent(pluginName)}/${endpoint}`, {
            method: 'POST'
        });

        if (res.ok) {
            // Refresh plugins list
            await fetchPlugins();
        } else {
            const data = await res.json();
            alert(`Error: ${data.detail || 'Failed to toggle plugin'}`);
        }
    } catch (err) {
        console.error("Failed to toggle plugin", err);
        alert(`Error: ${err.message}`);
    }
}

async function savePluginConfig(pluginName) {
    try {
        const plugin = pluginsData.find(p => p.name === pluginName);
        if (!plugin) return;

        let config = {};

        if (pluginName === 'Header Modifier') {
            try {
                const addHeaders = JSON.parse(document.getElementById('plugin-add-headers').value);
                const removeHeaders = document.getElementById('plugin-remove-headers').value.split('\n').filter(h => h.trim());
                const modifyHeaders = JSON.parse(document.getElementById('plugin-modify-headers').value);

                config = {
                    add_headers: addHeaders,
                    remove_headers: removeHeaders,
                    modify_headers: modifyHeaders
                };
            } catch (e) {
                alert('Invalid JSON in headers configuration');
                return;
            }
        }
        else if (pluginName === 'URL Blocklist') {
            const blockPatterns = document.getElementById('plugin-block-patterns').value.split('\n').filter(p => p.trim());
            const allowPatterns = document.getElementById('plugin-allow-patterns').value.split('\n').filter(p => p.trim());

            config = {
                block_patterns: blockPatterns,
                allow_patterns: allowPatterns
            };
        }
        else if (pluginName === 'Payload Injector') {
            const injectionPoints = document.getElementById('plugin-injection-points').value.split('\n').filter(p => p.trim());
            const payloads = document.getElementById('plugin-payloads').value.split('\n').filter(p => p.trim());

            config = {
                injection_points: injectionPoints,
                payloads: payloads
            };
        }

        const res = await fetch(`${API_BASE}/plugins/${encodeURIComponent(pluginName)}/config`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        });

        if (res.ok) {
            alert('Configuration saved successfully!');
            await fetchPlugins();
            if (selectedPluginName === pluginName) {
                renderPluginConfig(pluginName);
            }
        } else {
            const data = await res.json();
            alert(`Error: ${data.detail || 'Failed to save configuration'}`);
        }
    } catch (err) {
        console.error("Failed to save plugin config", err);
        alert(`Error: ${err.message}`);
    }
}

if (refreshPluginsBtn) {
    refreshPluginsBtn.addEventListener('click', () => {
        fetchPlugins();
    });
}

// Initialize plugins
fetchPlugins();
setInterval(fetchPlugins, 5000);

// === RESIZE HANDLE ===
const resizeHandle = document.getElementById('resize-handle');
const flowListPanel = document.getElementById('flow-list-panel');
const detailPanel = document.getElementById('detail-panel');

let isResizing = false;
let startX = 0;
let startWidth = 0;

if (resizeHandle && flowListPanel && detailPanel) {
    resizeHandle.addEventListener('mousedown', (e) => {
        isResizing = true;
        startX = e.clientX;
        startWidth = flowListPanel.offsetWidth;
        resizeHandle.classList.add('active');
        document.body.style.cursor = 'col-resize';
        document.body.style.userSelect = 'none';
        e.preventDefault();
    });

    document.addEventListener('mousemove', (e) => {
        if (!isResizing) return;

        const diff = e.clientX - startX;
        const newWidth = startWidth + diff;
        const minWidth = 250;
        const maxWidth = window.innerWidth * 0.8;

        if (newWidth >= minWidth && newWidth <= maxWidth) {
            flowListPanel.style.width = `${newWidth}px`;
            flowListPanel.style.flexShrink = '0';
        }
    });

    document.addEventListener('mouseup', () => {
        if (isResizing) {
            isResizing = false;
            resizeHandle.classList.remove('active');
            document.body.style.cursor = '';
            document.body.style.userSelect = '';
        }
    });
}

// === API TESTER RESIZE HANDLE ===
const apiResizeHandle = document.getElementById('api-resize-handle');
const apiTesterSidebar = document.getElementById('api-tester-sidebar');
const apiTesterMain = document.querySelector('.api-tester-main');

let isApiResizing = false;
let apiStartX = 0;
let apiStartWidth = 0;

if (apiResizeHandle && apiTesterSidebar && apiTesterMain) {
    apiResizeHandle.addEventListener('mousedown', (e) => {
        isApiResizing = true;
        apiStartX = e.clientX;
        apiStartWidth = apiTesterSidebar.offsetWidth;
        apiResizeHandle.classList.add('active');
        document.body.style.cursor = 'col-resize';
        document.body.style.userSelect = 'none';
        e.preventDefault();
    });

    document.addEventListener('mousemove', (e) => {
        if (!isApiResizing) return;

        const diff = e.clientX - apiStartX;
        const newWidth = apiStartWidth + diff;
        const minWidth = 200;
        const maxWidth = window.innerWidth * 0.6; // Max 60% of window width

        if (newWidth >= minWidth && newWidth <= maxWidth) {
            apiTesterSidebar.style.width = `${newWidth}px`;
            apiTesterSidebar.style.flexShrink = '0';
        }
    });

    document.addEventListener('mouseup', () => {
        if (isApiResizing) {
            isApiResizing = false;
            apiResizeHandle.classList.remove('active');
            document.body.style.cursor = '';
            document.body.style.userSelect = '';
        }
    });
}

// === VISUALIZATION RESIZE HANDLE ===
const vizResizeHandle = document.getElementById('viz-resize-handle');
const vizDomainsSidebar = document.getElementById('viz-domains-sidebar');

let isVizResizing = false;
let vizStartX = 0;
let vizStartWidth = 0;

if (vizResizeHandle && vizDomainsSidebar) {
    vizResizeHandle.addEventListener('mousedown', (e) => {
        isVizResizing = true;
        vizStartX = e.clientX;
        vizStartWidth = vizDomainsSidebar.offsetWidth;
        vizResizeHandle.classList.add('active');
        document.body.style.cursor = 'col-resize';
        document.body.style.userSelect = 'none';
        e.preventDefault();
    });

    document.addEventListener('mousemove', (e) => {
        if (!isVizResizing) return;

        const diff = e.clientX - vizStartX;
        const newWidth = vizStartWidth + diff;
        const minWidth = 300;
        const maxWidth = window.innerWidth * 0.6; // Max 60% of window width

        if (newWidth >= minWidth && newWidth <= maxWidth) {
            vizDomainsSidebar.style.width = `${newWidth}px`;
            vizDomainsSidebar.style.flexShrink = '0';
        }
    });

    document.addEventListener('mouseup', () => {
        if (isVizResizing) {
            isVizResizing = false;
            vizResizeHandle.classList.remove('active');
            document.body.style.cursor = '';
            document.body.style.userSelect = '';
        }
    });
}

// === WEBSOCKET RESIZE HANDLE ===
const wsResizeHandle = document.getElementById('ws-resize-handle');
const wsListPanel = document.getElementById('ws-list-panel');
const wsDetailPanel = document.getElementById('ws-detail-panel');

let isWsResizing = false;
let wsStartX = 0;
let wsStartWidth = 0;

if (wsResizeHandle && wsListPanel && wsDetailPanel) {
    wsResizeHandle.addEventListener('mousedown', (e) => {
        isWsResizing = true;
        wsStartX = e.clientX;
        wsStartWidth = wsListPanel.offsetWidth;
        wsResizeHandle.classList.add('active');
        document.body.style.cursor = 'col-resize';
        document.body.style.userSelect = 'none';
        e.preventDefault();
    });

    document.addEventListener('mousemove', (e) => {
        if (!isWsResizing) return;

        const diff = e.clientX - wsStartX;
        const newWidth = wsStartWidth + diff;
        const minWidth = 250;
        const maxWidth = window.innerWidth * 0.8;

        if (newWidth >= minWidth && newWidth <= maxWidth) {
            wsListPanel.style.width = `${newWidth}px`;
            wsListPanel.style.flexShrink = '0';
        }
    });

    document.addEventListener('mouseup', () => {
        if (isWsResizing) {
            isWsResizing = false;
            wsResizeHandle.classList.remove('active');
            document.body.style.cursor = '';
            document.body.style.userSelect = '';
        }
    });
}

// === REPEATER RESIZE HANDLE ===
let repeaterResizeData = null;

function setupRepeaterResizeHandle(tabId) {
    const resizeHandle = document.getElementById(`repeater-resize-handle-${tabId}`);
    const editorPanel = document.getElementById(`repeater-editor-${tabId}`);
    const responsePanel = document.getElementById(`repeater-response-${tabId}`);

    if (!resizeHandle || !editorPanel || !responsePanel) return;

    // Supprimer les anciens event listeners s'ils existent
    const newResizeHandle = resizeHandle.cloneNode(true);
    resizeHandle.parentNode.replaceChild(newResizeHandle, resizeHandle);

    newResizeHandle.addEventListener('mousedown', (e) => {
        repeaterResizeData = {
            tabId,
            startX: e.clientX,
            startWidth: editorPanel.offsetWidth,
            containerWidth: editorPanel.parentElement.offsetWidth
        };
        newResizeHandle.classList.add('active');
        document.body.style.cursor = 'col-resize';
        document.body.style.userSelect = 'none';
        e.preventDefault();
    });
}

document.addEventListener('mousemove', (e) => {
    if (!repeaterResizeData) return;

    const { tabId, startX, startWidth, containerWidth } = repeaterResizeData;
    const editorPanel = document.getElementById(`repeater-editor-${tabId}`);
    const responsePanel = document.getElementById(`repeater-response-${tabId}`);

    if (!editorPanel || !responsePanel) {
        repeaterResizeData = null;
        return;
    }

    const diff = e.clientX - startX;
    const newWidth = Math.max(300, Math.min(containerWidth - 300, startWidth + diff));

    editorPanel.style.width = `${newWidth}px`;
    editorPanel.style.flexShrink = '0';
});

document.addEventListener('mouseup', () => {
    if (repeaterResizeData) {
        const resizeHandle = document.getElementById(`repeater-resize-handle-${repeaterResizeData.tabId}`);
        if (resizeHandle) {
            resizeHandle.classList.remove('active');
        }
        document.body.style.cursor = '';
        document.body.style.userSelect = '';
        repeaterResizeData = null;
    }
});

// === INTERCEPT RESIZE HANDLE ===
const interceptResizeHandle = document.getElementById('intercept-resize-handle');
const interceptFlowListPanel = document.getElementById('intercept-flow-list-panel');
const interceptDetailPanel = document.getElementById('intercept-detail-panel');

let isInterceptResizing = false;
let interceptStartX = 0;
let interceptStartWidth = 0;

if (interceptResizeHandle && interceptFlowListPanel && interceptDetailPanel) {
    interceptResizeHandle.addEventListener('mousedown', (e) => {
        isInterceptResizing = true;
        interceptStartX = e.clientX;
        interceptStartWidth = interceptFlowListPanel.offsetWidth;
        interceptResizeHandle.classList.add('active');
        document.body.style.cursor = 'col-resize';
        document.body.style.userSelect = 'none';
        e.preventDefault();
    });

    document.addEventListener('mousemove', (e) => {
        if (!isInterceptResizing) return;

        const diff = e.clientX - interceptStartX;
        const newWidth = interceptStartWidth + diff;
        const minWidth = 250;
        const maxWidth = window.innerWidth * 0.8;

        if (newWidth >= minWidth && newWidth <= maxWidth) {
            interceptFlowListPanel.style.width = `${newWidth}px`;
            interceptFlowListPanel.style.flexShrink = '0';
        }
    });

    document.addEventListener('mouseup', () => {
        if (isInterceptResizing) {
            isInterceptResizing = false;
            interceptResizeHandle.classList.remove('active');
            document.body.style.cursor = '';
            document.body.style.userSelect = '';
        }
    });
}

// === TECHNOLOGY DETECTION ===
const techDetectionBtn = document.getElementById('tech-detection-btn');
const endpointsBtn = document.getElementById('endpoints-btn');
const compareResponsesBtn = document.getElementById('compare-responses-btn');

if (techDetectionBtn) {
    techDetectionBtn.addEventListener('click', async () => {
        await showTechDetection();
    });
}

if (endpointsBtn) {
    endpointsBtn.addEventListener('click', () => {
        showDiscoveredEndpoints();
    });
}

if (compareResponsesBtn) {
    compareResponsesBtn.addEventListener('click', () => {
        showCompareDialog();
    });
}

async function showDiscoveredEndpoints() {
    try {
        const res = await fetch(`${API_BASE}/endpoints`);
        const data = await res.json();

        let html = '<div style="padding: 20px; max-width: 1200px; margin: 0 auto;">';
        html += '<h3 style="margin-top: 0; color: #6200ea; display: flex; align-items: center; gap: 10px;">';
        html += '<span class="material-symbols-outlined">link</span>';
        html += `Discovered Endpoints (${data.total || 0})</h3>`;

        // Statistiques par catégorie
        if (data.category_counts) {
            html += '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin-bottom: 20px;">';
            Object.entries(data.category_counts).forEach(([category, count]) => {
                if (count > 0) {
                    html += `<div style="background: #f5f5f5; padding: 10px; border-radius: 6px; text-align: center;">`;
                    html += `<div style="font-size: 1.5em; font-weight: 600; color: #6200ea;">${count}</div>`;
                    html += `<div style="font-size: 0.85em; color: #666; text-transform: capitalize;">${category.replace('_', ' ')}</div>`;
                    html += `</div>`;
                }
            });
            html += '</div>';
        }

        // Liste des endpoints
        if (data.endpoints && data.endpoints.length > 0) {
            html += '<div style="margin-bottom: 30px;">';
            html += '<h4 style="color: #666; margin-bottom: 10px;">Endpoints API</h4>';
            html += '<div style="background: white; border: 1px solid #ddd; border-radius: 8px; max-height: 400px; overflow-y: auto;">';

            data.endpoints.forEach((endpoint, index) => {
                const isApi = endpoint.includes('/api/') || endpoint.includes('/v') || endpoint.includes('/rest/');
                html += `<div style="padding: 10px 15px; border-bottom: 1px solid #eee; display: flex; align-items: center; gap: 10px; ${index % 2 === 0 ? 'background: #fafafa;' : ''}">`;
                html += `<span class="material-symbols-outlined" style="color: ${isApi ? '#4caf50' : '#2196f3'}; font-size: 20px;">${isApi ? 'api' : 'link'}</span>`;
                html += `<code style="flex: 1; font-family: 'Fira Code', monospace; font-size: 0.9em; color: #333;">${endpoint}</code>`;
                html += `<button onclick="testEndpoint('${endpoint}')" style="padding: 5px 10px; background: #6200ea; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85em;">Test</button>`;
                html += `</div>`;
            });

            html += '</div></div>';
        }

        // Liste des liens
        if (data.links && data.links.length > 0) {
            html += '<div>';
            html += '<h4 style="color: #666; margin-bottom: 10px;">Discovered Links</h4>';
            html += '<div style="background: white; border: 1px solid #ddd; border-radius: 8px; max-height: 400px; overflow-y: auto;">';

            data.links.slice(0, 100).forEach((link, index) => {
                html += `<div style="padding: 8px 15px; border-bottom: 1px solid #eee; ${index % 2 === 0 ? 'background: #fafafa;' : ''}">`;
                html += `<a href="${link}" target="_blank" style="color: #2196f3; text-decoration: none; font-family: 'Fira Code', monospace; font-size: 0.9em;">${link}</a>`;
                html += `</div>`;
            });

            if (data.links.length > 100) {
                html += `<div style="padding: 10px; text-align: center; color: #666;">... et ${data.links.length - 100} autres liens</div>`;
            }

            html += '</div></div>';
        }

        if ((!data.endpoints || data.endpoints.length === 0) && (!data.links || data.links.length === 0)) {
            html += '<div style="text-align: center; padding: 40px; color: #888;">No endpoints discovered yet. Browse the site to discover endpoints.</div>';
        }

        html += '</div>';

        detailContentEl.innerHTML = html;
    } catch (err) {
        console.error("Failed to fetch endpoints", err);
        detailContentEl.innerHTML = '<div style="padding: 20px; color: #f44336;">Error loading endpoints</div>';
    }
}

function testEndpoint(endpoint) {
    // Ouvrir dans un nouvel onglet ou faire une requête
    window.open(endpoint, '_blank');
}

async function fetchModuleSuggestions(techCounts, configsSet) {
    const techList = [];
    Object.values(techCounts || {}).forEach(obj => {
        Object.keys(obj || {}).forEach(t => techList.push(t));
    });
    const configs = Array.from(configsSet || []);

    try {
        const res = await fetch(`${API_BASE}/modules/suggestions`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                technologies: techList,
                configurations: configs
            })
        });
        if (res.ok) {
            return await res.json();
        }
    } catch (err) {
        console.warn('Failed to fetch module suggestions', err);
    }
    return [];
}


async function showTechDetection() {
    // Compter les technologies détectées et collecter les fingerprints
    const techCounts = {
        frameworks: {},
        cms: {},
        servers: {},
        languages: {},
        security: {},
    };

    const allFingerprints = [];
    const allSuggestions = [];
    const vulnerabilities = [];
    const configs = new Set();
    const suggestionFlowMap = new Map();

    const findFlowForModule = (moduleName) => {
        if (!moduleName) return null;
        const normalized = moduleName.toLowerCase();
        return flowsData.find(flow => {
            const techs = flow.technologies || {};
            return Object.values(techs).some(arr =>
                (arr || []).some(tech => normalized.includes(String(tech).toLowerCase()))
            );
        }) || null;
    };

    flowsData.forEach(flow => {
        const techs = flow.technologies || {};
        Object.keys(techCounts).forEach(category => {
            (techs[category] || []).forEach(tech => {
                techCounts[category][tech] = (techCounts[category][tech] || 0) + 1;
            });
        });

        // Collecter les fingerprints
        if (flow.fingerprint) {
            allFingerprints.push(flow.fingerprint);
            if (flow.fingerprint.vulnerabilities) {
                vulnerabilities.push(...flow.fingerprint.vulnerabilities);
            }
            (flow.fingerprint.configurations || []).forEach(cfg => {
                if (!cfg) return;
                const description = typeof cfg === 'string' ? cfg : (cfg.description || '');
                if (description) {
                    configs.add(description);
                }
            });
        }

        // Collecter les suggestions
        if (flow.module_suggestions) {
            flow.module_suggestions.forEach(sugg => {
                allSuggestions.push(sugg);
                if (sugg?.module && flow.id && !suggestionFlowMap.has(sugg.module)) {
                    suggestionFlowMap.set(sugg.module, flow.id);
                }
            });
        }
    });

    // Récupérer des suggestions dynamiques côté backend
    const backendSuggestions = await fetchModuleSuggestions(techCounts, configs);
    if (Array.isArray(backendSuggestions)) {
        backendSuggestions.forEach(sugg => {
            allSuggestions.push(sugg);
            if (sugg?.module && !suggestionFlowMap.has(sugg.module)) {
                const mappedFlow = findFlowForModule(sugg.module) || (currentFlowId ? flowsData.find(f => f.id === currentFlowId) : flowsData[0]);
                if (mappedFlow?.id) {
                    suggestionFlowMap.set(sugg.module, mappedFlow.id);
                }
            }
        });
    }

    // Créer le HTML
    let html = '<div style="padding: 20px; max-width: 1200px; margin: 0 auto;">';
    html += '<h2 style="margin-top: 0; color: #6200ea; display: flex; align-items: center; gap: 10px;">';
    html += '<span class="material-symbols-outlined" style="font-size: 28px;">fingerprint</span>';
    html += 'Reconnaissance Automatique & Fingerprinting</h2>';

    // Technologies détectées
    html += '<div style="background: white; border-radius: 12px; padding: 24px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">';
    html += '<h3 style="margin-top: 0; color: #333; display: flex; align-items: center; gap: 8px;">';
    html += '<span class="material-symbols-outlined" style="font-size: 20px;">apps</span>';
    html += 'Detected Technologies</h3>';

    Object.keys(techCounts).forEach(category => {
        const techs = techCounts[category];
        if (Object.keys(techs).length > 0) {
            html += `<div style="margin-bottom: 16px;">`;
            html += `<h4 style="color: #666; text-transform: capitalize; margin-bottom: 8px; font-size: 14px; font-weight: 600;">${category}</h4>`;
            html += '<div style="display: flex; flex-wrap: wrap; gap: 8px;">';
            Object.entries(techs).sort((a, b) => b[1] - a[1]).forEach(([tech, count]) => {
                html += `<span style="background: linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%); color: #1976d2; padding: 8px 12px; border-radius: 6px; font-weight: 500; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">${tech} <span style="opacity: 0.7;">(${count})</span></span>`;
            });
            html += '</div></div>';
        }
    });
    html += '</div>';

    // Versions détectées
    const versions = {};
    allFingerprints.forEach(fp => {
        Object.entries(fp.versions || {}).forEach(([tech, vers]) => {
            if (!versions[tech]) versions[tech] = new Set();
            vers.forEach(v => versions[tech].add(v.version));
        });
    });

    if (Object.keys(versions).length > 0) {
        html += '<div style="background: white; border-radius: 12px; padding: 24px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">';
        html += '<h3 style="margin-top: 0; color: #333; display: flex; align-items: center; gap: 8px;">';
        html += '<span class="material-symbols-outlined" style="font-size: 20px;">tag</span>';
        html += 'Detected Versions</h3>';
        html += '<div style="display: flex; flex-wrap: wrap; gap: 8px;">';
        Object.entries(versions).forEach(([tech, vers]) => {
            Array.from(vers).forEach(version => {
                html += `<span style="background: linear-gradient(135deg, #fff3e0 0%, #ffe0b2 100%); color: #e65100; padding: 8px 12px; border-radius: 6px; font-weight: 500; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">${tech} ${version}</span>`;
            });
        });
        html += '</div></div>';
    }

    if (configs.size > 0) {
        html += '<div style="background: white; border-radius: 12px; padding: 24px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">';
        html += '<h3 style="margin-top: 0; color: #333; display: flex; align-items: center; gap: 8px;">';
        html += '<span class="material-symbols-outlined" style="font-size: 20px;">settings</span>';
        html += 'Detected Configurations</h3>';
        html += '<div style="display: flex; flex-wrap: wrap; gap: 8px;">';
        Array.from(configs).forEach(cfg => {
            html += `<span style="background: linear-gradient(135deg, #f3e5f5 0%, #e1bee7 100%); color: #7b1fa2; padding: 8px 12px; border-radius: 6px; font-weight: 500; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">${cfg}</span>`;
        });
        html += '</div></div>';
    }

    // Fonctionnalités de sécurité
    const securityFeatures = new Set();
    allFingerprints.forEach(fp => {
        (fp.security_features || []).forEach(feat => {
            securityFeatures.add(feat.description);
        });
    });

    if (securityFeatures.size > 0) {
        html += '<div style="background: white; border-radius: 12px; padding: 24px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">';
        html += '<h3 style="margin-top: 0; color: #333; display: flex; align-items: center; gap: 8px;">';
        html += '<span class="material-symbols-outlined" style="font-size: 20px;">security</span>';
        html += 'Security Features</h3>';
        html += '<div style="display: flex; flex-wrap: wrap; gap: 8px;">';
        Array.from(securityFeatures).forEach(feat => {
            html += `<span style="background: linear-gradient(135deg, #e8f5e9 0%, #c8e6c9 100%); color: #2e7d32; padding: 8px 12px; border-radius: 6px; font-weight: 500; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">${feat}</span>`;
        });
        html += '</div></div>';
    }

    // Vulnérabilités détectées
    if (vulnerabilities.length > 0) {
        html += '<div style="background: linear-gradient(135deg, #ffebee 0%, #ffcdd2 100%); border-radius: 12px; padding: 24px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); border-left: 4px solid #f44336;">';
        html += '<h3 style="margin-top: 0; color: #c62828; display: flex; align-items: center; gap: 8px;">';
        html += '<span class="material-symbols-outlined" style="font-size: 20px;">warning</span>';
        html += 'Potential Vulnerabilities</h3>';
        vulnerabilities.forEach(vuln => {
            const severityColor = vuln.severity === 'high' ? '#d32f2f' : '#f57c00';
            html += `<div style="background: white; padding: 12px; border-radius: 8px; margin-bottom: 8px; border-left: 3px solid ${severityColor};">`;
            html += `<div style="font-weight: 600; color: #333; margin-bottom: 4px;">${vuln.technology} ${vuln.version || ''}</div>`;
            html += `<div style="color: #666; font-size: 14px;">${vuln.description}</div>`;
            html += `<div style="margin-top: 4px;"><span style="background: ${severityColor}; color: white; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 500;">${vuln.severity.toUpperCase()}</span></div>`;
            html += `</div>`;
        });
        html += '</div>';
    }

    // Suggestions de modules
    if (allSuggestions.length > 0) {
        // Grouper et trier les suggestions
        const suggestionMap = new Map();
        allSuggestions.forEach(sugg => {
            const module = sugg.module;
            if (!suggestionMap.has(module)) {
                suggestionMap.set(module, {
                    module: module,
                    score: 0,
                    reasons: new Set(),
                    priority: 'low'
                });
            }
            const existing = suggestionMap.get(module);
            existing.score += sugg.score || 0;
            (sugg.reasons || []).forEach(r => existing.reasons.add(r));
            if (sugg.priority === 'high' || (sugg.priority === 'medium' && existing.priority === 'low')) {
                existing.priority = sugg.priority;
            }
        });

        const sortedSuggestions = Array.from(suggestionMap.values())
            .sort((a, b) => b.score - a.score)
            .slice(0, 10);

        html += '<div style="background: white; border-radius: 12px; padding: 24px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">';
        html += '<h3 style="margin-top: 0; color: #333; display: flex; align-items: center; gap: 8px;">';
        html += '<span class="material-symbols-outlined" style="font-size: 20px;">lightbulb</span>';
        html += `Suggestions de Modules (${sortedSuggestions.length})</h3>`;
        html += '<p style="color: #666; margin-bottom: 16px; font-size: 14px;">Suggested modules based on detected technologies</p>';

        sortedSuggestions.forEach((sugg, index) => {
            const priorityColor = sugg.priority === 'high' ? '#f44336' : sugg.priority === 'medium' ? '#ff9800' : '#4caf50';
            const suggestionFlowId = suggestionFlowMap.get(sugg.module) || currentFlowId || (flowsData[0]?.id || '');
            const safeModuleAttr = (sugg.module || '').replace(/'/g, "\\'");
            const safeFlowAttr = suggestionFlowId ? suggestionFlowId.replace(/'/g, "\\'") : '';
            html += `<div style="background: #f8f9fa; padding: 16px; border-radius: 8px; margin-bottom: 12px; border-left: 4px solid ${priorityColor}; cursor: pointer;"
                onmouseover="this.style.background='#f0f0f0'"
                onmouseout="this.style.background='#f8f9fa'"
                onclick="openModuleSuggestion('${safeModuleAttr}', '${safeFlowAttr}')">`;
            html += `<div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 8px;">`;
            html += `<div style="flex: 1;">`;
            html += `<div style="font-weight: 600; color: #333; margin-bottom: 4px;">${sugg.module}</div>`;
            html += `<div style="font-size: 12px; color: #666;">Score: ${sugg.score} | Priorité: <span style="color: ${priorityColor}; font-weight: 500;">${sugg.priority.toUpperCase()}</span></div>`;
            html += `</div>`;
            html += `<span style="background: ${priorityColor}; color: white; padding: 4px 12px; border-radius: 12px; font-size: 11px; font-weight: 500;">#${index + 1}</span>`;
            html += `</div>`;
            if (sugg.reasons.size > 0) {
                html += `<div style="margin-top: 8px; padding-top: 8px; border-top: 1px solid #e0e0e0;">`;
                html += `<div style="font-size: 12px; color: #666; margin-bottom: 4px;">Raisons:</div>`;
                html += '<div style="display: flex; flex-wrap: wrap; gap: 4px;">';
                Array.from(sugg.reasons).slice(0, 3).forEach(reason => {
                    html += `<span style="background: #e3f2fd; color: #1976d2; padding: 4px 8px; border-radius: 4px; font-size: 11px;">${reason}</span>`;
                });
                html += '</div></div>';
            }
            html += `</div>`;
        });
        html += '</div>';
    }

    html += '</div>';

    detailContentEl.innerHTML = html;
}

async function openModuleSuggestion(modulePath, flowId = null) {
    // Helpers: load a module on-demand when it's not in the cached list
    const encodeModulePathForApi = (p) => {
        try {
            return String(p || '')
                .split('/')
                .map(seg => encodeURIComponent(seg))
                .join('/');
        } catch (e) {
            return String(p || '');
        }
    };

    const ensureModuleInModulesData = async (p) => {
        const wanted = String(p || '');
        if (!wanted) return null;

        // Already present in list
        const existing = modulesData.find(m => m && m.name === wanted);
        if (existing) return existing;

        // Try to fetch full info from backend (works even if module not in "web" cache)
        try {
            const res = await fetch(`${API_BASE}/modules/${encodeModulePathForApi(wanted)}`);
            if (!res.ok) return null;
            const info = await res.json();

            if (info && info.name) {
                // Normalize shape + add minimal fields expected by the UI
                const moduleObj = {
                    name: info.name,
                    description: info.description || 'No description available',
                    author: info.author || 'Unknown',
                    category: (String(info.name).split('/')[0] || 'misc'),
                    options: Array.isArray(info.options) ? info.options : [],
                    tags: info.tags || []
                };
                modulesData.push(moduleObj);
                return moduleObj;
            }
        } catch (err) {
            console.warn('[MODULE] Failed to fetch module info for suggestion:', err);
        }

        return null;
    };

    // Utiliser le flowId fourni ou le currentFlowId
    const targetFlowId = flowId || currentFlowId;
    let flow = targetFlowId ? flowsData.find(f => f.id === targetFlowId) : null;

    if (!flow && targetFlowId) {
        try {
            const res = await fetch(`${API_BASE}/flows/${targetFlowId}`);
            if (res.ok) {
                const fetchedFlow = await res.json();
                flow = fetchedFlow;
                const existingIndex = flowsData.findIndex(f => f.id === targetFlowId);
                if (existingIndex !== -1) {
                    flowsData[existingIndex] = { ...flowsData[existingIndex], ...fetchedFlow };
                } else {
                    flowsData.push(fetchedFlow);
                }
            } else {
                console.warn(`[MODULE] Unable to fetch flow details (${res.status}) for ${targetFlowId}`);
            }
        } catch (err) {
            console.warn('[MODULE] Failed to fetch flow details for suggestion:', err);
        }
    }

    // Fallback: premier flow avec URL si le flow lié à la suggestion n'en a pas
    const flowWithUrl = (flow && flow.url) ? flow : (flowsData.find(f => f && f.url) || null);
    const urlToUse = flowWithUrl && (flowWithUrl.url || flowWithUrl.request?.url);

    console.log('[MODULE] Opening module suggestion:', modulePath, 'for flow:', targetFlowId, urlToUse || '(no URL)');

    const modulesTab = document.querySelector('[data-view="modules"]');
    if (!modulesTab) {
        console.error('[MODULE] Modules tab not found');
        return;
    }

    modulesTab.click();

    // Laisser l'onglet et le rendu se stabiliser (comme selectModuleFromFlow)
    await new Promise(r => setTimeout(r, 100));

    if (moduleSearchInput) {
        moduleSearchInput.value = '';
        moduleSearchTerm = '';
    }

    if (modulesData.length === 0 && typeof fetchModules === 'function') {
        await fetchModules();
    } else if (typeof renderModuleList === 'function') {
        renderModuleList();
    }

    const ensured = await ensureModuleInModulesData(modulePath);
    if (!ensured) {
        showToast(`Module introuvable dans la liste: ${modulePath}`, 'error');
        if (moduleConfigEl) {
            moduleConfigEl.innerHTML = `
                <div style="padding: 20px;">
                    <h4 style="margin: 0 0 10px 0; color: #d32f2f;">Module not available</h4>
                    <p style="margin: 0; color: #666;">
                        Le module <code style="font-family:'Fira Code', monospace;">${escapeHtml(String(modulePath || ''))}</code>
                        n'est pas disponible dans le cache actuel et n'a pas pu être chargé automatiquement.
                    </p>
                    <p style="margin: 10px 0 0 0; color: #888; font-size: 0.9em;">
                        Astuce: vérifiez que le module existe côté framework et que Kittyproxy peut l'importer (voir <code>/api/modules/debug</code>).
                    </p>
                </div>
            `;
        }
        return;
    }

    const resolvedModuleName = ensured?.name || modulePath;
    selectedModuleId = resolvedModuleName;
    if (typeof renderModuleList === 'function') renderModuleList();
    if (typeof renderModuleConfig === 'function') renderModuleConfig(resolvedModuleName);

    // Attendre que le panneau config soit rendu (comme selectModuleFromFlow)
    await new Promise(r => setTimeout(r, 200));

    const targetUrlInput = document.getElementById('module-target-url');
    if (targetUrlInput && urlToUse) {
        targetUrlInput.value = urlToUse;
        targetUrlInput.dispatchEvent(new Event('input', { bubbles: true }));

        try {
            await autoConfigureModuleFromUrl(resolvedModuleName, true);
            const moduleOutput = document.getElementById('module-output');
            if (moduleOutput) {
                moduleOutput.style.display = 'block';
                moduleOutput.style.color = '#2196f3';
                moduleOutput.style.background = '#e3f2fd';
                moduleOutput.style.border = '1px solid #90caf9';
                moduleOutput.style.padding = '12px';
                moduleOutput.textContent = `✓ Module préconfiguré pour: ${urlToUse}\nCliquez sur "Run Module" pour lancer.`;
                moduleOutput.scrollTop = moduleOutput.scrollHeight;
            }
        } catch (err) {
            console.error('[MODULE] Auto-config error:', err);
        }
    }

    const item = document.querySelector(`#module-list .flow-item[data-module-id="${CSS.escape(resolvedModuleName)}"]`);
    if (item) item.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function showCompareDialog() {
    if (flowsData.length < 2) {
        alert('You need at least 2 requests to compare');
        return;
    }

    // Simple comparaison - on peut améliorer ça
    const selectedFlows = flowsData.slice(0, 2); // Prendre les 2 premières pour l'exemple

    let html = '<div style="padding: 20px;">';
    html += '<h3 style="margin-top: 0; color: #6200ea;">Response Comparison</h3>';
    html += '<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">';

    selectedFlows.forEach((flow, index) => {
        html += `<div style="border: 1px solid #ddd; border-radius: 8px; padding: 15px;">`;
        html += `<h4 style="margin-top: 0;">Request ${index + 1}</h4>`;
        html += `<p><strong>URL:</strong> ${flow.url}</p>`;
        html += `<p><strong>Status:</strong> ${flow.status_code || 'N/A'}</p>`;
        html += `<p><strong>Method:</strong> ${flow.method}</p>`;
        if (flow.technologies) {
            const allTechs = [
                ...(flow.technologies.frameworks || []),
                ...(flow.technologies.cms || []),
            ];
            if (allTechs.length > 0) {
                html += `<p><strong>Technologies:</strong> ${allTechs.join(', ')}</p>`;
            }
        }
        html += `</div>`;
    });

    html += '</div>';
    html += '<p style="margin-top: 20px; color: #666; font-style: italic;">Feature under development - Detailed comparison coming soon</p>';
    html += '</div>';

    detailContentEl.innerHTML = html;
}

// === VISUALIZATION ===
const visualizationContent = document.getElementById('visualization-content');
let currentVizTab = 'dependencies';

// Initialize visualization tabs
const vizTabs = document.querySelectorAll('[data-viz-tab]');
vizTabs.forEach(tab => {
    tab.addEventListener('click', () => {
        const tabName = tab.dataset.vizTab;
        switchVizTab(tabName);
    });
});

// Initialize domain filter
const vizDomainFilter = document.getElementById('viz-domain-filter');
if (vizDomainFilter) {
    vizDomainFilter.addEventListener('input', (e) => {
        domainFilterTerm = e.target.value;
        renderDomainsList();
    });
}

// Load domains when visualization view is opened
const visualizeView = document.getElementById('visualize-view');
if (visualizeView) {
    // Watch for when the view becomes visible
    const observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
            if (mutation.type === 'attributes' && mutation.attributeName === 'style') {
                const isVisible = visualizeView.style.display !== 'none';
                if (isVisible) {
                    // Extract and display domains
                    extractAndDisplayDomains();
                }
            }
        });
    });
    observer.observe(visualizeView, { attributes: true, attributeFilter: ['style'] });
}


// Variable globale pour stocker les données de dépendances
let dependenciesGlobalData = null;
let selectedDomainForGraph = null;
let domainsList = []; // Liste des domaines avec statistiques
let domainFilterTerm = ''; // Terme de filtre pour les domaines

function getCurrentVizPanel() {
    const activePanel = document.querySelector('.viz-panel.active');
    return activePanel || document.getElementById('viz-panel-dependencies');
}

// Extraire et afficher les domaines
function extractAndDisplayDomains() {
    const domainsMap = new Map();

    // Analyser tous les flows pour extraire les domaines
    flowsData.forEach(flow => {
        try {
            const url = new URL(flow.url);
            const domain = url.hostname;

            if (!domainsMap.has(domain)) {
                domainsMap.set(domain, {
                    domain: domain,
                    requestCount: 0,
                    statusCodes: {},
                    methods: new Set(),
                    endpoints: new Set(), // Pour compter les endpoints uniques
                    discoveredEndpoints: new Set(), // Endpoints découverts mais non chargés
                    lastRequest: null
                });
            }

            const domainData = domainsMap.get(domain);
            domainData.requestCount++;

            // Compter les endpoints (paths uniques)
            const path = url.pathname;
            if (path && path !== '/') {
                domainData.endpoints.add(path);
            }

            // Compter les endpoints découverts
            if (flow.endpoints) {
                Object.values(flow.endpoints).flat().forEach(endpoint => {
                    try {
                        const endpointUrl = new URL(endpoint, flow.url);
                        if (endpointUrl.hostname === domain) {
                            domainData.discoveredEndpoints.add(endpointUrl.pathname);
                        }
                    } catch (e) {
                        // URL invalide, ignorer
                    }
                });
            }

            if (flow.status_code) {
                const statusGroup = Math.floor(flow.status_code / 100);
                domainData.statusCodes[statusGroup] = (domainData.statusCodes[statusGroup] || 0) + 1;
            }

            if (flow.method) {
                domainData.methods.add(flow.method);
            }

            if (!domainData.lastRequest || (flow.timestamp_start && flow.timestamp_start > domainData.lastRequest)) {
                domainData.lastRequest = flow.timestamp_start;
            }
        } catch (e) {
            // URL invalide, ignorer
        }
    });

    // Convertir en tableau et trier par nombre de requêtes
    domainsList = Array.from(domainsMap.values())
        .map(d => ({
            ...d,
            methods: Array.from(d.methods),
            endpointCount: d.endpoints.size,
            discoveredEndpointCount: d.discoveredEndpoints.size
        }))
        .sort((a, b) => b.requestCount - a.requestCount);

    // Afficher dans la sidebar
    renderDomainsList();
}

function renderDomainsList() {
    const domainsListEl = document.getElementById('viz-domains-list');
    if (!domainsListEl) return;

    // Filtrer les domaines selon le terme de recherche
    const filteredDomains = domainFilterTerm
        ? domainsList.filter(d => d.domain.toLowerCase().includes(domainFilterTerm.toLowerCase()))
        : domainsList;

    if (filteredDomains.length === 0) {
        domainsListEl.innerHTML = '<div style="text-align: center; padding: 50px; color: #888; font-size: 0.9rem;">Aucun domaine trouvé</div>';
        return;
    }

    domainsListEl.innerHTML = filteredDomains.map(domainData => {
        const isSelected = selectedDomainForGraph === domainData.domain;
        const successCount = domainData.statusCodes[2] || 0;
        const errorCount = (domainData.statusCodes[4] || 0) + (domainData.statusCodes[5] || 0);

        return `
            <div class="domain-item ${isSelected ? 'active' : ''}" 
                 data-domain="${escapeHtml(domainData.domain)}" 
                 style="padding: 16px; cursor: pointer; border-radius: 10px; margin-bottom: 12px; transition: all 0.2s; border: 2px solid ${isSelected ? 'var(--primary-color)' : '#e0e0e0'}; background: ${isSelected ? '#f3e5f5' : '#ffffff'}; box-shadow: ${isSelected ? '0 3px 12px rgba(98, 0, 234, 0.2)' : '0 2px 6px rgba(0,0,0,0.1)'}; position: relative;"
                 onclick="selectDomain('${escapeHtml(domainData.domain)}')">
                <div style="font-weight: 600; color: ${isSelected ? 'var(--primary-color)' : '#333'}; margin-bottom: 10px; font-size: 0.95rem; word-break: break-word; line-height: 1.4;">
                    ${escapeHtml(domainData.domain)}
                </div>
                <div style="display: flex; flex-wrap: wrap; gap: 12px; font-size: 0.75rem; color: #666; margin-bottom: 8px;">
                    <span style="display: flex; align-items: center; gap: 4px;"><strong>${domainData.requestCount}</strong> requests</span>
                    <span style="display: flex; align-items: center; gap: 4px;"><strong>${domainData.endpointCount || 0}</strong> endpoints</span>
                    ${domainData.discoveredEndpointCount > 0 ? `<span style="color: #ff9800; display: flex; align-items: center; gap: 4px;"><strong>${domainData.discoveredEndpointCount}</strong> discovered</span>` : ''}
                    ${successCount > 0 ? `<span style="color: #4caf50; display: flex; align-items: center; gap: 4px;"><strong>${successCount}</strong> OK</span>` : ''}
                    ${errorCount > 0 ? `<span style="color: #f44336; display: flex; align-items: center; gap: 4px;"><strong>${errorCount}</strong> errors</span>` : ''}
                </div>
                <div style="font-size: 0.7rem; color: #999; margin-top: 6px; display: flex; flex-wrap: wrap; gap: 4px;">
                    ${domainData.methods.map(m => `<span style="background: #f0f0f0; padding: 3px 8px; border-radius: 4px; font-weight: 500;">${m}</span>`).join('')}
                </div>
            </div>
        `;
    }).join('');
}

function selectDomain(domain) {
    selectedDomainForGraph = domain;
    renderDomainsList();

    // Recharger la visualisation active
    switchVizTab(currentVizTab, true);
}

// Make selectDomain globally accessible
window.selectDomain = selectDomain;

// Modifier switchVizTab pour accepter un paramètre de rechargement
function switchVizTab(tabName, forceReload = false) {
    // Update active tab
    vizTabs.forEach(t => t.classList.remove('active'));
    document.querySelector(`[data-viz-tab="${tabName}"]`).classList.add('active');

    // Update active panel
    document.querySelectorAll('.viz-panel').forEach(p => {
        p.style.display = 'none';
        p.classList.remove('active');
    });

    const activePanel = document.getElementById(`viz-panel-${tabName}`);
    if (activePanel) {
        activePanel.style.display = 'block';
        activePanel.classList.add('active');
    }

    currentVizTab = tabName;

    // Load content for the selected tab (only if domain is selected or forceReload)
    if (selectedDomainForGraph || forceReload) {
        switch (tabName) {
            case 'dependencies':
                showDependenciesGraph();
                break;
            case 'timeline':
                showTimeline();
                break;
            case 'heatmap':
                showHeatmap();
                break;
            case 'navigation':
                showNavigationTree();
                break;
        }
    }
}

// Fonction pour détecter le type de fichier depuis une URL
function getFileTypeFromUrl(url) {
    if (!url) return 'other';

    const urlLower = url.toLowerCase();
    const path = urlLower.split('?')[0]; // Enlever les query params

    // Images
    if (/\.(svg|png|jpg|jpeg|gif|webp|bmp|ico)$/i.test(path)) {
        return 'image';
    }

    // JavaScript
    if (/\.(js|mjs)$/i.test(path)) {
        return 'javascript';
    }

    // CSS
    if (/\.css$/i.test(path)) {
        return 'css';
    }

    // HTML
    if (/\.(html|htm)$/i.test(path)) {
        return 'html';
    }

    // JSON
    if (/\.json$/i.test(path)) {
        return 'json';
    }

    // Fonts
    if (/\.(woff|woff2|ttf|otf|eot)$/i.test(path)) {
        return 'font';
    }

    // Videos
    if (/\.(mp4|webm|ogg|avi|mov)$/i.test(path)) {
        return 'video';
    }

    // Audio
    if (/\.(mp3|wav|ogg|aac)$/i.test(path)) {
        return 'audio';
    }

    // PDF
    if (/\.pdf$/i.test(path)) {
        return 'pdf';
    }

    // XML
    if (/\.xml$/i.test(path)) {
        return 'xml';
    }

    return 'other';
}

// Fonction pour valider si un endpoint est valide (filtre les faux positifs)
function isValidEndpoint(path) {
    if (!path || path.length < 2) {
        return false;
    }

    // Exclure les fragments, data URIs, mailto, etc.
    if (path.startsWith('#') || path.startsWith('data:') || path.startsWith('mailto:') || path.startsWith('javascript:')) {
        return false;
    }

    // Exclure spécifiquement les faux positifs JavaScript courants
    const pathLower = path.toLowerCase().trim();
    if (pathLower === 'javascript:;' || pathLower === 'javascript:void(0)' || pathLower === 'javascript:void(0);' || pathLower === 'javascript:' || pathLower === 'javascript: ') {
        return false;
    }

    // Vérifier les chemins qui commencent par /
    if (path.startsWith('/')) {
        // Exclure les chemins trop courts (moins de 2 caractères après le /)
        // Sauf pour les chemins racine comme /api, /v1, etc.
        const pathPart = path.substring(1).split('?')[0].split('#')[0];
        if (pathPart.length < 2 && !['', 'api', 'v1', 'v2', 'v3', 'v4', 'v5'].includes(pathPart)) {
            return false;
        }

        // Exclure les chemins qui commencent par des caractères suspects
        // Comme /-u, /[QÜV, etc.
        if (pathPart.length > 0) {
            const firstChar = pathPart[0];
            // Vérifier si le premier caractère est suspect (non-alphanumérique sauf _-.)
            if (!/[a-zA-Z0-9._-]/.test(firstChar)) {
                return false;
            }

            // Exclure les chemins avec trop de caractères encodés consécutifs
            const encodedPattern = /%[0-9A-Fa-f]{2}%[0-9A-Fa-f]{2}%[0-9A-Fa-f]{2}%[0-9A-Fa-f]{2}/;
            if (encodedPattern.test(path)) {
                return false;
            }
        }
    }

    return true;
}

async function showDependenciesGraph() {
    const panel = getCurrentVizPanel();
    if (!panel) return;

    // Afficher un indicateur de chargement
    panel.innerHTML = '<div style="padding: 40px; text-align: center; color: #666;">Loading dependency graph...</div>';

    // Récupérer le flow sélectionné pour utiliser uniquement ses endpoints
    let selectedFlow = null;
    if (currentFlowId) {
        // Chercher dans le cache d'abord
        selectedFlow = flowsData.find(f => f.id === currentFlowId);

        // Si pas trouvé ou si le flow n'a pas tous les détails, le récupérer
        if (!selectedFlow || !selectedFlow.endpoints) {
            try {
                const res = await fetch(`${API_BASE}/flows/${currentFlowId}`);
                if (res.ok) {
                    selectedFlow = await res.json();
                    // Mettre à jour le cache
                    const index = flowsData.findIndex(f => f.id === currentFlowId);
                    if (index !== -1) {
                        flowsData[index] = selectedFlow;
                    }
                }
            } catch (e) {
                console.error("Failed to fetch selected flow", e);
            }
        }
    }

    // Récupérer les endpoints uniquement du flow sélectionné
    let flowEndpoints = [];
    if (selectedFlow) {
        // Utiliser flow.discovered_endpoints (liste aplatie) et flow.endpoints (dictionnaire catégorisé)
        flowEndpoints = selectedFlow.discovered_endpoints || [];

        // Si flow.endpoints existe, extraire tous les endpoints depuis toutes les catégories
        if (selectedFlow.endpoints && typeof selectedFlow.endpoints === 'object') {
            const endpointsFromDict = [];
            Object.values(selectedFlow.endpoints).forEach(categoryEndpoints => {
                if (Array.isArray(categoryEndpoints)) {
                    endpointsFromDict.push(...categoryEndpoints);
                }
            });
            // Combiner avec discovered_endpoints et dédupliquer
            flowEndpoints = [...new Set([...flowEndpoints, ...endpointsFromDict])];
        }
    }

    // Construire le graphe de dépendances avec données complètes
    const cyElements = [];
    const nodes = new Map();
    const edges = [];
    const edgeKeys = new Set(); // Pour éviter les doublons d'arêtes
    const nodeFlows = new Map(); // Stocker les flows associés à chaque nœud
    const domainsMap = new Map(); // Stocker les domaines et leurs statistiques

    // Créer un index des URLs réellement chargées pour distinguer appels directs vs découverts
    const loadedUrls = new Set();
    flowsData.forEach(flow => {
        if (flow.url) {
            try {
                const url = new URL(flow.url);
                // Normaliser l'URL (sans query params et hash pour la comparaison)
                const normalizedUrl = `${url.origin}${url.pathname}`;
                loadedUrls.add(normalizedUrl);
                // Aussi ajouter l'URL complète
                loadedUrls.add(flow.url);
            } catch (e) {
                // Ignorer
            }
        }
    });

    // Traiter d'abord les flows réels
    flowsData.forEach(flow => {
        try {
            const url = new URL(flow.url);
            const domain = url.hostname;
            const path = url.pathname;

            if (!domain) return;

            // Filtrer si un domaine est sélectionné
            if (selectedDomainForGraph && domain !== selectedDomainForGraph) {
                return;
            }

            // Créer un nœud pour le domaine
            if (!nodes.has(domain)) {
                nodes.set(domain, {
                    id: domain,
                    label: domain,
                    group: 1,
                    value: 1,
                    flows: []
                });
                nodeFlows.set(domain, []);
                domainsMap.set(domain, {
                    domain: domain,
                    requestCount: 1,
                    endpointCount: 0,
                    discoveredEndpointCount: 0
                });
            } else {
                nodes.get(domain).value++;
                domainsMap.get(domain).requestCount++;
            }
            nodeFlows.get(domain).push(flow);

            // Créer un nœud pour le path (tous les paths, pas seulement les APIs)
            if (path && path !== '/') {
                const pathId = `${domain}${path}`;
                const fileType = getFileTypeFromUrl(flow.url);
                if (!nodes.has(pathId)) {
                    nodes.set(pathId, {
                        id: pathId,
                        label: path,
                        group: 2,
                        value: 1,
                        parent: domain,
                        flows: [],
                        discovered: false, // Endpoint réellement chargé
                        fileType: fileType // Type de fichier
                    });
                    nodeFlows.set(pathId, []);
                } else {
                    nodes.get(pathId).value++;
                    // Mettre à jour le type de fichier si pas encore défini
                    if (!nodes.get(pathId).fileType) {
                        nodes.get(pathId).fileType = fileType;
                    }
                }
                nodeFlows.get(pathId).push(flow);

                // Mettre à jour le compteur d'endpoints du domaine
                if (domainsMap.has(domain)) {
                    domainsMap.get(domain).endpointCount++;
                }

                // Créer une arête
                const edgeKey = `${domain}->${pathId}`;
                if (!edgeKeys.has(edgeKey)) {
                    edgeKeys.add(edgeKey);
                    edges.push({
                        data: {
                            source: domain,
                            target: pathId,
                            type: 'to',
                            dashed: false,
                            discovered: 'false' // Endpoint réellement contacté (string pour Cytoscape)
                        }
                    });
                }
            }

            // Analyser les références dans les endpoints extraits du flow
            if (flow.endpoints) {
                Object.values(flow.endpoints).flat().forEach(endpoint => {
                    try {
                        const refUrl = new URL(endpoint, flow.url);
                        const refDomain = refUrl.hostname;
                        const refPath = refUrl.pathname;
                        const refFullUrl = refUrl.href;
                        const refNormalizedUrl = `${refUrl.origin}${refUrl.pathname}`;

                        if (!refDomain) return;

                        // Filtrer les faux endpoints (comme /-u, /[QÜV, etc.)
                        if (!isValidEndpoint(refPath)) {
                            return;
                        }

                        // Vérifier si cette ressource a été réellement chargée (appel direct)
                        const isDirectCall = loadedUrls.has(refFullUrl) || loadedUrls.has(refNormalizedUrl);

                        if (refDomain !== domain) {
                            if (!nodes.has(refDomain)) {
                                nodes.set(refDomain, {
                                    id: refDomain,
                                    label: refDomain,
                                    group: 3,
                                    value: 1,
                                    flows: []
                                });
                                nodeFlows.set(refDomain, []);
                            }

                            const edgeKey = `${domain}->${refDomain}`;
                            if (!edgeKeys.has(edgeKey)) {
                                edgeKeys.add(edgeKey);
                                edges.push({
                                    data: {
                                        source: domain,
                                        target: refDomain,
                                        type: 'to',
                                        dashed: !isDirectCall, // Ligne solide si appel direct, pointillée si découvert
                                        discovered: isDirectCall ? 'false' : 'true' // String pour Cytoscape
                                    }
                                });
                            }
                        } else if (refPath && refPath !== '/' && refPath !== path) {
                            // Endpoint sur le même domaine mais chemin différent
                            const refPathId = `${refDomain}${refPath}`;
                            const refFileType = getFileTypeFromUrl(refFullUrl);
                            if (!nodes.has(refPathId)) {
                                nodes.set(refPathId, {
                                    id: refPathId,
                                    label: refPath,
                                    group: 2,
                                    value: 1,
                                    parent: refDomain,
                                    flows: [],
                                    discovered: !isDirectCall, // Découvert seulement si non appelé
                                    fileType: refFileType // Type de fichier
                                });
                                nodeFlows.set(refPathId, []);

                                // Mettre à jour le compteur approprié
                                if (domainsMap.has(domain)) {
                                    if (isDirectCall) {
                                        // C'est un appel direct, compter comme endpoint réel
                                        domainsMap.get(domain).endpointCount++;
                                    } else {
                                        // C'est un endpoint découvert mais non appelé
                                        domainsMap.get(domain).discoveredEndpointCount++;
                                    }
                                }
                            }

                            const edgeKey = `${domain}->${refPathId}`;
                            if (!edgeKeys.has(edgeKey)) {
                                edgeKeys.add(edgeKey);
                                edges.push({
                                    data: {
                                        source: domain,
                                        target: refPathId,
                                        type: 'to',
                                        dashed: !isDirectCall, // Ligne solide si appel direct, pointillée si découvert
                                        discovered: isDirectCall ? 'false' : 'true' // String pour Cytoscape
                                    }
                                });
                            }
                        }
                    } catch (e) {
                        // Ignorer les URLs invalides
                    }
                });
            }
        } catch (e) {
            // Ignorer les URLs invalides
        }
    });

    // Ajouter les endpoints découverts du flow sélectionné (uniquement ceux qui n'ont pas été appelés)
    if (selectedFlow && flowEndpoints.length > 0) {
        flowEndpoints.forEach(endpoint => {
            try {
                // Normaliser l'endpoint (gérer les URLs relatives et absolues)
                let endpointUrl;
                if (endpoint.startsWith('http://') || endpoint.startsWith('https://')) {
                    endpointUrl = new URL(endpoint);
                } else if (endpoint.startsWith('/')) {
                    // URL relative, utiliser le domaine du flow sélectionné
                    if (selectedFlow.url) {
                        const baseUrl = new URL(selectedFlow.url);
                        endpointUrl = new URL(endpoint, baseUrl.origin);
                    } else {
                        return; // Pas de base URL, ignorer
                    }
                } else {
                    // URL relative sans slash, essayer de la résoudre
                    if (selectedFlow.url) {
                        const baseUrl = new URL(selectedFlow.url);
                        endpointUrl = new URL(endpoint, baseUrl);
                    } else {
                        return; // Pas de base URL, ignorer
                    }
                }

                const domain = endpointUrl.hostname;
                const path = endpointUrl.pathname;
                const normalized = `${endpointUrl.origin}${endpointUrl.pathname}`;

                if (!domain) return;

                // Filtrer si un domaine est sélectionné
                if (selectedDomainForGraph && domain !== selectedDomainForGraph) {
                    return;
                }

                // Filtrer les faux endpoints
                if (!isValidEndpoint(path)) {
                    return;
                }

                // Vérifier si cet endpoint a été réellement appelé
                const isDirectCall = loadedUrls.has(normalized) || loadedUrls.has(endpointUrl.href) || loadedUrls.has(endpoint);

                // Ne pas ajouter les endpoints déjà appelés (ils sont déjà dans le graphique via flowsData)
                if (isDirectCall) {
                    return;
                }

                // S'assurer que le domaine existe
                if (!nodes.has(domain)) {
                    nodes.set(domain, {
                        id: domain,
                        label: domain,
                        group: 1,
                        value: 1,
                        flows: []
                    });
                    nodeFlows.set(domain, []);
                    domainsMap.set(domain, {
                        domain: domain,
                        requestCount: 0,
                        endpointCount: 0,
                        discoveredEndpointCount: 0
                    });
                }

                // Ajouter l'endpoint découvert (non-appelé) s'il n'existe pas
                if (path && path !== '/') {
                    const pathId = `${domain}${path}`;
                    const fileType = getFileTypeFromUrl(endpointUrl.href);
                    if (!nodes.has(pathId)) {
                        nodes.set(pathId, {
                            id: pathId,
                            label: path,
                            group: 2,
                            value: 1,
                            parent: domain,
                            flows: [],
                            discovered: true, // Endpoint découvert mais non-appelé
                            fileType: fileType
                        });
                        nodeFlows.set(pathId, []);

                        // Mettre à jour le compteur
                        if (domainsMap.has(domain)) {
                            domainsMap.get(domain).discoveredEndpointCount++;
                        }

                        const edgeKey = `${domain}->${pathId}`;
                        if (!edgeKeys.has(edgeKey)) {
                            edgeKeys.add(edgeKey);
                            edges.push({
                                data: {
                                    source: domain,
                                    target: pathId,
                                    type: 'to',
                                    dashed: true, // Ligne pointillée pour endpoints découverts
                                    discovered: 'true' // String pour Cytoscape
                                }
                            });
                        }
                    }
                }
            } catch (e) {
                // Ignorer les URLs invalides
            }
        });
    }

    // Convertir les nodes pour Cytoscape
    nodes.forEach(node => {
        let color = '#2196f3'; // Domaine - bleu
        if (node.group === 2) {
            color = node.discovered ? '#ff9800' : '#4caf50'; // Orange (découvert) ou Vert (chargé)
        } else if (node.group === 3) {
            color = '#9c27b0'; // Externe - violet
        }

        cyElements.push({
            data: {
                id: node.id,
                label: node.label,
                weight: Math.max(10, Math.min(60, node.value * 5)),
                color: color,
                type: node.group === 1 ? 'domain' : 'endpoint',
                fileType: node.fileType || 'other', // Ajouter le type de fichier
                originalNode: node
            }
        });
    });

    // Ajouter les edges
    edges.forEach(edge => {
        // S'assurer que discovered est une string pour Cytoscape
        if (edge.data.discovered === undefined) {
            edge.data.discovered = 'false';
        } else if (typeof edge.data.discovered === 'boolean') {
            edge.data.discovered = edge.data.discovered.toString();
        }
        cyElements.push(edge);
    });

    // Initialiser Cytoscape
    panel.innerHTML = '';

    // Compter les nœuds et edges créés
    const totalNodes = nodes.size;
    const totalEdges = edges.length;

    // Ajouter des contrôles avancés pour filtrer et gérer le graphique
    const controlsContainer = document.createElement('div');
    controlsContainer.style.cssText = 'padding: 12px; background: white; border-bottom: 1px solid var(--border-color); display: flex; flex-direction: column; gap: 12px; flex-shrink: 0;';
    controlsContainer.innerHTML = `
        <div style="display: flex; gap: 12px; align-items: center; flex-wrap: wrap; justify-content: space-between;">
        <div style="display: flex; gap: 12px; align-items: center; flex-wrap: wrap;">
            <label style="display: flex; align-items: center; gap: 6px; cursor: pointer; font-size: 13px;">
                <input type="checkbox" id="viz-hide-discovered" checked style="cursor: pointer;">
                <span>Hide discovered</span>
            </label>
            <label style="display: flex; align-items: center; gap: 6px; cursor: pointer; font-size: 13px;">
                <input type="checkbox" id="viz-show-only-direct" style="cursor: pointer;">
                <span>Show only direct requests</span>
            </label>
            <label style="display: flex; align-items: center; gap: 6px; cursor: pointer; font-size: 13px;">
                <input type="checkbox" id="viz-limit-nodes" checked style="cursor: pointer;">
                    <span>Limit to 150 endpoints max</span>
            </label>
            </div>
            <div style="display: flex; gap: 8px; align-items: center;">
                <input type="text" id="viz-search-nodes" placeholder="Search an endpoint..." 
                    style="padding: 6px 10px; border: 1px solid var(--border-color); border-radius: 4px; font-size: 12px; width: 200px;">
                <button id="viz-reset-view" class="btn btn-secondary" style="padding: 6px 12px; font-size: 12px;">
                    <span class="material-symbols-outlined" style="font-size: 16px;">refresh</span>
                    Reset
                </button>
            </div>
        </div>
        <div style="display: flex; gap: 12px; align-items: center; flex-wrap: wrap; padding: 8px; background: #f5f5f5; border-radius: 6px;">
            <span style="font-size: 12px; font-weight: 600; color: #666; margin-right: 4px;">Filters by type:</span>
            <label style="display: flex; align-items: center; gap: 6px; cursor: pointer; font-size: 12px;">
                <input type="checkbox" id="viz-filter-image" checked style="cursor: pointer;">
                <span>Images</span>
            </label>
            <label style="display: flex; align-items: center; gap: 6px; cursor: pointer; font-size: 12px;">
                <input type="checkbox" id="viz-filter-javascript" checked style="cursor: pointer;">
                <span>JavaScript</span>
            </label>
            <label style="display: flex; align-items: center; gap: 6px; cursor: pointer; font-size: 12px;">
                <input type="checkbox" id="viz-filter-css" checked style="cursor: pointer;">
                <span>CSS</span>
            </label>
            <label style="display: flex; align-items: center; gap: 6px; cursor: pointer; font-size: 12px;">
                <input type="checkbox" id="viz-filter-html" checked style="cursor: pointer;">
                <span>HTML</span>
            </label>
            <label style="display: flex; align-items: center; gap: 6px; cursor: pointer; font-size: 12px;">
                <input type="checkbox" id="viz-filter-json" checked style="cursor: pointer;">
                <span>JSON</span>
            </label>
            <label style="display: flex; align-items: center; gap: 6px; cursor: pointer; font-size: 12px;">
                <input type="checkbox" id="viz-filter-other" checked style="cursor: pointer;">
                <span>Other</span>
            </label>
        </div>
        <div style="width: 100%; font-size: 11px; color: #666; margin-top: 4px;">
            ${totalNodes} nodes, ${totalEdges} connections
            ${selectedFlow ? ` | ${flowEndpoints.length} endpoints of the selected flow` : ' | Select a flow to see its endpoints'}
            ${totalNodes > 150 ? ` | <span style="color: #ff9800; font-weight: bold;">⚠ Very busy graph, use filters to improve readability</span>` : ''}
        </div>
    `;
    panel.appendChild(controlsContainer);

    const cyContainer = document.createElement('div');
    cyContainer.id = 'cy';
    cyContainer.style.width = '100%';
    cyContainer.style.height = 'calc(100% - 120px)'; // Increase to account for new controls
    cyContainer.style.background = '#fafafa';
    panel.appendChild(cyContainer);

    // Style pour le conteneur
    const style = document.createElement('style');
    style.textContent = `
        #cy {
            width: 100%;
            height: 100%;
            position: relative;
            flex: 1;
            min-height: 0;
        }
        .viz-panel {
            position: relative;
            height: 100%;
            overflow: hidden;
            display: flex;
            flex-direction: column;
        }
    `;
    panel.appendChild(style);

    const cy = cytoscape({
        container: cyContainer,
        elements: cyElements,
        style: [
            {
                selector: 'node',
                style: {
                    'background-color': 'data(color)',
                    'label': 'data(label)',
                    'width': 'data(weight)',
                    'height': 'data(weight)',
                    'font-size': '12px',
                    'color': '#333',
                    'text-valign': 'bottom',
                    'text-halign': 'center',
                    'text-margin-y': 5,
                    'text-background-color': '#fff',
                    'text-background-opacity': 0.7,
                    'text-background-padding': 2,
                    'text-background-shape': 'roundrectangle'
                }
            },
            {
                selector: 'edge',
                style: {
                    'width': 2.5,
                    'line-color': '#4caf50',
                    'target-arrow-color': '#4caf50',
                    'target-arrow-shape': 'triangle',
                    'curve-style': 'bezier',
                    'line-style': 'solid',
                    'opacity': 1
                }
            },
            {
                selector: 'edge[discovered = "true"]',  // Endpoints découverts (ligne pointillée, couleur atténuée)
                style: {
                    'line-color': '#ff9800',
                    'target-arrow-color': '#ff9800',
                    'line-style': 'dashed',
                    'line-dash-pattern': [6, 3],
                    'width': 1.5,
                    'opacity': 0.6
                }
            },
            {
                selector: ':selected',
                style: {
                    'border-width': 2,
                    'border-color': '#333'
                }
            }
        ],
        layout: {
            name: 'cose',
            animate: true,
            randomize: true,
            componentSpacing: 150, // Augmenter l'espacement pour mieux gérer beaucoup de nœuds
            nodeRepulsion: function (node) {
                // Augmenter la répulsion pour mieux espacer les nœuds
                return 800000;
            },
            nodeOverlap: 20, // Augmenter pour éviter le chevauchement
            idealEdgeLength: function (edge) { return 150; }, // Augmenter la longueur idéale
            edgeElasticity: function (edge) { return 200; },
            nestingFactor: 5,
            gravity: 100, // Augmenter la gravité pour mieux regrouper
            numIter: 2000, // Augmenter les itérations pour un meilleur layout
            initialTemp: 300,
            coolingFactor: 0.95,
            minTemp: 1.0
        }
    });

    // Gestionnaire de clic sur les nœuds
    cy.on('tap', 'node', function (evt) {
        const node = evt.target;
        const originalNode = node.data('originalNode');
        showNodeDetails(originalNode, nodeFlows);
    });

    // Fonction pour mettre à jour la visibilité des éléments
    function updateVisibility() {
        const hideDiscovered = document.getElementById('viz-hide-discovered')?.checked || false;
        const showOnlyDirect = document.getElementById('viz-show-only-direct')?.checked || false;
        const searchTerm = (document.getElementById('viz-search-nodes')?.value || '').toLowerCase().trim();

        // Récupérer les filtres par type de fichier
        const showImages = document.getElementById('viz-filter-image')?.checked !== false;
        const showJavaScript = document.getElementById('viz-filter-javascript')?.checked !== false;
        const showCss = document.getElementById('viz-filter-css')?.checked !== false;
        const showHtml = document.getElementById('viz-filter-html')?.checked !== false;
        const showJson = document.getElementById('viz-filter-json')?.checked !== false;
        const showOther = document.getElementById('viz-filter-other')?.checked !== false;

        cy.elements().forEach(element => {
            let shouldShow = true;

            // Filtrer par type (découvert vs direct)
            if (hideDiscovered) {
                const discovered = element.data('discovered');
                if (discovered === true || discovered === 'true') {
                    shouldShow = false;
                }
            }

            // Filtrer pour n'afficher que les requêtes directes
            if (showOnlyDirect) {
                const discovered = element.data('discovered');
                if (discovered === true || discovered === 'true') {
                    shouldShow = false;
                }
            }

            // Filtrer par type de fichier (uniquement pour les nœuds)
            if (element.isNode() && shouldShow) {
                const fileType = element.data('fileType') || 'other';
                const nodeType = element.data('type');

                // Les domaines (type === 'domain') sont toujours visibles
                if (nodeType === 'domain') {
                    // Les domaines restent visibles
                } else {
                    // Filtrer les endpoints par type de fichier
                    switch (fileType) {
                        case 'image':
                            if (!showImages) shouldShow = false;
                            break;
                        case 'javascript':
                            if (!showJavaScript) shouldShow = false;
                            break;
                        case 'css':
                            if (!showCss) shouldShow = false;
                            break;
                        case 'html':
                            if (!showHtml) shouldShow = false;
                            break;
                        case 'json':
                            if (!showJson) shouldShow = false;
                            break;
                        default:
                            if (!showOther) shouldShow = false;
                            break;
                    }
                }
            }

            // Filtrer par recherche
            if (searchTerm && shouldShow) {
                if (element.isNode()) {
                    const label = element.data('label') || '';
                    const id = element.id() || '';
                    if (!label.toLowerCase().includes(searchTerm) && !id.toLowerCase().includes(searchTerm)) {
                        shouldShow = false;
                    }
                } else if (element.isEdge()) {
                    // Pour les edges, vérifier les nœuds source et target
                    const sourceLabel = element.source().data('label') || '';
                    const targetLabel = element.target().data('label') || '';
                    if (!sourceLabel.toLowerCase().includes(searchTerm) && !targetLabel.toLowerCase().includes(searchTerm)) {
                        shouldShow = false;
                    }
                }
            }

            element.style('display', shouldShow ? 'element' : 'none');
        });

        // Masquer les nœuds isolés (sans arêtes visibles)
        cy.nodes().forEach(node => {
            const connectedEdges = node.connectedEdges().filter(edge => edge.style('display') !== 'none');
            if (connectedEdges.length === 0 && node.style('display') !== 'none') {
                // Vérifier si le nœud correspond à la recherche
                const searchTerm = (document.getElementById('viz-search-nodes')?.value || '').toLowerCase().trim();
                if (searchTerm) {
                    const label = node.data('label') || '';
                    const id = node.id() || '';
                    if (label.toLowerCase().includes(searchTerm) || id.toLowerCase().includes(searchTerm)) {
                        return; // Garder visible si correspond à la recherche
                    }
                }
                // Ne pas masquer les domaines même s'ils sont isolés
                const nodeType = node.data('type');
                if (nodeType !== 'domain') {
                    node.style('display', 'none');
                }
            }
        });
    }

    // Gestionnaire pour masquer/afficher les endpoints découverts
    const hideDiscoveredCheck = document.getElementById('viz-hide-discovered');
    if (hideDiscoveredCheck) {
        hideDiscoveredCheck.addEventListener('change', updateVisibility);
    }

    // Gestionnaire pour afficher uniquement les requêtes directes
    const showOnlyDirectCheck = document.getElementById('viz-show-only-direct');
    if (showOnlyDirectCheck) {
        showOnlyDirectCheck.addEventListener('change', updateVisibility);
    }

    // Gestionnaire pour la recherche
    const searchInput = document.getElementById('viz-search-nodes');
    if (searchInput) {
        let searchTimeout;
        searchInput.addEventListener('input', function () {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(updateVisibility, 300); // Debounce de 300ms
        });
    }

    // Gestionnaires pour les filtres par type de fichier
    const fileTypeFilters = ['viz-filter-image', 'viz-filter-javascript', 'viz-filter-css', 'viz-filter-html', 'viz-filter-json', 'viz-filter-other'];
    fileTypeFilters.forEach(filterId => {
        const filterCheck = document.getElementById(filterId);
        if (filterCheck) {
            filterCheck.addEventListener('change', updateVisibility);
        }
    });

    // Gestionnaire pour le bouton Reset
    const resetButton = document.getElementById('viz-reset-view');
    if (resetButton) {
        resetButton.addEventListener('click', function () {
            // Réinitialiser tous les filtres
            if (hideDiscoveredCheck) hideDiscoveredCheck.checked = false;
            if (showOnlyDirectCheck) showOnlyDirectCheck.checked = false;
            if (searchInput) searchInput.value = '';

            // Réinitialiser les filtres par type de fichier
            fileTypeFilters.forEach(filterId => {
                const filterCheck = document.getElementById(filterId);
                if (filterCheck) filterCheck.checked = true;
            });

            // Réinitialiser la vue
            cy.elements().style('display', 'element');
            cy.fit();
            cy.center();
        });
    }

    // Gestionnaire pour limiter le nombre de nœuds
    const limitNodesCheck = document.getElementById('viz-limit-nodes');
    if (limitNodesCheck) {
        limitNodesCheck.addEventListener('change', function () {
            // Si on limite, masquer les nœuds découverts en excès
            if (this.checked) {
                let visibleCount = 0;
                cy.nodes().forEach(node => {
                    const originalNode = node.data('originalNode');
                    if (originalNode && originalNode.discovered) {
                        if (visibleCount >= 50) {
                            node.style('display', 'none');
                        } else {
                            visibleCount++;
                        }
                    }
                });
            } else {
                // Afficher tous les nœuds
                cy.nodes().style('display', 'element');
            }
            updateVisibility();
        });
    }

    // Sauvegarder les données globales pour d'autres usages si nécessaire
    dependenciesGlobalData = { nodes, edges, nodeFlows };
}

// Fonction obsolète - le filtre est maintenant géré dans renderDomainsList()
// Gardée pour compatibilité mais ne fait plus rien
function filterDomainsList(filterText) {
    // Cette fonction n'est plus utilisée, le filtre est maintenant géré dans renderDomainsList
}

// Rendre les fonctions accessibles globalement
window.selectDomainForGraph = selectDomainForGraph;
window.filterDomainsList = filterDomainsList;
window.closeFileContentModal = closeFileContentModal;

// Fonction pour sélectionner un domaine et afficher son graphique
function selectDomainForGraph(domain) {
    // Cette fonction est maintenant remplacée par selectDomain
    // Gardée pour compatibilité
    selectDomain(domain);
}




function showNodeDetails(node, nodeFlows) {
    const nodeDetailsPanel = document.getElementById('node-details-panel');
    const overlay = document.getElementById('node-details-overlay');
    const title = document.getElementById('node-details-title');
    const content = document.getElementById('node-details-content');

    if (!nodeDetailsPanel || !overlay || !title || !content) return;

    // Récupérer les flows associés
    const flows = nodeFlows.get(node.id) || [];

    // Déterminer le type de nœud
    let nodeType = 'Domain';
    let nodeIcon = 'public';
    let nodeSubtitle = 'Domain node';
    if (node.group === 2) {
        nodeType = 'Endpoint';
        nodeIcon = 'link';
        nodeSubtitle = 'Endpoint node';
    } else if (node.group === 3) {
        nodeType = 'External Domain';
        nodeIcon = 'language';
        nodeSubtitle = 'External domain node';
    }

    // Mettre à jour le titre et l'icône
    title.textContent = node.label;
    const subtitleEl = document.getElementById('node-details-subtitle');
    if (subtitleEl) {
        subtitleEl.textContent = `${nodeType} • ${flows.length} request${flows.length !== 1 ? 's' : ''}`;
    }
    const iconEl = document.getElementById('node-details-icon');
    if (iconEl) {
        iconEl.textContent = nodeIcon;
    }

    // Calculer les statistiques
    const methods = {};
    const statusCodes = {};
    let totalDuration = 0;
    let successCount = 0;
    let errorCount = 0;

    flows.forEach(flow => {
        // Méthodes
        methods[flow.method] = (methods[flow.method] || 0) + 1;

        // Codes de statut
        const status = flow.status_code || 'N/A';
        statusCodes[status] = (statusCodes[status] || 0) + 1;

        // Durée
        if (flow.duration_ms) {
            totalDuration += flow.duration_ms;
        }

        // Succès/Erreurs
        if (status >= 200 && status < 300) successCount++;
        if (status >= 400) errorCount++;
    });

    const avgDuration = flows.length > 0 ? Math.round(totalDuration / flows.length) : 0;

    // Construire le contenu
    let html = '';

    // Informations générales - Cards sobres et professionnelles
    html += '<div style="margin-bottom: 24px;">';
    html += '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px;">';

    // Total Requests
    html += `<div style="background: white; border: 1px solid var(--border-color); border-left: 4px solid #6200ea; padding: 16px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.04);">`;
    html += `<div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">`;
    html += `<div style="width: 8px; height: 8px; border-radius: 50%; background: #6200ea;"></div>`;
    html += `<div style="font-size: 11px; color: #666; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 500;">Total Requests</div>`;
    html += `</div>`;
    html += `<div style="font-size: 28px; font-weight: 600; line-height: 1; color: #333;">${flows.length}</div>`;
    html += `</div>`;

    // Success
    html += `<div style="background: white; border: 1px solid var(--border-color); border-left: 4px solid #4caf50; padding: 16px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.04);">`;
    html += `<div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">`;
    html += `<div style="width: 8px; height: 8px; border-radius: 50%; background: #4caf50;"></div>`;
    html += `<div style="font-size: 11px; color: #666; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 500;">Success (2xx)</div>`;
    html += `</div>`;
    html += `<div style="font-size: 28px; font-weight: 600; line-height: 1; color: #333;">${successCount}</div>`;
    html += `</div>`;

    // Errors
    html += `<div style="background: white; border: 1px solid var(--border-color); border-left: 4px solid #d32f2f; padding: 16px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.04);">`;
    html += `<div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">`;
    html += `<div style="width: 8px; height: 8px; border-radius: 50%; background: #d32f2f;"></div>`;
    html += `<div style="font-size: 11px; color: #666; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 500;">Errors (4xx/5xx)</div>`;
    html += `</div>`;
    html += `<div style="font-size: 28px; font-weight: 600; line-height: 1; color: #333;">${errorCount}</div>`;
    html += `</div>`;

    // Avg Duration
    html += `<div style="background: white; border: 1px solid var(--border-color); border-left: 4px solid #666; padding: 16px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.04);">`;
    html += `<div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">`;
    html += `<div style="width: 8px; height: 8px; border-radius: 50%; background: #666;"></div>`;
    html += `<div style="font-size: 11px; color: #666; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 500;">Avg Duration</div>`;
    html += `</div>`;
    html += `<div style="font-size: 28px; font-weight: 600; line-height: 1; color: #333;">${avgDuration}ms</div>`;
    html += `</div>`;

    html += '</div>';
    html += '</div>';

    // Méthodes HTTP - Section sobre
    html += '<div style="margin-bottom: 24px; background: #fafafa; border-radius: 8px; padding: 16px; border: 1px solid var(--border-color);">';
    html += '<div style="display: flex; align-items: center; gap: 8px; margin-bottom: 12px;">';
    html += '<span class="material-symbols-outlined" style="font-size: 18px; color: #666;">http</span>';
    html += '<h4 style="margin: 0; color: #333; font-size: 14px; font-weight: 600;">HTTP Methods</h4>';
    html += '</div>';
    html += '<div style="display: flex; gap: 8px; flex-wrap: wrap;">';
    Object.entries(methods).sort((a, b) => b[1] - a[1]).forEach(([method, count]) => {
        let methodBg = '#f5f5f5';
        let methodColor = '#333';
        let borderColor = '#ddd';
        if (method === 'GET') { methodBg = '#e8f5e9'; methodColor = '#2e7d32'; borderColor = '#4caf50'; }
        else if (method === 'POST') { methodBg = '#fff3e0'; methodColor = '#e65100'; borderColor = '#ff9800'; }
        else if (method === 'PUT') { methodBg = '#f3e5f5'; methodColor = '#6a1b9a'; borderColor = '#9c27b0'; }
        else if (method === 'DELETE') { methodBg = '#ffebee'; methodColor = '#c62828'; borderColor = '#f44336'; }
        html += `<div style="background: ${methodBg}; color: ${methodColor}; border: 1px solid ${borderColor}; padding: 8px 12px; border-radius: 6px; font-weight: 600; display: flex; align-items: center; gap: 8px; font-size: 12px;">`;
        html += `<span style="font-weight: 700;">${method}</span>`;
        html += `<span style="background: ${methodColor}; color: white; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 600;">${count}</span>`;
        html += `</div>`;
    });
    html += '</div>';
    html += '</div>';

    // Codes de statut - Section sobre
    html += '<div style="margin-bottom: 24px; background: #fafafa; border-radius: 8px; padding: 16px; border: 1px solid var(--border-color);">';
    html += '<div style="display: flex; align-items: center; gap: 8px; margin-bottom: 12px;">';
    html += '<span class="material-symbols-outlined" style="font-size: 18px; color: #666;">info</span>';
    html += '<h4 style="margin: 0; color: #333; font-size: 14px; font-weight: 600;">Status Codes</h4>';
    html += '</div>';
    html += '<div style="display: flex; gap: 8px; flex-wrap: wrap;">';
    Object.entries(statusCodes).sort((a, b) => b[1] - a[1]).forEach(([status, count]) => {
        let statusBg = '#f5f5f5';
        let statusColor = '#333';
        let borderColor = '#ddd';
        if (status >= 200 && status < 300) { statusBg = '#e8f5e9'; statusColor = '#2e7d32'; borderColor = '#4caf50'; }
        else if (status >= 300 && status < 400) { statusBg = '#fff3e0'; statusColor = '#e65100'; borderColor = '#ff9800'; }
        else if (status >= 400) { statusBg = '#ffebee'; statusColor = '#c62828'; borderColor = '#f44336'; }
        html += `<div style="background: ${statusBg}; color: ${statusColor}; border: 1px solid ${borderColor}; padding: 8px 12px; border-radius: 6px; font-weight: 600; display: flex; align-items: center; gap: 8px; font-size: 12px;">`;
        html += `<span style="font-weight: 700;">${status}</span>`;
        html += `<span style="background: ${statusColor}; color: white; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 600;">${count}</span>`;
        html += `</div>`;
    });
    html += '</div>';
    html += '</div>';

    // Liste des requêtes - Design sobre
    html += '<div>';
    html += '<div style="display: flex; align-items: center; gap: 8px; margin-bottom: 12px;">';
    html += '<span class="material-symbols-outlined" style="font-size: 18px; color: #666;">list</span>';
    html += '<h4 style="margin: 0; color: #333; font-size: 14px; font-weight: 600;">Associated Requests</h4>';
    html += `<span style="background: #f5f5f5; color: #666; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 600; border: 1px solid var(--border-color);">${flows.length}</span>`;
    html += '</div>';
    html += '<div style="max-height: 350px; overflow-y: auto; border: 1px solid var(--border-color); border-radius: 8px; background: white;">';

    if (flows.length === 0) {
        html += '<div style="padding: 40px; text-align: center; color: #888;">';
        html += '<span class="material-symbols-outlined" style="font-size: 48px; opacity: 0.3; margin-bottom: 12px; display: block;">inbox</span>';
        html += '<div>No associated requests</div>';
        html += '</div>';
    } else {
        flows.forEach((flow, index) => {
            const statusBg = flow.status_code >= 400 ? '#ffebee' : flow.status_code >= 300 ? '#fff3e0' : '#e8f5e9';
            const statusColor = flow.status_code >= 400 ? '#c62828' : flow.status_code >= 300 ? '#e65100' : '#2e7d32';
            const statusBorder = flow.status_code >= 400 ? '#f44336' : flow.status_code >= 300 ? '#ff9800' : '#4caf50';

            const methodBg = flow.method === 'GET' ? '#e8f5e9' : flow.method === 'POST' ? '#fff3e0' : flow.method === 'PUT' ? '#f3e5f5' : flow.method === 'DELETE' ? '#ffebee' : '#f5f5f5';
            const methodColor = flow.method === 'GET' ? '#2e7d32' : flow.method === 'POST' ? '#e65100' : flow.method === 'PUT' ? '#6a1b9a' : flow.method === 'DELETE' ? '#c62828' : '#333';
            const methodBorder = flow.method === 'GET' ? '#4caf50' : flow.method === 'POST' ? '#ff9800' : flow.method === 'PUT' ? '#9c27b0' : flow.method === 'DELETE' ? '#f44336' : '#ddd';

            html += `<div style="padding: 12px 16px; border-bottom: 1px solid var(--border-color); display: flex; align-items: center; gap: 12px; cursor: pointer; transition: all 0.2s; background: white;" 
                onmouseover="this.style.background='#fafafa'" 
                onmouseout="this.style.background='white'"
                onclick="selectFlowFromTimeline('${flow.id}'); closeNodeDetails();">`;
            html += `<div style="background: ${methodBg}; color: ${methodColor}; border: 1px solid ${methodBorder}; padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: 600; min-width: 50px; text-align: center;">${flow.method}</div>`;
            html += `<div style="flex: 1; overflow: hidden; min-width: 0;">`;
            html += `<div style="font-weight: 500; color: #333; margin-bottom: 4px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 13px;">${flow.path || flow.url}</div>`;
            html += `<div style="font-size: 11px; color: #666; display: flex; align-items: center; gap: 6px;">`;
            html += `<span>${new Date(flow.timestamp_start * 1000).toLocaleString('en-US')}</span>`;
            if (flow.duration_ms) {
                html += `<span>• ${flow.duration_ms}ms</span>`;
            }
            html += `</div>`;
            html += `</div>`;
            html += `<div style="display: flex; align-items: center; gap: 8px;">`;
            html += `<span style="background: ${statusBg}; color: ${statusColor}; border: 1px solid ${statusBorder}; padding: 4px 10px; border-radius: 6px; font-weight: 600; min-width: 45px; text-align: center; font-size: 11px;">${flow.status_code || 'N/A'}</span>`;
            html += `<span class="material-symbols-outlined" style="font-size: 16px; color: #999;">chevron_right</span>`;
            html += `</div>`;
            html += `</div>`;
        });
    }

    html += '</div>';
    html += '</div>';

    content.innerHTML = html;

    // Afficher le panneau
    nodeDetailsPanel.style.display = 'block';
    overlay.style.display = 'block';
}

function closeNodeDetails() {
    const nodeDetailsPanel = document.getElementById('node-details-panel');
    const overlay = document.getElementById('node-details-overlay');
    if (nodeDetailsPanel) {
        nodeDetailsPanel.style.display = 'none';
        // Reset zoom when closing
        if (nodeDetailsPanel.style.transform) {
            nodeDetailsPanel.style.transform = 'translate(-50%, -50%) scale(1)';
        }
    }
    if (overlay) overlay.style.display = 'none';
}

function showTimeline() {
    const timelinePanel = getCurrentVizPanel();
    if (!timelinePanel) return;

    if (!selectedDomainForGraph) {
        timelinePanel.innerHTML = '<div style="text-align: center; padding: 50px; color: #888;">Sélectionnez un domaine pour voir la timeline</div>';
        return;
    }

    // Filtrer les flows par domaine sélectionné
    const filteredFlows = flowsData.filter(flow => {
        try {
            const url = new URL(flow.url);
            return url.hostname === selectedDomainForGraph;
        } catch {
            return false;
        }
    });

    if (filteredFlows.length === 0) {
        timelinePanel.innerHTML = '<div style="text-align: center; padding: 50px; color: #888;">No requests to display for this domain</div>';
        return;
    }

    // Trier les flows par timestamp
    const sortedFlows = [...filteredFlows].sort((a, b) =>
        (a.timestamp_start || 0) - (b.timestamp_start || 0)
    );

    if (sortedFlows.length === 0) {
        timelinePanel.innerHTML = '<div style="text-align: center; padding: 50px; color: #888;">No requests to display</div>';
        return;
    }

    const startTime = sortedFlows[0].timestamp_start || 0;
    const endTime = sortedFlows[sortedFlows.length - 1].timestamp_start || Date.now() / 1000;
    const duration = Math.max(endTime - startTime, 1); // Éviter division par zéro

    // Calculer les statistiques détaillées
    const successCount = sortedFlows.filter(f => f.status_code >= 200 && f.status_code < 300).length;
    const redirectCount = sortedFlows.filter(f => f.status_code >= 300 && f.status_code < 400).length;
    const errorCount = sortedFlows.filter(f => f.status_code >= 400).length;
    const avgDuration = sortedFlows.reduce((sum, f) => sum + (f.duration_ms || 0), 0) / sortedFlows.length;
    const maxDuration = Math.max(...sortedFlows.map(f => f.duration_ms || 0));
    const minDuration = Math.min(...sortedFlows.map(f => f.duration_ms || 0));

    // Grouper par endpoint (méthode + chemin) pour une meilleure visualisation
    const flowsByEndpoint = new Map();
    sortedFlows.forEach(flow => {
        try {
            const url = new URL(flow.url);
            const endpointKey = `${flow.method || 'GET'}:${url.pathname}`;
            if (!flowsByEndpoint.has(endpointKey)) {
                flowsByEndpoint.set(endpointKey, {
                    endpoint: endpointKey,
                    method: flow.method || 'GET',
                    path: url.pathname,
                    flows: [],
                    count: 0,
                    avgDuration: 0,
                    statusCodes: new Set()
                });
            }
            const endpointData = flowsByEndpoint.get(endpointKey);
            endpointData.flows.push(flow);
            endpointData.count++;
            endpointData.statusCodes.add(flow.status_code);
        } catch {
            // Ignorer les URLs invalides
        }
    });

    // Construire l'interface améliorée - Design épuré
    let html = '<div style="padding: 30px; background: var(--bg-color); min-height: 100%;">';

    // En-tête simplifié
    html += '<div style="margin-bottom: 24px;">';
    html += '<div style="display: flex; align-items: center; gap: 12px; margin-bottom: 20px;">';
    html += '<span class="material-symbols-outlined" style="font-size: 28px; color: var(--primary-color);">timeline</span>';
    html += '<h3 style="margin: 0; color: var(--primary-color); font-size: 1.5rem; font-weight: 600;">Request Timeline</h3>';
    html += '</div>';
    html += `<p style="margin: 0; color: var(--text-secondary); font-size: 0.95rem;">Domain: <strong>${escapeHtml(selectedDomainForGraph)}</strong></p>`;
    html += '</div>';

    // Statistiques simplifiées - 4 cartes seulement
    html += '<div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px;">';

    html += `<div style="background: white; padding: 20px; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); border: 1px solid var(--border-color);">`;
    html += `<div style="display: flex; align-items: center; gap: 10px; margin-bottom: 10px;">`;
    html += `<div style="width: 40px; height: 40px; background: #e8f5e9; border-radius: 10px; display: flex; align-items: center; justify-content: center;">`;
    html += `<span class="material-symbols-outlined" style="color: #4caf50; font-size: 20px;">check_circle</span>`;
    html += `</div>`;
    html += `<div style="font-size: 0.85em; color: var(--text-secondary); font-weight: 500;">Success</div>`;
    html += `</div>`;
    html += `<div style="font-size: 1.8em; font-weight: 700; color: #4caf50; font-family: 'Inter', sans-serif;">${successCount}</div>`;
    html += `</div>`;

    html += `<div style="background: white; padding: 20px; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); border: 1px solid var(--border-color);">`;
    html += `<div style="display: flex; align-items: center; gap: 10px; margin-bottom: 10px;">`;
    html += `<div style="width: 40px; height: 40px; background: #fff3e0; border-radius: 10px; display: flex; align-items: center; justify-content: center;">`;
    html += `<span class="material-symbols-outlined" style="color: #ff9800; font-size: 20px;">swap_horiz</span>`;
    html += `</div>`;
    html += `<div style="font-size: 0.85em; color: var(--text-secondary); font-weight: 500;">Redirects</div>`;
    html += `</div>`;
    html += `<div style="font-size: 1.8em; font-weight: 700; color: #ff9800; font-family: 'Inter', sans-serif;">${redirectCount}</div>`;
    html += `</div>`;

    html += `<div style="background: white; padding: 20px; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); border: 1px solid var(--border-color);">`;
    html += `<div style="display: flex; align-items: center; gap: 10px; margin-bottom: 10px;">`;
    html += `<div style="width: 40px; height: 40px; background: #ffebee; border-radius: 10px; display: flex; align-items: center; justify-content: center;">`;
    html += `<span class="material-symbols-outlined" style="color: #f44336; font-size: 20px;">error</span>`;
    html += `</div>`;
    html += `<div style="font-size: 0.85em; color: var(--text-secondary); font-weight: 500;">Errors</div>`;
    html += `</div>`;
    html += `<div style="font-size: 1.8em; font-weight: 700; color: #f44336; font-family: 'Inter', sans-serif;">${errorCount}</div>`;
    html += `</div>`;

    html += `<div style="background: white; padding: 20px; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); border: 1px solid var(--border-color);">`;
    html += `<div style="display: flex; align-items: center; gap: 10px; margin-bottom: 10px;">`;
    html += `<div style="width: 40px; height: 40px; background: #f3e5f5; border-radius: 10px; display: flex; align-items: center; justify-content: center;">`;
    html += `<span class="material-symbols-outlined" style="color: var(--primary-color); font-size: 20px;">timer</span>`;
    html += `</div>`;
    html += `<div style="font-size: 0.85em; color: var(--text-secondary); font-weight: 500;">Avg Duration</div>`;
    html += `</div>`;
    html += `<div style="font-size: 1.8em; font-weight: 700; color: var(--primary-color); font-family: 'Inter', sans-serif;">${avgDuration.toFixed(0)}<span style="font-size: 0.5em; color: var(--text-secondary);">ms</span></div>`;
    html += `</div>`;

    html += '</div>';

    // Contrôles simplifiés
    html += '<div style="background: white; border-radius: 12px; padding: 16px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); border: 1px solid var(--border-color);">';
    html += '<div style="display: flex; gap: 16px; align-items: center; flex-wrap: wrap;">';

    // Filtres par statut - style compact
    html += '<div style="display: flex; gap: 16px; align-items: center; flex-wrap: wrap; padding: 8px; background: #fafafa; border-radius: 8px; flex: 1;">';
    html += '<label style="display: flex; align-items: center; gap: 6px; cursor: pointer; font-size: 13px;">';
    html += '<input type="checkbox" id="timeline-filter-success" checked style="cursor: pointer;">';
    html += '<span style="color: var(--text-color); font-weight: 500;">Success</span>';
    html += '</label>';
    html += '<label style="display: flex; align-items: center; gap: 6px; cursor: pointer; font-size: 13px;">';
    html += '<input type="checkbox" id="timeline-filter-redirect" checked style="cursor: pointer;">';
    html += '<span style="color: var(--text-color); font-weight: 500;">Redirects</span>';
    html += '</label>';
    html += '<label style="display: flex; align-items: center; gap: 6px; cursor: pointer; font-size: 13px;">';
    html += '<input type="checkbox" id="timeline-filter-error" checked style="cursor: pointer;">';
    html += '<span style="color: var(--text-color); font-weight: 500;">Errors</span>';
    html += '</label>';

    // Filtre par méthode
    html += '<div style="margin-left: auto; display: flex; gap: 8px; align-items: center;">';
    html += '<label style="display: flex; align-items: center; gap: 6px; color: var(--text-secondary); font-size: 13px;">Method:</label>';
    html += '<select id="timeline-filter-method" style="padding: 6px 10px; border: 1px solid var(--border-color); border-radius: 6px; cursor: pointer; font-size: 13px; background: white;">';
    html += '<option value="all">All</option>';
    html += '<option value="GET">GET</option>';
    html += '<option value="POST">POST</option>';
    html += '<option value="PUT">PUT</option>';
    html += '<option value="DELETE">DELETE</option>';
    html += '<option value="PATCH">PATCH</option>';
    html += '</select>';
    html += '</div>';
    html += '</div>';

    // Contrôles zoom simplifiés
    html += '<div style="display: flex; gap: 8px; align-items: center;">';
    html += '<button id="timeline-zoom-in" class="btn btn-secondary" style="padding: 6px 12px; font-size: 12px;">';
    html += '<span class="material-symbols-outlined" style="font-size: 16px;">zoom_in</span>';
    html += '</button>';
    html += '<button id="timeline-zoom-out" class="btn btn-secondary" style="padding: 6px 12px; font-size: 12px;">';
    html += '<span class="material-symbols-outlined" style="font-size: 16px;">zoom_out</span>';
    html += '</button>';
    html += '<button id="timeline-reset" class="btn btn-secondary" style="padding: 6px 12px; font-size: 12px;">';
    html += '<span class="material-symbols-outlined" style="font-size: 16px;">refresh</span>';
    html += '</button>';
    html += '</div>';
    html += '</div>';

    // Timeline principale - Design épuré
    const timelineWidth = 100; // Pourcentage
    const rowHeight = 50; // Réduit pour plus de compacité
    const paddingTop = 50; // Pour l'axe temporel
    const sidebarWidth = 220; // Largeur de la sidebar des endpoints

    // Calculer la hauteur totale nécessaire
    let estimatedHeight = (flowsByEndpoint.size * rowHeight) + paddingTop + 40;

    html += '<div style="background: white; border-radius: 12px; padding: 0; box-shadow: 0 2px 8px rgba(0,0,0,0.08); border: 1px solid var(--border-color); overflow: auto; max-height: calc(100vh - 200px);">';
    html += '<div style="display: flex; min-height: 500px; height: auto;">';

    // Sidebar des endpoints (gauche) - Design épuré
    html += `<div style="width: ${sidebarWidth}px; background: #fafafa; border-right: 1px solid var(--border-color); overflow-y: auto; flex-shrink: 0;">`;
    html += '<div style="padding: 16px; background: white; border-bottom: 1px solid var(--border-color); position: sticky; top: 0; z-index: 10;">';
    html += '<div style="display: flex; align-items: center; gap: 8px; margin-bottom: 12px;">';
    html += '<span class="material-symbols-outlined" style="font-size: 18px; color: var(--primary-color);">list</span>';
    html += '<h4 style="margin: 0; color: var(--primary-color); font-size: 1rem; font-weight: 600;">Endpoints</h4>';
    html += '</div>';
    html += '<input type="text" id="timeline-search" placeholder="Search..." style="width: 100%; padding: 8px 10px; border: 1px solid var(--border-color); border-radius: 6px; font-size: 0.85rem; box-sizing: border-box; background: white;">';
    html += '</div>';

    html += '<div id="timeline-endpoints-list" style="padding: 8px;">';

    // Liste des endpoints
    Array.from(flowsByEndpoint.values())
        .sort((a, b) => b.count - a.count)
        .forEach((endpointData, index) => {
            const avgDur = endpointData.flows.reduce((sum, f) => sum + (f.duration_ms || 0), 0) / endpointData.count;
            const statusCodes = Array.from(endpointData.statusCodes);
            const hasErrors = statusCodes.some(s => s >= 400);

            const methodColor = getMethodColor(endpointData.method);
            html += `<div class="timeline-endpoint-item" data-endpoint="${escapeHtml(endpointData.endpoint)}" data-method="${endpointData.method}" style="
                padding: 10px 12px;
                margin-bottom: 6px;
                background: white;
                border: 1px solid var(--border-color);
                border-left: 3px solid ${methodColor};
                border-radius: 6px;
                cursor: pointer;
                transition: all 0.2s;
            " onmouseover="this.style.background='#f5f5f5'; this.style.borderLeftColor='${methodColor}'; this.style.borderLeftWidth='4px';" 
               onmouseout="this.style.background='white'; this.style.borderLeftWidth='3px';"
               onclick="scrollToTimelineEndpoint('${escapeHtml(endpointData.endpoint)}')">`;

            html += `<div style="display: flex; align-items: center; gap: 6px; margin-bottom: 6px;">`;
            html += `<span style="
                background: ${methodColor};
                color: white;
                padding: 2px 6px;
                border-radius: 4px;
                font-size: 0.7rem;
                font-weight: 600;
                font-family: 'Fira Code', monospace;
            ">${endpointData.method}</span>`;
            html += `<div style="flex: 1; font-weight: 500; color: var(--text-color); font-size: 0.85rem; word-break: break-word; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(endpointData.path.length > 25 ? endpointData.path.substring(0, 22) + '...' : endpointData.path)}</div>`;
            html += `</div>`;

            html += `<div style="display: flex; gap: 10px; font-size: 0.75rem; color: var(--text-secondary);">`;
            html += `<span>${endpointData.count} req</span>`;
            html += `<span>${avgDur.toFixed(0)}ms</span>`;
            if (hasErrors) {
                html += `<span style="color: #f44336; font-weight: 600;">!</span>`;
            }
            html += `</div>`;

            html += '</div>';
        });

    html += '</div>'; // Fin de la liste
    html += '</div>'; // Fin de la sidebar

    // Zone de timeline principale (droite) - Design épuré
    html += `<div style="flex: 1; position: relative; overflow-x: auto; overflow-y: auto; background: white;">`;
    html += `<div id="timeline-container" style="position: relative; min-height: ${estimatedHeight}px; min-width: ${Math.max(800, duration * 2)}px; padding-left: ${sidebarWidth}px;">`;

    // Axe temporel simplifié
    html += '<div style="position: sticky; top: 0; left: 0; right: 0; height: 45px; border-bottom: 2px solid var(--primary-color); background: white; z-index: 20; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">';
    html += '<div style="position: absolute; left: 0; top: 0; bottom: 0; width: 100%;">';

    // Marqueurs temporels simplifiés
    const numMarkers = Math.min(15, Math.max(8, Math.ceil(duration / 10)));
    for (let i = 0; i <= numMarkers; i++) {
        const timePos = (i / numMarkers) * 100;
        const timeValue = startTime + (duration * i / numMarkers);
        const date = new Date(timeValue * 1000);
        const timeStr = date.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        const isMajor = i % (numMarkers / 4) === 0;

        html += `<div style="position: absolute; left: ${timePos}%; top: 0; height: 100%; border-left: ${isMajor ? '2px' : '1px'} solid ${isMajor ? 'var(--primary-color)' : 'var(--border-color)'};">`;
        if (isMajor || i === 0 || i === numMarkers) {
            html += `<div style="position: absolute; top: 8px; left: 6px; font-size: 11px; color: ${isMajor ? 'var(--primary-color)' : 'var(--text-secondary)'}; font-weight: ${isMajor ? '600' : '400'}; white-space: nowrap; background: white; padding: 2px 6px; border-radius: 4px; font-family: 'Fira Code', monospace;">${timeStr}</div>`;
        }
        html += '</div>';
    }
    html += '</div>';
    html += '</div>';

    // Fonction pour calculer les positions sans chevauchement (algorithme de placement)
    function calculateLanes(flows, startTime, duration, timelineWidth) {
        const lanes = [];
        const barHeight = 24; // Hauteur réduite pour plus de compacité
        const minBarWidth = 4; // Largeur minimale en pixels

        flows.forEach(flow => {
            const timePos = ((flow.timestamp_start || 0) - startTime) / duration;
            const duration_ms = flow.duration_ms || 50;
            const barWidth = Math.max((duration_ms / duration / 10) * (timelineWidth * 10), minBarWidth);
            const endPos = timePos + (barWidth / (timelineWidth * 10));

            // Trouver une lane disponible
            let laneIndex = 0;
            let placed = false;

            while (!placed) {
                if (laneIndex >= lanes.length) {
                    lanes.push([]);
                }

                // Vérifier si cette lane est libre à cette position
                const conflicts = lanes[laneIndex].some(existing => {
                    const existingStart = ((existing.flow.timestamp_start || 0) - startTime) / duration;
                    const existingEnd = existingStart + (existing.width / (timelineWidth * 10));
                    // Vérifier chevauchement
                    return !(endPos <= existingStart || timePos >= existingEnd);
                });

                if (!conflicts) {
                    lanes[laneIndex].push({
                        flow: flow,
                        start: timePos,
                        width: barWidth,
                        lane: laneIndex
                    });
                    placed = true;
                } else {
                    laneIndex++;
                }
            }
        });

        return { lanes, barHeight };
    }

    // Barres de timeline par endpoint avec système de lanes amélioré
    let rowIndex = 0;
    Array.from(flowsByEndpoint.values())
        .sort((a, b) => b.count - a.count)
        .forEach((endpointData) => {
            const flows = endpointData.flows;
            // Calculer les lanes pour cet endpoint
            const { lanes, barHeight } = calculateLanes(flows, startTime, duration, timelineWidth);
            const endpointHeight = Math.max(lanes.length * (barHeight + 6), rowHeight);
            const yPos = paddingTop + (rowIndex * rowHeight);

            // Label de l'endpoint (dans la sidebar, déjà fait)
            // Ici on trace juste les barres dans la zone de timeline

            // Barres de requêtes dans leurs lanes respectives - Design amélioré
            lanes.forEach((lane, laneIndex) => {
                lane.forEach(({ flow, start, width, lane: laneNum }) => {
                    const timePos = start * 100;
                    const barWidth = Math.max(width, 4);

                    let statusColor, statusGradient, statusIcon, statusText;
                    if (flow.status_code >= 500) {
                        statusColor = '#d32f2f';
                        statusGradient = 'linear-gradient(135deg, #d32f2f 0%, #b71c1c 100%)';
                        statusIcon = 'error';
                        statusText = 'Server error';
                    } else if (flow.status_code >= 400) {
                        statusColor = '#f44336';
                        statusGradient = 'linear-gradient(135deg, #f44336 0%, #c62828 100%)';
                        statusIcon = 'warning';
                        statusText = 'Client error';
                    } else if (flow.status_code >= 300) {
                        statusColor = '#ff9800';
                        statusGradient = 'linear-gradient(135deg, #ff9800 0%, #f57c00 100%)';
                        statusIcon = 'redirect';
                        statusText = 'Redirection';
                    } else if (flow.status_code >= 200) {
                        statusColor = '#4caf50';
                        statusGradient = 'linear-gradient(135deg, #4caf50 0%, #388e3c 100%)';
                        statusIcon = 'check_circle';
                        statusText = 'Success';
                    } else {
                        statusColor = '#9e9e9e';
                        statusGradient = 'linear-gradient(135deg, #9e9e9e 0%, #616161 100%)';
                        statusIcon = 'help';
                        statusText = 'Inconnu';
                    }

                    // Couleur selon la méthode HTTP
                    let methodColor = '#2196f3';
                    let methodGradient = 'linear-gradient(135deg, #2196f3 0%, #1976d2 100%)';
                    if (flow.method === 'GET') {
                        methodColor = '#4caf50';
                        methodGradient = 'linear-gradient(135deg, #4caf50 0%, #388e3c 100%)';
                    } else if (flow.method === 'POST') {
                        methodColor = '#ff9800';
                        methodGradient = 'linear-gradient(135deg, #ff9800 0%, #f57c00 100%)';
                    } else if (flow.method === 'PUT') {
                        methodColor = '#9c27b0';
                        methodGradient = 'linear-gradient(135deg, #9c27b0 0%, #7b1fa2 100%)';
                    } else if (flow.method === 'DELETE') {
                        methodColor = '#f44336';
                        methodGradient = 'linear-gradient(135deg, #f44336 0%, #c62828 100%)';
                    } else if (flow.method === 'PATCH') {
                        methodColor = '#00bcd4';
                        methodGradient = 'linear-gradient(135deg, #00bcd4 0%, #0097a7 100%)';
                    }

                    const shortPath = flow.path && flow.path.length > 40 ? flow.path.substring(0, 37) + '...' : (flow.path || '/');
                    const laneYPos = yPos + (laneNum * (barHeight + 4)) + 4;
                    const actualBarWidth = Math.max(barWidth, 60);

                    // Couleur simplifiée selon le statut
                    let statusBg = statusColor;
                    if (flow.status_code >= 200 && flow.status_code < 300) {
                        statusBg = '#4caf50';
                    } else if (flow.status_code >= 300 && flow.status_code < 400) {
                        statusBg = '#ff9800';
                    } else if (flow.status_code >= 400) {
                        statusBg = '#f44336';
                    }

                    html += `<div class="timeline-bar" data-flow-id="${flow.id}" data-endpoint="${escapeHtml(endpointData.endpoint)}" data-status="${flow.status_code || 0}" data-method="${flow.method || 'GET'}" style="
                    position: absolute;
                        left: ${(timePos * (timelineWidth / 100))}%;
                    top: ${laneYPos}px;
                        width: ${actualBarWidth}px;
                    height: ${barHeight}px;
                        background: ${statusBg};
                        border-left: 3px solid ${methodColor};
                        border-radius: 4px;
                    cursor: pointer;
                        transition: all 0.2s ease;
                        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                    z-index: ${2 + laneNum};
                    display: flex;
                    align-items: center;
                        padding: 0 6px;
                    overflow: hidden;
                    " onmouseover="this.style.transform='translateY(-1px)'; this.style.zIndex='100'; this.style.boxShadow='0 3px 8px rgba(0,0,0,0.2)';" 
                       onmouseout="this.style.transform='translateY(0)'; this.style.zIndex='${2 + laneNum}'; this.style.boxShadow='0 1px 3px rgba(0,0,0,0.1)';"
                   onclick="selectFlowFromTimeline('${flow.id}')">`;

                    // Contenu de la barre simplifié
                    html += `<div style="display: flex; align-items: center; gap: 4px; width: 100%; overflow: hidden;">`;
                    html += `<span style="
                        font-weight: 600;
                        font-size: 10px;
                        color: white;
                        background: ${methodColor};
                        padding: 2px 5px;
                        border-radius: 3px;
                        white-space: nowrap;
                        flex-shrink: 0;
                        font-family: 'Fira Code', monospace;
                    ">${flow.method || 'GET'}</span>`;
                    if (actualBarWidth > 100) {
                        html += `<span style="
                            font-size: 10px;
                            color: white;
                            overflow: hidden;
                            text-overflow: ellipsis;
                            white-space: nowrap;
                            flex: 1;
                            font-weight: 500;
                        ">${escapeHtml(shortPath)}</span>`;
                    }
                    if (actualBarWidth > 80) {
                        html += `<span style="
                            font-weight: 600;
                            font-size: 10px;
                        color: white;
                        white-space: nowrap;
                        flex-shrink: 0;
                            font-family: 'Fira Code', monospace;
                    ">${flow.status_code || 'N/A'}</span>`;
                    }
                    html += `</div>`;

                    // Tooltip amélioré
                    const duration_ms = flow.duration_ms || 50;
                    const date = new Date((flow.timestamp_start || 0) * 1000);
                    const tooltipText = `${flow.method || 'GET'} ${flow.url || 'N/A'}\nStatus: ${flow.status_code || 'N/A'}\nDuration: ${duration_ms}ms\nTime: ${date.toLocaleString('fr-FR')}`;
                    html += `<div style="
                        position: absolute;
                        bottom: calc(100% + 8px);
                        left: 50%;
                        transform: translateX(-50%);
                        background: rgba(0,0,0,0.95);
                        color: white;
                        padding: 10px 14px;
                        border-radius: 8px;
                        font-size: 12px;
                        white-space: pre-line;
                        pointer-events: none;
                        opacity: 0;
                        transition: opacity 0.3s;
                        z-index: 1000;
                        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
                        max-width: 300px;
                        text-align: left;
                        line-height: 1.6;
                    " class="timeline-tooltip">${escapeHtml(tooltipText)}</div>`;

                    html += '</div>';
                });
            });

            // Ligne de séparation entre endpoints
            html += `<div style="
                position: absolute;
                left: 0;
                top: ${yPos + endpointHeight}px;
                right: 0;
                height: 1px;
                background: var(--border-color);
                opacity: 0.5;
                z-index: 1;
            "></div>`;

            // Ajuster rowIndex
            rowIndex += Math.max(1, Math.ceil(endpointHeight / rowHeight));
        });

    html += '</div>'; // Fin du conteneur timeline
    html += '</div>'; // Fin de la zone de timeline
    html += '</div>'; // Fin du flex container

    // Légende simplifiée
    html += '<div style="margin-top: 20px; padding: 14px 16px; background: white; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); border: 1px solid var(--border-color);">';
    html += '<div style="display: flex; gap: 20px; align-items: center; flex-wrap: wrap; justify-content: center;">';
    html += '<div style="display: flex; align-items: center; gap: 8px;">';
    html += '<div style="width: 16px; height: 16px; background: #4caf50; border-radius: 3px;"></div>';
    html += '<span style="font-size: 13px; color: var(--text-color); font-weight: 500;">Success (2xx)</span>';
    html += '</div>';
    html += '<div style="display: flex; align-items: center; gap: 8px;">';
    html += '<div style="width: 16px; height: 16px; background: #ff9800; border-radius: 3px;"></div>';
    html += '<span style="font-size: 13px; color: var(--text-color); font-weight: 500;">Redirects (3xx)</span>';
    html += '</div>';
    html += '<div style="display: flex; align-items: center; gap: 8px;">';
    html += '<div style="width: 16px; height: 16px; background: #f44336; border-radius: 3px;"></div>';
    html += '<span style="font-size: 13px; color: var(--text-color); font-weight: 500;">Errors (4xx/5xx)</span>';
    html += '</div>';
    html += '<div style="display: flex; align-items: center; gap: 8px; margin-left: 12px; padding-left: 12px; border-left: 1px solid var(--border-color);">';
    html += '<span style="font-size: 12px; color: var(--text-secondary);">Left border = HTTP Method</span>';
    html += '</div>';
    html += '</div>';
    html += '</div>';

    html += '</div>'; // Fin du padding principal

    const timelinePanel2 = getCurrentVizPanel();
    if (timelinePanel2) {
        timelinePanel2.innerHTML = html;
    }

    // Gérer les tooltips
    document.querySelectorAll('.timeline-bar').forEach(bar => {
        const tooltip = bar.querySelector('.timeline-tooltip');
        bar.addEventListener('mouseenter', () => {
            if (tooltip) tooltip.style.opacity = '1';
        });
        bar.addEventListener('mouseleave', () => {
            if (tooltip) tooltip.style.opacity = '0';
        });
    });

    // Gérer les filtres améliorés
    const filterSlider = document.getElementById('timeline-filter');
    const timelineInfo = document.getElementById('timeline-info');
    const filterSuccess = document.getElementById('timeline-filter-success');
    const filterRedirect = document.getElementById('timeline-filter-redirect');
    const filterError = document.getElementById('timeline-filter-error');
    const filterMethod = document.getElementById('timeline-filter-method');
    const searchInput = document.getElementById('timeline-search');
    const zoomInBtn = document.getElementById('timeline-zoom-in');
    const zoomOutBtn = document.getElementById('timeline-zoom-out');
    const resetBtn = document.getElementById('timeline-reset');
    const timelineContainer = document.getElementById('timeline-container');
    let zoomLevel = 1;

    function applyAllFilters() {
        const showSuccess = filterSuccess ? filterSuccess.checked : true;
        const showRedirect = filterRedirect ? filterRedirect.checked : true;
        const showError = filterError ? filterError.checked : true;
        const selectedMethod = filterMethod ? filterMethod.value : 'all';
        const searchTerm = searchInput ? searchInput.value.toLowerCase() : '';
        const percentage = filterSlider ? filterSlider.value : 100;
        const maxTime = startTime + (duration * percentage / 100);

        let visibleCount = 0;

        document.querySelectorAll('.timeline-bar').forEach(bar => {
            const flowId = bar.getAttribute('data-flow-id');
            const flow = sortedFlows.find(f => f.id === flowId);
            if (!flow) return;

            const status = flow.status_code || 0;
            const method = flow.method || 'GET';
            const endpoint = bar.getAttribute('data-endpoint') || '';
            const url = flow.url || '';

            // Filtre par statut
            let statusMatch = false;
            if (status >= 200 && status < 300) statusMatch = showSuccess;
            else if (status >= 300 && status < 400) statusMatch = showRedirect;
            else if (status >= 400) statusMatch = showError;

            // Filtre par méthode
            const methodMatch = selectedMethod === 'all' || method === selectedMethod;

            // Filtre par recherche
            const searchMatch = !searchTerm ||
                endpoint.toLowerCase().includes(searchTerm) ||
                url.toLowerCase().includes(searchTerm) ||
                (flow.path || '').toLowerCase().includes(searchTerm);

            // Filtre temporel
            const timeMatch = (flow.timestamp_start || 0) <= maxTime;

            const shouldShow = statusMatch && methodMatch && searchMatch && timeMatch;
            bar.style.display = shouldShow ? 'flex' : 'none';
            if (shouldShow) visibleCount++;
        });

        // Filtrer aussi la sidebar
        if (searchInput) {
            document.querySelectorAll('.timeline-endpoint-item').forEach(item => {
                const endpoint = item.getAttribute('data-endpoint') || '';
                const method = item.getAttribute('data-method') || '';
                const methodMatch = selectedMethod === 'all' || method === selectedMethod;
                const searchMatch = !searchTerm || endpoint.toLowerCase().includes(searchTerm);
                item.style.display = methodMatch && searchMatch ? 'block' : 'none';
            });
        }

        if (timelineInfo) {
            timelineInfo.textContent = `${visibleCount} requests displayed${percentage < 100 ? ` (${percentage}% of time)` : ''}`;
        }
    }

    if (filterSlider) filterSlider.addEventListener('input', applyAllFilters);
    if (filterSuccess) filterSuccess.addEventListener('change', applyAllFilters);
    if (filterRedirect) filterRedirect.addEventListener('change', applyAllFilters);
    if (filterError) filterError.addEventListener('change', applyAllFilters);
    if (filterMethod) filterMethod.addEventListener('change', applyAllFilters);
    if (searchInput) {
        searchInput.addEventListener('input', applyAllFilters);
        searchInput.addEventListener('keyup', (e) => {
            if (e.key === 'Enter') applyAllFilters();
        });
    }

    // Gérer le zoom
    if (zoomInBtn && zoomOutBtn && timelineContainer) {
        zoomInBtn.addEventListener('click', () => {
            zoomLevel = Math.min(zoomLevel * 1.3, 5);
            timelineContainer.style.transform = `scaleX(${zoomLevel})`;
            timelineContainer.style.transformOrigin = 'left top';
        });

        zoomOutBtn.addEventListener('click', () => {
            zoomLevel = Math.max(zoomLevel / 1.3, 0.5);
            timelineContainer.style.transform = `scaleX(${zoomLevel})`;
            timelineContainer.style.transformOrigin = 'left top';
        });
    }

    // Reset
    if (resetBtn) {
        resetBtn.addEventListener('click', () => {
            if (filterSlider) filterSlider.value = 100;
            if (filterSuccess) filterSuccess.checked = true;
            if (filterRedirect) filterRedirect.checked = true;
            if (filterError) filterError.checked = true;
            if (filterMethod) filterMethod.value = 'all';
            if (searchInput) searchInput.value = '';
            zoomLevel = 1;
            if (timelineContainer) {
                timelineContainer.style.transform = 'scaleX(1)';
                timelineContainer.style.transformOrigin = 'left top';
            }
            applyAllFilters();
        });
    }
}

function scrollToTimelineEndpoint(endpoint) {
    // Trouver la première barre de cet endpoint et scroller vers elle
    const firstBar = document.querySelector(`.timeline-bar[data-endpoint="${escapeHtml(endpoint)}"]`);
    if (firstBar) {
        firstBar.scrollIntoView({ behavior: 'smooth', block: 'center', inline: 'center' });
        // Highlight temporairement
        firstBar.style.boxShadow = '0 0 0 4px rgba(98, 0, 234, 0.3)';
        setTimeout(() => {
            firstBar.style.boxShadow = '';
        }, 2000);
    }
}

function selectFlowFromTimeline(flowId) {
    currentFlowId = flowId;
    renderFlowList();
    updateDetailButtons();
    renderDetail();
}

function showNavigationTree() {
    const navPanel = getCurrentVizPanel();
    if (!navPanel) return;

    if (flowsData.length === 0) {
        navPanel.innerHTML = '<div style="text-align: center; padding: 50px; color: #888;">No requests to display</div>';
        return;
    }

    // Filtrer les flows par domaine sélectionné
    const filteredFlows = selectedDomainForGraph
        ? flowsData.filter(flow => {
            try {
                const url = new URL(flow.url);
                return url.hostname === selectedDomainForGraph;
            } catch {
                return false;
            }
        })
        : flowsData;

    if (filteredFlows.length === 0) {
        navPanel.innerHTML = '<div style="text-align: center; padding: 50px; color: #888;">No requests to display for this domain</div>';
        return;
    }

    // Construire l'arbre de navigation
    const tree = {};
    const nodeData = new Map(); // Stocker les données pour chaque nœud

    filteredFlows.forEach(flow => {
        try {
            const url = new URL(flow.url);
            const domain = url.hostname;
            const path = url.pathname;

            // Initialiser le domaine s'il n'existe pas
            if (!tree[domain]) {
                tree[domain] = {};
                nodeData.set(domain, {
                    type: 'domain',
                    flows: [],
                    methods: new Set(),
                    statusCodes: new Set(),
                    totalRequests: 0
                });
            }

            // Ajouter les données du flow
            const domainData = nodeData.get(domain);
            domainData.flows.push(flow);
            domainData.methods.add(flow.method);
            if (flow.status_code) domainData.statusCodes.add(flow.status_code);
            domainData.totalRequests++;

            // Construire l'arbre de chemins
            const pathParts = path.split('/').filter(p => p);
            let current = tree[domain];

            let fullPath = '';
            pathParts.forEach((part, index) => {
                fullPath += '/' + part;
                if (!current[fullPath]) {
                    current[fullPath] = {};
                    nodeData.set(`${domain}${fullPath}`, {
                        type: 'path',
                        path: fullPath,
                        flows: [],
                        methods: new Set(),
                        statusCodes: new Set(),
                        totalRequests: 0
                    });
                }

                const pathData = nodeData.get(`${domain}${fullPath}`);
                pathData.flows.push(flow);
                pathData.methods.add(flow.method);
                if (flow.status_code) pathData.statusCodes.add(flow.status_code);
                pathData.totalRequests++;

                current = current[fullPath];
            });
        } catch (e) {
            // URL invalide, ignorer
        }
    });

    // Analyser les endpoints découverts pour enrichir l'arbre
    const endpointMap = new Map();
    filteredFlows.forEach(flow => {
        if (flow.endpoints) {
            Object.values(flow.endpoints).flat().forEach(endpoint => {
                try {
                    const url = new URL(endpoint, flow.url);
                    const domain = url.hostname;
                    const path = url.pathname;
                    const key = `${domain}${path}`;

                    if (!endpointMap.has(key)) {
                        endpointMap.set(key, {
                            domain: domain,
                            path: path,
                            discovered: true,
                            flows: []
                        });
                    }
                    endpointMap.get(key).flows.push(flow);
                } catch (e) {
                    // URL invalide
                }
            });
        }
    });

    // Construire le HTML - Style épuré
    let html = '<div style="padding: 20px; background: var(--bg-color);">';
    html += '<div style="background: white; border: 1px solid var(--border-color); border-radius: 8px; padding: 20px;">';
    html += '<h2 style="margin: 0 0 20px 0; color: var(--primary-color); font-size: 1.3rem; font-weight: 600; display: flex; align-items: center; gap: 10px;">';
    html += '<span class="material-symbols-outlined" style="font-size: 24px;">account_tree</span>';
    html += 'Navigation Tree</h2>';

    // Statistiques - Style épuré
    const totalDomains = Object.keys(tree).length;
    const totalPaths = Array.from(nodeData.values()).filter(n => n.type === 'path').length;
    const totalEndpoints = endpointMap.size;

    html += '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-bottom: 20px;">';
    html += `<div style="background: white; border: 1px solid var(--border-color); border-left: 3px solid var(--primary-color); border-radius: 6px; padding: 12px;">`;
    html += `<div style="font-size: 24px; font-weight: 600; color: #333; margin-bottom: 4px;">${totalDomains}</div>`;
    html += `<div style="font-size: 13px; color: var(--text-secondary);">Domains</div>`;
    html += `</div>`;
    html += `<div style="background: white; border: 1px solid var(--border-color); border-left: 3px solid var(--primary-color); border-radius: 6px; padding: 12px;">`;
    html += `<div style="font-size: 24px; font-weight: 600; color: #333; margin-bottom: 4px;">${totalPaths}</div>`;
    html += `<div style="font-size: 13px; color: var(--text-secondary);">Paths</div>`;
    html += `</div>`;
    html += `<div style="background: white; border: 1px solid var(--border-color); border-left: 3px solid var(--primary-color); border-radius: 6px; padding: 12px;">`;
    html += `<div style="font-size: 24px; font-weight: 600; color: #333; margin-bottom: 4px;">${totalEndpoints}</div>`;
    html += `<div style="font-size: 13px; color: var(--text-secondary);">Discovered Endpoints</div>`;
    html += `</div>`;
    html += '</div>';

    // Contrôles - Style cohérent
    html += '<div style="margin-bottom: 16px; display: flex; gap: 12px; align-items: center; flex-wrap: wrap; padding: 12px; background: #fafafa; border-radius: 6px; border: 1px solid var(--border-color);">';
    html += '<button id="nav-tree-expand-all" class="btn btn-secondary" style="padding: 6px 12px; font-size: 13px;">Expand All</button>';
    html += '<button id="nav-tree-collapse-all" class="btn btn-secondary" style="padding: 6px 12px; font-size: 13px;">Collapse All</button>';
    html += '<label style="display: flex; align-items: center; gap: 8px; color: var(--text-secondary); font-size: 14px;">';
    html += '<input type="checkbox" id="nav-tree-show-discovered" checked>';
    html += '<span>Show discovered endpoints</span>';
    html += '</label>';
    html += '</div>';

    // Arbre de navigation - Style épuré
    html += '<div style="background: white; border: 1px solid var(--border-color); border-radius: 6px; padding: 16px; max-height: calc(100vh - 300px); overflow: auto;">';
    html += '<div id="navigation-tree-container">';

    // Fonction récursive pour rendre l'arbre
    function renderTreeNode(domain, paths, level = 0) {
        const indent = level * 24;
        const isExpanded = level === 0;

        let nodeHtml = '';

        if (level === 0) {
            // Nœud domaine
            const domainData = nodeData.get(domain);
            const successCount = domainData.flows.filter(f => f.status_code >= 200 && f.status_code < 300).length;
            const errorCount = domainData.flows.filter(f => f.status_code >= 400).length;

            const hasChildren = Object.keys(paths).length > 0;
            nodeHtml += `<div class="nav-tree-node" data-level="${level}" data-path="${domain}" data-has-children="${hasChildren}" style="margin-left: ${indent}px; margin-bottom: 6px;">`;
            nodeHtml += `<div class="nav-tree-item" style="
                background: white;
                border: 1px solid var(--border-color);
                border-left: 3px solid var(--primary-color);
                color: var(--text-color);
                padding: 10px 14px;
                border-radius: 6px;
                cursor: pointer;
                display: flex;
                align-items: center;
                gap: 12px;
                transition: all 0.2s;
            " onmouseover="this.style.background='#fafafa'; this.style.borderColor='var(--primary-color)';" 
               onmouseout="this.style.background='white'; this.style.borderColor='var(--border-color)';"
               onclick="toggleNavTreeNode(this)">`;
            nodeHtml += `<span class="material-symbols-outlined nav-tree-icon" style="font-size: 20px; color: var(--primary-color);">public</span>`;
            nodeHtml += `<div style="flex: 1;">`;
            nodeHtml += `<div style="font-weight: 600; font-size: 14px; color: var(--text-color);">${domain}</div>`;
            nodeHtml += `<div style="font-size: 12px; color: var(--text-secondary); margin-top: 2px;">${domainData.totalRequests} requests | ${Array.from(domainData.methods).join(', ')}</div>`;
            nodeHtml += `</div>`;
            nodeHtml += `<div style="display: flex; gap: 6px; align-items: center;">`;
            if (successCount > 0) {
                nodeHtml += `<span style="background: #e8f5e9; color: #2e7d32; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 500; border: 1px solid #c8e6c9;">✓ ${successCount}</span>`;
            }
            if (errorCount > 0) {
                nodeHtml += `<span style="background: #ffebee; color: #c62828; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 500; border: 1px solid #ffcdd2;">✗ ${errorCount}</span>`;
            }
            nodeHtml += `<span class="material-symbols-outlined nav-tree-expand-icon" style="font-size: 18px; color: var(--text-secondary);">${hasChildren ? 'expand_more' : ''}</span>`;
            nodeHtml += `</div>`;
            nodeHtml += `</div>`;

            if (hasChildren) {
                nodeHtml += `<div class="nav-tree-children" style="display: ${isExpanded ? 'block' : 'none'}; margin-top: 4px;">`;
                Object.keys(paths).sort().forEach(path => {
                    nodeHtml += renderPathNode(domain, path, paths[path], level + 1);
                });
                nodeHtml += '</div>';
            }

            nodeHtml += '</div>';
        }

        return nodeHtml;
    }

    // Fonction pour rendre les nœuds de chemin
    function renderPathNode(domain, pathKey, children, level) {
        const pathData = nodeData.get(`${domain}${pathKey}`);
        if (!pathData) return '';

        const indent = level * 24;
        const pathName = pathKey.split('/').pop() || '/';
        const successCount = pathData.flows.filter(f => f.status_code >= 200 && f.status_code < 300).length;
        const errorCount = pathData.flows.filter(f => f.status_code >= 400).length;
        const statusColor = errorCount > 0 ? '#f44336' : successCount > 0 ? '#4caf50' : '#9e9e9e';
        const hasChildren = Object.keys(children).length > 0;

        // Stocker les IDs des flows dans un attribut data pour un accès facile
        const flowIds = pathData.flows.map(f => f.id).join(',');
        const fullPath = `${domain}${pathKey}`;
        let nodeHtml = `<div class="nav-tree-node" data-level="${level}" data-path="${fullPath}" data-has-children="${hasChildren}" data-flow-ids="${flowIds}" style="margin-left: ${indent}px; margin-bottom: 4px;">`;
        // Si c'est un dossier (a des enfants), le clic toggle seulement. Si c'est un fichier, le clic ouvre les détails
        const clickHandler = hasChildren
            ? "toggleNavTreeNode(this)"
            : `selectNavTreeNode('${fullPath}')`;
        nodeHtml += `<div class="nav-tree-item" style="
            background: white;
            border: 1px solid var(--border-color);
            border-left: 3px solid ${statusColor};
            color: var(--text-color);
            padding: 8px 12px;
            border-radius: 6px;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 10px;
            transition: all 0.2s;
        " onmouseover="this.style.background='#fafafa'; this.style.borderColor='${statusColor}';" 
           onmouseout="this.style.background='white'; this.style.borderColor='var(--border-color)';"
           onclick="${clickHandler}">`;
        nodeHtml += `<span class="material-symbols-outlined nav-tree-icon" style="font-size: 18px; color: ${statusColor};">${hasChildren ? 'folder' : 'description'}</span>`;
        nodeHtml += `<div style="flex: 1;">`;
        nodeHtml += `<div style="font-weight: 500; font-size: 13px; color: var(--text-color);">${pathName}</div>`;
        nodeHtml += `<div style="font-size: 11px; color: var(--text-secondary); margin-top: 2px;">${pathData.totalRequests} requests | ${Array.from(pathData.methods).join(', ')}</div>`;
        nodeHtml += `</div>`;
        nodeHtml += `<div style="display: flex; gap: 6px; align-items: center;">`;
        if (successCount > 0) {
            nodeHtml += `<span style="background: #e8f5e9; color: #2e7d32; padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: 500; border: 1px solid #c8e6c9;">${successCount}</span>`;
        }
        if (errorCount > 0) {
            nodeHtml += `<span style="background: #ffebee; color: #c62828; padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: 500; border: 1px solid #ffcdd2;">${errorCount}</span>`;
        }
        if (hasChildren) {
            nodeHtml += `<span class="material-symbols-outlined nav-tree-expand-icon" style="font-size: 16px; color: var(--text-secondary);">chevron_right</span>`;
        } else {
            // Pour les fichiers, ajouter une icône pour voir les détails (double-clic ou bouton séparé)
            nodeHtml += `<span class="material-symbols-outlined" style="font-size: 14px; color: var(--text-secondary); opacity: 0.6;" title="Double-clic pour voir les détails">visibility</span>`;
        }
        nodeHtml += `</div>`;
        nodeHtml += `</div>`;

        if (hasChildren) {
            nodeHtml += `<div class="nav-tree-children" style="display: none; margin-top: 4px;">`;
            Object.keys(children).sort().forEach(childPath => {
                nodeHtml += renderPathNode(domain, childPath, children[childPath], level + 1);
            });
            nodeHtml += '</div>';
        }

        nodeHtml += '</div>';
        return nodeHtml;
    }

    // Rendre chaque domaine
    Object.keys(tree).sort().forEach(domain => {
        html += renderTreeNode(domain, tree[domain], 0);
    });

    // Ajouter les endpoints découverts - Style épuré
    if (endpointMap.size > 0) {
        html += '<div id="discovered-endpoints-section" style="margin-top: 24px; padding-top: 20px; border-top: 1px solid var(--border-color);">';
        html += '<h3 style="color: var(--text-color); margin-bottom: 12px; font-size: 1rem; font-weight: 600; display: flex; align-items: center; gap: 8px;">';
        html += '<span class="material-symbols-outlined" style="font-size: 20px; color: var(--primary-color);">explore</span>';
        html += 'Discovered Endpoints (not visited)</h3>';

        const endpointsByDomain = new Map();
        endpointMap.forEach((data, key) => {
            if (!endpointsByDomain.has(data.domain)) {
                endpointsByDomain.set(data.domain, []);
            }
            endpointsByDomain.get(data.domain).push(data);
        });

        endpointsByDomain.forEach((endpoints, domain) => {
            html += `<div style="margin-bottom: 12px;">`;
            html += `<div style="font-weight: 600; color: var(--text-color); margin-bottom: 8px; font-size: 13px;">${domain}</div>`;
            endpoints.forEach(endpoint => {
                html += `<div style="
                    background: white;
                    border: 1px solid var(--border-color);
                    border-left: 3px solid #ff9800;
                    color: var(--text-color);
                    padding: 8px 12px;
                    border-radius: 6px;
                    margin-bottom: 4px;
                    font-size: 13px;
                    cursor: pointer;
                    transition: all 0.2s;
                " onmouseover="this.style.background='#fafafa'; this.style.borderColor='#ff9800';" 
                   onmouseout="this.style.background='white'; this.style.borderColor='var(--border-color)';"
                   onclick="selectNavTreeNode('${endpoint.domain}${endpoint.path}')">`;
                html += `<span class="material-symbols-outlined" style="font-size: 16px; vertical-align: middle; margin-right: 6px; color: #ff9800;">link</span>`;
                html += `${endpoint.path} <span style="color: var(--text-secondary); font-size: 11px;">(${endpoint.flows.length} references)</span>`;
                html += `</div>`;
            });
            html += `</div>`;
        });

        html += '</div>';
    }

    html += '</div></div>';
    html += '</div></div>';

    let vizPanel = getCurrentVizPanel();
    if (vizPanel) {
        vizPanel.innerHTML = html;
    }

    // Gérer les contrôles
    const expandAllBtn = document.getElementById('nav-tree-expand-all');
    const collapseAllBtn = document.getElementById('nav-tree-collapse-all');
    const showDiscoveredCheck = document.getElementById('nav-tree-show-discovered');

    if (expandAllBtn) {
        expandAllBtn.addEventListener('click', () => {
            // Développer TOUS les enfants
            document.querySelectorAll('.nav-tree-children').forEach(el => {
                el.style.display = 'block';
            });
            // Mettre à jour toutes les icônes
            document.querySelectorAll('.nav-tree-expand-icon').forEach(el => {
                const node = el.closest('.nav-tree-node');
                if (node) {
                    const level = parseInt(node.getAttribute('data-level') || '0');
                    // Pour les domaines (level 0), utiliser 'expand_less', pour les autres 'expand_more'
                    if (level === 0) {
                        el.textContent = 'expand_less';
                    } else {
                        el.textContent = 'expand_more';
                    }
                }
            });
        });
    }

    if (collapseAllBtn) {
        collapseAllBtn.addEventListener('click', () => {
            // Réduire TOUS les enfants, y compris ceux des domaines (level 0)
            document.querySelectorAll('.nav-tree-children').forEach(el => {
                el.style.display = 'none';
            });
            // Mettre à jour toutes les icônes
            document.querySelectorAll('.nav-tree-expand-icon').forEach(el => {
                const node = el.closest('.nav-tree-node');
                if (node) {
                    const level = parseInt(node.getAttribute('data-level') || '0');
                    // Pour les domaines (level 0), utiliser 'expand_more', pour les autres 'chevron_right'
                    if (level === 0) {
                        el.textContent = 'expand_more';
                    } else {
                        el.textContent = 'chevron_right';
                    }
                }
            });
        });
    }

    if (showDiscoveredCheck) {
        showDiscoveredCheck.addEventListener('change', (e) => {
            const discoveredSection = document.getElementById('discovered-endpoints-section');
            if (discoveredSection) {
                discoveredSection.style.display = e.target.checked ? 'block' : 'none';
            }
        });
    }
}

function toggleNavTreeNode(element) {
    const node = element.closest('.nav-tree-node');
    const children = node.querySelector('.nav-tree-children');
    const icon = element.querySelector('.nav-tree-expand-icon');
    const hasChildren = node.getAttribute('data-has-children') === 'true';

    // Si c'est un dossier (a des enfants), toggle l'ouverture/fermeture
    if (hasChildren && children) {
        const isExpanded = children.style.display !== 'none';
        children.style.display = isExpanded ? 'none' : 'block';

        if (icon) {
            const level = parseInt(node.getAttribute('data-level') || '0');
            if (isExpanded) {
                // Fermer
                if (level === 0) {
                    icon.textContent = 'expand_more';
                } else {
                    icon.textContent = 'chevron_right';
                }
            } else {
                // Ouvrir
                if (level === 0) {
                    icon.textContent = 'expand_less';
                } else {
                    icon.textContent = 'expand_more';
                }
            }
        }
    }
    // Si c'est un fichier (pas d'enfants), ne rien faire ici (selectNavTreeNode sera appelé)
}

function selectNavTreeNode(path) {
    console.log('[NAV TREE] Selecting node:', path);

    // Essayer d'abord de récupérer les flows depuis l'attribut data-flow-ids du DOM
    let matchingFlows = [];
    const nodeElement = document.querySelector(`[data-path="${path}"]`);
    if (nodeElement) {
        const flowIdsStr = nodeElement.getAttribute('data-flow-ids');
        if (flowIdsStr) {
            const flowIds = flowIdsStr.split(',').filter(id => id);
            matchingFlows = flowsData.filter(flow => flowIds.includes(flow.id));
            console.log('[NAV TREE] Found', matchingFlows.length, 'flows from DOM data attribute');
        }
    }

    // Si pas de flows trouvés via DOM, utiliser la recherche par chemin
    if (matchingFlows.length === 0) {
        matchingFlows = flowsData.filter(flow => {
            try {
                const url = new URL(flow.url);
                const flowPath = `${url.hostname}${url.pathname}`;

                // Correspondance exacte
                if (flowPath === path) {
                    return true;
                }

                // Normaliser les chemins (enlever trailing slash)
                const normalizedPath = path.replace(/\/$/, '');
                const normalizedFlowPath = flowPath.replace(/\/$/, '');
                if (normalizedFlowPath === normalizedPath) {
                    return true;
                }

                // Correspondance : le flowPath commence par le path (pour les dossiers)
                if (normalizedFlowPath.startsWith(normalizedPath + '/') || normalizedFlowPath === normalizedPath) {
                    return true;
                }

                // Correspondance inverse : le path contient le flowPath complet
                if (normalizedPath.includes(normalizedFlowPath) && normalizedFlowPath.length > 5) {
                    return true;
                }

                // Correspondance par nom de fichier (dernier segment)
                const pathFileName = normalizedPath.split('/').pop();
                const flowFileName = normalizedFlowPath.split('/').pop();
                if (pathFileName && flowFileName && pathFileName === flowFileName && pathFileName.length > 0) {
                    // Vérifier que le domaine correspond aussi
                    const pathDomain = path.split('/')[0];
                    const flowDomain = url.hostname;
                    if (pathDomain === flowDomain || path.startsWith(flowDomain)) {
                        return true;
                    }
                }

                return false;
            } catch (e) {
                console.warn('[NAV TREE] Error processing flow:', e, flow.url);
                return false;
            }
        });
    }

    console.log('[NAV TREE] Found', matchingFlows.length, 'matching flows for path:', path);
    if (matchingFlows.length > 0) {
        console.log('[NAV TREE] Sample flow URLs:', matchingFlows.slice(0, 3).map(f => {
            try {
                const url = new URL(f.url);
                return `${url.hostname}${url.pathname}`;
            } catch {
                return f.url;
            }
        }));
    }

    if (matchingFlows.length > 0) {
        // Sélectionner le premier flow (ou le plus récent)
        const selectedFlow = matchingFlows.sort((a, b) =>
            (b.timestamp_start || 0) - (a.timestamp_start || 0)
        )[0];

        // Afficher le contenu du fichier dans une modal
        showFileContentModal(selectedFlow, path);
    } else {
        console.warn('[NAV TREE] No matching flows found for path:', path);
        console.warn('[NAV TREE] Available flows sample:', flowsData.slice(0, 5).map(f => {
            try {
                const url = new URL(f.url);
                return `${url.hostname}${url.pathname}`;
            } catch {
                return f.url;
            }
        }));
        alert(`No matching flows found for this path: ${path}\n\nCheck the console for more details.`);
    }
}

// Fonction pour afficher le contenu d'un fichier dans une modal
async function showFileContentModal(flow, path) {
    const overlay = document.getElementById('file-content-overlay');
    const modal = document.getElementById('file-content-modal');
    const titleEl = document.getElementById('file-content-title');
    const subtitleEl = document.getElementById('file-content-subtitle');
    const iconEl = document.getElementById('file-content-icon');
    const bodyEl = document.getElementById('file-content-body');

    if (!overlay || !modal || !titleEl || !subtitleEl || !iconEl || !bodyEl) {
        console.error('[FILE MODAL] Modal elements not found');
        return;
    }

    // Extraire le nom du fichier depuis le path
    const fileName = path.split('/').pop() || path;
    titleEl.textContent = fileName;
    subtitleEl.textContent = flow.url || path;

    // Afficher un indicateur de chargement
    bodyEl.innerHTML = '<div style="padding: 40px; text-align: center; color: #888;"><span class="material-symbols-outlined" style="font-size: 40px; animation: spin 1s linear infinite; display: inline-block; color: #888; margin-bottom: 16px;">sync</span><p style="margin: 0; color: #666; font-size: 14px;">Loading content...</p></div>';
    overlay.style.display = 'flex';
    modal.style.display = 'block';

    // Si le flow n'a pas de réponse ou pas de contenu, récupérer les détails complets
    if (!flow.response || (!flow.response.content_bs64 && !flow.response.content)) {
        console.log('[FILE MODAL] Flow content not available, fetching details for flow:', flow.id);
        try {
            const res = await fetch(`${API_BASE}/flows/${flow.id}`);
            if (res.ok) {
                flow = await res.json();
                // Mettre à jour le flow dans flowsData cache
                const index = flowsData.findIndex(f => f.id === flow.id);
                if (index !== -1) {
                    flowsData[index] = flow;
                }
                console.log('[FILE MODAL] Flow details fetched successfully');
            } else {
                console.warn('[FILE MODAL] Failed to fetch flow details:', res.status);
            }
        } catch (err) {
            console.error('[FILE MODAL] Error fetching flow details:', err);
        }
    }

    // Récupérer le contenu de la réponse
    let bodyContent = '';
    let contentType = '';

    if (flow.response) {
        contentType = flow.response.headers?.['content-type'] || '';

        if (flow.response.content_bs64) {
            try {
                bodyContent = atob(flow.response.content_bs64);
            } catch (e) {
                console.warn('[FILE MODAL] Error decoding base64 content:', e);
                bodyContent = '';
            }
        } else if (flow.response.content) {
            bodyContent = typeof flow.response.content === 'string'
                ? flow.response.content
                : String(flow.response.content);
        }
    }

    // Déterminer le type de contenu et formater en conséquence
    let formattedContent = '';
    let iconName = 'description';

    if (!bodyContent || bodyContent.trim() === '') {
        formattedContent = '<div style="padding: 40px; text-align: center; color: #888;"><p>No content available</p></div>';
        iconName = 'description';
    } else if (isImageContent(contentType, fileName)) {
        // Afficher l'image
        iconName = 'image';
        try {
            // Créer une data URL pour l'image
            const imageDataUrl = flow.response.content_bs64
                ? `data:${contentType || 'image/png'};base64,${flow.response.content_bs64}`
                : null;

            if (imageDataUrl) {
                formattedContent = `
                    <div style="text-align: center; padding: 20px;">
                        <img src="${imageDataUrl}" 
                             alt="${escapeHtml(fileName)}" 
                             style="max-width: 100%; max-height: 70vh; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.15);"
                             onerror="this.parentElement.innerHTML='<div style=\\'padding: 40px; color: #f44336;\\'>Error loading image</div>'">
                    </div>
                `;
            } else {
                formattedContent = '<div style="padding: 40px; text-align: center; color: #888;"><p>Image data not available in base64 format</p></div>';
            }
        } catch (e) {
            console.error('Error displaying image:', e);
            formattedContent = '<div style="padding: 40px; text-align: center; color: #f44336;"><p>Error displaying image</p></div>';
        }
    } else if (isJsonContent(contentType, bodyContent)) {
        // Formater le JSON
        iconName = 'code';
        try {
            const json = JSON.parse(bodyContent);
            const formattedJson = JSON.stringify(json, null, 2);
            formattedContent = `
                <div style="background: #282c34; border-radius: 8px; padding: 20px; overflow-x: auto;">
                    <pre style="margin: 0; color: #abb2bf; font-family: 'Fira Code', monospace; font-size: 0.9em; line-height: 1.6; white-space: pre-wrap; word-wrap: break-word;"><code>${escapeHtml(formattedJson)}</code></pre>
                </div>
            `;
        } catch (e) {
            // Si le parsing JSON échoue, afficher comme texte brut
            formattedContent = `
                <div style="background: #282c34; border-radius: 8px; padding: 20px; overflow-x: auto;">
                    <pre style="margin: 0; color: #abb2bf; font-family: 'Fira Code', monospace; font-size: 0.9em; line-height: 1.6; white-space: pre-wrap; word-wrap: break-word;"><code>${escapeHtml(bodyContent)}</code></pre>
                </div>
            `;
        }
    } else if (isHtmlContent(contentType, fileName)) {
        // Afficher le HTML avec coloration syntaxique
        iconName = 'code';
        formattedContent = `
            <div style="background: #282c34; border-radius: 8px; padding: 20px; overflow-x: auto;">
                <pre style="margin: 0; color: #abb2bf; font-family: 'Fira Code', monospace; font-size: 0.9em; line-height: 1.6; white-space: pre-wrap; word-wrap: break-word;"><code>${escapeHtml(bodyContent)}</code></pre>
            </div>
        `;
    } else if (isCssContent(contentType, fileName)) {
        // Afficher le CSS
        iconName = 'style';
        formattedContent = `
            <div style="background: #282c34; border-radius: 8px; padding: 20px; overflow-x: auto;">
                <pre style="margin: 0; color: #abb2bf; font-family: 'Fira Code', monospace; font-size: 0.9em; line-height: 1.6; white-space: pre-wrap; word-wrap: break-word;"><code>${escapeHtml(bodyContent)}</code></pre>
            </div>
        `;
    } else if (isJavaScriptContent(contentType, fileName)) {
        // Afficher le JavaScript
        iconName = 'javascript';
        formattedContent = `
            <div style="background: #282c34; border-radius: 8px; padding: 20px; overflow-x: auto;">
                <pre style="margin: 0; color: #abb2bf; font-family: 'Fira Code', monospace; font-size: 0.9em; line-height: 1.6; white-space: pre-wrap; word-wrap: break-word;"><code>${escapeHtml(bodyContent)}</code></pre>
            </div>
        `;
    } else {
        // Texte brut par défaut
        iconName = 'description';
        formattedContent = `
            <div style="background: #282c34; border-radius: 8px; padding: 20px; overflow-x: auto;">
                <pre style="margin: 0; color: #abb2bf; font-family: 'Fira Code', monospace; font-size: 0.9em; line-height: 1.6; white-space: pre-wrap; word-wrap: break-word;"><code>${escapeHtml(bodyContent)}</code></pre>
            </div>
        `;
    }

    // Mettre à jour l'icône
    iconEl.textContent = iconName;

    // Afficher le contenu
    bodyEl.innerHTML = formattedContent;

    // Afficher la modal
    overlay.style.display = 'block';
    modal.style.display = 'flex';
}

// Fonction pour fermer la modal
function closeFileContentModal() {
    const overlay = document.getElementById('file-content-overlay');
    const modal = document.getElementById('file-content-modal');

    if (overlay) overlay.style.display = 'none';
    if (modal) modal.style.display = 'none';
}

// Fonctions helper pour détecter le type de contenu
function isImageContent(contentType, fileName) {
    const imageTypes = ['image/', 'image/png', 'image/jpeg', 'image/jpg', 'image/gif', 'image/webp', 'image/svg+xml', 'image/bmp', 'image/ico'];
    const imageExtensions = ['.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.bmp', '.ico', '.ico'];

    if (contentType) {
        return imageTypes.some(type => contentType.toLowerCase().includes(type));
    }

    const lowerFileName = fileName.toLowerCase();
    return imageExtensions.some(ext => lowerFileName.endsWith(ext));
}

function isJsonContent(contentType, bodyContent) {
    if (contentType && contentType.toLowerCase().includes('json')) {
        return true;
    }

    const trimmed = bodyContent.trim();
    return (trimmed.startsWith('{') && trimmed.endsWith('}')) ||
        (trimmed.startsWith('[') && trimmed.endsWith(']'));
}

function isHtmlContent(contentType, fileName) {
    if (contentType && contentType.toLowerCase().includes('html')) {
        return true;
    }

    const lowerFileName = fileName.toLowerCase();
    return lowerFileName.endsWith('.html') || lowerFileName.endsWith('.htm');
}

function isCssContent(contentType, fileName) {
    if (contentType && contentType.toLowerCase().includes('css')) {
        return true;
    }

    const lowerFileName = fileName.toLowerCase();
    return lowerFileName.endsWith('.css');
}

function isJavaScriptContent(contentType, fileName) {
    if (contentType && (contentType.toLowerCase().includes('javascript') || contentType.toLowerCase().includes('application/javascript'))) {
        return true;
    }

    const lowerFileName = fileName.toLowerCase();
    return lowerFileName.endsWith('.js') || lowerFileName.endsWith('.mjs');
}

function showHeatmap() {
    const heatmapPanel = getCurrentVizPanel();
    if (!heatmapPanel) return;

    if (!selectedDomainForGraph) {
        heatmapPanel.innerHTML = '<div style="text-align: center; padding: 50px; color: #888;">Sélectionnez un domaine pour voir la heatmap</div>';
        return;
    }

    // Filtrer les flows par domaine sélectionné
    const filteredFlows = flowsData.filter(flow => {
        try {
            const url = new URL(flow.url);
            return url.hostname === selectedDomainForGraph;
        } catch {
            return false;
        }
    });

    if (filteredFlows.length === 0) {
        heatmapPanel.innerHTML = '<div style="text-align: center; padding: 50px; color: #888;">No requests to display for this domain</div>';
        return;
    }

    // Analyser les vulnérabilités et risques
    const riskMap = new Map();

    filteredFlows.forEach(flow => {
        const url = new URL(flow.url);
        const path = url.pathname;
        const domain = url.hostname;

        let risk = 0;

        // Calculer le risque
        if (flow.status_code >= 500) risk += 3;
        else if (flow.status_code >= 400) risk += 2;
        else if (flow.status_code >= 300) risk += 1;

        // Endpoints sensibles
        const sensitivePatterns = ['/admin', '/api', '/login', '/auth', '/config', '/debug', '/test'];
        if (sensitivePatterns.some(p => path.includes(p))) risk += 2;

        // Technologies avec vulnérabilités connues
        if (flow.technologies) {
            const riskyTechs = ['PHP', 'WordPress', 'Drupal'];
            Object.values(flow.technologies).flat().forEach(tech => {
                if (riskyTechs.includes(tech)) risk += 1;
            });
        }

        // Endpoints découverts mais non chargés
        // Exclure les fichiers statiques (CSS, JS, images, fonts, etc.) car ils référencent naturellement d'autres ressources
        const fileType = getFileTypeFromUrl(flow.url);
        const isStaticFile = ['css', 'javascript', 'image', 'font', 'video', 'audio'].includes(fileType);

        if (flow.endpoints && !isStaticFile) {
            const endpointCount = Object.values(flow.endpoints).flat().length;
            risk += Math.min(endpointCount / 10, 2);
        }

        const key = `${domain}${path}`;
        riskMap.set(key, {
            url: flow.url,
            path: path,
            domain: domain,
            risk: risk,
            status: flow.status_code,
            method: flow.method
        });
    });

    // Trier par risque
    const sortedRisks = Array.from(riskMap.values()).sort((a, b) => b.risk - a.risk);

    let html = '<div style="padding: 20px;">';
    html += '<h3 style="margin-top: 0; color: #6200ea;">Vulnerability Heatmap</h3>';
    html += '<p style="color: #666; margin-bottom: 20px;">Heat map showing risk areas</p>';

    // Légende
    html += '<div style="margin-bottom: 20px; display: flex; gap: 20px; align-items: center; justify-content: center;">';
    html += '<div style="display: flex; align-items: center; gap: 5px;"><div style="width: 30px; height: 20px; background: #4caf50; border-radius: 4px;"></div><span>Faible (0-2)</span></div>';
    html += '<div style="display: flex; align-items: center; gap: 5px;"><div style="width: 30px; height: 20px; background: #ff9800; border-radius: 4px;"></div><span>Moyen (3-5)</span></div>';
    html += '<div style="display: flex; align-items: center; gap: 5px;"><div style="width: 30px; height: 20px; background: #f44336; border-radius: 4px;"></div><span>High (6+)</span></div>';
    html += '</div>';

    // Heatmap
    html += '<div style="background: white; border: 1px solid #ddd; border-radius: 8px; padding: 20px;">';

    sortedRisks.forEach(item => {
        const riskColor = item.risk >= 6 ? '#f44336' : item.risk >= 3 ? '#ff9800' : '#4caf50';
        const intensity = Math.min(item.risk / 10, 1);

        html += `<div style="
            padding: 12px 15px;
            margin-bottom: 8px;
            border-left: 4px solid ${riskColor};
            background: ${riskColor}${Math.floor(intensity * 20).toString(16).padStart(2, '0')};
            border-radius: 4px;
            display: flex;
            align-items: center;
            gap: 15px;
        ">`;
        html += `<div style="
            width: 40px;
            height: 40px;
            background: ${riskColor};
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: 600;
            flex-shrink: 0;
        ">${item.risk.toFixed(1)}</div>`;
        html += `<div style="flex: 1;">`;
        html += `<div style="font-weight: 600; color: #333;">${item.method} ${item.path}</div>`;
        html += `<div style="font-size: 0.85em; color: #666;">${item.domain}</div>`;
        html += `</div>`;
        html += `<div style="color: #666; font-size: 0.9em;">Status: ${item.status || 'N/A'}</div>`;
        html += `</div>`;
    });

    html += '</div></div>';

    const heatmapPanel2 = getCurrentVizPanel();
    if (heatmapPanel2) {
        heatmapPanel2.innerHTML = html;
    }
}

// === PERFORMANCE MONITORING ===
const refreshMonitorBtn = document.getElementById('refresh-monitor-btn');
const monitorContent = document.getElementById('monitor-content');
let monitorInterval = null;

if (refreshMonitorBtn) {
    refreshMonitorBtn.addEventListener('click', () => {
        loadPerformanceData();
    });
}

// Détecter quand on entre dans la vue monitor
document.addEventListener('DOMContentLoaded', () => {
    const monitorView = document.getElementById('monitor-view');
    if (monitorView) {
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                if (mutation.type === 'attributes' && mutation.attributeName === 'style') {
                    const isVisible = monitorView.style.display !== 'none';
                    if (isVisible && !monitorInterval) {
                        loadPerformanceData();
                        monitorInterval = setInterval(loadPerformanceData, 2000);
                    } else if (!isVisible && monitorInterval) {
                        clearInterval(monitorInterval);
                        monitorInterval = null;
                    }
                }
            });
        });
        observer.observe(monitorView, { attributes: true });
    }
});

async function loadPerformanceData() {
    if (!monitorContent) return;

    try {
        // Load fast mode settings
        await loadFastModeSettings();

        // Load performance data
        const res = await fetch(`${API_BASE}/performance`);
        const data = await res.json();

        renderPerformanceDashboard(data);
    } catch (err) {
        console.error("Failed to fetch performance data", err);
        monitorContent.innerHTML = '<div style="padding: 20px; color: #f44336;">Error loading performance data</div>';
    }
}

// Fast mode state (disabled by default)
let fastModeEnabled = false;
let fastModeThreshold = 100;

async function loadFastModeSettings() {
    try {
        const res = await fetch(`${API_BASE}/performance/fast-mode`);
        if (res.ok) {
            const data = await res.json();
            fastModeEnabled = data.fast_mode;
            fastModeThreshold = data.threshold_kb;
        }
    } catch (err) {
        console.error("Failed to load fast mode settings", err);
    }
}

async function saveFastModeSettings() {
    try {
        const res = await fetch(`${API_BASE}/performance/fast-mode`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                enabled: fastModeEnabled,
                threshold_kb: fastModeThreshold
            })
        });
        if (res.ok) {
            showToast('Fast mode settings saved', 'success');
        } else {
            showToast('Failed to save fast mode settings', 'error');
        }
    } catch (err) {
        console.error("Failed to save fast mode settings", err);
        showToast('Failed to save fast mode settings', 'error');
    }
}

function updateFastModeThresholdState() {
    const thresholdInput = document.getElementById('fast-mode-threshold');
    if (thresholdInput) {
        thresholdInput.disabled = !fastModeEnabled;
    }
}

function renderPerformanceDashboard(data) {
    let html = '<div style="padding: 30px; max-width: 1400px; margin: 0 auto; background: var(--bg-color);">';

    // Fast Mode Settings Section
    html += '<div style="background: white; border-radius: 8px; padding: 20px; margin-bottom: 30px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">';
    html += '<h3 style="margin: 0 0 15px 0; color: #333; font-size: 1.1em;">Performance Optimization</h3>';
    html += '<div style="display: flex; flex-direction: column; gap: 15px;">';

    // Fast Mode Toggle
    html += '<div style="display: flex; align-items: center; justify-content: space-between;">';
    html += '<div>';
    html += '<div style="font-weight: 600; color: #333; margin-bottom: 5px;">Fast Mode</div>';
    html += '<div style="font-size: 0.85em; color: #666;">Skip heavy analysis (tech detection, fingerprinting, endpoint extraction) for large responses to improve proxy responsiveness</div>';
    html += '</div>';
    html += `<label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
        <input type="checkbox" id="fast-mode-toggle" ${fastModeEnabled ? 'checked' : ''} 
               onchange="fastModeEnabled = this.checked; saveFastModeSettings(); updateFastModeThresholdState();"
               style="width: 18px; height: 18px; cursor: pointer;">
        <span style="color: ${fastModeEnabled ? '#4caf50' : '#888'}; font-weight: 500;">
            Enable
        </span>
    </label>`;
    html += '</div>';

    // Threshold Setting
    html += '<div style="display: flex; align-items: center; justify-content: space-between;">';
    html += '<div>';
    html += '<div style="font-weight: 600; color: #333; margin-bottom: 5px;">Response Size Threshold</div>';
    html += '<div style="font-size: 0.85em; color: #666;">Skip analysis for responses larger than this size (KB)</div>';
    html += '</div>';
    html += `<input type="number" id="fast-mode-threshold" value="${fastModeThreshold}" min="10" max="10000" step="10"
            onchange="fastModeThreshold = parseInt(this.value) || 100; saveFastModeSettings(); updateFastModeThresholdState();"
            style="width: 100px; padding: 6px 10px; border: 1px solid #ddd; border-radius: 4px; font-size: 0.9em;"
            ${!fastModeEnabled ? 'disabled' : ''}>`;
    html += '<span style="margin-left: 8px; color: #666;">KB</span>';
    html += '</div>';

    html += '</div>';
    html += '</div>';

    // En-tête avec alertes
    html += '<div style="margin-bottom: 30px;">';
    html += '<div style="display: flex; align-items: center; gap: 12px; margin-bottom: 20px;">';
    html += '<span class="material-symbols-outlined" style="font-size: 28px; color: var(--primary-color);">speed</span>';
    html += '<h3 style="margin: 0; color: var(--primary-color); font-size: 1.5rem; font-weight: 600;">Performance Monitor</h3>';
    html += '</div>';

    if (data.alerts && data.alerts.length > 0) {
        html += '<div style="margin-bottom: 20px;">';
        data.alerts.forEach(alert => {
            const alertColor = alert.severity === 'error' ? '#f44336' : '#ff9800';
            const alertIcon = alert.severity === 'error' ? 'error' : 'warning';
            html += `<div style="background: white; border-left: 4px solid ${alertColor}; padding: 12px 16px; margin-bottom: 10px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); display: flex; align-items: center; gap: 10px;">`;
            html += `<span class="material-symbols-outlined" style="color: ${alertColor}; font-size: 20px;">${alertIcon}</span>`;
            html += `<div style="flex: 1;"><strong style="color: ${alertColor}; font-size: 0.9rem;">${alert.type.toUpperCase()}:</strong> <span style="color: #333; font-size: 0.9rem;">${alert.message}</span></div>`;
            html += `</div>`;
        });
        html += '</div>';
    }
    html += '</div>';

    // Statistiques principales avec icônes
    html += '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 20px; margin-bottom: 30px;">';

    html += `<div style="background: white; padding: 24px; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); border: 1px solid var(--border-color); transition: transform 0.2s, box-shadow 0.2s;" onmouseover="this.style.transform='translateY(-2px)'; this.style.boxShadow='0 4px 12px rgba(0,0,0,0.12)'" onmouseout="this.style.transform=''; this.style.boxShadow='0 2px 8px rgba(0,0,0,0.08)'">`;
    html += `<div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">`;
    html += `<div style="width: 40px; height: 40px; background: #f3e5f5; border-radius: 10px; display: flex; align-items: center; justify-content: center;">`;
    html += `<span class="material-symbols-outlined" style="color: var(--primary-color); font-size: 22px;">schedule</span>`;
    html += `</div>`;
    html += `<div style="font-size: 0.85em; color: var(--text-secondary); font-weight: 500;">Uptime</div>`;
    html += `</div>`;
    html += `<div style="font-size: 2em; font-weight: 700; color: var(--primary-color); font-family: 'Inter', sans-serif;">${formatUptime(data.uptime)}</div>`;
    html += `</div>`;

    html += `<div style="background: white; padding: 24px; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); border: 1px solid var(--border-color); transition: transform 0.2s, box-shadow 0.2s;" onmouseover="this.style.transform='translateY(-2px)'; this.style.boxShadow='0 4px 12px rgba(0,0,0,0.12)'" onmouseout="this.style.transform=''; this.style.boxShadow='0 2px 8px rgba(0,0,0,0.08)'">`;
    html += `<div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">`;
    html += `<div style="width: 40px; height: 40px; background: #e3f2fd; border-radius: 10px; display: flex; align-items: center; justify-content: center;">`;
    html += `<span class="material-symbols-outlined" style="color: #2196f3; font-size: 22px;">http</span>`;
    html += `</div>`;
    html += `<div style="font-size: 0.85em; color: var(--text-secondary); font-weight: 500;">Total Requests</div>`;
    html += `</div>`;
    html += `<div style="font-size: 2em; font-weight: 700; color: #2196f3; font-family: 'Inter', sans-serif;">${data.total_requests || 0}</div>`;
    html += `</div>`;

    html += `<div style="background: white; padding: 24px; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); border: 1px solid var(--border-color); transition: transform 0.2s, box-shadow 0.2s;" onmouseover="this.style.transform='translateY(-2px)'; this.style.boxShadow='0 4px 12px rgba(0,0,0,0.12)'" onmouseout="this.style.transform=''; this.style.boxShadow='0 2px 8px rgba(0,0,0,0.08)'">`;
    html += `<div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">`;
    html += `<div style="width: 40px; height: 40px; background: #e8f5e9; border-radius: 10px; display: flex; align-items: center; justify-content: center;">`;
    html += `<span class="material-symbols-outlined" style="color: #4caf50; font-size: 22px;">trending_up</span>`;
    html += `</div>`;
    html += `<div style="font-size: 0.85em; color: var(--text-secondary); font-weight: 500;">Requests/sec</div>`;
    html += `</div>`;
    html += `<div style="font-size: 2em; font-weight: 700; color: #4caf50; font-family: 'Inter', sans-serif;">${(data.requests_per_second || 0).toFixed(2)}</div>`;
    html += `</div>`;

    const errorColor = data.errors && data.errors.rate > 10 ? '#f44336' : '#ff9800';
    const errorBg = data.errors && data.errors.rate > 10 ? '#ffebee' : '#fff3e0';
    html += `<div style="background: white; padding: 24px; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); border: 1px solid var(--border-color); transition: transform 0.2s, box-shadow 0.2s;" onmouseover="this.style.transform='translateY(-2px)'; this.style.boxShadow='0 4px 12px rgba(0,0,0,0.12)'" onmouseout="this.style.transform=''; this.style.boxShadow='0 2px 8px rgba(0,0,0,0.08)'">`;
    html += `<div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">`;
    html += `<div style="width: 40px; height: 40px; background: ${errorBg}; border-radius: 10px; display: flex; align-items: center; justify-content: center;">`;
    html += `<span class="material-symbols-outlined" style="color: ${errorColor}; font-size: 22px;">${data.errors && data.errors.rate > 10 ? 'error' : 'warning'}</span>`;
    html += `</div>`;
    html += `<div style="font-size: 0.85em; color: var(--text-secondary); font-weight: 500;">Error Rate</div>`;
    html += `</div>`;
    html += `<div style="font-size: 2em; font-weight: 700; color: ${errorColor}; font-family: 'Inter', sans-serif;">${(data.errors && data.errors.rate || 0).toFixed(1)}%</div>`;
    html += `</div>`;

    html += `</div>`;

    // Temps de réponse
    html += '<div style="background: white; padding: 24px; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); border: 1px solid var(--border-color); margin-bottom: 20px;">';
    html += '<div style="display: flex; align-items: center; gap: 10px; margin-bottom: 20px;">';
    html += '<span class="material-symbols-outlined" style="color: var(--primary-color); font-size: 22px;">timer</span>';
    html += '<h4 style="margin: 0; color: var(--primary-color); font-size: 1.1rem; font-weight: 600;">Response Time</h4>';
    html += '</div>';
    html += '<div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 20px; padding: 16px; background: #fafafa; border-radius: 8px;">';
    html += `<div style="text-align: center;"><div style="font-size: 0.8em; color: var(--text-secondary); margin-bottom: 6px; font-weight: 500;">Average</div><div style="font-size: 1.5em; font-weight: 700; color: #2196f3;">${(data.response_times.avg * 1000).toFixed(0)}<span style="font-size: 0.6em; color: var(--text-secondary);">ms</span></div></div>`;
    html += `<div style="text-align: center;"><div style="font-size: 0.8em; color: var(--text-secondary); margin-bottom: 6px; font-weight: 500;">Min</div><div style="font-size: 1.5em; font-weight: 700; color: #4caf50;">${(data.response_times.min * 1000).toFixed(0)}<span style="font-size: 0.6em; color: var(--text-secondary);">ms</span></div></div>`;
    html += `<div style="text-align: center;"><div style="font-size: 0.8em; color: var(--text-secondary); margin-bottom: 6px; font-weight: 500;">Max</div><div style="font-size: 1.5em; font-weight: 700; color: #ff9800;">${(data.response_times.max * 1000).toFixed(0)}<span style="font-size: 0.6em; color: var(--text-secondary);">ms</span></div></div>`;
    html += '</div>';

    // Graphique simple des temps de réponse
    if (data.response_times.current && data.response_times.current.length > 0) {
        html += '<div style="height: 120px; display: flex; align-items: flex-end; gap: 3px; border-top: 1px solid var(--border-color); padding-top: 15px; background: #fafafa; border-radius: 8px; padding: 15px;">';
        const maxTime = Math.max(...data.response_times.current);
        data.response_times.current.forEach((time, index) => {
            const height = (time / maxTime) * 100;
            const color = time > 1 ? '#f44336' : time > 0.5 ? '#ff9800' : '#4caf50';
            html += `<div style="flex: 1; background: ${color}; height: ${height}%; border-radius: 4px 4px 0 0; transition: opacity 0.2s; cursor: pointer;" onmouseover="this.style.opacity='0.8'; this.style.transform='scaleY(1.05)'" onmouseout="this.style.opacity='1'; this.style.transform='scaleY(1)'" title="${(time * 1000).toFixed(0)}ms"></div>`;
        });
        html += '</div>';
    }
    html += '</div>';

    // Bande passante
    html += '<div style="background: white; padding: 24px; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); border: 1px solid var(--border-color); margin-bottom: 20px;">';
    html += '<div style="display: flex; align-items: center; gap: 10px; margin-bottom: 20px;">';
    html += '<span class="material-symbols-outlined" style="color: var(--primary-color); font-size: 22px;">swap_vert</span>';
    html += '<h4 style="margin: 0; color: var(--primary-color); font-size: 1.1rem; font-weight: 600;">Bandwidth</h4>';
    html += '</div>';
    html += '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 20px; padding: 16px; background: #fafafa; border-radius: 8px;">';
    html += `<div><div style="font-size: 0.8em; color: var(--text-secondary); margin-bottom: 6px; font-weight: 500;">Total</div><div style="font-size: 1.3em; font-weight: 700; color: #333; font-family: 'Fira Code', monospace;">${formatBytes(data.bandwidth.total)}</div></div>`;
    html += `<div><div style="font-size: 0.8em; color: var(--text-secondary); margin-bottom: 6px; font-weight: 500;">Avg Request</div><div style="font-size: 1.3em; font-weight: 700; color: #333; font-family: 'Fira Code', monospace;">${formatBytes(data.bandwidth.avg_request_size)}</div></div>`;
    html += `<div><div style="font-size: 0.8em; color: var(--text-secondary); margin-bottom: 6px; font-weight: 500;">Avg Response</div><div style="font-size: 1.3em; font-weight: 700; color: #333; font-family: 'Fira Code', monospace;">${formatBytes(data.bandwidth.avg_response_size)}</div></div>`;
    html += `<div><div style="font-size: 0.8em; color: var(--text-secondary); margin-bottom: 6px; font-weight: 500;">Per Second</div><div style="font-size: 1.3em; font-weight: 700; color: #2196f3; font-family: 'Fira Code', monospace;">${formatBytes(data.bandwidth.per_second)}/s</div></div>`;
    html += '</div>';

    // Graphique de bande passante
    if (data.bandwidth.history && data.bandwidth.history.length > 0) {
        html += '<div style="height: 120px; display: flex; align-items: flex-end; gap: 3px; border-top: 1px solid var(--border-color); padding-top: 15px; background: #fafafa; border-radius: 8px; padding: 15px;">';
        const maxBw = Math.max(...data.bandwidth.history.map(b => b.total_size));
        data.bandwidth.history.forEach((bw, index) => {
            const height = (bw.total_size / maxBw) * 100;
            html += `<div style="flex: 1; background: linear-gradient(to top, #2196f3, #42a5f5); height: ${height}%; border-radius: 4px 4px 0 0; transition: opacity 0.2s; cursor: pointer;" onmouseover="this.style.opacity='0.8'; this.style.transform='scaleY(1.05)'" onmouseout="this.style.opacity='1'; this.style.transform='scaleY(1)'" title="${formatBytes(bw.total_size)}"></div>`;
        });
        html += '</div>';
    }
    html += '</div>';

    // Requêtes lentes
    if (data.slow_requests && data.slow_requests.length > 0) {
        html += '<div style="background: white; padding: 24px; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); border: 1px solid var(--border-color); margin-bottom: 20px;">';
        html += '<div style="display: flex; align-items: center; gap: 10px; margin-bottom: 20px;">';
        html += '<span class="material-symbols-outlined" style="color: #ff9800; font-size: 22px;">slow_motion_video</span>';
        html += '<h4 style="margin: 0; color: var(--primary-color); font-size: 1.1rem; font-weight: 600;">Slow Requests (> 1s)</h4>';
        html += '</div>';
        html += '<div style="max-height: 400px; overflow-y: auto; border-radius: 8px;">';
        data.slow_requests.forEach((req, index) => {
            const isEven = index % 2 === 0;
            html += `<div style="padding: 14px 16px; border-bottom: 1px solid var(--border-color); background: ${isEven ? '#fff' : '#fafafa'}; display: flex; justify-content: space-between; align-items: center; transition: background 0.2s;" onmouseover="this.style.background='#f0f0f0'" onmouseout="this.style.background='${isEven ? '#fff' : '#fafafa'}'">`;
            html += `<div style="flex: 1; min-width: 0;">`;
            html += `<div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">`;
            html += `<span style="padding: 2px 8px; background: ${getMethodColor(req.method)}; color: white; border-radius: 4px; font-size: 0.75em; font-weight: 600; font-family: 'Fira Code', monospace;">${req.method}</span>`;
            html += `<div style="font-weight: 600; color: #333; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${req.url}</div>`;
            html += `</div>`;
            html += `<div style="font-size: 0.85em; color: var(--text-secondary); display: flex; align-items: center; gap: 6px;">`;
            html += `<span class="material-symbols-outlined" style="font-size: 16px;">info</span>`;
            html += `<span>Status: ${req.status_code || 'N/A'}</span>`;
            html += `</div>`;
            html += `</div>`;
            html += `<div style="display: flex; align-items: center; gap: 6px; color: #f44336; font-weight: 700; font-size: 1.1em; font-family: 'Fira Code', monospace; margin-left: 16px;">`;
            html += `<span class="material-symbols-outlined" style="font-size: 20px;">timer</span>`;
            html += `<span>${(req.response_time * 1000).toFixed(0)}ms</span>`;
            html += `</div>`;
            html += `</div>`;
        });
        html += '</div></div>';
    }

    // Timeouts
    if (data.timeouts > 0) {
        html += '<div style="background: white; border-left: 4px solid #f44336; padding: 16px 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); margin-bottom: 20px; display: flex; align-items: center; gap: 12px;">';
        html += '<span class="material-symbols-outlined" style="color: #f44336; font-size: 24px;">error</span>';
        html += `<div><strong style="color: #f44336; font-size: 1rem;">${data.timeouts} timeout(s) detected</strong><div style="color: var(--text-secondary); font-size: 0.9em; margin-top: 4px;">Some requests exceeded the maximum timeout</div></div>`;
        html += '</div>';
    }

    html += '</div>';

    monitorContent.innerHTML = html;
}

function formatUptime(seconds) {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);
    if (hours > 0) {
        return `${hours}h ${minutes}m ${secs}s`;
    } else if (minutes > 0) {
        return `${minutes}m ${secs}s`;
    } else {
        return `${secs}s`;
    }
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

// Initialize
// Initialize sorting headers
function initSortingHeaders() {
    const sortableHeaders = document.querySelectorAll('.sortable-header');
    sortableHeaders.forEach(header => {
        // Remove existing listeners to avoid duplicates
        const newHeader = header.cloneNode(true);
        header.parentNode.replaceChild(newHeader, header);

        newHeader.style.cursor = 'pointer';
        newHeader.style.userSelect = 'none';
        newHeader.addEventListener('click', () => {
            const column = newHeader.dataset.sort;
            if (sortColumn === column) {
                // Toggle sort order
                sortOrder = sortOrder === 'asc' ? 'desc' : 'asc';
            } else {
                // New column, default to ascending
                sortColumn = column;
                sortOrder = 'asc';
            }
            updateSortIndicators();
            renderFlowList();
        });
    });
    updateSortIndicators();
}

// Initialize on DOM ready or immediately if already loaded
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initSortingHeaders);
} else {
    initSortingHeaders();
}

function updateSortIndicators() {
    const sortableHeaders = document.querySelectorAll('.sortable-header');
    sortableHeaders.forEach(header => {
        const indicator = header.querySelector('.sort-indicator');
        const column = header.dataset.sort;

        if (sortColumn === column) {
            indicator.textContent = sortOrder === 'asc' ? ' ▲' : ' ▼';
            indicator.style.opacity = '1';
            header.style.color = '#6200ea';
            header.style.fontWeight = '600';
        } else {
            indicator.textContent = ' ↕';
            indicator.style.opacity = '0.3';
            header.style.color = '';
            header.style.fontWeight = '';
        }
    });
}

setInterval(fetchFlows, 2000);
fetchFlows();
fetchModules();

// Initialize sorting headers after initial load
setTimeout(() => {
    initSortingHeaders();
}, 200);

// === COLLABORATION ===
// Collaboration Server Configuration (SaaS)
let currentViewId = null;
function normalizeCollabUrl(url) {
    if (!url) return 'https://proxy.kittysploit.com';
    let normalized = url.trim();
    // For the official SaaS host, always force HTTPS to avoid CORS preflight redirects
    if (normalized.startsWith('http://proxy.kittysploit.com')) {
        normalized = normalized.replace('http://', 'https://');
    }
    // Remove trailing slash
    if (normalized.endsWith('/')) {
        normalized = normalized.slice(0, -1);
    }
    return normalized;
}

let COLLABORATION_SERVER_URL = normalizeCollabUrl(localStorage.getItem('collaboration_server_url') || 'https://proxy.kittysploit.com');
let COLLAB_API_TOKEN = localStorage.getItem('collaboration_api_token') || null;
let collabAuthValid = false;
let collabContentDefaultHTML = null;

function renderCollabApiKeyRequired(message) {
    if (currentViewId !== 'collaborate') return;
    const content = document.getElementById('collaboration-content');
    const noSession = document.getElementById('collab-no-session');
    const activeSession = document.getElementById('collab-active-session');
    if (noSession) noSession.style.display = 'flex';
    if (activeSession) activeSession.style.display = 'none';
    if (content) {
        if (!collabContentDefaultHTML) {
            collabContentDefaultHTML = content.innerHTML;
        }
        content.innerHTML = `
            <div style="width: 100%; display: flex; align-items: center; justify-content: center; padding: 20px 0;">
                <div style="max-width: 420px; width: 90%; padding: 22px; border: 1px solid rgba(0,255,255,0.25); border-radius: 12px; background: #181a23; color: #fff; font-family: 'Segoe UI', sans-serif; box-shadow: 0 10px 30px rgba(0,0,0,0.35);">
                    <h3 style="margin: 0 0 8px 0; color: #00ffff; font-size: 20px;">Pro feature – API key required</h3>
                    <p style="margin: 6px 0 12px 0; color: rgba(255,255,255,0.9);">${message || 'Collaboration Pro requires a valid API key.'}</p>
                    <div style="padding: 12px; border: 1px dashed rgba(0,255,255,0.35); border-radius: 10px; background: rgba(0,255,255,0.06); color: rgba(255,255,255,0.95); font-size: 13px;">
                        <p style="margin: 0 0 6px 0;">Add your key in <code style="background: rgba(255,255,255,0.12); padding: 2px 6px; border-radius: 6px; color: #00ffff;">config.toml</code> :</p>
                        <p style="margin: 0; font-family: Consolas, monospace;">
                            [FRAMEWORK]<br>
                            api_key = "your_api_key"
                        </p>
                    </div>
                    <p style="margin: 14px 0 0 0; color: rgba(255,255,255,0.75); font-size: 12px;">Restart KittyProxy after updating.</p>
                </div>
            </div>
        `;
        content.style.display = 'flex';
        content.style.justifyContent = 'center';
        content.style.alignItems = 'center';
    }
    const createBtn = document.getElementById('btn-create-collab-session') || document.querySelector('[onclick*="createCollaborationSession"]');
    if (createBtn) createBtn.disabled = true;
}

async function ensureCollabAuth(forceRetry = false) {
    // Si forceRetry est true, on ignore le cache et on réessaie
    if (!forceRetry) {
        // Vérifier si on a déjà tenté de valider et que ça a échoué
        // Si c'est le cas, on ne refait pas la requête (il faudra redémarrer pour retester)
        const lastFailed = localStorage.getItem('collab_auth_last_failed');
        if (lastFailed === 'true') {
            console.log('[COLLAB] Previous validation failed. Clearing cache and retrying...');
            // Nettoyer le cache et réessayer automatiquement
            localStorage.removeItem('collab_auth_last_failed');
            // Réessayer une fois après avoir nettoyé le cache
            return await ensureCollabAuth(true);
        }
    } else {
        // Si on force le retry, on nettoie le cache
        localStorage.removeItem('collab_auth_last_failed');
    }

    try {
        const res = await fetch(`${API_BASE}/collab/auth`);
        if (!res.ok) {
            const data = await res.json().catch(() => ({}));
            const errorMsg = data.detail || data.message || 'API key invalid or missing.';
            renderCollabApiKeyRequired(errorMsg);
            collabAuthValid = false;
            // Marquer l'échec dans le cache (permanent jusqu'au rechargement)
            localStorage.setItem('collab_auth_last_failed', 'true');
            console.error('[COLLAB] Auth failed:', errorMsg);
            return false;
        }
        const data = await res.json();
        console.log('[COLLAB] Auth response:', { valid: data.valid, hasToken: !!data.token, server_url: data.server_url });

        // Vérifier à la fois valid ET token (comme pour SideChannel)
        collabAuthValid = !!(data.valid === true && data.token);

        // Si la validation réussit, on supprime le cache d'échec
        if (collabAuthValid) {
            localStorage.removeItem('collab_auth_last_failed');
            console.log('[COLLAB] Auth successful');
        } else {
            // Si valid est false, on marque l'échec
            const errorMsg = data.detail || data.message || `API key invalid (valid: ${data.valid}, hasToken: ${!!data.token})`;
            console.error('[COLLAB] Auth failed:', errorMsg);
            localStorage.setItem('collab_auth_last_failed', 'true');
            renderCollabApiKeyRequired(errorMsg);
        }

        if (data.server_url) {
            COLLABORATION_SERVER_URL = normalizeCollabUrl(data.server_url);
            localStorage.setItem('collaboration_server_url', COLLABORATION_SERVER_URL);
        }
        if (data.token) {
            COLLAB_API_TOKEN = data.token;
            localStorage.setItem('collaboration_api_token', COLLAB_API_TOKEN);
        }
        return collabAuthValid;
    } catch (e) {
        console.error('[COLLAB] Auth error:', e);
        renderCollabApiKeyRequired('Unable to validate API key.');
        collabAuthValid = false;
        // Marquer l'échec dans le cache (permanent jusqu'au rechargement)
        localStorage.setItem('collab_auth_last_failed', 'true');
        return false;
    }
}

function collabHeaders(extra = {}) {
    const headers = { ...(extra || {}) };
    if (COLLAB_API_TOKEN) {
        headers['Authorization'] = `Bearer ${COLLAB_API_TOKEN}`;
    }
    return headers;
}

function removeCollabApiOverlay() {
    const content = document.getElementById('collaboration-content');
    const noSession = document.getElementById('collab-no-session');
    if (content && collabContentDefaultHTML) {
        content.innerHTML = collabContentDefaultHTML;
        collabContentDefaultHTML = null;
    }
    if (content) {
        content.style.display = 'flex';
        content.style.justifyContent = '';
        content.style.alignItems = '';
    }
    if (noSession) noSession.style.display = 'flex';
}

// Validate API key on load (async; rest of UI will gate on collabAuthValid)
ensureCollabAuth();

let currentSessionId = null;
let currentUserId = null;
let currentUsername = 'User_' + Math.random().toString(36).substr(2, 5);
let collaborationWebSocket = null;
let collaborationFlows = [];
let collaborationParticipants = [];
let collaborationMessages = [];
let browserMirror = null;
let mirrorViewers = {}; // {user_id: {image, url, user}}
let currentMirrorUserId = null; // ID de l'utilisateur dont on affiche le mirroring
let aiAccessUnavailable = false; // Flag pour désactiver les appels AI si l'endpoint n'existe pas

// Met à jour le badge "live" sur l'onglet Collaboration
function updateCollabLiveIndicator(isLive) {
    const indicator = collabLiveIndicator || document.getElementById('collab-live-indicator');
    const collabNavItem = document.querySelector('.nav-item[data-view="collaborate"]');
    if (!indicator || !collabNavItem) return;

    if (isLive) {
        indicator.style.display = 'flex';
        indicator.setAttribute('aria-hidden', 'false');
        collabNavItem.classList.add('collab-live');
    } else {
        indicator.style.display = 'none';
        indicator.setAttribute('aria-hidden', 'true');
        collabNavItem.classList.remove('collab-live');
    }
}

// Fonctions pour sauvegarder/restaurer l'état de la session
function saveCollaborationState() {
    if (currentSessionId) {
        const state = {
            sessionId: currentSessionId,
            userId: currentUserId,
            username: currentUsername,
            isMirroring: browserMirror && browserMirror.isMirroring,
            chatInput: document.getElementById('collab-chat-input')?.value || '',
            viewingMirrorUserId: currentMirrorUserId, // Sauvegarder quel utilisateur on regarde
            currentAIFlowId: collabCurrentAIFlow?.id || null // Sauvegarder le flow IA actuellement analysé
        };
        localStorage.setItem('kittyproxy_collaboration_state', JSON.stringify(state));
        console.log('[Collaboration] State saved:', state);
    }
}

// Sauvegarder les résultats de l'IA Assistant
function saveAIAssistantResults() {
    if (currentSessionId) {
        const key = `kittyproxy_ai_results_${currentSessionId}`;
        localStorage.setItem(key, JSON.stringify(collabAIResults));
        console.log('[AI] Results saved for session:', currentSessionId);
    }
}

// Restaurer les résultats de l'IA Assistant
function restoreAIAssistantResults() {
    if (!currentSessionId) return;

    try {
        const key = `kittyproxy_ai_results_${currentSessionId}`;
        const saved = localStorage.getItem(key);
        if (saved) {
            collabAIResults = JSON.parse(saved);
            console.log('[AI] Results restored for session:', currentSessionId, Object.keys(collabAIResults).length, 'flows');
            return true;
        }
    } catch (error) {
        console.error('[AI] Error restoring results:', error);
    }
    return false;
}

// Nettoyer les résultats IA pour une session
function clearAIAssistantResults() {
    if (currentSessionId) {
        const key = `kittyproxy_ai_results_${currentSessionId}`;
        localStorage.removeItem(key);
        collabAIResults = {};
        console.log('[AI] Results cleared for session:', currentSessionId);
    }
}

function clearCollaborationState() {
    localStorage.removeItem('kittyproxy_collaboration_state');
    clearAIAssistantResults();
    console.log('[Collaboration] State cleared');
}

function restoreCollaborationState() {
    try {
        const saved = localStorage.getItem('kittyproxy_collaboration_state');
        if (!saved) return null;

        const state = JSON.parse(saved);
        console.log('[Collaboration] Restoring state:', state);
        return state;
    } catch (error) {
        console.error('[Collaboration] Error restoring state:', error);
        return null;
    }
}

async function restoreCollaborationStateAfterJoin() {
    const state = restoreCollaborationState();
    if (!state) return;

    // Restaurer le texte du champ de chat
    const collabChatInput = document.getElementById('collab-chat-input');
    if (collabChatInput && state.chatInput) {
        collabChatInput.value = state.chatInput;
    }

    // Restaurer les résultats IA
    restoreAIAssistantResults();

    // Restaurer l'affichage des résultats IA si un flow était analysé
    if (state.currentAIFlowId && collabAIResults[state.currentAIFlowId]) {
        const aiResults = collabAIResults[state.currentAIFlowId];
        // Attendre un peu pour que l'UI soit prête
        setTimeout(() => {
            renderAISuggestions(
                aiResults.suggestions || [],
                aiResults.tech_stack || {},
                aiResults.summary || '',
                aiResults.next_steps || []
            );
            // Restaurer aussi le flow courant pour les tests de payload
            const flow = collaborationFlows.find(f => f.id === state.currentAIFlowId);
            if (flow) {
                collabCurrentAIFlow = flow;
            }
            // Mettre à jour l'indicateur visuel
            updateSelectedAIFlow(state.currentAIFlowId);
        }, 500);
    }

    // Restaurer le mirroring si il était actif
    if (state.isMirroring && currentUserId === state.userId) {
        // Attendre un peu pour que le WebSocket soit bien connecté
        setTimeout(async () => {
            try {
                await startBrowserMirroring();
            } catch (error) {
                console.error('[Collaboration] Error restoring mirroring:', error);
            }
        }, 1000);
    }

    // Les flows et messages seront chargés automatiquement via les messages WebSocket
    // et loadChatHistory()
}

// DOM Elements
const collabNoSession = document.getElementById('collab-no-session');
const collabActiveSession = document.getElementById('collab-active-session');
const collabCreateBtn = document.getElementById('collab-create-session-btn');
const collabCreateBtn2 = document.getElementById('collab-create-session-btn-2');
const collabJoinBtn = document.getElementById('collab-join-session-btn');
const collabJoinBtn2 = document.getElementById('collab-join-session-btn-2');
const collabHistoryBtn = document.getElementById('collab-ai-history-btn');
const collabLeaveBtn = document.getElementById('collab-leave-session-btn');
const collabInviteBtn = document.getElementById('collab-invite-btn');
const collabChatInput = document.getElementById('collab-chat-input');
const collabChatSendBtn = document.getElementById('collab-chat-send-btn');
const collabParticipantsList = document.getElementById('collab-participants-list');
const collabFlowsList = document.getElementById('collab-flows-list');
const collabFlowsListContainer = document.getElementById('collab-flows-list-container');
const collabChatMessages = document.getElementById('collab-chat-messages');
const collabSessionName = document.getElementById('collab-session-name');
const collabInviteCode = document.getElementById('collab-invite-code');
const collabParticipantCount = document.getElementById('collab-participant-count');

// Fonctions pour gérer les modales
function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'flex';
        // Focus sur le premier input si disponible
        const input = modal.querySelector('input');
        if (input) {
            setTimeout(() => input.focus(), 100);
        }
        // Charger le scope si on ouvre la modal scope
        if (modalId === 'modal-scope') {
            loadScopeToModal();
        }
    }
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'none';
    }
}

function showErrorModal(message) {
    const errorModal = document.getElementById('modal-error');
    const errorMessage = document.getElementById('modal-error-message');
    if (errorModal && errorMessage) {
        errorMessage.textContent = message;
        errorModal.style.display = 'flex';
    } else {
        // Fallback vers alert si la modale n'existe pas
        alert(message);
    }
}

// Fermer les modales en cliquant sur l'overlay
document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('.modal-overlay').forEach(overlay => {
        overlay.addEventListener('click', function (e) {
            if (e.target === overlay) {
                overlay.style.display = 'none';
            }
        });
    });

    // Fermer les modales avec la touche Escape
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') {
            document.querySelectorAll('.modal-overlay').forEach(modal => {
                if (modal.style.display === 'flex') {
                    modal.style.display = 'none';
                }
            });
        }
    });

    // Permettre de soumettre avec Enter dans les modales
    const sessionNameInput = document.getElementById('modal-session-name');
    if (sessionNameInput) {
        sessionNameInput.addEventListener('keypress', function (e) {
            if (e.key === 'Enter') {
                confirmCreateSession();
            }
        });
    }

    const inviteCodeInput = document.getElementById('modal-invite-code');
    if (inviteCodeInput) {
        // Transformer automatiquement en majuscules
        inviteCodeInput.addEventListener('input', function (e) {
            e.target.value = e.target.value.toUpperCase();
        });

        inviteCodeInput.addEventListener('keypress', function (e) {
            if (e.key === 'Enter') {
                confirmJoinSession();
            }
        });
    }
});

// Create Session - Ouvre la modale
function createCollaborationSession() {
    openModal('modal-create-session');
}

// Confirme la création de session
async function confirmCreateSession() {
    if (!collabAuthValid) {
        renderCollabApiKeyRequired('API key required for collaboration.');
        return;
    }
    const nameInput = document.getElementById('modal-session-name');
    const name = nameInput ? nameInput.value.trim() : '';

    if (!name) {
        showErrorModal('Please enter a session name.');
        return;
    }

    closeModal('modal-create-session');

    try {
        // Créer une session (pas besoin d'API key)
        const apiUrl = `${COLLABORATION_SERVER_URL}/api/v1/sessions`;

        const res = await fetch(apiUrl, {
            method: 'POST',
            headers: collabHeaders({
                'Content-Type': 'application/json'
            }),
            body: JSON.stringify({
                name: name,
                target_url: ''
            })
        });

        if (res.ok) {
            const data = await res.json();
            currentSessionId = data.id || data.session_id;
            currentUserId = data.owner_id || `user_${Date.now()}`;
            await joinCollaborationSession(currentSessionId);
        } else {
            const error = await res.json().catch(() => ({ detail: 'Unknown error' }));
            showErrorModal(`Error creating session: ${error.detail || res.statusText}`);
        }
    } catch (err) {
        console.error('Error creating session:', err);
        showErrorModal('Connection error to collaboration server. Please ensure the SaaS server is running.');
    }
}

// Join Session - Ouvre la modale si pas de sessionId
function joinCollaborationSession(sessionId = null) {
    if (!sessionId) {
        openModal('modal-join-session');
        return;
    }
    // Si sessionId est fourni, continuer avec le processus de connexion
    doJoinCollaborationSession(sessionId);
}

// Confirme le join de session
async function confirmJoinSession() {
    if (!collabAuthValid) {
        renderCollabApiKeyRequired('API key required for collaboration.');
        return;
    }
    const codeInput = document.getElementById('modal-invite-code');
    const code = codeInput ? codeInput.value.trim() : '';

    if (!code || code.trim() === '') {
        showErrorModal('Please enter an invitation code.');
        return;
    }

    closeModal('modal-join-session');

    // Tenter d'abord de résoudre comme ID de session (UUID), puis comme code d'invitation
    try {
        const trimmedCode = code.trim();
        const normalizedCode = trimmedCode.toUpperCase();

        // 1) Vérifier si c'est directement un ID de session valide
        try {
            const resById = await fetch(`${COLLABORATION_SERVER_URL}/api/v1/sessions/${trimmedCode}`, {
                method: 'GET',
                headers: collabHeaders({ 'Content-Type': 'application/json' })
            });

            if (resById.ok) {
                console.log(`[DEBUG] Session found by ID: ${trimmedCode}`);
                await doJoinCollaborationSession(trimmedCode);
                return;
            } else {
                console.log(`[DEBUG] No session for ID ${trimmedCode}, trying invite code... (status ${resById.status})`);
            }
        } catch (err) {
            console.warn(`[WARN] Error while checking session by ID: ${err.message}. Will try invite code.`);
        }

        // 2) Essayer comme code d'invitation (quelle que soit la longueur)
        console.log(`[DEBUG] Joining session with invite code: ${normalizedCode}`);
        const res = await fetch(`${COLLABORATION_SERVER_URL}/api/v1/sessions/invite/${normalizedCode}`, {
            method: 'GET',
            headers: collabHeaders({ 'Content-Type': 'application/json' })
        });

        if (res.ok) {
            const data = await res.json();
            const sessionId = data.id || data.session_id;
            console.log(`[DEBUG] Session found via invite: ${sessionId}`);
            await doJoinCollaborationSession(sessionId);
        } else {
            const errorData = await res.json().catch(() => ({ detail: res.statusText }));
            console.error(`[ERROR] Failed to get session via invite: ${res.status} - ${JSON.stringify(errorData)}`);
            showErrorModal(`Session not found: ${errorData.detail || 'Please check the invitation code.'}`);
            return;
        }
    } catch (err) {
        console.error('Error getting session by invite:', err);
        showErrorModal(`Connection error to collaboration server: ${err.message}`);
        return;
    }
}

// Effectue réellement la connexion à la session
async function doJoinCollaborationSession(sessionId) {
    if (!sessionId) return;

    if (!sessionId) return;

    try {
        // Construire l'URL WebSocket (toujours utiliser le serveur SaaS)
        const wsProtocol = COLLABORATION_SERVER_URL.startsWith('https') ? 'wss:' : 'ws:';
        const wsHost = COLLABORATION_SERVER_URL.replace('http://', '').replace('https://', '');
        const wsUrl = `${wsProtocol}//${wsHost}/ws/v1/sessions/${sessionId}`;

        console.log('Connecting to WebSocket:', wsUrl);
        collaborationWebSocket = new WebSocket(wsUrl);

        collaborationWebSocket.onopen = () => {
            console.log('WebSocket connected, sending join message...');
            // Send join message (pas besoin d'API key)
            const joinData = {
                name: currentUsername,
                username: currentUsername,
                color: getRandomColor(),
                user_id: currentUserId || `user_${Date.now()}`
            };

            console.log('Sending join data:', { ...joinData, api_key: joinData.api_key ? '***' : undefined });
            collaborationWebSocket.send(JSON.stringify(joinData));

            currentSessionId = sessionId;
            if (!currentUserId) {
                currentUserId = joinData.user_id;
            }
            saveCollaborationState();
            showCollaborationSession();

            // Vérifier l'accès à l'IA
            checkAIAccess(sessionId);

            // Synchroniser les flows existants après un court délai pour laisser le WebSocket se stabiliser
            setTimeout(() => {
                syncExistingFlowsToCollaboration();
                // Synchroniser les flows partagés pour activer les boutons share
                syncSharedFlowsFromCollaboration();
            }, 1000);
        };

        collaborationWebSocket.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                console.log('[Collaboration] Received message:', data.type, data);
                handleCollaborationMessage(data);
            } catch (error) {
                console.error('[Collaboration] Error parsing message:', error, event.data);
            }
        };

        collaborationWebSocket.onerror = (error) => {
            console.error('WebSocket error:', error);
            showErrorModal('WebSocket connection error');
        };

        collaborationWebSocket.onclose = (event) => {
            console.log('WebSocket closed:', event.code, event.reason);
            if (event.code !== 1000) {
                console.warn('Unexpected WebSocket closure');
                if (event.code === 1006) {
                    showErrorModal('Connection closed unexpectedly. Please ensure the server is running and the API key is correct.');
                }
            }
            leaveCollaborationSession();
        };

    } catch (err) {
        console.error('Error joining session:', err);
        showErrorModal('Connection error');
    }
}

// Leave Session
function leaveCollaborationSession() {
    if (collaborationWebSocket) {
        collaborationWebSocket.close();
        collaborationWebSocket = null;
    }

    // Arrêter le mirroring si actif
    if (browserMirror && browserMirror.isMirroring) {
        stopBrowserMirroring();
    }

    currentSessionId = null;
    currentUserId = null;
    collaborationFlows = [];
    collaborationParticipants = [];
    collaborationMessages = [];
    clearCollaborationState();

    resetCollaborationHeader();
    hideCollaborationSession();
}

// Handle WebSocket Messages
function handleCollaborationMessage(data) {
    switch (data.type) {
        case 'session_joined':
            updateSessionInfo(data.session);
            console.log('[Collaboration] session_joined, session data:', data.session);

            // Vérifier si le serveur renvoie les flows existants dans la session
            if (data.session && data.session.flows && Array.isArray(data.session.flows)) {
                console.log('[Collaboration] Found', data.session.flows.length, 'flows in session data');
                data.session.flows.forEach(flow => {
                    if (!collaborationFlows.find(f => f.id === flow.id)) {
                        console.log('[Collaboration] Adding flow from session_joined:', flow.id, flow.url, 'from user:', flow.shared_by_user_id);
                        addCollaborationFlow(flow, flow.shared_by_user_id || flow.user_id);
                    }
                });
            } else {
                console.log('[Collaboration] No flows found in session data, flows:', data.session?.flows);
            }

            // Charger l'historique du chat
            loadChatHistory();

            // Charger les flows existants partagés dans la session depuis les messages
            setTimeout(() => {
                loadExistingSharedFlows();
            }, 500);

            // Demander au serveur de renvoyer tous les flows existants de la session
            // En envoyant un message pour demander les flows
            if (collaborationWebSocket && collaborationWebSocket.readyState === WebSocket.OPEN) {
                try {
                    collaborationWebSocket.send(JSON.stringify({
                        type: 'get_flows'
                    }));
                    console.log('[Collaboration] Requested existing flows from server');
                } catch (error) {
                    console.error('[Collaboration] Error requesting flows:', error);
                }
            }
            // Restaurer les mirrorings actifs
            if (data.session && data.session.active_mirrors) {
                // Attendre un peu pour que les participants soient chargés
                setTimeout(() => {
                    const savedState = restoreCollaborationState();
                    data.session.active_mirrors.forEach(userId => {
                        if (userId !== currentUserId) {
                            // Simuler un message mirror_started pour chaque utilisateur qui partage déjà son écran
                            handleMirrorStarted(userId);

                            // Si on regardait cet utilisateur avant le refresh, restaurer la vue
                            if (savedState && savedState.viewingMirrorUserId === userId) {
                                setTimeout(() => {
                                    switchToMirrorUser(userId);
                                }, 200);
                            }
                        }
                    });
                }, 500);
            }
            // Restaurer l'état sauvegardé
            restoreCollaborationStateAfterJoin();
            // Synchroniser les flows partagés pour activer les boutons share
            syncSharedFlowsFromCollaboration();
            break;
        case 'collaborator_joined':
            addParticipant(data.collaborator);
            break;
        case 'collaborator_left':
            // Gérer collaborator_id ou user_id
            const leftUserId = data.collaborator_id || data.user_id;
            if (leftUserId) {
                removeParticipant(leftUserId);
            }
            break;
        case 'flow_added':
            console.log('[Collaboration] Received flow_added message:', data);
            addCollaborationFlow(data.flow, data.user_id || data.userId);
            // Si c'est notre propre flow, s'assurer qu'il est marqué comme partagé
            if ((data.user_id || data.userId) === currentUserId) {
                sharedFlows.add(data.flow.id);
                renderFlowList(); // Mettre à jour les boutons share
            }
            break;
        case 'flows_list':
            // Réception de la liste des flows existants de la session
            if (data.flows && Array.isArray(data.flows)) {
                console.log('[Collaboration] Received flows_list with', data.flows.length, 'flows');
                data.flows.forEach(flow => {
                    if (!collaborationFlows.find(f => f.id === flow.id)) {
                        addCollaborationFlow(flow, flow.shared_by_user_id || flow.user_id || data.user_id);
                    }
                });
            }
            break;
        case 'flow_selected':
            highlightFlow(data.flow_id, data.user_id);
            // Optionnel: afficher une notification visuelle
            if (data.user_id !== currentUserId) {
                const participant = collaborationParticipants.find(p => p.user_id === data.user_id);
                if (participant) {
                    console.log(`${participant.username} selected a flow`);
                }
            }
            break;
        case 'participant_joined':
            if (data.participant) {
                addParticipant(data.participant);
            }
            break;
        case 'participant_left':
            if (data.user_id) {
                removeParticipant(data.user_id);
            }
            break;
        case 'chat_message':
            addChatMessage(data.message);
            break;
        case 'annotation':
            // Handle annotation
            break;
        case 'mirror_started':
            handleMirrorStarted(data.user_id);
            break;
        case 'mirror_stopped':
            handleMirrorStopped(data.user_id);
            break;
        case 'mirror_data':
            handleMirrorData(data.user_id, data.data);
            break;
        case 'repeater_tab_created':
            // Ajouter un onglet créé par un autre utilisateur
            if (data.user_id !== currentUserId && data.tab) {
                const existingTab = collabRepeaterTabs.find(t => t.id === data.tab.id);
                if (!existingTab) {
                    collabRepeaterTabs.push(data.tab);
                    renderCollabRepeaterTabs();
                    // Ne pas activer automatiquement l'onglet créé par un autre utilisateur
                }
            }
            break;
        case 'repeater_tab_update':
            // Mettre à jour un onglet avec les modifications d'un autre utilisateur
            if (data.user_id !== currentUserId && data.tab) {
                updateCollabRepeaterTabFromSync(data.tab);
            }
            break;
        case 'repeater_tab_activated':
            // Activer un onglet activé par un autre utilisateur
            if (data.user_id !== currentUserId && data.tab_id) {
                const tab = collabRepeaterTabs.find(t => t.id === data.tab_id);
                if (tab) {
                    activeCollabRepeaterTabId = data.tab_id;
                    renderCollabRepeaterTabs();
                    renderCollabRepeaterContent();
                }
            }
            break;
        case 'repeater_tab_closed':
            // Supprimer un onglet fermé par un autre utilisateur
            if (data.user_id !== currentUserId && data.tab_id) {
                const index = collabRepeaterTabs.findIndex(t => t.id === data.tab_id);
                if (index !== -1) {
                    collabRepeaterTabs.splice(index, 1);
                    if (activeCollabRepeaterTabId === data.tab_id) {
                        if (collabRepeaterTabs.length > 0) {
                            activeCollabRepeaterTabId = collabRepeaterTabs[collabRepeaterTabs.length - 1].id;
                        } else {
                            activeCollabRepeaterTabId = null;
                        }
                    }
                    renderCollabRepeaterTabs();
                    renderCollabRepeaterContent();
                }
            }
            break;
        case 'repeater_cursor':
            // Afficher le curseur d'un autre utilisateur
            if (data.user_id !== currentUserId) {
                displayRemoteCursor(data.user_id, data.tab_id, data.field, data.position, data.color, data.username);
            }
            break;
        case 'repeater_sent':
            // Notifier qu'un utilisateur a envoyé une requête
            if (data.user_id !== currentUserId) {
                console.log(`[Collaboration] ${data.user_id} sent a request`);
            }
            break;
        case 'ai_results':
            // Recevoir des résultats IA partagés par un autre utilisateur
            if (data.flow_id && data.suggestions) {
                const flowId = data.flow_id;
                collabAIResults[flowId] = {
                    suggestions: data.suggestions || [],
                    tech_stack: data.tech_stack || {},
                    summary: data.summary || '',
                    next_steps: data.next_steps || [],
                    timestamp: data.timestamp || Date.now()
                };
                console.log('[Collaboration] Received AI results for flow:', flowId, 'from user:', data.user_id);

                // Sauvegarder les résultats IA
                saveAIAssistantResults();

                // Toujours mettre à jour la liste des flows AI (même si l'onglet n'est pas actif, pour qu'elle soit prête)
                loadAIFlowsList();

                // Si c'est le flow actuellement sélectionné, afficher les résultats
                if (collabCurrentAIFlow && collabCurrentAIFlow.id === flowId) {
                    renderAISuggestions(
                        data.suggestions || [],
                        data.tech_stack || {},
                        data.summary || '',
                        data.next_steps || []
                    );
                }
            }
            break;
        case 'participant_name_change':
            // Mettre à jour le nom d'un participant
            if (data.user_id && data.new_name) {
                console.log('[Collaboration] Received name change:', data);
                // Chercher le participant de plusieurs façons pour être sûr de le trouver
                let participant = collaborationParticipants.find(p =>
                    (p.user_id && p.user_id === data.user_id) ||
                    (p.id && p.id === data.user_id) ||
                    (p.collaborator && p.collaborator.id === data.user_id) ||
                    (p.collaborator && p.collaborator.user_id === data.user_id)
                );

                if (participant) {
                    console.log('[Collaboration] Found participant, updating name:', participant);
                    participant.name = data.new_name;
                    participant.username = data.new_name;
                    // Mettre à jour aussi dans collaborator si présent
                    if (participant.collaborator) {
                        participant.collaborator.name = data.new_name;
                        participant.collaborator.username = data.new_name;
                    }
                    // Si c'est l'utilisateur actuel, mettre à jour aussi currentUsername
                    if (data.user_id === currentUserId) {
                        currentUsername = data.new_name;
                        console.log('[Collaboration] Updated currentUsername to:', currentUsername);
                    }
                    renderParticipants();
                    // Mettre à jour immédiatement tous les flows pour refléter le nouveau nom
                    renderCollaborationFlows();
                    console.log('[Collaboration] Participants and flows re-rendered');
                    updateChatAuthorNames(data.user_id, data.new_name);
                } else {
                    console.warn('[Collaboration] Participant not found for user_id:', data.user_id);
                    console.warn('[Collaboration] Available participants:', collaborationParticipants.map(p => ({
                        user_id: p.user_id,
                        id: p.id,
                        name: p.name
                    })));
                }
            }
            break;
    }
}

// UI Functions
function showCollaborationSession() {
    if (collabNoSession) collabNoSession.style.display = 'none';
    if (collabActiveSession) collabActiveSession.style.display = 'flex';
    if (collabLeaveBtn) collabLeaveBtn.style.display = 'block';
    if (collabCreateBtn) collabCreateBtn.style.display = 'none';
    if (collabJoinBtn) collabJoinBtn.style.display = 'none';
}

function hideCollaborationSession() {
    if (collabNoSession) collabNoSession.style.display = 'flex';
    if (collabActiveSession) collabActiveSession.style.display = 'none';
    if (collabLeaveBtn) collabLeaveBtn.style.display = 'none';
    if (collabCreateBtn) collabCreateBtn.style.display = 'block';
    if (collabJoinBtn) collabJoinBtn.style.display = 'block';
    resetCollaborationHeader();
}

// Remet le header collaboration à l'état par défaut
function resetCollaborationHeader() {
    if (collabSessionName) collabSessionName.textContent = 'Collaboration & IA';
    if (collabInviteCode) collabInviteCode.textContent = '';
}

function updateSessionInfo(session) {
    if (collabSessionName) {
        // Afficher le nom de la session au lieu de l'ID
        collabSessionName.textContent = session.name || session.invite_code || 'Collaboration & IA';
    }
    if (collabInviteCode) {
        const sessionId = session.id || session.session_id || session.invite_code || currentSessionId || '';
        collabInviteCode.textContent = sessionId ? `Session ID: ${sessionId}` : '';
    }
    if (session.participants && Array.isArray(session.participants)) {
        collaborationParticipants = session.participants;
        renderParticipants();
    } else if (session.collaborators && Array.isArray(session.collaborators)) {
        collaborationParticipants = session.collaborators;
        renderParticipants();
    }
}

function renderParticipants() {
    if (!collabParticipantsList) return;

    collabParticipantsList.innerHTML = '';

    if (collabParticipantCount) {
        collabParticipantCount.textContent = collaborationParticipants.length;
    }

    collaborationParticipants.forEach(participant => {
        const div = document.createElement('div');
        div.className = 'participant-item';
        div.style.cssText = 'display: flex; align-items: center; gap: 10px; padding: 10px; border-radius: 6px; margin-bottom: 8px; background: #f5f5f5; cursor: pointer; transition: background 0.2s;';
        div.onmouseover = () => {
            if (participant.user_id !== currentUserId) {
                div.style.background = '#e8e8e8';
            }
        };
        div.onmouseout = () => {
            if (participant.user_id !== currentUserId) {
                div.style.background = '#f5f5f5';
            }
        };

        const statusDot = document.createElement('div');
        const color = participant.color || '#4caf50';
        statusDot.style.cssText = `width: 10px; height: 10px; border-radius: 50%; background: ${color}; border: 2px solid white; box-shadow: 0 0 0 1px rgba(0,0,0,0.1);`;

        const nameContainer = document.createElement('div');
        nameContainer.style.cssText = 'flex: 1; display: flex; align-items: center; gap: 6px; min-width: 0;';

        const name = document.createElement('span');
        name.textContent = participant.name || participant.username || 'Anonymous';
        name.style.cssText = 'font-size: 13px; color: #333; flex: 1; font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;';
        name.id = `participant-name-${participant.user_id}`;

        nameContainer.appendChild(name);

        // Indicateur si c'est l'utilisateur actuel
        const isCurrentUser = participant.user_id === currentUserId;
        if (isCurrentUser) {
            div.style.background = '#e3f2fd';
            div.style.borderLeft = `3px solid ${color}`;

            // Ajouter un bouton d'édition pour l'utilisateur actuel
            const editBtn = document.createElement('button');
            editBtn.innerHTML = '<span class="material-symbols-outlined" style="font-size: 16px;">edit</span>';
            editBtn.style.cssText = 'background: transparent; border: none; cursor: pointer; padding: 4px; display: flex; align-items: center; opacity: 0.6; transition: opacity 0.2s; color: #333;';
            editBtn.title = 'Modifier mon nom';
            editBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                editParticipantName(participant);
            });
            editBtn.addEventListener('mouseenter', () => {
                editBtn.style.opacity = '1';
            });
            editBtn.addEventListener('mouseleave', () => {
                editBtn.style.opacity = '0.6';
            });

            nameContainer.appendChild(editBtn);
        }

        div.appendChild(statusDot);
        div.appendChild(nameContainer);
        collabParticipantsList.appendChild(div);
    });
}

// Fonction pour éditer le nom d'un participant (seulement pour l'utilisateur actuel)
function editParticipantName(participant) {
    if (participant.user_id !== currentUserId) return;

    const nameEl = document.getElementById(`participant-name-${participant.user_id}`);
    if (!nameEl) return;

    const currentName = participant.name || participant.username || 'Anonymous';

    // Créer un input inline
    const input = document.createElement('input');
    input.type = 'text';
    input.value = currentName;
    input.style.cssText = 'font-size: 13px; color: #333; font-weight: 500; border: 1px solid #2196f3; border-radius: 4px; padding: 4px 8px; width: 100%; background: white; font-family: inherit;';
    input.maxLength = 50;

    // Remplacer le span par l'input
    const nameContainer = nameEl.parentElement;
    nameEl.style.display = 'none';
    nameContainer.insertBefore(input, nameEl);
    input.focus();
    input.select();

    // Fonction pour sauvegarder
    const saveName = () => {
        const newName = input.value.trim();
        if (newName && newName !== currentName) {
            // Mettre à jour localement
            participant.name = newName;
            participant.username = newName;
            currentUsername = newName;

            // Mettre à jour l'affichage
            nameEl.textContent = newName;
            nameEl.style.display = 'block';
            input.remove();

            // Synchroniser avec les autres utilisateurs
            if (collaborationWebSocket && collaborationWebSocket.readyState === WebSocket.OPEN) {
                try {
                    const message = {
                        type: 'participant_name_change',
                        user_id: currentUserId,
                        new_name: newName
                    };
                    console.log('[Collaboration] Sending name change:', message);
                    collaborationWebSocket.send(JSON.stringify(message));
                } catch (error) {
                    console.error('[Collaboration] Error sending name change:', error);
                }
            } else {
                console.warn('[Collaboration] WebSocket not ready, cannot send name change');
            }

            // Re-rendre pour mettre à jour l'affichage
            renderParticipants();
            // Mettre à jour immédiatement tous les flows pour refléter le nouveau nom
            renderCollaborationFlows();
        } else {
            // Annuler si vide ou identique
            nameEl.style.display = 'block';
            input.remove();
        }
    };

    // Sauvegarder sur Enter ou blur
    input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            saveName();
        } else if (e.key === 'Escape') {
            e.preventDefault();
            nameEl.style.display = 'block';
            input.remove();
        }
    });

    input.addEventListener('blur', saveName);
}

function addParticipant(participant) {
    // Normaliser le participant pour avoir à la fois id et user_id
    const normalizedParticipant = {
        ...participant,
        id: participant.id || participant.user_id || participant.collaborator?.id,
        user_id: participant.user_id || participant.id || participant.collaborator?.id
    };

    if (!collaborationParticipants.find(p =>
        (p.id && p.id === normalizedParticipant.id) ||
        (p.user_id && p.user_id === normalizedParticipant.user_id) ||
        (p.id && p.id === participant.id)
    )) {
        collaborationParticipants.push(normalizedParticipant);
        renderParticipants();
    }
}

function removeParticipant(userId) {
    // Retirer le participant de la liste (vérifier à la fois id et user_id)
    collaborationParticipants = collaborationParticipants.filter(p =>
        (p.id !== userId) && (p.user_id !== userId) &&
        (p.collaborator?.id !== userId) && (p.collaborator?.user_id !== userId)
    );
    renderParticipants();

    // Si cet utilisateur partageait son écran, retirer aussi le mirroring
    if (mirrorViewers[userId]) {
        console.log(`[Collaboration] User ${userId} left and was sharing screen, removing mirroring`);
        handleMirrorStopped(userId);
    }
}

function addCollaborationFlow(flow, userId) {
    console.log('[Collaboration] Adding flow:', flow?.id, flow?.url, 'from user:', userId);

    if (!flow || !flow.id) {
        console.warn('[Collaboration] Invalid flow data:', flow);
        return;
    }

    if (!collaborationFlows.find(f => f.id === flow.id)) {
        // Ajouter l'information de l'utilisateur au flow
        flow.shared_by_user_id = userId || currentUserId;
        collaborationFlows.push(flow);

        // Si c'est notre propre flow, marquer comme partagé
        if (userId === currentUserId || !userId) {
            sharedFlows.add(flow.id);
        }

        console.log('[Collaboration] Flow added, total flows:', collaborationFlows.length);
        renderCollaborationFlows();

        // Re-render la liste principale pour mettre à jour le bouton Share
        renderFlowList();

        // Toujours mettre à jour la liste des flows AI (même si l'onglet n'est pas actif, pour qu'elle soit prête)
        loadAIFlowsList();
    } else {
        console.log('[Collaboration] Flow already exists:', flow.id);
        // Même si le flow existe déjà, s'assurer qu'il est marqué comme partagé si c'est le nôtre
        if (userId === currentUserId || !userId) {
            sharedFlows.add(flow.id);
            renderFlowList(); // Mettre à jour les boutons share
        }
        // Mettre à jour quand même la liste AI au cas où
        loadAIFlowsList();
    }
}

// Synchroniser les flows partagés depuis collaborationFlows vers sharedFlows
function syncSharedFlowsFromCollaboration() {
    if (!currentSessionId || !collaborationWebSocket) {
        return;
    }

    console.log('[Collaboration] Syncing shared flows from collaboration list...');

    // Parcourir tous les flows dans collaborationFlows
    collaborationFlows.forEach(collabFlow => {
        // Si le flow appartient à l'utilisateur actuel, le marquer comme partagé
        const isOurFlow = collabFlow.shared_by_user_id === currentUserId;
        // Ou si le flow existe dans notre liste locale (flowsData), c'est qu'on l'a partagé
        const existsInOurFlows = flowsData.find(f => f.id === collabFlow.id);

        if (isOurFlow || existsInOurFlows) {
            sharedFlows.add(collabFlow.id);
            console.log('[Collaboration] Marked flow as shared:', collabFlow.id, 'isOurFlow:', isOurFlow, 'existsInOurFlows:', !!existsInOurFlows);
        }
    });

    // Re-render la liste principale pour activer les boutons share
    renderFlowList();

    console.log('[Collaboration] Shared flows synced, total:', sharedFlows.size);
}

function renderCollaborationFlows() {
    const collabFlowsList = document.getElementById('collab-flows-list');
    if (!collabFlowsList) {
        console.warn('[Collaboration] collab-flows-list element not found');
        return;
    }

    console.log('[Collaboration] Rendering flows, count:', collaborationFlows.length);

    if (collaborationFlows.length === 0) {
        collabFlowsList.innerHTML = '<div style="padding: 40px; text-align: center; color: #888;">No flow shared</div>';
        return;
    }

    collabFlowsList.innerHTML = '';

    collaborationFlows.forEach(flow => {
        // Status code avec classe appropriée
        const statusCode = flow.status_code;
        let statusClass = '';
        let statusText = '-';
        if (statusCode !== null && statusCode !== undefined) {
            statusText = statusCode.toString();
            if (statusCode >= 500) {
                statusClass = 'status-5xx';
            } else if (statusCode >= 400) {
                statusClass = 'status-4xx';
            } else if (statusCode >= 300) {
                statusClass = 'status-3xx';
            } else if (statusCode >= 200) {
                statusClass = 'status-2xx';
            }
        }

        // Durée en millisecondes
        let timeText = '-';
        if (flow.duration_ms !== null && flow.duration_ms !== undefined) {
            timeText = `${Math.round(flow.duration_ms)}ms`;
        } else if (flow.duration !== null && flow.duration !== undefined) {
            timeText = `${Math.round(flow.duration * 1000)}ms`;
        }

        // Technologies détectées
        const techs = flow.technologies || {};
        const allTechs = [
            ...(techs.frameworks || []),
            ...(techs.cms || []),
            ...(techs.servers || []),
            ...(techs.languages || []),
        ];
        const techBadges = allTechs.slice(0, 3).map(tech =>
            `<span style="background: #e3f2fd; color: #1976d2; padding: 2px 6px; border-radius: 3px; font-size: 0.7em; margin-left: 4px;">${tech}</span>`
        ).join('');

        const flowItem = document.createElement('div');
        flowItem.className = 'collab-flow-item';
        flowItem.dataset.flowId = flow.id;

        // Colonne User - afficher l'utilisateur qui a partagé le flow
        const userEl = document.createElement('div');
        userEl.className = 'flow-user';
        const sharedByUserId = flow.shared_by_user_id || flow.user_id;
        const participant = collaborationParticipants.find(p => p.user_id === sharedByUserId);
        const username = participant ? participant.username : (sharedByUserId === currentUserId ? 'You' : sharedByUserId || 'Unknown');
        userEl.textContent = username;
        userEl.title = `Shared by: ${username}`;

        // Méthode HTTP - style simple et professionnel
        const methodEl = document.createElement('div');
        methodEl.className = `flow-method method-${flow.method?.toUpperCase() || 'UNKNOWN'}`;
        methodEl.textContent = flow.method || '-';

        // Statut HTTP - style simple et professionnel
        const statusEl = document.createElement('div');
        statusEl.className = `flow-status status-${statusCode !== null && statusCode !== undefined ? Math.floor(statusCode / 100) + 'xx' : 'unknown'}`;
        statusEl.textContent = statusText;

        const urlEl = document.createElement('div');
        urlEl.className = 'flow-url';
        urlEl.style.overflow = 'hidden';
        urlEl.style.textOverflow = 'ellipsis';
        urlEl.style.whiteSpace = 'nowrap';
        urlEl.style.display = 'flex';
        urlEl.style.alignItems = 'center';
        urlEl.style.gap = '6px';

        // Add source indicators (API Tester, PCAP import)
        let sourceIndicator = '';
        if (flow.source === 'api_tester')
            sourceIndicator = '<span class="material-symbols-outlined" style="font-size: 16px; color: #6200ea; flex-shrink: 0;" title="Sent from API Tester">api</span>';
        else if (flow.source === 'pcap')
            sourceIndicator = '<span class="material-symbols-outlined" style="font-size: 16px; color: #ff9800; flex-shrink: 0;" title="Imported from PCAP">upload_file</span>';

        urlEl.innerHTML = `${sourceIndicator}<span style="flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${flow.url || '-'}</span>${techBadges}`;
        const sourceNote = flow.source === 'api_tester' ? '\nSource: API Tester' : (flow.source === 'pcap' ? '\nSource: PCAP import' : '');
        urlEl.title = flow.url + (allTechs.length > 0 ? `\nTechnologies: ${allTechs.join(', ')}` : '') + sourceNote;

        // Size - calculate from response_size (always available) or response.content_length (detail view)
        let sizeText = '-';
        let responseSize = null;
        // Prefer response_size (always available in list view)
        if (flow.response_size !== null && flow.response_size !== undefined && flow.response_size >= 0) {
            responseSize = flow.response_size;
        } else if (flow.response && flow.response.content_length !== null && flow.response.content_length !== undefined) {
            responseSize = flow.response.content_length;
        }
        if (responseSize !== null && responseSize !== undefined && responseSize >= 0) {
            sizeText = formatBytes(responseSize);
        }

        const sizeEl = document.createElement('div');
        sizeEl.className = 'flow-size';
        sizeEl.textContent = sizeText;
        sizeEl.style.fontFamily = 'monospace';
        sizeEl.style.fontSize = '0.9em';
        sizeEl.style.color = '#666';
        sizeEl.style.textAlign = 'right';

        const timeEl = document.createElement('div');
        timeEl.className = 'flow-time';
        timeEl.textContent = timeText;
        timeEl.style.fontFamily = 'monospace';
        timeEl.style.fontSize = '0.9em';

        flowItem.appendChild(userEl);
        flowItem.appendChild(methodEl);
        flowItem.appendChild(statusEl);
        flowItem.appendChild(urlEl);
        flowItem.appendChild(sizeEl);
        flowItem.appendChild(timeEl);

        // Ajouter une colonne "Share" - visible uniquement pour le propriétaire du flow
        const shareCol = document.createElement('div');
        shareCol.className = 'flow-share';
        shareCol.style.cssText = 'display: flex; align-items: center; justify-content: center; padding: 4px;';

        // Vérifier si l'utilisateur actuel est le propriétaire du flow
        const isOwner = sharedByUserId === currentUserId;
        const isShared = sharedFlows.has(flow.id);

        if (isOwner) {
            // Le propriétaire peut un-share
            if (isShared) {
                shareCol.innerHTML = '<span class="material-symbols-outlined" style="font-size: 18px; color: #4caf50;">check_circle</span>';
                shareCol.title = 'Click to unshare';
                shareCol.style.cursor = 'pointer';
                shareCol.onclick = (e) => {
                    e.stopPropagation();
                    toggleShareFlow(flow);
                };
            } else {
                shareCol.innerHTML = '<span class="material-symbols-outlined" style="font-size: 18px; color: #666;">group</span>';
                shareCol.title = 'Share in collaboration';
                shareCol.style.cursor = 'pointer';
                shareCol.onclick = (e) => {
                    e.stopPropagation();
                    toggleShareFlow(flow);
                };
            }
        } else {
            // Les autres utilisateurs voient juste l'icône de partage (non cliquable)
            shareCol.innerHTML = '<span class="material-symbols-outlined" style="font-size: 18px; color: #4caf50;">check_circle</span>';
            shareCol.title = `Shared by ${username}`;
            shareCol.style.cursor = 'default';
            shareCol.style.opacity = '0.7';
        }

        flowItem.appendChild(shareCol);

        flowItem.addEventListener('click', () => {
            // Notifier les autres participants
            if (collaborationWebSocket && collaborationWebSocket.readyState === WebSocket.OPEN) {
                try {
                    collaborationWebSocket.send(JSON.stringify({
                        type: 'flow_selected',
                        flow_id: flow.id
                    }));
                } catch (error) {
                    console.error('[Collaboration] Error sending flow_selected:', error);
                }
            }

            // Afficher la modal avec les détails
            showCollaborationFlowModal(flow);

            // Option: Charger dans le Repeater avec un double-clic ou un bouton
            // Pour l'instant, on peut ajouter un bouton dans la modal
        });

        collabFlowsList.appendChild(flowItem);
    });
}

function showCollaborationFlowModal(flow) {
    // Créer la modal si elle n'existe pas
    let modal = document.getElementById('collab-flow-modal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'collab-flow-modal';
        modal.style.cssText = 'display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 10000; overflow-y: auto;';
        modal.onclick = (e) => {
            if (e.target === modal) {
                closeCollaborationFlowModal();
            }
        };
        document.body.appendChild(modal);

        const modalContent = document.createElement('div');
        modalContent.id = 'collab-flow-modal-content';
        modalContent.style.cssText = 'background: white; margin: 20px auto; max-width: 95%; width: 1400px; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.15); overflow: hidden; border: 1px solid #e0e0e0;';
        modal.appendChild(modalContent);
    }

    const modalContent = document.getElementById('collab-flow-modal-content');

    // Récupérer les détails complets du flow
    fetch(`${API_BASE}/flows/${flow.id}`)
        .then(res => res.json())
        .then(fullFlow => {
            renderCollaborationFlowDetails(modalContent, fullFlow);
            modal.style.display = 'block';
        })
        .catch(err => {
            console.error('Error loading flow details:', err);
            renderCollaborationFlowDetails(modalContent, flow);
            modal.style.display = 'block';
        });
}

function getStatusText(code) {
    const statusTexts = {
        200: 'OK', 201: 'Created', 202: 'Accepted', 204: 'No Content',
        301: 'Moved Permanently', 302: 'Found', 304: 'Not Modified',
        400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found',
        500: 'Internal Server Error', 502: 'Bad Gateway', 503: 'Service Unavailable'
    };
    return statusTexts[code] || '';
}

// Envoyer un flow partagé vers le Repeater personnel
function sendSharedFlowToPersonalRepeater(flow) {
    if (!flow || !flow.request) {
        alert('Request details not available');
        return;
    }
    try {
        const headers = flow.request.headers || {};
        let bodyContent = '';
        if (flow.request.content_bs64) {
            try {
                bodyContent = atob(flow.request.content_bs64);
            } catch (e) {
                bodyContent = '';
            }
        } else if (typeof flow.request.content === 'string') {
            bodyContent = flow.request.content;
        }

        createRepeaterTab({
            method: flow.method || 'GET',
            url: flow.url || '',
            headers: JSON.stringify(headers, null, 2),
            body: bodyContent
        });

        const replayNavItem = document.querySelector('[data-view="replay"]');
        if (replayNavItem) {
            replayNavItem.click();
        }
    } catch (err) {
        console.error('Send shared flow to repeater error', err);
        alert('Failed to load request into repeater');
    }
}

// Envoyer un flow partagé vers l'Intruder personnel
function sendSharedFlowToIntruder(flow) {
    if (!flow || !flow.request) {
        alert('Request details not available');
        return;
    }
    try {
        const headers = flow.request.headers || {};
        let bodyContent = '';
        if (flow.request.content_bs64) {
            try {
                bodyContent = atob(flow.request.content_bs64);
            } catch (e) {
                bodyContent = '';
            }
        } else if (typeof flow.request.content === 'string') {
            bodyContent = flow.request.content;
        }

        createIntruderTab({
            method: flow.method || 'GET',
            url: flow.url || '',
            headers: JSON.stringify(headers, null, 2),
            body: bodyContent,
            payloads: [],
            marker: '§payload§',
            attackType: 'url'
        });

        const intruderNavItem = document.querySelector('[data-view="intruder"]');
        if (intruderNavItem) {
            intruderNavItem.click();
        }
    } catch (err) {
        console.error('Send shared flow to intruder error', err);
        alert('Failed to load request into intruder');
    }
}

function renderCollaborationFlowDetails(container, flow) {
    const statusCode = flow.status_code || flow.status || '-';
    let statusBg = '#f5f5f5';
    let statusColor = '#666';
    let statusBorder = '#ddd';
    if (statusCode >= 200 && statusCode < 300) {
        statusBg = '#e8f5e9';
        statusColor = '#2e7d32';
        statusBorder = '#2e7d32';
    } else if (statusCode >= 300 && statusCode < 400) {
        statusBg = '#fff3e0';
        statusColor = '#f57c00';
        statusBorder = '#f57c00';
    } else if (statusCode >= 400) {
        statusBg = '#ffebee';
        statusColor = '#c62828';
        statusBorder = '#c62828';
    }

    // Utiliser les couleurs du projet pour les méthodes HTTP
    const methodColors = {
        'GET': { bg: '#e3f2fd', color: '#61affe', border: '#61affe' },
        'POST': { bg: '#e8f5e9', color: '#49cc90', border: '#49cc90' },
        'PUT': { bg: '#fff3e0', color: '#fca130', border: '#fca130' },
        'DELETE': { bg: '#ffebee', color: '#f93e3e', border: '#f93e3e' },
        'PATCH': { bg: '#e0f2f1', color: '#00695c', border: '#00695c' }
    };
    const methodStyle = methodColors[flow.method] || { bg: '#f5f5f5', color: '#666', border: '#ddd' };

    // Trouver l'utilisateur qui a partagé ce flow
    let sharedByUser = null;
    if (flow.shared_by_user_id) {
        sharedByUser = collaborationParticipants.find(p => p.user_id === flow.shared_by_user_id);
    }

    let html = `
        <div style="background: #fff; border-bottom: 1px solid #e0e0e0; padding: 20px 24px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
                <h2 style="margin: 0; font-size: 18px; font-weight: 600; color: #333;">Flow Details</h2>
                <div style="display: flex; gap: 8px; align-items: center;">
                    <button onclick="window.currentModalFlow = ${JSON.stringify(flow).replace(/"/g, '&quot;')}; sendSharedFlowToPersonalRepeater(window.currentModalFlow); closeCollaborationFlowModal();" class="btn btn-primary" style="padding: 6px 12px; font-size: 12px;">
                        <span class="material-symbols-outlined" style="font-size: 16px;">replay</span>
                        Send to Repeater
                    </button>
                    <button onclick="window.currentModalFlow = ${JSON.stringify(flow).replace(/"/g, '&quot;')}; sendSharedFlowToIntruder(window.currentModalFlow); closeCollaborationFlowModal();" class="btn btn-secondary" style="padding: 6px 12px; font-size: 12px;">
                        <span class="material-symbols-outlined" style="font-size: 16px;">target</span>
                        Send to Intruder
                    </button>
                    <button onclick="closeCollaborationFlowModal()" style="background: #f5f5f5; border: 1px solid #e0e0e0; color: #666; width: 32px; height: 32px; border-radius: 6px; cursor: pointer; display: flex; align-items: center; justify-content: center; font-size: 20px; transition: all 0.2s;" onmouseover="this.style.background='#e0e0e0'; this.style.color='#333';" onmouseout="this.style.background='#f5f5f5'; this.style.color='#666';">×</button>
                </div>
            </div>
            <div style="display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 12px;">
                <span style="background: ${methodStyle.bg}; color: ${methodStyle.color}; border: 1px solid ${methodStyle.border}; padding: 6px 12px; border-radius: 6px; font-weight: 700; font-size: 11px; letter-spacing: 0.5px;">${flow.method || 'GET'}</span>
                <span style="background: ${statusBg}; color: ${statusColor}; border: 1px solid ${statusBorder}; padding: 6px 12px; border-radius: 6px; font-weight: 700; font-size: 11px;">${statusCode}</span>
                <span style="background: #f5f5f5; color: #666; border: 1px solid #e0e0e0; padding: 6px 12px; border-radius: 6px; font-size: 11px; font-family: monospace;">ID: #${flow.id || '-'}</span>
                ${flow.response_size ? `<span style="background: #f5f5f5; color: #666; border: 1px solid #e0e0e0; padding: 6px 12px; border-radius: 6px; font-size: 11px; font-family: monospace;">Size: ${formatBytes(flow.response_size)}</span>` : ''}
            </div>
            ${sharedByUser ? `
            <div style="display: flex; align-items: center; gap: 8px; padding: 8px 12px; background: #f8f9fa; border: 1px solid #e0e0e0; border-radius: 6px;">
                <span class="material-symbols-outlined" style="font-size: 16px; color: #666;">person</span>
                <span style="font-size: 12px; color: #666;">Partagé par:</span>
                <span style="font-size: 12px; font-weight: 600; color: #333;">${escapeHtml(sharedByUser.username || sharedByUser.name || 'Unknown')}</span>
                ${sharedByUser.color ? `<span style="display: inline-block; width: 12px; height: 12px; border-radius: 50%; background: ${sharedByUser.color}; border: 1px solid #e0e0e0;"></span>` : ''}
            </div>
            ` : ''}
        </div>
        <div style="padding: 24px; background: #fafafa;">
    `;

    // Requête complète
    html += `
        <div style="margin-bottom: 32px;">
            <h3 style="margin: 0 0 16px 0; font-size: 14px; font-weight: 600; color: #333; text-transform: uppercase; letter-spacing: 0.5px; display: flex; align-items: center; gap: 8px; padding-bottom: 8px; border-bottom: 2px solid #e0e0e0;">
                <span class="material-symbols-outlined" style="font-size: 18px; color: #61affe;">arrow_upward</span>
                Complete Request
            </h3>
            <div style="background: #fff; border: 1px solid #e0e0e0; border-radius: 6px; overflow: hidden;">
    `;

    // Request Line
    const requestLine = `${flow.method || 'GET'} ${flow.url || flow.path || '/'} HTTP/1.1`;
    html += `
        <div style="background: ${methodStyle.bg}; border-bottom: 1px solid ${methodStyle.border}; padding: 12px 16px;">
            <div style="font-family: 'Fira Code', monospace; font-size: 13px; font-weight: 600; color: ${methodStyle.color}; word-break: break-all;">${escapeHtml(requestLine)}</div>
        </div>
    `;

    // Request Headers
    if (flow.request && flow.request.headers) {
        html += `<div style="border-bottom: 1px solid #e0e0e0; max-height: 300px; overflow-y: auto;">`;
        let isEven = false;
        for (const [key, value] of Object.entries(flow.request.headers)) {
            const headerValue = Array.isArray(value) ? value.join(', ') : value;
            html += `<div style="padding: 10px 16px; background: ${isEven ? '#fafafa' : '#fff'}; border-bottom: 1px solid #f0f0f0; font-family: 'Fira Code', monospace; font-size: 12px; display: flex; gap: 12px;"><strong style="color: #61affe; min-width: 200px; flex-shrink: 0;">${escapeHtml(key)}:</strong> <span style="color: #333; word-break: break-all; flex: 1;">${escapeHtml(headerValue)}</span></div>`;
            isEven = !isEven;
        }
        html += `</div>`;
    }

    // Request Body
    let requestBody = '';
    if (flow.request) {
        if (flow.request.content_bs64) {
            try {
                requestBody = atob(flow.request.content_bs64);
            } catch (e) {
                console.warn('[Collaboration] Error decoding request body (base64):', e);
                requestBody = '';
            }
        } else if (flow.request.content) {
            if (typeof flow.request.content === 'string') {
                requestBody = flow.request.content;
            } else if (flow.request.content instanceof ArrayBuffer) {
                try {
                    requestBody = new TextDecoder().decode(flow.request.content);
                } catch (e) {
                    console.warn('[Collaboration] Error decoding request body (ArrayBuffer):', e);
                    requestBody = '';
                }
            }
        }

        if (requestBody) {
            html += `
            <div style="background: #282c34; padding: 15px; border-top: 2px solid #e0e0e0;">
                    <div style="font-family: 'Fira Code', monospace; font-size: 12px; white-space: pre-wrap; word-wrap: break-word; color: #abb2bf; max-height: 400px; overflow-y: auto;">${escapeHtml(requestBody)}</div>
            </div>
        `;
        } else {
            html += `<div style="padding: 12px 16px; color: #999; font-size: 12px; font-style: italic;">No request body</div>`;
        }
    }

    html += `</div></div>`;

    // Réponse complète
    html += `
        <div style="margin-bottom: 32px;">
            <h3 style="margin: 0 0 16px 0; font-size: 14px; font-weight: 600; color: #333; text-transform: uppercase; letter-spacing: 0.5px; display: flex; align-items: center; gap: 8px; padding-bottom: 8px; border-bottom: 2px solid #e0e0e0;">
                <span class="material-symbols-outlined" style="font-size: 18px; color: #49cc90;">arrow_downward</span>
                Réponse Complète
            </h3>
            <div style="background: #fff; border: 1px solid #e0e0e0; border-radius: 6px; overflow: hidden;">
    `;

    // Status Line
    const statusLine = `HTTP/1.1 ${statusCode} ${getStatusText(statusCode)}`;
    html += `
        <div style="background: ${statusBg}; border-bottom: 1px solid ${statusBorder}; padding: 12px 16px;">
            <div style="font-family: 'Fira Code', monospace; font-size: 13px; font-weight: 600; color: ${statusColor};">${escapeHtml(statusLine)}</div>
        </div>
    `;

    // Response Headers
    if (flow.response && flow.response.headers) {
        html += `<div style="border-bottom: 1px solid #e0e0e0; max-height: 300px; overflow-y: auto;">`;
        let isEven = false;
        for (const [key, value] of Object.entries(flow.response.headers)) {
            const headerValue = Array.isArray(value) ? value.join(', ') : value;
            html += `<div style="padding: 10px 16px; background: ${isEven ? '#fafafa' : '#fff'}; border-bottom: 1px solid #f0f0f0; font-family: 'Fira Code', monospace; font-size: 12px; display: flex; gap: 12px;"><strong style="color: #49cc90; min-width: 200px; flex-shrink: 0;">${escapeHtml(key)}:</strong> <span style="color: #333; word-break: break-all; flex: 1;">${escapeHtml(headerValue)}</span></div>`;
            isEven = !isEven;
        }
        html += `</div>`;
    }

    // Response Body
    let responseBody = '';
    if (flow.response) {
        if (flow.response.content_bs64) {
            try {
                responseBody = atob(flow.response.content_bs64);
            } catch (e) {
                console.warn('[Collaboration] Error decoding response body (base64):', e);
                responseBody = '';
            }
        } else if (flow.response.content) {
            if (typeof flow.response.content === 'string') {
                responseBody = flow.response.content;
            } else if (flow.response.content instanceof ArrayBuffer) {
                try {
                    responseBody = new TextDecoder().decode(flow.response.content);
                } catch (e) {
                    console.warn('[Collaboration] Error decoding response body (ArrayBuffer):', e);
                    responseBody = '';
                }
            }
        }

        if (responseBody) {
            html += `
            <div style="background: #282c34; padding: 15px; border-top: 2px solid #e0e0e0;">
                    <div style="font-family: 'Fira Code', monospace; font-size: 12px; white-space: pre-wrap; word-wrap: break-word; color: #abb2bf; max-height: 500px; overflow-y: auto;">${escapeHtml(responseBody)}</div>
            </div>
        `;
        } else {
            html += `<div style="padding: 12px 16px; color: #999; font-size: 12px; font-style: italic;">No response body</div>`;
        }
    }

    html += `</div></div>`;

    // Informations supplémentaires
    html += `
        <div style="margin-top: 32px; padding-top: 24px; border-top: 2px solid #e0e0e0;">
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px;">
    `;

    if (flow.timestamp_start) {
        const date = new Date(flow.timestamp_start * 1000);
        html += `
            <div>
                <div style="font-size: 11px; color: #666; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px;">Timestamp</div>
                <div style="background: #fff; border: 1px solid #e0e0e0; padding: 10px; border-radius: 6px; font-size: 12px; color: #333; font-family: 'Fira Code', monospace;">${date.toLocaleString('fr-FR')}</div>
            </div>
        `;
    }

    if (flow.duration_ms) {
        html += `
            <div>
                <div style="font-size: 11px; color: #666; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px;">Duration</div>
                <div style="background: #fff; border: 1px solid #e0e0e0; padding: 10px; border-radius: 6px; font-size: 12px; color: #333; font-family: 'Fira Code', monospace;">${flow.duration_ms} ms</div>
            </div>
        `;
    }

    if (flow.response_size) {
        html += `
            <div>
                <div style="font-size: 11px; color: #666; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px;">Size</div>
                <div style="background: #fff; border: 1px solid #e0e0e0; padding: 10px; border-radius: 6px; font-size: 12px; color: #333; font-family: 'Fira Code', monospace;">${formatBytes(flow.response_size)}</div>
            </div>
        `;
    }

    html += `
            </div>
        </div>
    `;

    html += `</div>`;
    container.innerHTML = html;
}

function closeCollaborationFlowModal() {
    const modal = document.getElementById('collab-flow-modal');
    if (modal) {
        modal.style.display = 'none';
    }
}

// Rendre les fonctions accessibles globalement
if (typeof window !== 'undefined') {
    window.closeCollaborationFlowModal = closeCollaborationFlowModal;
    window.sendSharedFlowToPersonalRepeater = sendSharedFlowToPersonalRepeater;
    window.sendSharedFlowToIntruder = sendSharedFlowToIntruder;
}

// ==================== Browser Mirroring ====================

// Initialiser les event listeners pour les onglets Flows/Repeater/Mirror
function initCollaborationTabs() {
    const collabTabFlows = document.getElementById('collab-tab-flows');
    const collabTabRepeater = document.getElementById('collab-tab-repeater');
    const collabTabMirror = document.getElementById('collab-tab-mirror');
    const collabTabAI = document.getElementById('collab-tab-ai');
    const collabFlowsList = document.getElementById('collab-flows-list');
    const collabFlowsListContainer = document.getElementById('collab-flows-list-container');
    const collabRepeaterContainer = document.getElementById('collab-repeater-container');
    const collabMirrorContainer = document.getElementById('collab-mirror-container');
    const collabAIContainer = document.getElementById('collab-ai-container');

    // Gestion des onglets
    if (collabTabFlows) {
        collabTabFlows.addEventListener('click', () => {
            collabTabFlows.classList.add('active');
            if (collabTabRepeater) collabTabRepeater.classList.remove('active');
            if (collabTabMirror) collabTabMirror.classList.remove('active');
            if (collabTabAI) collabTabAI.classList.remove('active');
            // Désactiver tous les boutons utilisateurs
            document.querySelectorAll('.collab-mirror-user-tab').forEach(btn => {
                btn.classList.remove('active');
                btn.style.background = '#f5f5f5';
                btn.style.color = '';
            });
            currentMirrorUserId = null;
            if (collabFlowsListContainer) {
                collabFlowsListContainer.style.display = 'flex';
                collabFlowsListContainer.classList.add('active');
            }
            if (collabRepeaterContainer) {
                collabRepeaterContainer.style.display = 'none';
                collabRepeaterContainer.classList.remove('active');
            }
            if (collabMirrorContainer) {
                collabMirrorContainer.style.display = 'none';
                collabMirrorContainer.classList.remove('active');
            }
            if (collabAIContainer) {
                collabAIContainer.style.display = 'none';
                collabAIContainer.classList.remove('active');
            }
        });
    }

    if (collabTabRepeater) {
        collabTabRepeater.addEventListener('click', () => {
            collabTabRepeater.classList.add('active');
            if (collabTabFlows) collabTabFlows.classList.remove('active');
            if (collabTabMirror) collabTabMirror.classList.remove('active');
            if (collabTabAI) collabTabAI.classList.remove('active');
            // Désactiver tous les boutons utilisateurs
            document.querySelectorAll('.collab-mirror-user-tab').forEach(btn => {
                btn.classList.remove('active');
                btn.style.background = '#f5f5f5';
                btn.style.color = '';
            });
            currentMirrorUserId = null;
            if (collabFlowsListContainer) {
                collabFlowsListContainer.style.display = 'none';
                collabFlowsListContainer.classList.remove('active');
            }
            if (collabRepeaterContainer) {
                collabRepeaterContainer.style.display = 'flex';
                collabRepeaterContainer.classList.add('active');
            }
            if (collabMirrorContainer) {
                collabMirrorContainer.style.display = 'none';
                collabMirrorContainer.classList.remove('active');
            }
            if (collabAIContainer) {
                collabAIContainer.style.display = 'none';
                collabAIContainer.classList.remove('active');
            }
        });
    }

    if (collabTabMirror) {
        collabTabMirror.addEventListener('click', () => {
            collabTabMirror.classList.add('active');
            if (collabTabFlows) collabTabFlows.classList.remove('active');
            if (collabTabRepeater) collabTabRepeater.classList.remove('active');
            if (collabTabAI) collabTabAI.classList.remove('active');

            // Désactiver tous les boutons utilisateurs pour revenir à la vue "Live Mirror"
            document.querySelectorAll('.collab-mirror-user-tab').forEach(btn => {
                btn.classList.remove('active');
                btn.style.background = '#f5f5f5';
                btn.style.color = '';
            });
            currentMirrorUserId = null;

            if (collabFlowsListContainer) {
                collabFlowsListContainer.style.display = 'none';
                collabFlowsListContainer.classList.remove('active');
            }
            if (collabRepeaterContainer) {
                collabRepeaterContainer.style.display = 'none';
                collabRepeaterContainer.classList.remove('active');
            }
            if (collabMirrorContainer) {
                collabMirrorContainer.style.display = 'flex';
                collabMirrorContainer.classList.add('active');
            }
            if (collabAIContainer) {
                collabAIContainer.style.display = 'none';
                collabAIContainer.classList.remove('active');
            }

            // Afficher les contrôles pour permettre de partager son propre écran
            const collabMirrorControls = document.getElementById('collab-mirror-controls');
            if (collabMirrorControls) {
                collabMirrorControls.style.display = 'flex';
            }

            // Si on regardait l'écran d'un autre utilisateur, afficher le placeholder
            const placeholder = document.getElementById('collab-mirror-placeholder');
            const content = document.getElementById('collab-mirror-content');
            if (!browserMirror || !browserMirror.isMirroring) {
                if (placeholder) placeholder.style.display = 'block';
                if (content) content.style.display = 'none';
            }
        });
    }

    // Gestion de l'onglet AI Assistant
    if (collabTabAI) {
        collabTabAI.addEventListener('click', () => {
            collabTabAI.classList.add('active');
            if (collabTabFlows) collabTabFlows.classList.remove('active');
            if (collabTabRepeater) collabTabRepeater.classList.remove('active');
            if (collabTabMirror) collabTabMirror.classList.remove('active');

            // Désactiver tous les boutons utilisateurs
            document.querySelectorAll('.collab-mirror-user-tab').forEach(btn => {
                btn.classList.remove('active');
                btn.style.background = '#f5f5f5';
                btn.style.color = '';
            });
            currentMirrorUserId = null;

            if (collabFlowsListContainer) {
                collabFlowsListContainer.style.display = 'none';
                collabFlowsListContainer.classList.remove('active');
            }
            if (collabRepeaterContainer) {
                collabRepeaterContainer.style.display = 'none';
                collabRepeaterContainer.classList.remove('active');
            }
            if (collabMirrorContainer) {
                collabMirrorContainer.style.display = 'none';
                collabMirrorContainer.classList.remove('active');
            }
            if (collabAIContainer) {
                collabAIContainer.style.display = 'flex';
                collabAIContainer.classList.add('active');
            }

            // Toujours charger la liste des flows (même si collabAIAccess n'est pas encore défini)
            // Le check d'accès sera fait lors de l'analyse, pas lors de l'affichage de la liste
            console.log('[Collaboration] Loading AI flows list on tab click, total flows:', collaborationFlows.length);
            loadAIFlowsList();

            // Restaurer les résultats IA si disponibles
            const state = restoreCollaborationState();
            if (state && state.currentAIFlowId && collabAIResults[state.currentAIFlowId]) {
                const aiResults = collabAIResults[state.currentAIFlowId];
                setTimeout(() => {
                    renderAISuggestions(
                        aiResults.suggestions || [],
                        aiResults.tech_stack || {},
                        aiResults.summary || '',
                        aiResults.next_steps || []
                    );
                    // Restaurer aussi le flow courant pour les tests de payload
                    const flow = collaborationFlows.find(f => f.id === state.currentAIFlowId);
                    if (flow) {
                        collabCurrentAIFlow = flow;
                    }
                    // Mettre à jour l'indicateur visuel
                    updateSelectedAIFlow(state.currentAIFlowId);
                }, 100);
            }
        });
    }

    // Initialiser les boutons de mirroring
    const collabMirrorStartBtn = document.getElementById('collab-mirror-start-btn');
    const collabMirrorStopBtn = document.getElementById('collab-mirror-stop-btn');

    if (collabMirrorStartBtn) {
        collabMirrorStartBtn.addEventListener('click', startBrowserMirroring);
    }

    if (collabMirrorStopBtn) {
        collabMirrorStopBtn.addEventListener('click', stopBrowserMirroring);
    }

    // Initialiser l'éditeur Repeater
    initCollaborationRepeater();

    // Initialiser l'AI Assistant
    initAIAssistant();
}

// === AI Assistant Functions ===
let collabAIAccess = null;
let collabAIFlows = [];
let collabCurrentAIFlow = null; // Flow actuellement analysé, utilisé pour tester les payloads
let collabAIResults = {}; // {flowId: {suggestions, tech_stack, summary, next_steps}}

// Initialiser l'AI Assistant
function initAIAssistant() {
    // Ajouter les event listeners pour les boutons de configuration
    const createKeyBtn = document.getElementById('collab-ai-create-key-btn');
    const configureKeyBtn = document.getElementById('collab-ai-configure-key-btn');

    if (createKeyBtn) {
        createKeyBtn.addEventListener('click', createAIAPIKey);
    }

    if (configureKeyBtn) {
        configureKeyBtn.addEventListener('click', configureAIAPIKey);
    }

    // Vérifier l'accès quand une session est active
    if (currentSessionId) {
        checkAIAccess(currentSessionId);
    }
}

// Vérifier l'accès à l'IA
async function checkAIAccess(sessionId) {
    if (!sessionId || aiAccessUnavailable) return;

    const sessionPathId = (sessionId || '').toLowerCase();

    try {
        // API key non requise côté serveur pour l'IA ; on garde 'public' pour compat mais on ne bloque pas si absente
        const apiKey = localStorage.getItem('collab_api_key') || 'public';

        // Toujours afficher l'onglet AI pour permettre la configuration
        const aiTab = document.getElementById('collab-tab-ai');
        if (aiTab) {
            aiTab.style.display = 'flex';
        }

        const headers = {
            'Content-Type': 'application/json'
        };
        if (COLLAB_API_TOKEN) {
            headers['Authorization'] = `Bearer ${COLLAB_API_TOKEN}`;
        }
        // Ancien fallback pour compat, mais inutile si token présent
        if (apiKey && !headers['Authorization']) {
            headers['X-API-Key'] = apiKey;
        }

        const response = await fetch(`${COLLABORATION_SERVER_URL}/api/v1/sessions/${sessionPathId}/ai/check-access`, {
            headers
        });

        if (response.ok) {
            const data = await response.json();
            collabAIAccess = data || { has_access: true };
            if (collabAIAccess.has_access === undefined) collabAIAccess.has_access = true;
            window.collabAIAccess = collabAIAccess;

            // Afficher/masquer l'onglet AI
            const aiNoAccess = document.getElementById('collab-ai-no-access');
            const aiMain = document.getElementById('collab-ai-main');

            if (collabAIAccess.has_access) {
                if (aiNoAccess) aiNoAccess.style.display = 'none';
                if (aiMain) aiMain.style.display = 'flex';
                updateAIQuotaDisplay({
                    remaining: collabAIAccess.requests_remaining,
                    used: collabAIAccess.requests_used,
                    limit: collabAIAccess.requests_limit
                });
            } else {
                if (aiNoAccess) aiNoAccess.style.display = 'flex';
                if (aiMain) aiMain.style.display = 'none';
                updateAIQuotaDisplay({ remaining: '-' });
                updateAIConfigStatus();
            }
        } else {
            // En dev : ne pas bloquer l'IA, même si le check échoue ou 401
            console.warn('[AI] Access check failed or unauthorized, enabling dev fallback. Status:', response.status);
            collabAIAccess = { has_access: true };
            window.collabAIAccess = collabAIAccess;
            const aiNoAccess = document.getElementById('collab-ai-no-access');
            const aiMain = document.getElementById('collab-ai-main');
            if (aiNoAccess) aiNoAccess.style.display = 'none';
            if (aiMain) aiMain.style.display = 'flex';
            updateAIQuotaDisplay({ remaining: '-' });
            updateAIConfigStatus('AI access enabled (dev fallback)', response.status === 404 ? 'warning' : 'info');
        }
    } catch (error) {
        console.error('[AI] Error checking access:', error);
        // Afficher l'interface de configuration en cas d'erreur
        const aiTab = document.getElementById('collab-tab-ai');
        const aiNoAccess = document.getElementById('collab-ai-no-access');
        const aiMain = document.getElementById('collab-ai-main');
        if (aiTab) aiTab.style.display = 'flex';
        if (aiNoAccess) aiNoAccess.style.display = 'flex';
        if (aiMain) aiMain.style.display = 'none';
        updateAIConfigStatus(`Connection error: ${error.message}. Make sure the collaboration server is running on ${COLLABORATION_SERVER_URL}`);
    }
}

// Mettre à jour le statut de configuration
function updateAIConfigStatus(message) {
    const statusEl = document.getElementById('collab-ai-config-status');
    const infoEl = document.getElementById('collab-ai-config-info');

    if (!statusEl || !infoEl) return;

    const apiKey = localStorage.getItem('collab_api_key');
    const serverUrl = localStorage.getItem('collaboration_server_url') || 'https://proxy.kittysploit.com';

    let html = '';
    if (apiKey) {
        html += `<div style="margin-bottom: 8px;"><strong>API Key:</strong> <code style="background: #fff; padding: 2px 6px; border-radius: 3px; font-size: 11px;">${apiKey.substring(0, 20)}...</code></div>`;
    } else {
        html += `<div style="margin-bottom: 8px; color: #d32f2f;"><strong>API Key:</strong> Not configured</div>`;
    }
    html += `<div style="margin-bottom: 8px;"><strong>Server URL:</strong> <code style="background: #fff; padding: 2px 6px; border-radius: 3px; font-size: 11px;">${serverUrl}</code></div>`;

    if (message) {
        html += `<div style="margin-top: 8px; padding-top: 8px; border-top: 1px solid #e0e0e0; color: #d32f2f;">${escapeHtml(message)}</div>`;
    }

    infoEl.innerHTML = html;
    statusEl.style.display = 'block';
}

// Créer une nouvelle API key
async function createAIAPIKey() {
    try {
        const name = prompt('Enter a name for your API key:', 'My API Key');
        if (!name) return;

        const response = await fetch(`${COLLABORATION_SERVER_URL}/api/v1/api-keys`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                name: name,
                plan: 'free'
            })
        });

        if (response.ok) {
            const data = await response.json();
            // Sauvegarder la clé API
            localStorage.setItem('collab_api_key', data.key);

            alert(`API Key created successfully!\n\nYour API Key: ${data.key}\n\nThis key has been saved. Please refresh the page.`);

            // Recharger la page pour appliquer les changements
            location.reload();
        } else {
            const errorData = await response.json().catch(() => ({ detail: 'Unknown error' }));
            alert(`Failed to create API key: ${errorData.detail || response.statusText}`);
        }
    } catch (error) {
        alert(`Error creating API key: ${error.message}\n\nMake sure the collaboration server is running on ${COLLABORATION_SERVER_URL}`);
    }
}

// Configurer une API key existante
function configureAIAPIKey() {
    const currentKey = localStorage.getItem('collab_api_key') || '';
    const serverUrl = localStorage.getItem('collaboration_server_url') || 'https://proxy.kittysploit.com';

    const apiKey = prompt('Enter your API key (starts with kp_):', currentKey);
    if (apiKey === null) return; // User cancelled

    if (apiKey && !apiKey.startsWith('kp_')) {
        alert('Invalid API key format. API keys must start with "kp_"');
        return;
    }

    if (apiKey) {
        localStorage.setItem('collab_api_key', apiKey);
    } else {
        localStorage.removeItem('collab_api_key');
    }

    const newServerUrl = prompt('Enter collaboration server URL:', serverUrl);
    if (newServerUrl !== null) {
        if (newServerUrl) {
            localStorage.setItem('collaboration_server_url', newServerUrl);
        } else {
            localStorage.removeItem('collaboration_server_url');
        }
    }

    alert('Configuration saved! Refreshing page...');
    location.reload();
}

// Mettre à jour l'affichage du quota IA (used / remaining)
function updateAIQuotaDisplay({ used, remaining, limit } = {}) {
    const elemRemaining = document.getElementById('collab-ai-requests-remaining');
    const elemUsed = document.getElementById('collab-ai-requests-used');

    const safeRemaining = remaining !== undefined && remaining !== null ? remaining : '-';
    let safeUsed = used !== undefined && used !== null ? used : '-';

    if ((safeUsed === '-' || isNaN(safeUsed)) && limit !== undefined && limit !== null && safeRemaining !== '-' && !isNaN(safeRemaining)) {
        safeUsed = Math.max(0, Number(limit) - Number(safeRemaining));
    }

    if (elemRemaining) elemRemaining.textContent = safeRemaining;
    if (elemUsed) elemUsed.textContent = safeUsed;
}

// Historique IA (stocké localement)
const AI_HISTORY_KEY = 'collab_ai_history';
const AI_HISTORY_MAX = 100;
let aiHistoryCache = [];

function loadAIHistory() {
    try {
        const raw = localStorage.getItem(AI_HISTORY_KEY);
        const parsed = raw ? JSON.parse(raw) : [];
        aiHistoryCache = Array.isArray(parsed) ? parsed : [];
        return aiHistoryCache;
    } catch (e) {
        console.warn('[AI] Failed to load history', e);
        aiHistoryCache = [];
        return aiHistoryCache;
    }
}

function saveAIHistory(list) {
    try {
        localStorage.setItem(AI_HISTORY_KEY, JSON.stringify(list.slice(0, AI_HISTORY_MAX)));
    } catch (e) {
        console.warn('[AI] Failed to save history', e);
    }
}

function addAIHistoryEntry(entry) {
    const list = loadAIHistory();
    list.unshift({
        id: entry.id || `ai_${Date.now()}`,
        ts: entry.ts || Date.now(),
        url: entry.url || '',
        method: entry.method || '',
        status: entry.status || '',
        summary: entry.summary || '',
        suggestionsCount: entry.suggestionsCount || 0,
        suggestions: entry.suggestions ? [...entry.suggestions] : [],
        techStack: entry.techStack || {},
        nextSteps: entry.nextSteps ? [...entry.nextSteps] : [],
        flowId: entry.flowId || '',
        sessionId: entry.sessionId || '',
        used: entry.used,
        remaining: entry.remaining,
        limit: entry.limit
    });
    saveAIHistory(list);
}

function clearAIHistory() {
    saveAIHistory([]);
    renderAIHistory();
}

function renderAIHistory() {
    const list = loadAIHistory();
    const container = document.getElementById('ai-history-list');
    const empty = document.getElementById('ai-history-empty');
    const detail = document.getElementById('ai-history-detail');
    const wrapper = document.getElementById('ai-history-wrapper');
    if (!container || !empty || !detail || !wrapper) return;

    if (!list.length) {
        container.innerHTML = '';
        detail.innerHTML = '<div style="color:#666;">No details.</div>';
        empty.style.display = 'block';
        wrapper.style.display = 'none';
        return;
    }

    empty.style.display = 'none';
    wrapper.style.display = 'flex';

    container.innerHTML = list.map(item => {
        const date = new Date(item.ts);
        const time = date.toLocaleString();
        const quota = item.limit !== undefined && item.remaining !== undefined
            ? `Quota: ${item.limit - item.remaining}/${item.limit} used`
            : '';
        return `
            <button class="ai-history-item" data-id="${item.id}" style="text-align:left; border:1px solid var(--border-color); border-radius:8px; padding:10px; background:white; cursor:pointer;">
                <div style="font-size: 12px; color: #666; margin-bottom: 4px;">${time}</div>
                <div style="font-size: 13px; color: #333; margin-bottom: 4px;">
                    ${item.method ? `<strong>${item.method}</strong> ` : ''}${item.url || ''}${item.status ? ` • ${item.status}` : ''}
                </div>
                <div style="font-size: 12px; color: #777;">${quota || ''}</div>
            </button>
        `;
    }).join('');

    // Attach listeners
    container.querySelectorAll('.ai-history-item').forEach((btn, idx) => {
        btn.addEventListener('click', () => {
            container.querySelectorAll('.ai-history-item').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            const id = btn.getAttribute('data-id');
            renderAIHistoryDetails(id);
        });
        if (idx === 0) {
            btn.classList.add('active');
        }
    });

    // Auto select first
    if (list.length > 0) {
        renderAIHistoryDetails(list[0].id);
    }
}

function renderAIHistoryDetails(id) {
    const detail = document.getElementById('ai-history-detail');
    if (!detail) return;
    const item = (aiHistoryCache || []).find(e => e.id === id);
    if (!item) {
        detail.innerHTML = '<div style="color:#666; padding: 20px; text-align: center;">No details available.</div>';
        return;
    }
    const date = new Date(item.ts);
    const time = date.toLocaleString();
    const quota = item.limit !== undefined && item.remaining !== undefined
        ? `Quota: ${item.limit - item.remaining}/${item.limit} used`
        : '';

    // Format suggestions avec structure améliorée
    let suggestionsHtml = '';
    if (item.suggestions && item.suggestions.length) {
        suggestionsHtml = item.suggestions.map((s, idx) => {
            // Si c'est un objet structuré (comme dans l'image)
            if (typeof s === 'object' && s !== null && !Array.isArray(s)) {
                const technique = s.technique || s.title || 'Unknown technique';
                const description = s.description || s.desc || '';
                const confidence = s.confidence !== undefined ? (s.confidence * 100).toFixed(0) + '%' : '';
                const targetParam = s.target_param || '';
                const evidence = s.evidence || [];
                const payloads = s.payloads || [];

                const confidenceColor = s.confidence >= 0.8 ? '#4caf50' : s.confidence >= 0.6 ? '#ff9800' : '#f44336';

                return `
                    <div style="background: white; border: 1px solid var(--border-color); border-radius: 8px; padding: 16px; margin-bottom: 16px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
                        <div style="display: flex; align-items: start; justify-content: space-between; margin-bottom: 12px;">
                            <h4 style="margin: 0; font-size: 15px; font-weight: 600; color: #333; flex: 1;">${technique}</h4>
                            ${confidence ? `<span style="background: ${confidenceColor}; color: white; padding: 4px 10px; border-radius: 12px; font-size: 11px; font-weight: 600;">${confidence}</span>` : ''}
                        </div>
                        ${description ? `<p style="margin: 0 0 12px 0; color: #555; font-size: 13px; line-height: 1.5;">${description}</p>` : ''}
                        ${targetParam ? `<div style="margin-bottom: 8px;"><span style="font-size: 12px; color: #666; font-weight: 600;">Target Parameter:</span> <code style="background: #f5f5f5; padding: 2px 6px; border-radius: 4px; font-size: 11px; color: #333;">${targetParam}</code></div>` : ''}
                        ${evidence.length > 0 ? `
                            <div style="margin-bottom: 12px;">
                                <div style="font-size: 12px; color: #666; font-weight: 600; margin-bottom: 6px;">Evidence:</div>
                                <div style="display: flex; flex-wrap: wrap; gap: 6px;">
                                    ${evidence.map(e => `<span style="background: #e3f2fd; color: #1976d2; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-family: monospace;">${typeof e === 'string' ? e : JSON.stringify(e)}</span>`).join('')}
                                </div>
                            </div>
                        ` : ''}
                        ${payloads.length > 0 ? `
                            <div>
                                <div style="font-size: 12px; color: #666; font-weight: 600; margin-bottom: 6px;">Payloads:</div>
                                ${payloads.map((p, pIdx) => {
                    const payloadValue = typeof p === 'object' ? (p.value || p.payload || JSON.stringify(p)) : p;
                    const payloadDesc = typeof p === 'object' ? (p.description || '') : '';
                    return `
                                        <div style="background: #f9f9f9; border-left: 3px solid var(--primary-color); padding: 10px; margin-bottom: 8px; border-radius: 4px;">
                                            ${payloadDesc ? `<div style="font-size: 11px; color: #666; margin-bottom: 4px;">${payloadDesc}</div>` : ''}
                                            <code style="background: white; padding: 6px 8px; border-radius: 4px; font-size: 11px; color: #333; display: block; word-break: break-all; font-family: 'Fira Code', monospace;">${payloadValue}</code>
                                        </div>
                                    `;
                }).join('')}
                            </div>
                        ` : ''}
                    </div>
                `;
            } else {
                // Format simple pour les strings
                const text = typeof s === 'string' ? s : JSON.stringify(s);
                return `<div style="background: white; border: 1px solid var(--border-color); border-radius: 8px; padding: 12px; margin-bottom: 12px;"><div style="color: #333; font-size: 13px; line-height: 1.5;">${text}</div></div>`;
            }
        }).join('');
    } else {
        suggestionsHtml = '<div style="color:#888; font-size:13px; padding: 20px; text-align: center; background: white; border-radius: 8px;">No suggestions available.</div>';
    }

    // Format next steps
    const nextStepsHtml = (item.nextSteps && item.nextSteps.length)
        ? item.nextSteps.map(s => {
            const text = typeof s === 'string' ? s : (s.text || s.content || JSON.stringify(s));
            return `<li style="margin-bottom: 8px; padding-left: 8px; color: #333; font-size: 13px; line-height: 1.5;">${text}</li>`;
        }).join('')
        : '<div style="color:#888; font-size:13px; padding: 20px; text-align: center;">No next steps available.</div>';

    // Format tech stack
    const techHtml = (item.techStack && Object.keys(item.techStack).length)
        ? Object.entries(item.techStack).map(([k, v]) => {
            const values = Array.isArray(v) ? v : [v];
            return `
                <div style="margin-bottom: 12px; padding: 10px; background: white; border-radius: 6px; border: 1px solid var(--border-color);">
                    <div style="font-weight: 600; font-size: 12px; color: #666; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.5px;">${k}</div>
                    <div style="display: flex; flex-wrap: wrap; gap: 6px;">
                        ${values.map(val => `<span style="background: #f0f0f0; color: #333; padding: 4px 10px; border-radius: 12px; font-size: 11px;">${val}</span>`).join('')}
                    </div>
                </div>
            `;
        }).join('')
        : '<div style="color:#888; font-size:13px; padding: 20px; text-align: center; background: white; border-radius: 8px;">No tech stack information available.</div>';

    detail.innerHTML = `
        <div style="max-width: 900px; margin: 0 auto;">
            <!-- Header -->
            <div style="background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; border: 1px solid var(--border-color);">
                <div style="font-size: 12px; color: #666; margin-bottom: 8px;">${time}</div>
                <div style="font-size: 16px; color: #333; margin-bottom: 8px; font-weight: 600;">
                    ${item.method ? `<span style="background: ${getMethodColor(item.method)}; color: white; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; margin-right: 8px;">${item.method}</span>` : ''}
                    <span style="word-break: break-all;">${item.url || 'No URL'}</span>
                    ${item.status ? `<span style="margin-left: 8px; color: #666;">• ${item.status}</span>` : ''}
                </div>
                ${item.summary ? `<div style="font-size: 14px; color: #555; line-height: 1.6; margin-top: 12px; padding-top: 12px; border-top: 1px solid var(--border-color);">${item.summary}</div>` : ''}
                ${quota ? `<div style="font-size: 11px; color: #888; margin-top: 8px;">${quota}</div>` : ''}
            </div>
            
            <!-- Suggestions Section -->
            <div style="margin-bottom: 24px;">
                <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 16px;">
                    <span class="material-symbols-outlined" style="font-size: 20px; color: var(--primary-color);">lightbulb</span>
                    <h3 style="margin: 0; font-size: 16px; font-weight: 600; color: #333;">Suggestions</h3>
                </div>
                <div style="display: flex; flex-direction: column; gap: 0;">
                    ${suggestionsHtml}
                </div>
            </div>
            
            <!-- Next Steps Section -->
            ${item.nextSteps && item.nextSteps.length > 0 ? `
                <div style="margin-bottom: 24px;">
                    <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 12px;">
                        <span class="material-symbols-outlined" style="font-size: 20px; color: var(--primary-color);">arrow_forward</span>
                        <h3 style="margin: 0; font-size: 16px; font-weight: 600; color: #333;">Next Steps</h3>
                    </div>
                    <div style="background: white; border-radius: 8px; padding: 16px; border: 1px solid var(--border-color);">
                        <ul style="margin: 0; padding-left: 20px; color: #333;">
                            ${nextStepsHtml}
                        </ul>
                    </div>
                </div>
            ` : ''}
            
            <!-- Tech Stack Section -->
            ${item.techStack && Object.keys(item.techStack).length > 0 ? `
                <div style="margin-bottom: 24px;">
                    <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 12px;">
                        <span class="material-symbols-outlined" style="font-size: 20px; color: var(--primary-color);">memory</span>
                        <h3 style="margin: 0; font-size: 16px; font-weight: 600; color: #333;">Tech Stack</h3>
                    </div>
                    <div>
                        ${techHtml}
                    </div>
                </div>
            ` : ''}
        </div>
    `;
}

// Mettre à jour l'indicateur visuel du flow sélectionné
function updateSelectedAIFlow(flowId) {
    const flowsList = document.getElementById('collab-ai-flows-list');
    if (!flowsList) return;

    // Retirer le style "selected" de tous les flows
    const allFlowItems = flowsList.querySelectorAll('[data-flow-id]');
    allFlowItems.forEach(item => {
        item.style.background = 'white';
        item.style.borderLeft = 'none';
    });

    // Appliquer le style "selected" au flow actuel
    if (flowId) {
        const selectedItem = flowsList.querySelector(`[data-flow-id="${flowId}"]`);
        if (selectedItem) {
            selectedItem.style.background = '#e3f2fd';
            selectedItem.style.borderLeft = '3px solid #2196f3';
        }
    }
}

// Mettre à jour l'icône check pour un flow après analyse
function updateFlowCheckIcon(flowId) {
    const flowsList = document.getElementById('collab-ai-flows-list');
    if (!flowsList) return;

    const flowItem = flowsList.querySelector(`[data-flow-id="${flowId}"]`);
    if (!flowItem) return;

    const hasResults = collabAIResults[flowId] ? true : false;
    const checkIconContainer = flowItem.querySelector('.ai-flow-check-icon');

    if (hasResults) {
        // Ajouter l'icône check si elle n'existe pas
        if (!checkIconContainer) {
            const checkIcon = document.createElement('span');
            checkIcon.className = 'ai-flow-check-icon material-symbols-outlined';
            checkIcon.style.cssText = 'font-size: 14px; color: #4caf50;';
            checkIcon.setAttribute('title', 'Analysis results available');
            checkIcon.textContent = 'check_circle';

            // Insérer avant le bouton d'analyse
            const analyzeBtn = flowItem.querySelector('.ai-analyze-flow-btn');
            if (analyzeBtn && analyzeBtn.parentNode) {
                analyzeBtn.parentNode.insertBefore(checkIcon, analyzeBtn);
            }
        }
    } else {
        // Retirer l'icône check si elle existe
        if (checkIconContainer) {
            checkIconContainer.remove();
        }
    }
}

// Mettre à jour l'état du bouton d'analyse (spinner/disabled)
function updateAnalyzeButtonState(flowId, isLoading) {
    const flowsList = document.getElementById('collab-ai-flows-list');
    if (!flowsList) return;

    const flowItem = flowsList.querySelector(`[data-flow-id="${flowId}"]`);
    if (!flowItem) return;

    const analyzeBtn = flowItem.querySelector('.ai-analyze-flow-btn');
    if (!analyzeBtn) return;

    if (isLoading) {
        // Afficher le spinner et désactiver le bouton
        analyzeBtn.disabled = true;
        analyzeBtn.style.cursor = 'not-allowed';
        analyzeBtn.style.opacity = '0.6';
        const icon = analyzeBtn.querySelector('.material-symbols-outlined');
        if (icon) {
            icon.textContent = 'sync';
            icon.style.animation = 'spin 1s linear infinite';
        }
    } else {
        // Restaurer l'état normal
        analyzeBtn.disabled = false;
        analyzeBtn.style.cursor = 'pointer';
        analyzeBtn.style.opacity = '1';
        const icon = analyzeBtn.querySelector('.material-symbols-outlined');
        if (icon) {
            icon.textContent = 'auto_awesome';
            icon.style.animation = 'none';
        }
    }
}

// Charger la liste des flows pour l'IA
function loadAIFlowsList() {
    const flowsList = document.getElementById('collab-ai-flows-list');
    if (!flowsList) {
        console.log('[AI] collab-ai-flows-list element not found');
        return;
    }

    console.log('[AI] Loading AI flows list, collaborationFlows.length:', collaborationFlows ? collaborationFlows.length : 0);

    flowsList.innerHTML = '';

    // Utiliser les flows de collaboration existants
    if (collaborationFlows && collaborationFlows.length > 0) {
        console.log('[AI] Rendering', collaborationFlows.length, 'flows in AI Assistant');
        collaborationFlows.forEach(flow => {
            const flowItem = document.createElement('div');
            const hasResults = collabAIResults[flow.id] ? true : false;
            flowItem.setAttribute('data-flow-id', flow.id);
            flowItem.style.cssText = 'padding: 10px 12px; border-bottom: 1px solid #e8e8e8; cursor: pointer; transition: background 0.2s, border-left 0.2s; background: white; position: relative; border-left: 3px solid transparent;';
            flowItem.onmouseover = () => {
                if (!flowItem.classList.contains('selected')) {
                    flowItem.style.background = '#fafafa';
                }
            };
            flowItem.onmouseout = () => {
                if (!flowItem.classList.contains('selected')) {
                    flowItem.style.background = 'white';
                }
            };

            const method = flow.method || 'GET';
            const url = flow.url || '';
            const status = flow.response?.status_code || flow.status_code || '-';
            const methodColor = getMethodColor(method);

            flowItem.innerHTML = `
                <div style="display: flex; align-items: center; gap: 10px;">
                    <span style="font-weight: 600; color: ${methodColor}; min-width: 50px; font-size: 12px;">${method}</span>
                    <span style="flex: 1; font-size: 12px; color: #333; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(url)}">${escapeHtml(url)}</span>
                    <span style="font-size: 11px; color: #888; font-family: monospace; min-width: 40px; text-align: right;">${status}</span>
                    ${hasResults ? '<span class="ai-flow-check-icon material-symbols-outlined" style="font-size: 14px; color: #4caf50;" title="Analysis results available">check_circle</span>' : ''}
                    <button class="ai-analyze-flow-btn" data-flow-id="${flow.id}" title="Run new AI analysis" style="padding: 6px 8px; background: #f5f5f5; border: 1px solid #e0e0e0; border-radius: 4px; cursor: pointer; color: #666; transition: all 0.2s; display: flex; align-items: center; justify-content: center; flex-shrink: 0;" onmouseover="if (!this.disabled) { this.style.background='#e8e8e8'; this.style.borderColor='#d0d0d0'; this.style.color='#333'; }" onmouseout="if (!this.disabled) { this.style.background='#f5f5f5'; this.style.borderColor='#e0e0e0'; this.style.color='#666'; }">
                        <span class="material-symbols-outlined" style="font-size: 16px;">auto_awesome</span>
                    </button>
                </div>
            `;

            // Ajouter l'event listener pour le bouton
            const analyzeBtn = flowItem.querySelector('.ai-analyze-flow-btn');
            if (analyzeBtn) {
                analyzeBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    const flowId = analyzeBtn.getAttribute('data-flow-id');
                    const flowToAnalyze = collaborationFlows.find(f => f.id === flowId);
                    if (flowToAnalyze) {
                        // Mettre à jour l'indicateur visuel avant de lancer l'analyse
                        updateSelectedAIFlow(flowId);
                        analyzeFlowWithAI(flowToAnalyze);
                    }
                });
            }

            // Cliquer sur le flow → afficher les résultats existants (si disponibles)
            flowItem.addEventListener('click', (e) => {
                // Ne pas déclencher si on clique sur le bouton
                if (e.target.closest('.ai-analyze-flow-btn')) {
                    return;
                }

                const flowId = flow.id;

                // Mettre à jour l'indicateur visuel
                updateSelectedAIFlow(flowId);

                // Vérifier si des résultats existent pour ce flow
                if (collabAIResults[flowId]) {
                    const aiResults = collabAIResults[flowId];
                    // Afficher les résultats sauvegardés
                    renderAISuggestions(
                        aiResults.suggestions || [],
                        aiResults.tech_stack || {},
                        aiResults.summary || '',
                        aiResults.next_steps || []
                    );
                    // Restaurer le flow courant pour les tests de payload
                    collabCurrentAIFlow = flow;
                    // Mettre à jour l'état sauvegardé
                    saveCollaborationState();
                } else {
                    // Pas de résultats, afficher un message
                    const analysisContainer = document.getElementById('collab-ai-analysis');
                    if (analysisContainer) {
                        analysisContainer.innerHTML = `
                            <div style="text-align: center; color: #888; padding: 60px 20px;">
                                <span class="material-symbols-outlined" style="font-size: 40px; margin-bottom: 16px; display: block; color: #ccc;">info</span>
                                <p style="margin: 0; font-size: 14px; color: #666; margin-bottom: 16px;">No analysis results for this flow yet.</p>
                                <p style="margin: 0; font-size: 12px; color: #999;">Click the <span class="material-symbols-outlined" style="font-size: 14px; vertical-align: middle;">auto_awesome</span> button to analyze this flow.</p>
                            </div>
                        `;
                    }
                }
            });

            flowsList.appendChild(flowItem);
        });
    } else {
        flowsList.innerHTML = '<div style="padding: 40px 20px; text-align: center; color: #888; font-size: 13px;">No flows available</div>';
    }
}

// Analyser un flow avec l'IA
async function analyzeFlowWithAI(flow) {
    if (!currentSessionId) {
        alert('No active session');
        return;
    }

    // Dev: ne pas bloquer si has_access absent
    if (!collabAIAccess) {
        collabAIAccess = { has_access: true };
    }

    // Mémoriser le flow pour les tests de payload
    try {
        collabCurrentAIFlow = JSON.parse(JSON.stringify(flow || {}));
    } catch (e) {
        collabCurrentAIFlow = flow || null;
    }

    // Mettre à jour l'indicateur visuel du flow sélectionné
    if (flow && flow.id) {
        updateSelectedAIFlow(flow.id);
        // Afficher le spinner sur le bouton
        updateAnalyzeButtonState(flow.id, true);
    }

    const analysisContainer = document.getElementById('collab-ai-analysis');
    if (!analysisContainer) return;

    analysisContainer.innerHTML = '<div style="text-align: center; padding: 60px 20px;"><span class="material-symbols-outlined" style="font-size: 40px; animation: spin 1s linear infinite; display: inline-block; color: #888; margin-bottom: 16px;">sync</span><p style="margin: 0; color: #666; font-size: 14px;">Analyzing with AI...</p></div>';

    try {
        // Pour le moment, l'API key est optionnelle
        const apiKey = localStorage.getItem('collab_api_key');

        // Préparer les données du flow enrichies
        const requestHeaders = {};
        if (flow.request && flow.request.headers) {
            Object.entries(flow.request.headers).forEach(([key, value]) => {
                requestHeaders[key] = Array.isArray(value) ? value[0] : value;
            });
        }

        let body = '';
        if (flow.request && flow.request.content) {
            try {
                if (flow.request.content_bs64) {
                    body = atob(flow.request.content_bs64);
                } else if (typeof flow.request.content === 'string') {
                    body = flow.request.content;
                }
            } catch (e) {
                console.warn('[AI] Error decoding request body:', e);
            }
        }

        // Extraire les paramètres de la requête
        const queryParams = {};
        const bodyParams = {};
        try {
            const urlObj = new URL(flow.url || '');
            urlObj.searchParams.forEach((value, key) => {
                queryParams[key] = value;
            });
        } catch (e) {
            // URL invalide, ignorer
        }

        // Extraire les paramètres du body (JSON ou form-urlencoded)
        try {
            const contentType = requestHeaders['content-type'] || requestHeaders['Content-Type'] || '';
            if (contentType.includes('application/json') && body) {
                const jsonBody = JSON.parse(body);
                Object.assign(bodyParams, jsonBody);
            } else if (contentType.includes('application/x-www-form-urlencoded') && body) {
                const params = new URLSearchParams(body);
                params.forEach((value, key) => {
                    bodyParams[key] = value;
                });
            }
        } catch (e) {
            // Body non parsable, ignorer
        }

        // Préparer la réponse
        let response = '';
        let responseHeaders = {};
        let responseStatus = null;
        if (flow.response) {
            responseStatus = flow.response.status_code || flow.status_code;
            if (flow.response.headers) {
                Object.entries(flow.response.headers).forEach(([key, value]) => {
                    responseHeaders[key] = Array.isArray(value) ? value[0] : value;
                });
            }
            if (flow.response.content) {
                try {
                    if (flow.response.content_bs64) {
                        response = atob(flow.response.content_bs64);
                    } else if (typeof flow.response.content === 'string') {
                        response = flow.response.content;
                    }
                } catch (e) {
                    console.warn('[AI] Error decoding response body:', e);
                }
            }
        }

        // Technologies détectées
        const technologies = flow.technologies || {};

        // Endpoints découverts (principaux seulement pour éviter trop de données)
        const endpoints = {
            api_endpoints: (flow.endpoints?.api_endpoints || []).slice(0, 20),
            form_actions: (flow.endpoints?.form_actions || []).slice(0, 10),
            react_api_endpoints: (flow.endpoints?.react_api_endpoints || []).slice(0, 20),
            discovered_endpoints: (flow.discovered_endpoints || []).slice(0, 30)
        };

        const aiFetchHeaders = {
            'Content-Type': 'application/json'
        };
        if (COLLAB_API_TOKEN) {
            aiFetchHeaders['Authorization'] = `Bearer ${COLLAB_API_TOKEN}`;
        } else if (apiKey) {
            aiFetchHeaders['X-API-Key'] = apiKey;
        }

        const response_api = await fetch(`${COLLABORATION_SERVER_URL}/api/v1/sessions/${currentSessionId}/ai/analyze`, {
            method: 'POST',
            headers: aiFetchHeaders,
            body: JSON.stringify({
                method: flow.method || 'GET',
                url: flow.url || '',
                headers: requestHeaders,
                body: body,
                response: {
                    status: responseStatus,
                    headers: responseHeaders,
                    content: response
                },
                technologies: technologies,
                endpoints: endpoints,
                parameters: {
                    query: queryParams,
                    body: bodyParams
                }
            })
        });

        if (response_api.status === 402) {
            const data = await response_api.json().catch(() => ({}));
            updateAIQuotaDisplay({
                remaining: data.requests_remaining,
                used: data.requests_used,
                limit: data.requests_limit
            });
            alert(data.detail || 'AI Assistant requires a paid plan. Please upgrade your plan to access this feature.');
            analysisContainer.innerHTML = '<div style="text-align: center; padding: 60px 20px;"><span class="material-symbols-outlined" style="font-size: 40px; color: #ccc; margin-bottom: 16px; display: block;">lock</span><p style="margin: 0; color: #666; font-size: 14px;">Upgrade required</p></div>';
            // Restaurer l'état normal du bouton
            if (flow && flow.id) {
                updateAnalyzeButtonState(flow.id, false);
            }
            return;
        }

        if (response_api.status === 429) {
            const errorData = await response_api.json().catch(() => ({}));
            updateAIQuotaDisplay({
                remaining: errorData.requests_remaining,
                used: errorData.requests_used,
                limit: errorData.requests_limit
            });
            alert(errorData.detail || 'AI request limit exceeded. Please upgrade your plan.');
            analysisContainer.innerHTML = '<div style="text-align: center; padding: 60px 20px;"><span class="material-symbols-outlined" style="font-size: 40px; color: #d32f2f; margin-bottom: 16px; display: block;">error</span><p style="margin: 0; color: #666; font-size: 14px;">Request limit exceeded</p></div>';
            // Restaurer l'état normal du bouton
            if (flow && flow.id) {
                updateAnalyzeButtonState(flow.id, false);
            }
            return;
        }

        if (!response_api.ok) {
            const err = await response_api.json().catch(() => ({}));
            updateAIQuotaDisplay({
                remaining: err.requests_remaining,
                used: err.requests_used,
                limit: err.requests_limit
            });
            throw new Error(err.detail || `HTTP ${response_api.status}`);
        }

        const data = await response_api.json();

        // Mettre à jour le quota si présent dans la réponse
        updateAIQuotaDisplay({
            remaining: data.requests_remaining,
            used: data.requests_used,
            limit: data.requests_limit
        });
        // Sauvegarder dans l'historique local
        addAIHistoryEntry({
            url: flow.url,
            method: flow.method,
            status: responseStatus,
            summary: data.summary,
            suggestionsCount: (data.suggestions || []).length,
            suggestions: data.suggestions || [],
            techStack: data.tech_stack || {},
            nextSteps: data.next_steps || [],
            flowId: flow.id,
            sessionId: currentSessionId,
            used: data.requests_used,
            remaining: data.requests_remaining,
            limit: data.requests_limit
        });

        // Sauvegarder les résultats IA pour ce flow
        if (flow && flow.id) {
            collabAIResults[flow.id] = {
                suggestions: data.suggestions,
                tech_stack: data.tech_stack,
                summary: data.summary,
                next_steps: data.next_steps,
                timestamp: Date.now()
            };
            saveAIAssistantResults();

            // Partager les résultats IA avec tous les utilisateurs de la session via WebSocket
            if (collaborationWebSocket && collaborationWebSocket.readyState === WebSocket.OPEN) {
                try {
                    collaborationWebSocket.send(JSON.stringify({
                        type: 'ai_results',
                        flow_id: flow.id,
                        suggestions: data.suggestions,
                        tech_stack: data.tech_stack,
                        summary: data.summary,
                        next_steps: data.next_steps,
                        timestamp: Date.now()
                    }));
                    console.log('[Collaboration] Shared AI results for flow:', flow.id);
                } catch (error) {
                    console.error('[Collaboration] Error sharing AI results:', error);
                }
            }
        }

        renderAISuggestions(data.suggestions, data.tech_stack, data.summary, data.next_steps);
        updateAIQuotaDisplay({
            remaining: data.requests_remaining,
            used: data.requests_used,
            limit: data.requests_limit
        });
        collabAIAccess.requests_remaining = data.requests_remaining;

        // Restaurer l'état normal du bouton après succès
        if (flow && flow.id) {
            updateAnalyzeButtonState(flow.id, false);
        }

    } catch (error) {
        console.error('[AI] Error analyzing flow:', error);
        analysisContainer.innerHTML = '<div style="text-align: center; padding: 60px 20px;"><span class="material-symbols-outlined" style="font-size: 40px; color: #d32f2f; margin-bottom: 16px; display: block;">error</span><p style="margin: 0; color: #666; font-size: 14px;">Error analyzing flow. Please try again.</p></div>';
        // Restaurer l'état normal du bouton en cas d'erreur
        if (flow && flow.id) {
            updateAnalyzeButtonState(flow.id, false);
        }
    } finally {
        // Filet de sécurité : s'assurer que le bouton revient à l'état normal
        if (flow && flow.id) {
            updateAnalyzeButtonState(flow.id, false);
        }
    }
}

// Rendre les suggestions IA
function renderAISuggestions(suggestions, techStack = {}, summary = '', nextSteps = []) {
    const container = document.getElementById('collab-ai-analysis');
    if (!container) return;

    let html = '<div style="max-width: 1000px; margin: 0 auto; padding: 0 8px;">';

    // Afficher le résumé si disponible
    if (summary) {
        html += `
            <div style="margin-bottom: 20px; padding: 16px; background: #f8f9fa; border-left: 4px solid #333; border-radius: 4px;">
                <div style="font-weight: 600; margin-bottom: 8px; color: #333; font-size: 14px;">Summary</div>
                <div style="color: #666; font-size: 13px; line-height: 1.5;">${escapeHtml(summary)}</div>
            </div>
        `;
    }

    // Afficher la tech stack si disponible
    if (techStack && Object.keys(techStack).length > 0) {
        const techItems = [];
        Object.entries(techStack).forEach(([category, items]) => {
            if (Array.isArray(items) && items.length > 0) {
                techItems.push(`<strong>${category}:</strong> ${items.join(', ')}`);
            }
        });
        if (techItems.length > 0) {
            html += `
                <div style="margin-bottom: 20px; padding: 12px; background: #f0f4f8; border-radius: 4px; font-size: 12px; color: #555;">
                    <div style="font-weight: 600; margin-bottom: 6px; color: #333;">Technology Stack</div>
                    <div>${techItems.join(' | ')}</div>
                </div>
            `;
        }
    }

    if (!suggestions || suggestions.length === 0) {
        html += '<div style="text-align: center; padding: 40px; color: #888; font-size: 14px;">No vulnerability suggestions available</div>';
        html += '</div>';
        container.innerHTML = html;
        return;
    }

    suggestions.forEach((suggestion, index) => {
        const icon = getTechniqueIcon(suggestion.technique);
        const confidence = Math.round((suggestion.confidence || 0) * 100);

        // Déterminer la couleur de confiance de manière sobre
        let confidenceColor = '#888';
        let confidenceBg = '#f5f5f5';
        if (confidence >= 80) {
            confidenceColor = '#333';
            confidenceBg = '#e8e8e8';
        } else if (confidence >= 60) {
            confidenceColor = '#666';
            confidenceBg = '#f0f0f0';
        }

        html += `
            <div style="margin-bottom: 16px; border: 1px solid #e0e0e0; border-radius: 6px; overflow: hidden; background: white; box-shadow: 0 1px 2px rgba(0,0,0,0.02);">
                <div style="background: #fafafa; padding: 14px 16px; border-bottom: 1px solid #e8e8e8;">
                    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: ${suggestion.description ? '8px' : '0'};">
                        <span class="material-symbols-outlined" style="font-size: 18px; color: #555; font-weight: 400;">${icon}</span>
                        <h4 style="margin: 0; font-size: 14px; font-weight: 600; color: #333; flex: 1;">${escapeHtml(suggestion.technique)}</h4>
                        <span style="font-size: 11px; color: ${confidenceColor}; background: ${confidenceBg}; padding: 4px 10px; border-radius: 12px; font-weight: 500; white-space: nowrap;">${confidence}%</span>
                </div>
                    ${suggestion.description ? `<p style="margin: 0; font-size: 12px; color: #666; line-height: 1.5; padding-left: 28px;">${escapeHtml(suggestion.description)}</p>` : ''}
                </div>
                <div style="padding: 12px 16px;">
        `;

        if (suggestion.payloads && suggestion.payloads.length > 0) {
            suggestion.payloads.forEach((payload, payloadIndex) => {
                const payloadValue = payload.value || payload;
                const payloadDesc = payload.description || '';
                const encoded = payload.encoded || encodeURIComponent(payloadValue);

                html += `
                    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: ${payloadIndex < suggestion.payloads.length - 1 ? '10px' : '0'}; padding: 10px 12px; background: #fafafa; border: 1px solid #f0f0f0; border-radius: 4px; transition: background 0.2s;" onmouseover="this.style.background='#f5f5f5'; this.style.borderColor='#e8e8e8';" onmouseout="this.style.background='#fafafa'; this.style.borderColor='#f0f0f0';">
                        <code style="flex: 1; font-size: 12px; word-break: break-all; font-family: 'Fira Code', 'Consolas', monospace; color: #333; line-height: 1.4;">${escapeHtml(payloadValue)}</code>
                        ${payloadDesc ? `<span style="font-size: 11px; color: #888; min-width: 120px; text-align: right; flex-shrink: 0;">${escapeHtml(payloadDesc)}</span>` : ''}
                        <button class="ai-copy-btn btn btn-sm" data-payload="${escapeHtml(payloadValue).replace(/"/g, '&quot;')}" title="Copy" style="padding: 6px 8px; background: white; border: 1px solid #ddd; border-radius: 4px; cursor: pointer; color: #666; transition: all 0.2s; flex-shrink: 0;" onmouseover="this.style.background='#f5f5f5'; this.style.borderColor='#ccc'; this.style.color='#333';" onmouseout="this.style.background='white'; this.style.borderColor='#ddd'; this.style.color='#666';">
                            <span class="material-symbols-outlined" style="font-size: 16px;">content_copy</span>
                        </button>
                        <button class="ai-test-btn btn btn-sm btn-primary" data-payload="${escapeHtml(payloadValue).replace(/"/g, '&quot;')}" data-param="${suggestion.target_param || ''}" title="Test in Repeater" style="padding: 6px 8px; background: #333; color: white; border: none; border-radius: 4px; cursor: pointer; transition: all 0.2s; flex-shrink: 0;" onmouseover="this.style.background='#444';" onmouseout="this.style.background='#333';">
                            <span class="material-symbols-outlined" style="font-size: 16px;">play_arrow</span>
                        </button>
                    </div>
                `;
            });
        } else {
            html += '<div style="padding: 12px; color: #888; font-size: 12px; text-align: center;">No payloads available for this technique</div>';
        }

        html += `
                </div>
            </div>
        `;
    });

    // Afficher les next steps si disponibles
    if (nextSteps && nextSteps.length > 0) {
        html += `
            <div style="margin-top: 24px; padding: 16px; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 4px;">
                <div style="font-weight: 600; margin-bottom: 8px; color: #856404; font-size: 14px;">Next Steps</div>
                <ul style="margin: 0; padding-left: 20px; color: #856404; font-size: 13px; line-height: 1.6;">
                    ${nextSteps.map(step => `<li>${escapeHtml(step)}</li>`).join('')}
                </ul>
            </div>
        `;
    }

    html += '</div>';
    container.innerHTML = html;

    // Ajouter les event listeners pour les boutons
    container.querySelectorAll('.ai-copy-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            e.stopPropagation();
            const payload = btn.getAttribute('data-payload');
            if (!payload) {
                console.warn('[AI] No payload to copy');
                return;
            }

            try {
                const success = await copyToClipboard(payload);
                if (success) {
                    // Feedback visuel : changer l'icône temporairement
                    const icon = btn.querySelector('.material-symbols-outlined');
                    if (icon) {
                        const originalText = icon.textContent;
                        icon.textContent = 'check';
                        icon.style.color = '#4caf50';
                        setTimeout(() => {
                            icon.textContent = originalText;
                            icon.style.color = '';
                        }, 1000);
                    }
                    showToast('Copied to clipboard', 'success');
                } else {
                    showToast('Failed to copy', 'error');
                }
            } catch (error) {
                console.error('[AI] Error copying payload:', error);
                showToast('Failed to copy', 'error');
            }
        });
    });

    container.querySelectorAll('.ai-test-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const payload = btn.getAttribute('data-payload');
            const param = btn.getAttribute('data-param');
            testPayloadInRepeater(payload, param);
        });
    });
}

// Obtenir l'icône pour une technique
function getTechniqueIcon(technique) {
    const icons = {
        'SQL Injection': 'database',
        'XSS': 'code',
        'Command Injection': 'terminal',
        'IDOR': 'key',
        'Path Traversal': 'folder',
        'Generic Security Testing': 'security'
    };
    return icons[technique] || 'bug_report';
}

// Obtenir la couleur pour une méthode HTTP
function getMethodColor(method) {
    const colors = {
        'GET': '#61affe',
        'POST': '#49cc90',
        'PUT': '#fca130',
        'DELETE': '#f93e3e',
        'PATCH': '#50e3c2'
    };
    return colors[method] || '#666';
}

// Échapper HTML
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Note: La fonction copyToClipboard principale est définie plus haut (ligne 65)
// Cette fonction dupliquée a été supprimée pour éviter les conflits

// Tester un payload dans le Repeater local
function testPayloadInRepeater(payload, targetParam) {
    if (!payload) {
        console.warn('[AI] No payload provided.');
        return;
    }

    // Vérifier si le payload est une URL complète (commence par http:// ou https://)
    let isFullUrl = false;
    try {
        const urlTest = new URL(payload);
        isFullUrl = urlTest.protocol === 'http:' || urlTest.protocol === 'https:';
    } catch (e) {
        // Ce n'est pas une URL valide, on continue avec le traitement normal
    }

    // Si le payload est une URL complète, l'utiliser directement
    if (isFullUrl) {
        const method = 'GET'; // Par défaut GET pour les URLs complètes
        const headers = {};

        // Créer un nouvel onglet Repeater local avec l'URL directement
        const tabData = {
            method: method,
            url: payload,
            headers: JSON.stringify(headers, null, 2),
            body: ''
        };

        const tabId = createRepeaterTab(tabData);

        // Basculer vers la vue Repeater locale
        const replayNavItem = document.querySelector('[data-view="replay"]');
        if (replayNavItem) {
            replayNavItem.click();
        }

        console.log(`[AI] Full URL sent to local Repeater tab ${tabId}: ${payload}`);
        return;
    }

    // Sinon, utiliser le flow analysé comme base
    if (!collabCurrentAIFlow) {
        console.warn('[AI] No analyzed flow available to replay.');
        alert('Please analyze a flow first.');
        return;
    }

    // Cloner le flow courant pour éviter de muter l'état
    let flowToReplay;
    try {
        flowToReplay = JSON.parse(JSON.stringify(collabCurrentAIFlow));
    } catch (e) {
        flowToReplay = { ...(collabCurrentAIFlow || {}) };
    }

    // Préparer headers sous forme d'objet (pour le repeater local)
    const headersObj = {};
    if (flowToReplay.request && flowToReplay.request.headers) {
        Object.entries(flowToReplay.request.headers).forEach(([key, value]) => {
            if (Array.isArray(value)) {
                // Prendre la première valeur si c'est un tableau
                headersObj[key] = value[0] || '';
            } else {
                headersObj[key] = String(value);
            }
        });
    }

    // Décoder le body si présent
    let body = '';
    if (flowToReplay.request && flowToReplay.request.content) {
        try {
            if (flowToReplay.request.content_bs64) {
                body = atob(flowToReplay.request.content_bs64);
            } else if (typeof flowToReplay.request.content === 'string') {
                body = flowToReplay.request.content;
            } else if (flowToReplay.request.content instanceof ArrayBuffer) {
                body = new TextDecoder().decode(flowToReplay.request.content);
            }
        } catch (e) {
            console.warn('[AI] Error decoding request body:', e);
        }
    }

    // Déterminer la méthode en priorité à partir du flow analysé
    const inferredMethod = flowToReplay.method || flowToReplay.request?.method || (flowToReplay.request?.content ? 'POST' : 'GET');
    const method = inferredMethod.toString().toUpperCase();

    // Injection du payload : privilégier le body pour POST/PUT/PATCH avec JSON ou x-www-form-urlencoded
    // Sinon, fallback sur la query string.
    let url = flowToReplay.url || '';
    const contentTypeHeader = headersObj['content-type'] || headersObj['Content-Type'] || '';
    const ct = contentTypeHeader ? contentTypeHeader.toLowerCase() : '';
    const shouldUseBody = targetParam && ['POST', 'PUT', 'PATCH'].includes(method) && (ct.includes('application/json') || ct.includes('application/x-www-form-urlencoded'));

    if (shouldUseBody) {
        if (ct.includes('application/json')) {
            try {
                const jsonBody = body ? JSON.parse(body) : {};
                jsonBody[targetParam] = payload;
                body = JSON.stringify(jsonBody, null, 2);
            } catch (e) {
                body = payload;
            }
        } else if (ct.includes('application/x-www-form-urlencoded')) {
            const params = new URLSearchParams(body || '');
            params.set(targetParam, payload);
            body = params.toString();
        } else {
            body = payload;
        }
    } else if (targetParam) {
        try {
            const parsed = new URL(url);
            parsed.searchParams.set(targetParam, payload);
            url = parsed.toString();
        } catch (e) {
            const sep = url.includes('?') ? '&' : '?';
            url = `${url}${sep}${encodeURIComponent(targetParam)}=${encodeURIComponent(payload)}`;
        }
        if (!body) {
            body = payload;
        }
    } else if (!body) {
        body = payload;
    }

    // Ajouter un Content-Type par défaut si on envoie un body mais qu'il manque
    if (!headersObj['content-type'] && !headersObj['Content-Type'] && body && ['POST', 'PUT', 'PATCH'].includes(method)) {
        headersObj['Content-Type'] = 'application/x-www-form-urlencoded';
    }

    // Créer un nouvel onglet Repeater local pré-rempli
    const tabData = {
        method: method,
        url: url,
        headers: JSON.stringify(headersObj, null, 2),
        body: body
    };

    const tabId = createRepeaterTab(tabData);

    // Basculer vers la vue Repeater locale
    const replayNavItem = document.querySelector('[data-view="replay"]');
    if (replayNavItem) {
        replayNavItem.click();
    }

    console.log(`[AI] Payload sent to local Repeater tab ${tabId} (param: ${targetParam || 'none'})`);
}

// État de l'éditeur Repeater collaboratif
let collabRepeaterTabs = [];
let activeCollabRepeaterTabId = null;
let collabRepeaterDebounceTimer = null;
let collabRepeaterCursorDebounceTimer = null;
let collabRepeaterCursors = {}; // {user_id: {field, position, color, username}}

// Initialiser l'éditeur Repeater collaboratif
function initCollaborationRepeater() {
    // Créer le premier onglet si aucun n'existe
    if (collabRepeaterTabs.length === 0) {
        createCollabRepeaterTab();
    }

    // Rendre les onglets et le contenu
    renderCollabRepeaterTabs();
    renderCollabRepeaterContent();
}

// Créer un nouvel onglet dans le Repeater collaboratif
function createCollabRepeaterTab(tabData = null) {
    const tabId = `collab-repeater-tab-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const method = tabData?.method || 'GET';
    const url = tabData?.url || '';

    const tab = {
        id: tabId,
        method: method,
        url: url,
        headers: tabData?.headers || [],
        body: tabData?.body || '',
        response: tabData?.response || null,
        title: generateRepeaterTabTitle(method, url)
    };

    collabRepeaterTabs.push(tab);
    activeCollabRepeaterTabId = tabId;
    renderCollabRepeaterTabs();
    renderCollabRepeaterContent();

    // Synchroniser la création avec les autres utilisateurs
    if (collaborationWebSocket && collaborationWebSocket.readyState === WebSocket.OPEN) {
        try {
            collaborationWebSocket.send(JSON.stringify({
                type: 'repeater_tab_created',
                tab: tab
            }));
        } catch (error) {
            console.error('[Collaboration] Error sending tab creation:', error);
        }
    }

    return tabId;
}

// Rendre les onglets du Repeater collaboratif
function renderCollabRepeaterTabs() {
    const tabsContainer = document.getElementById('collab-repeater-tabs-container');
    if (!tabsContainer) return;

    tabsContainer.innerHTML = '';

    // Ajouter le bouton "New Tab" comme premier onglet
    const newTabEl = document.createElement('div');
    newTabEl.className = 'collab-repeater-tab-item collab-repeater-new-tab';
    newTabEl.style.cssText = 'display: flex; align-items: center; justify-content: center; gap: 4px; padding: 6px 12px; background: #e8e8e8; border-radius: 6px 6px 0 0; cursor: pointer; font-size: 12px; border: 1px solid #ddd; border-bottom: none; min-width: 60px; transition: background 0.2s;';
    newTabEl.innerHTML = '<span class="material-symbols-outlined" style="font-size: 16px;">add</span>';
    newTabEl.title = 'New tab';
    newTabEl.addEventListener('click', () => {
        createCollabRepeaterTab();
    });
    newTabEl.addEventListener('mouseenter', () => {
        newTabEl.style.background = '#d0d0d0';
    });
    newTabEl.addEventListener('mouseleave', () => {
        newTabEl.style.background = '#e8e8e8';
    });
    tabsContainer.appendChild(newTabEl);

    // Ajouter les onglets existants
    collabRepeaterTabs.forEach(tab => {
        const tabEl = document.createElement('div');
        tabEl.className = `collab-repeater-tab-item ${activeCollabRepeaterTabId === tab.id ? 'active' : ''}`;
        tabEl.style.cssText = 'display: flex; align-items: center; gap: 6px; padding: 6px 12px; background: #f5f5f5; border-radius: 6px 6px 0 0; cursor: pointer; font-size: 12px; border: 1px solid #ddd; border-bottom: none; position: relative;';

        if (activeCollabRepeaterTabId === tab.id) {
            tabEl.style.background = '#fff';
            tabEl.style.borderBottom = '2px solid #333';
        }

        // Mettre à jour le titre
        tab.title = generateRepeaterTabTitle(tab.method, tab.url);

        const titleEl = document.createElement('span');
        titleEl.textContent = tab.title;
        titleEl.style.cssText = 'flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 200px;';

        const methodBadge = document.createElement('span');
        methodBadge.textContent = tab.method;
        methodBadge.style.cssText = 'padding: 2px 6px; background: #333; color: white; border-radius: 3px; font-size: 10px; font-weight: 600;';

        const closeBtn = document.createElement('button');
        closeBtn.innerHTML = '<span class="material-symbols-outlined" style="font-size: 14px;">close</span>';
        closeBtn.style.cssText = 'background: transparent; border: none; cursor: pointer; padding: 2px; display: flex; align-items: center; opacity: 0.6; transition: opacity 0.2s;';
        closeBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            closeCollabRepeaterTab(tab.id);
        });
        closeBtn.addEventListener('mouseenter', () => {
            closeBtn.style.opacity = '1';
        });
        closeBtn.addEventListener('mouseleave', () => {
            closeBtn.style.opacity = '0.6';
        });

        tabEl.appendChild(titleEl);
        tabEl.appendChild(methodBadge);
        tabEl.appendChild(closeBtn);

        tabEl.addEventListener('click', () => {
            activateCollabRepeaterTab(tab.id);
        });

        tabsContainer.appendChild(tabEl);
    });
}

// Activer un onglet
function activateCollabRepeaterTab(tabId) {
    activeCollabRepeaterTabId = tabId;
    renderCollabRepeaterTabs();
    renderCollabRepeaterContent();

    // Synchroniser l'activation avec les autres utilisateurs
    if (collaborationWebSocket && collaborationWebSocket.readyState === WebSocket.OPEN) {
        try {
            collaborationWebSocket.send(JSON.stringify({
                type: 'repeater_tab_activated',
                tab_id: tabId
            }));
        } catch (error) {
            console.error('[Collaboration] Error sending tab activation:', error);
        }
    }
}

// Fermer un onglet
function closeCollabRepeaterTab(tabId) {
    const index = collabRepeaterTabs.findIndex(t => t.id === tabId);
    if (index === -1) return;

    collabRepeaterTabs.splice(index, 1);

    // Si l'onglet fermé était actif, activer un autre
    if (activeCollabRepeaterTabId === tabId) {
        if (collabRepeaterTabs.length > 0) {
            activeCollabRepeaterTabId = collabRepeaterTabs[collabRepeaterTabs.length - 1].id;
        } else {
            activeCollabRepeaterTabId = null;
            // Créer un nouvel onglet si plus aucun n'existe
            createCollabRepeaterTab();
        }
    }

    renderCollabRepeaterTabs();
    renderCollabRepeaterContent();

    // Notifier les autres utilisateurs
    if (collaborationWebSocket && collaborationWebSocket.readyState === WebSocket.OPEN) {
        collaborationWebSocket.send(JSON.stringify({
            type: 'repeater_tab_closed',
            tab_id: tabId
        }));
    }
}

// Rendre le contenu de l'onglet actif
function renderCollabRepeaterContent() {
    const contentContainer = document.getElementById('collab-repeater-tab-content-container');
    if (!contentContainer) return;

    const activeTab = collabRepeaterTabs.find(t => t.id === activeCollabRepeaterTabId);
    if (!activeTab) {
        contentContainer.innerHTML = '<div style="padding: 40px; text-align: center; color: #888;">No active tab</div>';
        return;
    }

    // Créer le contenu de l'onglet avec suivi du curseur
    contentContainer.innerHTML = `
        <div style="flex: 1; display: flex; flex-direction: column; overflow: hidden; gap: 0;">
            <div style="padding: 12px 16px; border-bottom: 1px solid var(--border-color); background: #fafafa;">
                <div style="display: flex; align-items: center; gap: 10px; width: 100%;">
                    <select id="collab-repeater-method-${activeTab.id}" style="height: 36px; padding: 8px 10px; border: 1px solid #ddd; border-radius: 6px; font-size: 13px; font-weight: 600; box-sizing: border-box;">
                        <option value="GET" ${activeTab.method === 'GET' ? 'selected' : ''}>GET</option>
                        <option value="POST" ${activeTab.method === 'POST' ? 'selected' : ''}>POST</option>
                        <option value="PUT" ${activeTab.method === 'PUT' ? 'selected' : ''}>PUT</option>
                        <option value="PATCH" ${activeTab.method === 'PATCH' ? 'selected' : ''}>PATCH</option>
                        <option value="DELETE" ${activeTab.method === 'DELETE' ? 'selected' : ''}>DELETE</option>
                        <option value="HEAD" ${activeTab.method === 'HEAD' ? 'selected' : ''}>HEAD</option>
                        <option value="OPTIONS" ${activeTab.method === 'OPTIONS' ? 'selected' : ''}>OPTIONS</option>
                    </select>
                    <div style="flex: 1; position: relative; min-width: 0;">
                        <input type="text" id="collab-repeater-url-${activeTab.id}" placeholder="https://example.com/api/endpoint" 
                               value="${escapeHtml(activeTab.url)}"
                               style="width: 100%; padding: 10px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 13px; font-family: 'Fira Code', monospace; box-sizing: border-box;">
                        <div id="collab-repeater-cursors-url-${activeTab.id}" style="position: absolute; top: 0; left: 0; right: 0; bottom: 0; pointer-events: none; z-index: 10;"></div>
                    </div>
                    <button id="collab-repeater-send-btn-${activeTab.id}" class="btn btn-primary" style="height: 38px; min-width: 72px; padding: 10px 16px; display: inline-flex; align-items: center; gap: 6px; border-radius: 6px;">
                        <span class="material-symbols-outlined" style="font-size: 18px;">send</span>
                        <span style="font-size: 13px;">Send</span>
                    </button>
                </div>
            </div>
            <div style="flex: 1; display: flex; flex-direction: column; overflow: hidden;">
                <!-- Headers Section (textarea, Burp-like) -->
                <div style="border-bottom: 1px solid var(--border-color); background: #fafafa; padding: 8px 16px;">
                    <div style="font-weight: 600; font-size: 13px; color: #333; margin-bottom: 8px;">Headers (one per line, e.g., Host: example.com)</div>
                </div>
                <div style="flex: 0 0 200px; position: relative; padding: 8px 16px; border-bottom: 1px solid var(--border-color); background: white;">
                    <textarea id="collab-repeater-headers-text-${activeTab.id}" placeholder="Header-Name: value&#10;Content-Type: application/json"
                              spellcheck="false" autocomplete="off" autocorrect="off" autocapitalize="none"
                              style="width: 100%; height: 180px; max-height: 240px; padding: 10px; border: 1px solid #ddd; border-radius: 6px; font-family: 'Fira Code', monospace; font-size: 12px; resize: vertical; line-height: 1.4; box-sizing: border-box; overflow: auto;"></textarea>
                    <div id="collab-repeater-cursors-headers-${activeTab.id}" style="position: absolute; top: 8px; left: 16px; right: 16px; bottom: 8px; pointer-events: none; z-index: 10;"></div>
                    </div>
                
                <!-- Body Section -->
                <div style="flex: 1; display: flex; flex-direction: column; overflow: hidden; background: white;">
                    <div style="border-bottom: 1px solid var(--border-color); background: #fafafa; padding: 8px 16px;">
                        <div style="font-weight: 600; font-size: 13px; color: #333;">Body</div>
                </div>
                    <div style="flex: 1; position: relative; padding: 12px 16px; min-height: 200px; overflow: hidden;">
                    <textarea id="collab-repeater-body-${activeTab.id}" placeholder="Request body..." 
                                  spellcheck="false" autocomplete="off" autocorrect="off" autocapitalize="none"
                                  style="width: 100%; height: 100%; min-height: 200px; padding: 12px; border: 1px solid #ddd; border-radius: 6px; font-family: 'Fira Code', monospace; font-size: 13px; resize: vertical; position: relative; z-index: 1; box-sizing: border-box; overflow: auto;"></textarea>
                    <div id="collab-repeater-cursors-body-${activeTab.id}" style="position: absolute; top: 0; left: 0; right: 0; bottom: 0; pointer-events: none; z-index: 10;"></div>
                    </div>
                    
                    <!-- Response Section -->
                    <div style="border-top: 1px solid var(--border-color); background: #fafafa; padding: 8px 16px; margin-top: 12px;">
                        <div style="font-weight: 600; font-size: 13px; color: #333;">Response</div>
                    </div>
                    <div style="flex: 1; position: relative; padding: 12px 16px; min-height: 120px; max-height: 240px; overflow: auto; background: white;">
                        <div id="collab-repeater-response-${activeTab.id}" style="font-family: 'Fira Code', monospace; font-size: 12px; color: #333; white-space: pre-wrap; word-break: break-word;">
                            ${activeTab.response ? `
                                <div style="margin-bottom: 8px; font-weight: 600; color: #333;">Status: ${activeTab.response.status_code || activeTab.response.status || '-'}</div>
                                <div style="color: #555;">${escapeHtml(activeTab.response.reason || '')}</div>
                            ` : '<div style="color: #888;">No response yet. Send a request to see the result.</div>'}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;

    // Initialiser les event listeners pour cet onglet
    initCollabRepeaterTabEvents(activeTab);
}

// Initialiser les event listeners pour un onglet
function initCollabRepeaterTabEvents(tab) {
    const methodEl = document.getElementById(`collab-repeater-method-${tab.id}`);
    const urlEl = document.getElementById(`collab-repeater-url-${tab.id}`);
    const headersTextEl = document.getElementById(`collab-repeater-headers-text-${tab.id}`);
    const bodyEl = document.getElementById(`collab-repeater-body-${tab.id}`);
    const sendBtn = document.getElementById(`collab-repeater-send-btn-${tab.id}`);

    // Synchronisation en temps réel des modifications
    if (methodEl) {
        methodEl.addEventListener('change', () => {
            tab.method = methodEl.value;
            tab.title = generateRepeaterTabTitle(tab.method, tab.url);
            renderCollabRepeaterTabs();
            syncCollabRepeaterTab(tab);
        });
    }

    if (urlEl) {
        urlEl.value = tab.url;
        urlEl.addEventListener('input', () => {
            tab.url = urlEl.value;
            tab.title = generateRepeaterTabTitle(tab.method, tab.url);
            renderCollabRepeaterTabs();
            syncCollabRepeaterTab(tab);
        });

        // Suivi du curseur pour l'URL
        setupCursorTracking(urlEl, `url-${tab.id}`, tab.id);
    }

    if (headersTextEl) {
        const headersToText = (headersArr = []) => headersArr.map(h => `${h.key || ''}: ${h.value || ''}`.trim()).join('\n');
        const parseHeadersText = (text = '') => {
            return text.split('\n').map(line => line.trim()).filter(Boolean).map(line => {
                const sepIndex = line.indexOf(':');
                if (sepIndex === -1) return { key: line, value: '' };
                return { key: line.slice(0, sepIndex).trim(), value: line.slice(sepIndex + 1).trim() };
            });
        };

        headersTextEl.value = headersToText(tab.headers || []);
        headersTextEl.addEventListener('input', () => {
            tab.headers = parseHeadersText(headersTextEl.value);
            syncCollabRepeaterTab(tab);
        });

        // Suivi du curseur pour les headers
        setupCursorTracking(headersTextEl, `headers-${tab.id}`, tab.id);
    }

    if (bodyEl) {
        bodyEl.value = tab.body;
        bodyEl.addEventListener('input', () => {
            tab.body = bodyEl.value;
            syncCollabRepeaterTab(tab);
        });

        // Suivi du curseur pour le body
        setupCursorTracking(bodyEl, `body-${tab.id}`, tab.id);
    }

    // Plus besoin du bouton "Add Header" - les headers sont directement éditables

    // Envoyer la requête
    if (sendBtn) {
        sendBtn.addEventListener('click', () => {
            sendCollabRepeaterRequest(tab.id);
        });
    }
}

// Configurer le suivi du curseur pour un élément
function setupCursorTracking(element, fieldId, tabId) {
    if (!element) return;

    // Détecter les changements de position du curseur
    element.addEventListener('click', () => {
        sendCursorPosition(fieldId, tabId, element);
    });

    element.addEventListener('keyup', () => {
        sendCursorPosition(fieldId, tabId, element);
    });

    element.addEventListener('selectionchange', () => {
        sendCursorPosition(fieldId, tabId, element);
    });

    // Détecter aussi avec setInterval pour capturer les mouvements
    let lastPosition = -1;
    setInterval(() => {
        if (document.activeElement === element) {
            const currentPosition = element.selectionStart || 0;
            if (currentPosition !== lastPosition) {
                lastPosition = currentPosition;
                sendCursorPosition(fieldId, tabId, element);
            }
        }
    }, 100);
}

// Envoyer la position du curseur
function sendCursorPosition(fieldId, tabId, element) {
    if (!collaborationWebSocket || collaborationWebSocket.readyState !== WebSocket.OPEN) return;
    if (document.activeElement !== element) return;

    const position = element.selectionStart || 0;
    const participant = collaborationParticipants.find(p => p.user_id === currentUserId);

    // Debounce pour éviter trop de messages
    if (collabRepeaterCursorDebounceTimer) {
        clearTimeout(collabRepeaterCursorDebounceTimer);
    }

    collabRepeaterCursorDebounceTimer = setTimeout(() => {
        try {
            collaborationWebSocket.send(JSON.stringify({
                type: 'repeater_cursor',
                tab_id: tabId,
                field: fieldId,
                position: position,
                user_id: currentUserId,
                username: currentUsername,
                color: participant?.color || getRandomColor()
            }));
        } catch (error) {
            console.error('[Collaboration] Error sending cursor position:', error);
        }
    }, 50); // 50ms de debounce pour le curseur
}

// Afficher le curseur d'un autre utilisateur
function displayRemoteCursor(userId, tabId, fieldId, position, color, username) {
    if (!tabId || !fieldId) return;

    // Stocker la position du curseur
    if (!collabRepeaterCursors[userId]) {
        collabRepeaterCursors[userId] = {};
    }
    collabRepeaterCursors[userId][tabId] = {
        field: fieldId,
        position: position,
        color: color,
        username: username
    };

    // Afficher seulement si c'est l'onglet actif
    if (activeCollabRepeaterTabId !== tabId) return;

    const cursorContainer = document.getElementById(`collab-repeater-cursors-${fieldId}`);
    if (!cursorContainer) return;

    // Supprimer l'ancien curseur de cet utilisateur
    const oldCursor = cursorContainer.querySelector(`[data-user-id="${userId}"]`);
    if (oldCursor) oldCursor.remove();

    // Trouver l'élément correspondant
    let element = null;
    if (fieldId.startsWith('url-')) {
        element = document.getElementById(`collab-repeater-url-${tabId}`);
    } else if (fieldId.startsWith('body-')) {
        element = document.getElementById(`collab-repeater-body-${tabId}`);
    }

    if (!element) return;

    // Calculer la position du curseur de manière plus précise
    const elementRect = element.getBoundingClientRect();
    const containerRect = cursorContainer.getBoundingClientRect();

    // Pour les input/textarea, utiliser une méthode plus simple
    let cursorX = 0;
    let cursorY = 0;

    if (element.tagName === 'INPUT' || element.tagName === 'TEXTAREA') {
        // Créer un élément temporaire pour mesurer le texte
        const textBeforeCursor = element.value.substring(0, position);
        const style = window.getComputedStyle(element);

        const tempDiv = document.createElement('div');
        tempDiv.style.cssText = `
            position: absolute;
            visibility: hidden;
            white-space: pre-wrap;
            font-family: ${style.fontFamily};
            font-size: ${style.fontSize};
            font-weight: ${style.fontWeight};
            padding: ${style.padding};
            border: ${style.border};
            box-sizing: ${style.boxSizing};
            width: ${element.offsetWidth}px;
            word-wrap: break-word;
        `;
        tempDiv.textContent = textBeforeCursor;
        document.body.appendChild(tempDiv);

        const tempRect = tempDiv.getBoundingClientRect();
        cursorX = tempRect.width;

        // Pour les textarea multilignes, calculer la ligne
        if (element.tagName === 'TEXTAREA') {
            const lines = textBeforeCursor.split('\n');
            const lineHeight = parseInt(style.lineHeight) || parseInt(style.fontSize) * 1.2;
            cursorY = (lines.length - 1) * lineHeight;
        }

        document.body.removeChild(tempDiv);
    }

    // Créer l'indicateur de curseur
    const cursorEl = document.createElement('div');
    cursorEl.dataset.userId = userId;
    cursorEl.style.cssText = `
        position: absolute;
        left: ${cursorX}px;
        top: ${cursorY}px;
        width: 2px;
        height: ${element.tagName === 'TEXTAREA' ? '20px' : '18px'};
        background: ${color};
        z-index: 100;
        pointer-events: none;
        box-shadow: 0 0 4px ${color};
        animation: blink 1s infinite;
    `;

    // Ajouter un label avec le nom d'utilisateur
    const labelEl = document.createElement('div');
    labelEl.textContent = username;
    labelEl.style.cssText = `
        position: absolute;
        left: ${cursorX + 4}px;
        top: ${cursorY - 18}px;
        background: ${color};
        color: white;
        padding: 2px 6px;
        border-radius: 4px;
        font-size: 11px;
        white-space: nowrap;
        pointer-events: none;
        z-index: 101;
        opacity: 0.9;
    `;

    cursorContainer.appendChild(cursorEl);
    cursorContainer.appendChild(labelEl);

    // Supprimer le label après 2 secondes
    setTimeout(() => {
        if (labelEl.parentNode) {
            labelEl.style.opacity = '0.5';
        }
    }, 2000);

    // Supprimer le curseur si l'utilisateur n'est plus actif (après 5 secondes sans mise à jour)
    setTimeout(() => {
        if (cursorEl.parentNode) {
            cursorEl.remove();
            if (labelEl.parentNode) labelEl.remove();
        }
    }, 5000);
}

// Mettre à jour un onglet depuis une synchronisation (sans déclencher de nouveau sync)
function updateCollabRepeaterTabFromSync(syncedTab) {
    // Trouver ou créer l'onglet
    let tab = collabRepeaterTabs.find(t => t.id === syncedTab.id);
    if (!tab) {
        // Créer un nouvel onglet si il n'existe pas (peut arriver si on rejoint une session)
        collabRepeaterTabs.push(syncedTab);
        tab = syncedTab;
        renderCollabRepeaterTabs();
    } else {
        // Mettre à jour l'onglet existant sans perdre les références
        tab.method = syncedTab.method || tab.method;
        tab.url = syncedTab.url || tab.url;
        tab.headers = syncedTab.headers || tab.headers;
        tab.body = syncedTab.body !== undefined ? syncedTab.body : tab.body;
        tab.title = generateRepeaterTabTitle(tab.method, tab.url);
    }

    // Si c'est l'onglet actif, mettre à jour l'UI
    if (activeCollabRepeaterTabId === tab.id) {
        const methodEl = document.getElementById(`collab-repeater-method-${tab.id}`);
        const urlEl = document.getElementById(`collab-repeater-url-${tab.id}`);
        const bodyEl = document.getElementById(`collab-repeater-body-${tab.id}`);

        if (methodEl && methodEl.value !== tab.method) {
            methodEl.value = tab.method;
        }

        if (urlEl && urlEl.value !== tab.url) {
            urlEl.value = tab.url;
        }

        if (bodyEl && bodyEl.value !== tab.body) {
            bodyEl.value = tab.body;
        }

        renderCollabRepeaterHeaders(tab.id);
        renderCollabRepeaterTabs();
    } else {
        // Même si ce n'est pas l'onglet actif, mettre à jour le titre dans la liste
        renderCollabRepeaterTabs();
    }
}

// Synchroniser un onglet avec les autres utilisateurs
function syncCollabRepeaterTab(tab) {
    if (!collaborationWebSocket || collaborationWebSocket.readyState !== WebSocket.OPEN) return;

    if (collabRepeaterDebounceTimer) {
        clearTimeout(collabRepeaterDebounceTimer);
    }

    collabRepeaterDebounceTimer = setTimeout(() => {
        try {
            collaborationWebSocket.send(JSON.stringify({
                type: 'repeater_tab_update',
                tab: tab
            }));
        } catch (error) {
            console.error('[Collaboration] Error syncing repeater tab:', error);
        }
    }, 300);
}

// Ajouter un header dans un onglet
function addCollabRepeaterHeader(tabId, key = '', value = '', isNewRow = false) {
    const tab = collabRepeaterTabs.find(t => t.id === tabId);
    if (!tab) return;

    const headersContainer = document.getElementById(`collab-repeater-headers-container-${tabId}`);
    if (!headersContainer) return;

    const index = tab.headers.length;
    if (!isNewRow && (key || value)) {
        tab.headers.push({ key, value });
    }

    const headerRow = document.createElement('div');
    headerRow.className = 'kv-editor-row';
    headerRow.dataset.isNewRow = isNewRow ? 'true' : 'false';
    headerRow.style.cssText = 'display: flex; gap: 8px; align-items: center; position: relative;';
    headerRow.innerHTML = `
        <input type="text" class="kv-key" placeholder="Header name" value="${escapeHtml(key)}" 
               style="flex: 0 0 30%; padding: 6px 8px; border: 1px solid #ddd; border-radius: 3px; font-size: 12px; font-family: monospace;"
               data-tab-id="${tabId}" data-index="${index}" data-field="key">
        <input type="text" class="kv-value" placeholder="Header value" value="${escapeHtml(value)}" 
               style="flex: 1; padding: 6px 8px; border: 1px solid #ddd; border-radius: 3px; font-size: 12px; font-family: monospace;"
               data-tab-id="${tabId}" data-index="${index}" data-field="value">
        <button class="kv-remove" style="flex: 0 0 auto; padding: 6px 8px; border: 1px solid #ddd; border-radius: 3px; background: #fff; cursor: pointer; color: #666; transition: all 0.2s;" 
                onmouseover="this.style.background='#f5f5f5'; this.style.borderColor='#ccc';" 
                onmouseout="this.style.background='#fff'; this.style.borderColor='#ddd';">
            <span class="material-symbols-outlined" style="font-size: 16px;">close</span>
        </button>
    `;

    // Event listeners pour la synchronisation
    const keyInput = headerRow.querySelector('input[data-field="key"]');
    const valueInput = headerRow.querySelector('input[data-field="value"]');
    const removeBtn = headerRow.querySelector('.kv-remove');

    // Fonction pour mettre à jour le header dans le tableau
    const updateHeader = () => {
        const isCurrentlyNewRow = headerRow.dataset.isNewRow === 'true';
        const hasContent = keyInput.value.trim() || valueInput.value.trim();

        // Si c'est une nouvelle ligne et qu'elle a du contenu, l'ajouter au tableau
        if (isCurrentlyNewRow && hasContent) {
            tab.headers.push({ key: keyInput.value, value: valueInput.value });
            headerRow.dataset.isNewRow = 'false';
            // Mettre à jour l'index pour cette ligne
            keyInput.dataset.index = (tab.headers.length - 1).toString();
            valueInput.dataset.index = (tab.headers.length - 1).toString();
        } else if (!isCurrentlyNewRow) {
            // Mettre à jour le header existant
            const currentIndex = parseInt(keyInput.dataset.index) || index;
            if (currentIndex < tab.headers.length) {
                tab.headers[currentIndex].key = keyInput.value;
                tab.headers[currentIndex].value = valueInput.value;
            }
        }
        syncCollabRepeaterTab(tab);
    };

    keyInput.addEventListener('input', updateHeader);
    valueInput.addEventListener('input', updateHeader);

    // Ajouter automatiquement une nouvelle ligne vide quand on tape dans la dernière ligne
    const addNewRowIfNeeded = () => {
        const existingRows = headersContainer.querySelectorAll('.kv-editor-row');
        const isLastRow = existingRows[existingRows.length - 1] === headerRow;
        const hasContent = keyInput.value.trim() || valueInput.value.trim();
        const isCurrentlyNewRow = headerRow.dataset.isNewRow === 'true';

        if (isLastRow && hasContent && !isCurrentlyNewRow) {
            // Vérifier qu'il n'y a pas déjà une ligne vide après
            const lastRow = existingRows[existingRows.length - 1];
            const lastKeyInput = lastRow?.querySelector('.kv-key');
            const lastValueInput = lastRow?.querySelector('.kv-value');
            const isEmpty = !lastKeyInput?.value.trim() && !lastValueInput?.value.trim();

            if (isEmpty) {
                // Il y a déjà une ligne vide, ne rien faire
                return;
            }

            // Ajouter une nouvelle ligne vide
            setTimeout(() => {
                addCollabRepeaterHeader(tabId, '', '', true);
            }, 10);
        }
    };

    keyInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === 'Tab') {
            e.preventDefault();
            valueInput.focus();
        }
    });

    valueInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === 'Tab') {
            e.preventDefault();
            addNewRowIfNeeded();
            // Focus sur la prochaine ligne ou créer une nouvelle
            const nextRow = headerRow.nextElementSibling;
            if (nextRow) {
                const nextKeyInput = nextRow.querySelector('.kv-key');
                if (nextKeyInput) nextKeyInput.focus();
            } else {
                addCollabRepeaterHeader(tabId, '', '', true);
                setTimeout(() => {
                    const newRow = headersContainer.querySelector('.kv-editor-row:last-child');
                    if (newRow) {
                        const newKeyInput = newRow.querySelector('.kv-key');
                        if (newKeyInput) newKeyInput.focus();
                    }
                }, 10);
            }
        }
    });

    keyInput.addEventListener('input', addNewRowIfNeeded);
    valueInput.addEventListener('input', addNewRowIfNeeded);

    // Suivi du curseur pour les headers
    setupCursorTracking(keyInput, `header-key-${tabId}-${index}`, tabId);
    setupCursorTracking(valueInput, `header-value-${tabId}-${index}`, tabId);

    removeBtn.addEventListener('click', () => {
        if (index < tab.headers.length) {
            tab.headers.splice(index, 1);
        }
        renderCollabRepeaterHeaders(tabId);
        syncCollabRepeaterTab(tab);
    });

    headersContainer.appendChild(headerRow);
}

// Rendre tous les headers d'un onglet
function renderCollabRepeaterHeaders(tabId) {
    const tab = collabRepeaterTabs.find(t => t.id === tabId);
    if (!tab) return;

    const headersContainer = document.getElementById(`collab-repeater-headers-container-${tabId}`);
    if (!headersContainer) return;

    headersContainer.innerHTML = '';

    // Rendre les headers existants
    tab.headers.forEach((header, index) => {
        addCollabRepeaterHeader(tabId, header.key, header.value, false);
    });

    // Toujours ajouter une ligne vide à la fin pour permettre l'édition directe
    addCollabRepeaterHeader(tabId, '', '', true);
}

// Charger un flow dans un nouvel onglet du Repeater collaboratif
function loadFlowIntoRepeater(flow) {
    if (!flow) return;

    // Préparer les données du flow
    const headers = [];
    if (flow.request && flow.request.headers) {
        Object.entries(flow.request.headers).forEach(([key, value]) => {
            if (Array.isArray(value)) {
                value.forEach(v => headers.push({ key, value: v }));
            } else {
                headers.push({ key, value: String(value) });
            }
        });
    }

    let body = '';
    if (flow.request && flow.request.content) {
        try {
            if (flow.request.content_bs64) {
                body = atob(flow.request.content_bs64);
            } else if (typeof flow.request.content === 'string') {
                body = flow.request.content;
            } else if (Buffer.isBuffer(flow.request.content)) {
                body = flow.request.content.toString('utf-8');
            }
        } catch (e) {
            console.warn('[Collaboration] Error decoding request body:', e);
        }
    }

    // Créer un nouvel onglet avec les données du flow
    const tabData = {
        method: flow.method || 'GET',
        url: flow.url || '',
        headers: headers,
        body: body
    };

    const tabId = createCollabRepeaterTab(tabData);

    // Basculer vers l'onglet Repeater
    const collabTabRepeater = document.getElementById('collab-tab-repeater');
    if (collabTabRepeater) {
        collabTabRepeater.click();
    }
}

// Envoyer la requête modifiée d'un onglet
async function sendCollabRepeaterRequest(tabId) {
    const tab = collabRepeaterTabs.find(t => t.id === tabId);
    if (!tab || !tab.url) {
        alert('Please enter a URL');
        return;
    }

    // Désactiver le bouton pendant l'envoi pour éviter les doubles clics
    const sendBtn = document.getElementById(`collab-repeater-send-btn-${tabId}`);
    if (sendBtn) {
        sendBtn.disabled = true;
        sendBtn.style.opacity = '0.7';
        sendBtn.style.cursor = 'not-allowed';
    }

    try {
        // Préparer les headers sous forme d'objet
        const headersObj = (tab.headers || []).reduce((acc, h) => {
            if (h.key && h.value) {
                acc[h.key] = h.value;
            }
            return acc;
        }, {});

        const bodyBs64 = tab.body ? btoa(tab.body) : '';

        const response = await fetch('/api/send_custom', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                method: tab.method,
                url: tab.url,
                headers: headersObj,
                body_bs64: bodyBs64 || undefined
            })
        });

        if (response.ok) {
            const result = await response.json();
            console.log('[Collaboration] Request sent successfully:', result);

            // Stocker la réponse dans l'onglet et re-render
            tab.response = result;
            renderCollabRepeaterContent();
            syncCollabRepeaterTab(tab);

            // Notifier les autres utilisateurs
            if (collaborationWebSocket && collaborationWebSocket.readyState === WebSocket.OPEN) {
                collaborationWebSocket.send(JSON.stringify({
                    type: 'repeater_sent',
                    tab_id: tabId,
                    request: {
                        method: tab.method,
                        url: tab.url,
                        headers: tab.headers,
                        body: tab.body
                    },
                    result: result
                }));
            }
        } else {
            const error = await response.json();
            alert(`Error: ${error.detail || 'Failed to send request'}`);
        }
    } catch (error) {
        console.error('[Collaboration] Error sending request:', error);
        alert('Error sending request: ' + error.message);
    } finally {
        if (sendBtn) {
            sendBtn.disabled = false;
            sendBtn.style.opacity = '1';
            sendBtn.style.cursor = 'pointer';
        }
    }
}

// État des sidebars (réduites ou non)
let participantsSidebarCollapsed = false;
let chatSidebarCollapsed = false;

// Fonction pour toggle la sidebar Participants
function toggleParticipantsSidebar() {
    participantsSidebarCollapsed = !participantsSidebarCollapsed;
    const sidebar = document.getElementById('collab-participants-sidebar');
    const toggleBtn = document.getElementById('collab-toggle-participants'); // peut être absent
    const toggleTop = document.getElementById('collab-toggle-participants-top');
    const grid = document.getElementById('collab-main-grid');
    const mainContent = grid ? grid.children[1] : null; // La colonne du milieu (index 1)

    if (sidebar && grid) {
        if (participantsSidebarCollapsed) {
            // Réduire la sidebar - utiliser width: 0 au lieu de display: none pour garder dans la grille
            sidebar.style.width = '0';
            sidebar.style.minWidth = '0';
            sidebar.style.overflow = 'hidden';
            sidebar.style.padding = '0';
            sidebar.style.border = 'none';
            // Ajuster la grille selon l'état du chat
            if (chatSidebarCollapsed) {
                grid.style.gridTemplateColumns = '0 1fr 0';
            } else {
                grid.style.gridTemplateColumns = '0 1fr 320px';
            }
            // Changer la flèche et repositionner le bouton pour qu'il soit visible à gauche
            if (toggleBtn) {
                const icon = toggleBtn.querySelector('.material-symbols-outlined');
                if (icon) icon.textContent = 'chevron_right';
            }
            if (toggleTop) {
                const iconTop = toggleTop.querySelector('.material-symbols-outlined');
                if (iconTop) iconTop.textContent = 'chevron_right';
            }
        } else {
            // Agrandir la sidebar
            sidebar.style.width = '';
            sidebar.style.minWidth = '';
            sidebar.style.overflow = '';
            sidebar.style.padding = '';
            sidebar.style.border = '';
            sidebar.style.borderRight = '1px solid var(--border-color)';
            // Ajuster la grille selon l'état du chat
            if (chatSidebarCollapsed) {
                grid.style.gridTemplateColumns = '250px 1fr 0';
            } else {
                grid.style.gridTemplateColumns = '250px 1fr 320px';
            }
            // Changer la flèche et remettre le bouton dans le header à droite
            if (toggleBtn) {
                const icon = toggleBtn.querySelector('.material-symbols-outlined');
                if (icon) icon.textContent = 'chevron_left';
            }
            if (toggleTop) {
                const iconTop = toggleTop.querySelector('.material-symbols-outlined');
                if (iconTop) iconTop.textContent = 'chevron_left';
            }
        }

        // S'assurer que le contenu principal ne déborde pas
        if (mainContent) {
            mainContent.style.minWidth = '0';
            mainContent.style.overflow = 'hidden';
        }
    }
}

// Fonction pour toggle la sidebar Chat
function toggleChatSidebar() {
    chatSidebarCollapsed = !chatSidebarCollapsed;
    const sidebar = document.getElementById('collab-chat-sidebar');
    const toggleTop = document.getElementById('collab-toggle-chat-top');
    const grid = document.getElementById('collab-main-grid');
    const mainContent = grid ? grid.children[1] : null; // La colonne du milieu (index 1)

    if (sidebar && grid) {
        if (chatSidebarCollapsed) {
            // Réduire la sidebar - utiliser width: 0 au lieu de display: none pour garder dans la grille
            sidebar.style.width = '0';
            sidebar.style.minWidth = '0';
            sidebar.style.overflow = 'hidden';
            sidebar.style.padding = '0';
            sidebar.style.border = 'none';
            // Ajuster la grille selon l'état des participants
            if (participantsSidebarCollapsed) {
                grid.style.gridTemplateColumns = '0 1fr 0';
            } else {
                grid.style.gridTemplateColumns = '250px 1fr 0';
            }

            // Mettre à jour le bouton de toggle dans le header
            if (toggleTop) {
                const iconTop = toggleTop.querySelector('.material-symbols-outlined');
                if (iconTop) iconTop.textContent = 'chevron_left';
            }
        } else {
            // Agrandir la sidebar
            sidebar.style.width = '';
            sidebar.style.minWidth = '';
            sidebar.style.overflow = '';
            sidebar.style.padding = '';
            sidebar.style.border = '';
            sidebar.style.borderLeft = '1px solid var(--border-color)';
            // Ajuster la grille selon l'état des participants
            if (participantsSidebarCollapsed) {
                grid.style.gridTemplateColumns = '0 1fr 320px';
            } else {
                grid.style.gridTemplateColumns = '250px 1fr 320px';
            }

            // Mettre à jour le bouton de toggle dans le header
            if (toggleTop) {
                const iconTop = toggleTop.querySelector('.material-symbols-outlined');
                if (iconTop) iconTop.textContent = 'chevron_right';
            }
        }

        // S'assurer que le contenu principal ne déborde pas
        if (mainContent) {
            mainContent.style.minWidth = '0';
            mainContent.style.overflow = 'hidden';
        }
    }
}

// Initialiser les event listeners pour les boutons de toggle
function initCollaborationSidebars() {
    const toggleParticipants = document.getElementById('collab-toggle-participants');
    const toggleParticipantsTop = document.getElementById('collab-toggle-participants-top');
    const toggleChatTop = document.getElementById('collab-toggle-chat-top');
    const toggleChatFloating = document.getElementById('collab-toggle-chat-floating');

    // Event listeners pour les participants
    if (toggleParticipants) {
        toggleParticipants.addEventListener('click', (e) => {
            e.stopPropagation();
            toggleParticipantsSidebar();
        });
    }

    if (toggleParticipantsTop) {
        toggleParticipantsTop.addEventListener('click', (e) => {
            e.stopPropagation();
            toggleParticipantsSidebar();
        });
    }

    // Event listeners pour le chat
    if (toggleChatTop) {
        toggleChatTop.addEventListener('click', (e) => {
            e.stopPropagation();
            toggleChatSidebar();
        });
    }

    // Cacher définitivement le bouton flottant pour éviter les doublons
    if (toggleChatFloating) {
        toggleChatFloating.style.display = 'none';
        // Ne pas ajouter d'event listener pour éviter les conflits
    }
}

// Initialiser les onglets au chargement
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        initCollaborationTabs();
        initCollaborationSidebars();
    });
} else {
    initCollaborationTabs();
    initCollaborationSidebars();
}

async function startBrowserMirroring() {
    if (!currentSessionId || !currentUserId || !collaborationWebSocket) {
        alert('You must be in a collaboration session');
        return;
    }

    // Vérifier que le WebSocket de collaboration est prêt
    if (collaborationWebSocket.readyState !== WebSocket.OPEN) {
        alert('WebSocket connection not established. Please wait...');
        return;
    }

    try {
        // Envoyer un message via le WebSocket de collaboration pour démarrer le mirroring
        collaborationWebSocket.send(JSON.stringify({
            type: 'mirror_start',
            user_id: currentUserId
        }));

        // Créer l'instance de mirroring qui utilisera le WebSocket de collaboration
        if (typeof BrowserMirror === 'undefined') {
            alert('BrowserMirror script not loaded. Please refresh the page.');
            return;
        }

        // Utiliser le WebSocket de collaboration existant
        browserMirror = new BrowserMirror(null, currentSessionId, currentUserId);
        browserMirror.ws = collaborationWebSocket;
        browserMirror.isMirroring = true;

        // Démarrer la capture
        await browserMirror.captureInitialDOM();
        browserMirror.startDOMObserver();
        browserMirror.startScreenshotCapture();

        console.log('[Collaboration] Browser mirroring started using collaboration WebSocket');

        // Basculer automatiquement vers l'onglet Live Mirror si on est sur un autre onglet
        const collabTabMirror = document.getElementById('collab-tab-mirror');
        if (collabTabMirror && !collabTabMirror.classList.contains('active')) {
            // Simuler un clic sur l'onglet Live Mirror pour basculer
            collabTabMirror.click();
        }

        // Mettre à jour l'UI
        const collabMirrorStartBtn = document.getElementById('collab-mirror-start-btn');
        const collabMirrorStopBtn = document.getElementById('collab-mirror-stop-btn');
        if (collabMirrorStartBtn) collabMirrorStartBtn.style.display = 'none';
        if (collabMirrorStopBtn) collabMirrorStopBtn.style.display = 'block';

        // Masquer le placeholder et afficher le contenu du mirroring
        const placeholder = document.getElementById('collab-mirror-placeholder');
        const content = document.getElementById('collab-mirror-content');
        const loadingEl = document.getElementById('collab-mirror-loading');
        const imageEl = document.getElementById('collab-mirror-image');

        if (placeholder) placeholder.style.display = 'none';
        if (content) content.style.display = 'block';
        if (loadingEl) loadingEl.style.display = 'flex'; // Afficher le message "Sharing in progress..."
        if (imageEl) imageEl.style.display = 'none'; // Cacher l'image jusqu'à ce qu'elle arrive

        // S'assurer que currentMirrorUserId est défini pour afficher nos propres images
        if (!currentMirrorUserId) {
            currentMirrorUserId = currentUserId;
        }

        console.log('[Collaboration] Browser mirroring started');
        updateCollabLiveIndicator(true);
        saveCollaborationState();
    } catch (error) {
        console.error('[Collaboration] Error starting mirror:', error);
        alert(`Error starting mirroring: ${error.message}`);
    }
}

function stopBrowserMirroring() {
    // Envoyer un message pour arrêter le mirroring (sans fermer le WebSocket de collaboration)
    if (collaborationWebSocket && collaborationWebSocket.readyState === WebSocket.OPEN) {
        collaborationWebSocket.send(JSON.stringify({
            type: 'mirror_stop',
            user_id: currentUserId
        }));
    }

    if (browserMirror) {
        // Arrêter le mirroring sans fermer le WebSocket (car c'est le même que collaborationWebSocket)
        browserMirror.isMirroring = false;

        if (browserMirror.observer) {
            browserMirror.observer.disconnect();
            browserMirror.observer = null;
        }

        if (browserMirror.screenshotInterval) {
            clearInterval(browserMirror.screenshotInterval);
            browserMirror.screenshotInterval = null;
        }

        // Ne PAS fermer le WebSocket car c'est le même que collaborationWebSocket
        // this.ws.close() serait appelé dans browserMirror.stop(), donc on ne l'appelle pas

        browserMirror = null;
    }

    // Mettre à jour l'UI
    const collabMirrorStartBtn = document.getElementById('collab-mirror-start-btn');
    const collabMirrorStopBtn = document.getElementById('collab-mirror-stop-btn');
    if (collabMirrorStartBtn) collabMirrorStartBtn.style.display = 'block';
    if (collabMirrorStopBtn) collabMirrorStopBtn.style.display = 'none';

    // Réinitialiser la vue
    const placeholder = document.getElementById('collab-mirror-placeholder');
    const content = document.getElementById('collab-mirror-content');
    const loadingEl = document.getElementById('collab-mirror-loading');
    const imageEl = document.getElementById('collab-mirror-image');
    if (placeholder) placeholder.style.display = 'block';
    if (content) content.style.display = 'none';
    if (loadingEl) loadingEl.style.display = 'none';
    if (imageEl) {
        imageEl.src = '';
        imageEl.style.display = 'none';
    }

    console.log('[Collaboration] Browser mirroring stopped');
    updateCollabLiveIndicator(false);
    saveCollaborationState();
}

function handleMirrorStarted(userId) {
    console.log('[Collaboration] Mirror started for user:', userId);
    console.log('[Collaboration] Available participants:', collaborationParticipants);

    // Chercher le participant par user_id, id, ou collaborator.id
    let participant = collaborationParticipants.find(p =>
        (p.user_id && p.user_id === userId) ||
        (p.id && p.id === userId) ||
        (p.collaborator && p.collaborator.id === userId) ||
        (p.collaborator && p.collaborator.user_id === userId)
    );

    // Si pas trouvé, essayer de chercher dans tous les champs possibles
    if (!participant) {
        participant = collaborationParticipants.find(p => {
            const pStr = JSON.stringify(p);
            return pStr.includes(userId);
        });
    }

    if (participant) {
        console.log(`[Collaboration] Found participant:`, participant);
        const participantName = participant.username || participant.name || participant.collaborator?.name || 'Unknown';
        const participantColor = participant.color || participant.collaborator?.color || '#2196f3';
        console.log(`[Collaboration] ${participantName} started mirroring`);
        // Initialiser le viewer pour cet utilisateur
        mirrorViewers[userId] = {
            user: participantName,
            url: '',
            image: null,
            color: participantColor
        };
        // Ajouter un bouton pour cet utilisateur
        addMirrorUserTab(userId, {
            username: participantName,
            name: participantName,
            color: participantColor,
            user_id: userId
        });
    } else {
        console.warn(`[Collaboration] Participant not found for user_id: ${userId}`);
        console.warn(`[Collaboration] Will create default participant`);
        // Créer un participant par défaut si non trouvé
        const defaultParticipant = {
            username: `User_${userId.substring(0, 8)}`,
            name: `User_${userId.substring(0, 8)}`,
            color: '#2196f3',
            user_id: userId
        };
        mirrorViewers[userId] = {
            user: defaultParticipant.username,
            url: '',
            image: null,
            color: defaultParticipant.color
        };
        addMirrorUserTab(userId, defaultParticipant);
    }

    if (userId === currentUserId) {
        updateCollabLiveIndicator(true);
    }
}

function handleMirrorStopped(userId) {
    delete mirrorViewers[userId];

    // Retirer le bouton de cet utilisateur
    removeMirrorUserTab(userId);

    // Si c'est le seul viewer actif, réinitialiser
    if (Object.keys(mirrorViewers).length === 0) {
        const placeholder = document.getElementById('collab-mirror-placeholder');
        const content = document.getElementById('collab-mirror-content');
        if (placeholder) placeholder.style.display = 'block';
        if (content) content.style.display = 'none';
    }

    console.log(`[Collaboration] Mirroring stopped for user ${userId}`);

    if (userId === currentUserId) {
        updateCollabLiveIndicator(false);
    }
}

function restoreCollaborationLayout() {
    // Restaurer l'affichage des contrôles
    const collabMirrorControls = document.getElementById('collab-mirror-controls');
    if (collabMirrorControls) {
        collabMirrorControls.style.display = 'flex';
    }
}

function addMirrorUserTab(userId, participant) {
    const tabsContainer = document.getElementById('collab-mirror-users-tabs');
    if (!tabsContainer) return;

    // Vérifier si le bouton existe déjà
    if (document.getElementById(`collab-mirror-tab-${userId}`)) return;

    const button = document.createElement('button');
    button.id = `collab-mirror-tab-${userId}`;
    button.className = 'collab-tab-btn collab-mirror-user-tab';
    button.style.cssText = 'padding: 6px 12px; border: none; background: #f5f5f5; border-radius: 6px; cursor: pointer; font-size: 13px; font-weight: 500; display: flex; align-items: center; gap: 6px;';

    // Point de couleur pour l'utilisateur
    const colorDot = document.createElement('span');
    colorDot.style.cssText = `width: 8px; height: 8px; border-radius: 50%; background: ${participant.color || '#2196f3'}; display: inline-block;`;
    button.appendChild(colorDot);

    // Nom de l'utilisateur
    const nameSpan = document.createElement('span');
    nameSpan.textContent = participant.username || participant.name || 'Unknown';
    button.appendChild(nameSpan);

    // Icône de partage
    const icon = document.createElement('span');
    icon.className = 'material-symbols-outlined';
    icon.textContent = 'desktop_windows';
    icon.style.cssText = 'font-size: 14px;';
    button.appendChild(icon);

    // Event listener
    button.addEventListener('click', () => {
        switchToMirrorUser(userId);
    });

    tabsContainer.appendChild(button);
}

function removeMirrorUserTab(userId) {
    const button = document.getElementById(`collab-mirror-tab-${userId}`);
    if (button) {
        button.remove();
    }

    // Si c'était l'utilisateur actuellement affiché, réinitialiser et revenir aux flows
    if (currentMirrorUserId === userId) {
        currentMirrorUserId = null;

        // Réinitialiser l'affichage du mirror
        const placeholder = document.getElementById('collab-mirror-placeholder');
        const content = document.getElementById('collab-mirror-content');
        if (placeholder) placeholder.style.display = 'block';
        if (content) content.style.display = 'none';

        // Revenir à l'affichage des flows
        const collabFlowsList = document.getElementById('collab-flows-list');
        const collabFlowsListContainer = document.getElementById('collab-flows-list-container');
        const collabMirrorContainer = document.getElementById('collab-mirror-container');
        const collabTabFlows = document.getElementById('collab-tab-flows');
        const collabTabMirror = document.getElementById('collab-tab-mirror');
        const collabMirrorControls = document.getElementById('collab-mirror-controls');

        if (collabFlowsListContainer) {
            collabFlowsListContainer.style.display = 'flex';
            collabFlowsListContainer.classList.add('active');
        }
        if (collabMirrorContainer) {
            collabMirrorContainer.style.display = 'none';
            collabMirrorContainer.classList.remove('active');
        }
        if (collabTabFlows) {
            collabTabFlows.classList.add('active');
        }
        if (collabTabMirror) {
            collabTabMirror.classList.remove('active');
        }
        if (collabMirrorControls) {
            collabMirrorControls.style.display = 'flex';
        }
    }
}

function switchToMirrorUser(userId) {
    currentMirrorUserId = userId;
    saveCollaborationState(); // Sauvegarder quel utilisateur on regarde
    const viewer = mirrorViewers[userId];
    if (!viewer) return;

    // Vérifier si c'est notre propre écran ou celui d'un autre utilisateur
    const isViewingOwnScreen = userId === currentUserId;

    // Afficher le conteneur mirror et masquer les flows
    const collabFlowsList = document.getElementById('collab-flows-list');
    const collabFlowsListContainer = document.getElementById('collab-flows-list-container');
    const collabMirrorContainer = document.getElementById('collab-mirror-container');
    const collabTabFlows = document.getElementById('collab-tab-flows');
    const collabTabMirror = document.getElementById('collab-tab-mirror');
    const collabTabRepeater = document.getElementById('collab-tab-repeater');
    const collabTabAI = document.getElementById('collab-tab-ai');
    const collabRepeaterContainer = document.getElementById('collab-repeater-container');
    const collabAIContainer = document.getElementById('collab-ai-container');
    const collabMirrorControls = document.getElementById('collab-mirror-controls');
    const collabMirrorStartBtn = document.getElementById('collab-mirror-start-btn');
    const collabMirrorStopBtn = document.getElementById('collab-mirror-stop-btn');

    // Activer l'onglet Live Mirror et désactiver les autres
    if (collabTabMirror) collabTabMirror.classList.add('active');
    if (collabTabFlows) collabTabFlows.classList.remove('active');
    if (collabTabRepeater) collabTabRepeater.classList.remove('active');
    if (collabTabAI) collabTabAI.classList.remove('active');

    // Masquer tous les autres conteneurs
    if (collabFlowsListContainer) {
        collabFlowsListContainer.style.display = 'none';
        collabFlowsListContainer.classList.remove('active');
    }
    if (collabRepeaterContainer) {
        collabRepeaterContainer.style.display = 'none';
        collabRepeaterContainer.classList.remove('active');
    }
    if (collabAIContainer) {
        collabAIContainer.style.display = 'none';
        collabAIContainer.classList.remove('active');
    }
    // Afficher le conteneur mirror
    if (collabMirrorContainer) {
        collabMirrorContainer.style.display = 'flex';
        collabMirrorContainer.classList.add('active');
    }
    // Ne pas désactiver le bouton "Live Mirror" - il doit rester cliquable
    // pour permettre de partager son propre écran même quand on regarde celui d'un autre

    // Masquer les contrôles "Start Mirroring" si on regarde l'écran d'un autre utilisateur
    if (collabMirrorControls) {
        if (isViewingOwnScreen) {
            // Si on regarde notre propre écran, afficher les contrôles
            collabMirrorControls.style.display = 'flex';
        } else {
            // Si on regarde l'écran d'un autre, masquer les contrôles
            collabMirrorControls.style.display = 'none';
        }
    }

    // Mettre à jour les styles des boutons
    document.querySelectorAll('.collab-mirror-user-tab').forEach(btn => {
        btn.classList.remove('active');
        btn.style.background = '#f5f5f5';
        btn.style.color = '';
    });

    const activeButton = document.getElementById(`collab-mirror-tab-${userId}`);
    if (activeButton) {
        activeButton.classList.add('active');
        activeButton.style.background = '#333';
        activeButton.style.color = 'white';
    }

    // Afficher le contenu du mirroring
    const placeholder = document.getElementById('collab-mirror-placeholder');
    const content = document.getElementById('collab-mirror-content');
    const imageEl = document.getElementById('collab-mirror-image');
    const userEl = document.getElementById('collab-mirror-user');
    const urlEl = document.getElementById('collab-mirror-url');

    // Si on a une image, l'afficher, sinon afficher un message d'attente
    if (viewer.image && imageEl) {
        // On a une image, l'afficher
        imageEl.src = viewer.image;
        if (placeholder) placeholder.style.display = 'none';
        if (content) content.style.display = 'block';
    } else {
        // Pas d'image encore, afficher un message d'attente
        if (placeholder) {
            placeholder.innerHTML = `
                <span class="material-symbols-outlined" style="font-size: 64px; color: #444; display: block; margin-bottom: 16px;">hourglass_empty</span>
                <p style="margin: 0; font-size: 14px;">En attente de l'image...</p>
                <p style="margin: 8px 0 0 0; font-size: 12px; color: #888;">L'image devrait apparaître dans quelques instants</p>
            `;
            placeholder.style.display = 'block';
        }
        if (content) content.style.display = 'none';
    }

    if (viewer.url && urlEl) {
        urlEl.textContent = viewer.url;
    }

    if (userEl) {
        userEl.textContent = viewer.user;
        if (viewer.color) {
            userEl.style.color = viewer.color;
        }
    }

    // Pas besoin de modifier le layout - on garde les sidebars (participants et chat)
}

function handleMirrorData(userId, data) {
    const viewer = mirrorViewers[userId];
    if (!viewer) return;

    if (data.type === 'screenshot') {
        // Stocker l'image
        viewer.image = data.image;

        // Afficher l'image si c'est l'utilisateur actuellement sélectionné
        if (currentMirrorUserId === userId) {
            const imageEl = document.getElementById('collab-mirror-image');
            const loadingEl = document.getElementById('collab-mirror-loading');
            if (imageEl) {
                imageEl.src = data.image;
                imageEl.style.display = 'block';
            }
            if (loadingEl) {
                loadingEl.style.display = 'none';
            }

            const placeholder = document.getElementById('collab-mirror-placeholder');
            const content = document.getElementById('collab-mirror-content');
            if (placeholder) placeholder.style.display = 'none';
            if (content) content.style.display = 'block';
        }
    }

    if (data.url) {
        viewer.url = data.url;

        // Mettre à jour l'URL seulement si c'est l'utilisateur actuellement sélectionné
        if (currentMirrorUserId === userId) {
            const urlEl = document.getElementById('collab-mirror-url');
            if (urlEl) {
                urlEl.textContent = data.url;
            }
        }
    }

    // Si on regarde cet utilisateur mais qu'on n'avait pas encore d'image, mettre à jour l'affichage
    if (currentMirrorUserId === userId && viewer.image) {
        const imageEl = document.getElementById('collab-mirror-image');
        const loadingEl = document.getElementById('collab-mirror-loading');
        const placeholder = document.getElementById('collab-mirror-placeholder');
        const content = document.getElementById('collab-mirror-content');

        if (imageEl && viewer.image) {
            imageEl.src = viewer.image;
            imageEl.style.display = 'block';
            if (loadingEl) loadingEl.style.display = 'none';
            if (placeholder) placeholder.style.display = 'none';
            if (content) content.style.display = 'block';
        }
    }
}

function addChatMessage(message) {
    if (!collabChatMessages) return;

    // Éviter les doublons
    if (collaborationMessages.find(m => m.id === message.id)) {
        return;
    }

    collaborationMessages.push(message);

    const div = document.createElement('div');
    div.dataset.userId = message.user_id || '';
    if (message.id) div.dataset.msgId = message.id;
    const isOwnMessage = message.user_id === currentUserId;
    div.style.cssText = `padding: 10px 12px; margin-bottom: 8px; border-radius: 8px; background: ${isOwnMessage ? '#e3f2fd' : 'white'}; border: 1px solid var(--border-color); max-width: 85%; ${isOwnMessage ? 'margin-left: auto;' : ''}`;

    const author = document.createElement('div');
    const participant = collaborationParticipants.find(p => p.user_id === message.user_id);
    const color = participant ? (participant.color || '#666') : '#666';
    author.style.cssText = `font-size: 11px; font-weight: 600; color: ${color}; margin-bottom: 4px; display: flex; align-items: center; gap: 6px;`;

    // Ajouter un point de couleur pour l'auteur
    const authorDot = document.createElement('span');
    authorDot.style.cssText = `width: 6px; height: 6px; border-radius: 50%; background: ${color}; display: inline-block;`;
    author.appendChild(authorDot);
    const authorName = document.createElement('span');
    authorName.className = 'chat-author-name';
    authorName.textContent = message.username || message.author_name || 'Anonymous';
    author.appendChild(authorName);

    const content = document.createElement('div');
    content.textContent = message.content;
    content.style.cssText = 'font-size: 13px; color: #333; word-wrap: break-word;';

    // Timestamp
    const timestamp = document.createElement('div');
    if (message.created_at) {
        const date = new Date(message.created_at * 1000);
        timestamp.textContent = date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
        timestamp.style.cssText = 'font-size: 10px; color: #999; margin-top: 4px;';
        div.appendChild(timestamp);
    }

    div.insertBefore(author, div.firstChild);
    div.appendChild(content);
    collabChatMessages.appendChild(div);

    // Scroll to bottom
    collabChatMessages.scrollTop = collabChatMessages.scrollHeight;
}

function updateChatAuthorNames(userId, newName) {
    if (!collabChatMessages) return;
    const safeName = newName || 'Anonymous';
    Array.from(collabChatMessages.children).forEach(msgEl => {
        if (msgEl.dataset && msgEl.dataset.userId === userId) {
            const nameEl = msgEl.querySelector('.chat-author-name');
            if (nameEl) nameEl.textContent = safeName;
        }
    });
}

async function loadChatHistory() {
    if (!currentSessionId) return;

    try {
        const res = await fetch(`${COLLABORATION_SERVER_URL}/api/v1/sessions/${currentSessionId}/messages?limit=100`, {
            headers: {
                'Content-Type': 'application/json'
            }
        });

        if (res.ok) {
            const data = await res.json();
            if (data.messages && Array.isArray(data.messages)) {
                // Vider les messages actuels
                collaborationMessages = [];
                if (collabChatMessages) {
                    collabChatMessages.innerHTML = '';
                }
                // Ajouter les messages dans l'ordre chronologique
                data.messages.forEach(msg => {
                    addChatMessage(msg);
                });
            }
        }
    } catch (err) {
        console.error('Error loading chat history:', err);
    }
}

// Charger les flows existants partagés dans la session et les résultats IA
async function loadExistingSharedFlows() {
    if (!currentSessionId) {
        console.log('[Collaboration] No session ID, cannot load existing flows');
        return;
    }

    console.log('[Collaboration] Loading existing shared flows for session:', currentSessionId);

    try {
        // Charger les messages du chat pour extraire les flows partagés et résultats IA
        const res = await fetch(`${COLLABORATION_SERVER_URL}/api/v1/sessions/${currentSessionId}/messages?limit=200`, {
            headers: {
                'Content-Type': 'application/json'
            }
        });

        if (res.ok) {
            const data = await res.json();
            console.log('[Collaboration] Loaded', data.messages?.length || 0, 'messages from session');

            if (data.messages && Array.isArray(data.messages)) {
                const flowsLoaded = new Set();

                // Parcourir tous les messages pour trouver les flows partagés et résultats IA
                data.messages.forEach(msg => {
                    console.log('[Collaboration] Processing message type:', msg.type);
                    // Vérifier si le message contient un flow (format flow_added)
                    if (msg.type === 'flow_added' && msg.flow) {
                        const flowId = msg.flow.id || msg.flow_id;
                        if (flowId && !flowsLoaded.has(flowId)) {
                            flowsLoaded.add(flowId);
                            // Ajouter le flow à la liste de collaboration
                            addCollaborationFlow(msg.flow, msg.user_id || msg.userId);
                            console.log('[Collaboration] Loaded existing shared flow:', flowId, 'from user:', msg.user_id || msg.userId);
                        }
                    }

                    // Vérifier si le message contient des résultats IA
                    if (msg.type === 'ai_results' || (msg.type === 'chat_message' && msg.ai_results)) {
                        const aiResults = msg.ai_results || msg.content;
                        const flowId = msg.flow_id || aiResults?.flow_id;
                        if (flowId && aiResults) {
                            // Stocker les résultats IA pour ce flow
                            if (!collabAIResults[flowId]) {
                                collabAIResults[flowId] = {
                                    suggestions: aiResults.suggestions || [],
                                    tech_stack: aiResults.tech_stack || {},
                                    summary: aiResults.summary || '',
                                    next_steps: aiResults.next_steps || []
                                };
                                console.log('[Collaboration] Loaded AI results for flow:', flowId);
                            }
                        }
                    }

                    // Vérifier aussi dans le contenu du message si c'est un message de chat avec flow ou résultats IA
                    if (msg.type === 'chat_message' && msg.content) {
                        try {
                            const content = typeof msg.content === 'string' ? JSON.parse(msg.content) : msg.content;

                            // Flow partagé dans le chat
                            if (content.type === 'flow_added' && content.flow) {
                                const flowId = content.flow.id || content.flow_id;
                                if (flowId && !flowsLoaded.has(flowId)) {
                                    flowsLoaded.add(flowId);
                                    addCollaborationFlow(content.flow, msg.user_id || content.user_id);
                                    console.log('[Collaboration] Loaded existing shared flow from chat:', flowId);
                                }
                            }

                            // Résultats IA dans le chat
                            if (content.type === 'ai_results' && content.flow_id) {
                                if (!collabAIResults[content.flow_id]) {
                                    collabAIResults[content.flow_id] = {
                                        suggestions: content.suggestions || [],
                                        tech_stack: content.tech_stack || {},
                                        summary: content.summary || '',
                                        next_steps: content.next_steps || []
                                    };
                                    console.log('[Collaboration] Loaded AI results from chat for flow:', content.flow_id);
                                }
                            }
                        } catch (e) {
                            // Ignorer si ce n'est pas du JSON
                        }
                    }
                });

                console.log('[Collaboration] Loaded', flowsLoaded.size, 'existing shared flows and', Object.keys(collabAIResults).length, 'AI results');
                console.log('[Collaboration] Total collaborationFlows after loading:', collaborationFlows.length);
                console.log('[Collaboration] collaborationFlows details:', collaborationFlows.map(f => ({ id: f.id, url: f.url })));

                // Si aucun flow n'a été trouvé dans les messages, peut-être qu'ils sont dans data.session
                if (flowsLoaded.size === 0 && data.session && data.session.flows) {
                    console.log('[Collaboration] Found flows in session data:', data.session.flows.length);
                    data.session.flows.forEach(flow => {
                        if (!collaborationFlows.find(f => f.id === flow.id)) {
                            addCollaborationFlow(flow, flow.shared_by_user_id);
                        }
                    });
                }

                // Sauvegarder les résultats IA restaurés
                saveAIAssistantResults();

                // Synchroniser les flows partagés pour activer les boutons share
                syncSharedFlowsFromCollaboration();

                // Attendre un peu pour s'assurer que tous les flows sont bien ajoutés à collaborationFlows
                setTimeout(() => {
                    console.log('[Collaboration] Refreshing AI flows list, total flows:', collaborationFlows.length);
                    // Toujours mettre à jour la liste des flows AI (même si l'onglet n'est pas actif, pour qu'elle soit prête)
                    loadAIFlowsList();
                }, 200);
            }
        }
    } catch (err) {
        console.error('[Collaboration] Error loading existing shared flows:', err);
    }
}

function sendCollabMessage() {
    if (!collabChatInput || !collabChatInput.value.trim() || !collaborationWebSocket) return;

    // Vérifier que le WebSocket est prêt
    if (collaborationWebSocket.readyState !== WebSocket.OPEN) {
        showErrorModal('WebSocket connection not established. Please wait...');
        return;
    }

    const message = {
        type: 'chat_message',
        content: collabChatInput.value.trim()
    };

    try {
        collaborationWebSocket.send(JSON.stringify(message));
        collabChatInput.value = '';
        saveCollaborationState();
    } catch (error) {
        console.error('[Collaboration] Error sending chat message:', error);
        showErrorModal('Error sending message');
    }
}

function getRandomColor() {
    const colors = ['#2196f3', '#4caf50', '#ff9800', '#9c27b0', '#f44336', '#00bcd4'];
    return colors[Math.floor(Math.random() * colors.length)];
}

// Event Listeners
if (collabCreateBtn) {
    collabCreateBtn.addEventListener('click', createCollaborationSession);
}
if (collabCreateBtn2) {
    collabCreateBtn2.addEventListener('click', createCollaborationSession);
}
if (collabJoinBtn) {
    collabJoinBtn.addEventListener('click', () => joinCollaborationSession());
}
if (collabJoinBtn2) {
    collabJoinBtn2.addEventListener('click', () => joinCollaborationSession());
}
if (typeof collabHistoryBtn !== 'undefined' && collabHistoryBtn) {
    collabHistoryBtn.addEventListener('click', () => {
        openModal('modal-ai-history');
        renderAIHistory();
    });
}
if (collabLeaveBtn) {
    collabLeaveBtn.addEventListener('click', leaveCollaborationSession);
}
if (collabChatInput) {
    collabChatInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            sendCollabMessage();
        }
    });

    // Sauvegarder l'état quand on tape dans le champ de chat (avec debounce)
    let chatInputSaveTimeout = null;
    collabChatInput.addEventListener('input', () => {
        clearTimeout(chatInputSaveTimeout);
        chatInputSaveTimeout = setTimeout(() => {
            saveCollaborationState();
        }, 500); // Sauvegarder après 500ms d'inactivité
    });
}
if (collabChatSendBtn) {
    collabChatSendBtn.addEventListener('click', sendCollabMessage);
}
if (collabInviteBtn) {
    collabInviteBtn.addEventListener('click', async () => {
        if (currentSessionId) {
            try {
                // Récupérer le code d'invitation depuis le serveur
                const res = await fetch(`${COLLABORATION_SERVER_URL}/api/v1/sessions/${currentSessionId}`, {
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });

                if (res.ok) {
                    const data = await res.json();
                    const inviteCode = data.invite_code || currentSessionId.substring(0, 8).toUpperCase();

                    const copied = await copyToClipboard(inviteCode);
                    if (copied) {
                        showToast(`Code copied: ${inviteCode}`, 'success');
                    } else {
                        showToast(`Copy blocked. Code to share: ${inviteCode}`, 'error');
                    }
                } else {
                    // Fallback si l'API échoue
                    const code = currentSessionId.substring(0, 8).toUpperCase();
                    const copied = await copyToClipboard(code);
                    if (copied) {
                        showToast(`Code copied: ${code}`, 'success');
                    } else {
                        showToast(`Copy blocked. Code to share: ${code}`, 'error');
                    }
                }
            } catch (err) {
                console.error('Error getting invite code:', err);
                // Fallback
                const code = currentSessionId.substring(0, 8).toUpperCase();
                const copied = await copyToClipboard(code);
                if (copied) {
                    showToast(`Code copied: ${code}`, 'success');
                } else {
                    showToast(`Copy blocked. Code to share: ${code}`, 'error');
                }
            }
        }
    });
}

// Toggle le partage d'un flow
function toggleShareFlow(flow) {
    if (!currentSessionId || !collaborationWebSocket) {
        alert('Please join a collaboration session first');
        return;
    }

    if (collaborationWebSocket.readyState !== WebSocket.OPEN) {
        alert('Collaboration connection not ready');
        return;
    }

    const isShared = sharedFlows.has(flow.id);

    if (isShared) {
        // Unshare - retirer le flow de la liste de collaboration
        sharedFlows.delete(flow.id);
        console.log('[Collaboration] Unsharing flow:', flow.id);

        // Retirer le flow de la liste de collaboration
        const flowIndex = collaborationFlows.findIndex(f => f.id === flow.id);
        if (flowIndex !== -1) {
            collaborationFlows.splice(flowIndex, 1);
            renderCollaborationFlows();
        }
    } else {
        // Share
        sharedFlows.add(flow.id);
        console.log('[Collaboration] Sharing flow:', flow.id, flow.url);

        try {
            collaborationWebSocket.send(JSON.stringify({
                type: 'flow_added',
                flow: flow
            }));

            // Ajouter le flow localement immédiatement pour qu'il apparaisse dans la vue collaboration
            addCollaborationFlow(flow, currentUserId);
        } catch (error) {
            console.error('[Collaboration] Error sharing flow:', error);
            sharedFlows.delete(flow.id); // Revert on error
            alert('Error sharing flow: ' + error.message);
            return;
        }
    }

    // Re-render pour mettre à jour l'UI
    renderFlowList();
}

// Sync flows from main flow list (seulement les flows partagés)
function syncFlowsToCollaboration() {
    if (!currentSessionId || !collaborationWebSocket) {
        console.log('[Collaboration] Cannot sync: no session or websocket');
        return;
    }

    // Vérifier que le WebSocket est prêt (OPEN = 1)
    if (collaborationWebSocket.readyState !== WebSocket.OPEN) {
        console.log('[Collaboration] WebSocket not ready, state:', collaborationWebSocket.readyState);
        return;
    }

    // Ne synchroniser que les flows marqués comme partagés
    const flowsToSync = flowsData.filter(flow => sharedFlows.has(flow.id));
    console.log('[Collaboration] Syncing shared flows, count:', flowsToSync.length);

    flowsToSync.forEach(flow => {
        if (!collaborationFlows.find(f => f.id === flow.id)) {
            try {
                console.log('[Collaboration] Sending shared flow:', flow.id, flow.url);
                collaborationWebSocket.send(JSON.stringify({
                    type: 'flow_added',
                    flow: flow
                }));
            } catch (error) {
                console.error('[Collaboration] Error sending flow:', error);
            }
        }
    });
}

// Sync flows periodically (seulement les flows partagés)
setInterval(() => {
    if (currentSessionId && collaborationWebSocket && sharedFlows.size > 0) {
        syncFlowsToCollaboration();
    }
}, 3000);

// Synchroniser les flows existants au démarrage de la collaboration
function syncExistingFlowsToCollaboration() {
    if (currentSessionId && collaborationWebSocket && flowsData.length > 0) {
        // Ne synchroniser que les flows déjà marqués comme partagés
        const sharedCount = Array.from(sharedFlows).filter(id => flowsData.find(f => f.id === id)).length;
        console.log('[Collaboration] Syncing existing shared flows on session start:', sharedCount);
        syncFlowsToCollaboration();
    }
}

function toggleNavTreeNode(element) {
    const node = element.closest('.nav-tree-node');
    const children = node.querySelector('.nav-tree-children');
    const icon = element.querySelector('.nav-tree-expand-icon');
    const hasChildren = node.getAttribute('data-has-children') === 'true';

    // Si c'est un dossier (a des enfants), toggle l'ouverture/fermeture
    if (hasChildren && children) {
        const isExpanded = children.style.display !== 'none';
        children.style.display = isExpanded ? 'none' : 'block';

        if (icon) {
            const level = parseInt(node.getAttribute('data-level') || '0');
            if (isExpanded) {
                // Fermer
                if (level === 0) {
                    icon.textContent = 'expand_more';
                } else {
                    icon.textContent = 'chevron_right';
                }
            } else {
                // Ouvrir
                if (level === 0) {
                    icon.textContent = 'expand_less';
                } else {
                    icon.textContent = 'expand_more';
                }
            }
        }
    }
    // Si c'est un fichier (pas d'enfants), ne rien faire ici (selectNavTreeNode sera appelé)
}

function selectNavTreeNode(path) {
    console.log('[NAV TREE] Selecting node:', path);

    // Essayer d'abord de récupérer les flows depuis l'attribut data-flow-ids du DOM
    let matchingFlows = [];
    const nodeElement = document.querySelector(`[data-path="${path}"]`);
    if (nodeElement) {
        const flowIdsStr = nodeElement.getAttribute('data-flow-ids');
        if (flowIdsStr) {
            const flowIds = flowIdsStr.split(',').filter(id => id);
            matchingFlows = flowsData.filter(flow => flowIds.includes(flow.id));
            console.log('[NAV TREE] Found', matchingFlows.length, 'flows from DOM data attribute');
        }
    }

    // Si pas de flows trouvés via DOM, utiliser la recherche par chemin
    if (matchingFlows.length === 0) {
        matchingFlows = flowsData.filter(flow => {
            try {
                const url = new URL(flow.url);
                const flowPath = `${url.hostname}${url.pathname}`;

                // Correspondance exacte
                if (flowPath === path) {
                    return true;
                }

                // Normaliser les chemins (enlever trailing slash)
                const normalizedPath = path.replace(/\/$/, '');
                const normalizedFlowPath = flowPath.replace(/\/$/, '');
                if (normalizedFlowPath === normalizedPath) {
                    return true;
                }

                // Correspondance : le flowPath commence par le path (pour les dossiers)
                if (normalizedFlowPath.startsWith(normalizedPath + '/') || normalizedFlowPath === normalizedPath) {
                    return true;
                }

                // Correspondance inverse : le path contient le flowPath complet
                if (normalizedPath.includes(normalizedFlowPath) && normalizedFlowPath.length > 5) {
                    return true;
                }

                // Correspondance par nom de fichier (dernier segment)
                const pathFileName = normalizedPath.split('/').pop();
                const flowFileName = normalizedFlowPath.split('/').pop();
                if (pathFileName && flowFileName && pathFileName === flowFileName && pathFileName.length > 0) {
                    // Vérifier que le domaine correspond aussi
                    const pathDomain = path.split('/')[0];
                    const flowDomain = url.hostname;
                    if (pathDomain === flowDomain || path.startsWith(flowDomain)) {
                        return true;
                    }
                }

                return false;
            } catch (e) {
                console.warn('[NAV TREE] Error processing flow:', e, flow.url);
                return false;
            }
        });
    }

    console.log('[NAV TREE] Found', matchingFlows.length, 'matching flows for path:', path);
    if (matchingFlows.length > 0) {
        console.log('[NAV TREE] Sample flow URLs:', matchingFlows.slice(0, 3).map(f => {
            try {
                const url = new URL(f.url);
                return `${url.hostname}${url.pathname}`;
            } catch {
                return f.url;
            }
        }));
    }

    if (matchingFlows.length > 0) {
        // Sélectionner le premier flow (ou le plus récent)
        const selectedFlow = matchingFlows.sort((a, b) =>
            (b.timestamp_start || 0) - (a.timestamp_start || 0)
        )[0];

        // Afficher le contenu du fichier dans une modal
        showFileContentModal(selectedFlow, path);
    } else {
        console.warn('[NAV TREE] No matching flows found for path:', path);
        console.warn('[NAV TREE] Available flows sample:', flowsData.slice(0, 5).map(f => {
            try {
                const url = new URL(f.url);
                return `${url.hostname}${url.pathname}`;
            } catch {
                return f.url;
            }
        }));
        alert(`No matching flows found for this path: ${path}\n\nCheck the console for more details.`);
    }
}

function selectFlowFromHeatmap(method, path) {
    // Trouver le flow correspondant et l'afficher dans l'onglet Analyze
    const matchingFlow = flowsData.find(flow => {
        try {
            const url = new URL(flow.url);
            return flow.method === method && url.pathname === path && url.hostname === selectedDomainForGraph;
        } catch {
            return false;
        }
    });

    if (matchingFlow) {
        // Basculer vers l'onglet Analyze et sélectionner le flow
        switchView('analyze');
        setTimeout(() => {
            currentFlowId = matchingFlow.id;
            renderFlowList();
            updateDetailButtons();
            renderDetail();
        }, 100);
    }
}


// Initialize
// Initialize sorting headers
function initSortingHeaders() {
    const sortableHeaders = document.querySelectorAll('.sortable-header');
    sortableHeaders.forEach(header => {
        // Remove existing listeners to avoid duplicates
        const newHeader = header.cloneNode(true);
        header.parentNode.replaceChild(newHeader, header);

        newHeader.style.cursor = 'pointer';
        newHeader.style.userSelect = 'none';
        newHeader.addEventListener('click', () => {
            const column = newHeader.dataset.sort;
            if (sortColumn === column) {
                // Toggle sort order
                sortOrder = sortOrder === 'asc' ? 'desc' : 'asc';
            } else {
                // New column, default to ascending
                sortColumn = column;
                sortOrder = 'asc';
            }
            updateSortIndicators();
            renderFlowList();
        });
    });
    updateSortIndicators();
}

// Initialize on DOM ready or immediately if already loaded
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initSortingHeaders);
} else {
    initSortingHeaders();
}

function updateSortIndicators() {
    const sortableHeaders = document.querySelectorAll('.sortable-header');
    sortableHeaders.forEach(header => {
        const indicator = header.querySelector('.sort-indicator');
        const column = header.dataset.sort;

        if (sortColumn === column) {
            indicator.textContent = sortOrder === 'asc' ? ' ▲' : ' ▼';
            indicator.style.opacity = '1';
            header.style.color = '#6200ea';
            header.style.fontWeight = '600';
        } else {
            indicator.textContent = ' ↕';
            indicator.style.opacity = '0.3';
            header.style.color = '';
            header.style.fontWeight = '';
        }
    });
}

setInterval(fetchFlows, 2000);
fetchFlows();
fetchModules();

// Initialize sorting headers after initial load
setTimeout(() => {
    initSortingHeaders();
}, 200);

// ===== WEBSOCKET VIEW FUNCTIONS =====

let wsConnections = [];
let selectedWsId = null;
let wsSearchTerm = '';

function getHeaderValue(headers, key) {
    if (!headers || !key) return null;
    const lowerKey = key.toLowerCase();
    if (headers.get && typeof headers.get === 'function') {
        return headers.get(key) || headers.get(lowerKey) || null;
    }
    if (Array.isArray(headers)) {
        for (const entry of headers) {
            if (!entry || entry.length < 2) continue;
            const [entryKey, entryValue] = entry;
            if (typeof entryKey === 'string' && entryKey.toLowerCase() === lowerKey) {
                return entryValue;
            }
        }
    }
    if (typeof headers === 'object') {
        for (const headerKey of Object.keys(headers)) {
            if (headerKey.toLowerCase() === lowerKey) {
                return headers[headerKey];
            }
        }
    }
    return null;
}

function getWebSocketMessages(flow) {
    if (!flow) return [];
    if (Array.isArray(flow.ws_messages)) {
        return flow.ws_messages;
    }
    if (Array.isArray(flow.messages)) {
        return flow.messages;
    }
    if (flow.websocket && Array.isArray(flow.websocket.messages)) {
        return flow.websocket.messages;
    }
    return [];
}

function hasWebSocketMessages(flow) {
    const messages = getWebSocketMessages(flow);
    return Array.isArray(messages) && messages.length > 0;
}

function isWebSocketFlow(flow) {
    if (!flow) return false;

    // Check explicit flag first (set by backend) - this is the most reliable
    if (flow.is_websocket === true) {
        return true;
    }

    const url = (flow.url || flow.request?.url || '').toLowerCase();
    if (url.startsWith('ws://') || url.startsWith('wss://')) {
        return true;
    }

    if (hasWebSocketMessages(flow)) {
        return true;
    }

    // Check status code 101 (Switching Protocols) - this is a strong indicator
    const statusCode = flow.status_code ?? flow.response?.status_code;
    if (statusCode === 101) {
        return true;
    }

    // Check headers (may not be available in minimal serialization)
    const headers = flow.request?.headers;
    if (headers) {
        const upgrade = getHeaderValue(headers, 'Upgrade');
        const connection = getHeaderValue(headers, 'Connection');
        if (upgrade && typeof upgrade === 'string' && upgrade.toLowerCase().includes('websocket')) {
            return true;
        }

        // Check for specific WebSocket headers
        const secKey = getHeaderValue(headers, 'Sec-WebSocket-Key');
        if (secKey) {
            return true;
        }
        if (upgrade && connection && typeof connection === 'string' && connection.toLowerCase().includes('upgrade')) {
            return true;
        }
    }

    if (flow.websocket) {
        return true;
    }

    return false;
}

function getSocketIoInfo(flow) {
    if (!flow || !flow.url) return null;
    try {
        const url = new URL(flow.url);
        if (!url.pathname.includes('socket.io')) {
            return null;
        }
        const sid = url.searchParams.get('sid');
        const transport = url.searchParams.get('transport') || 'polling';
        const timestamp = flow.timestamp_start || flow.request?.timestamp_start || flow.timestamp || Date.now() / 1000;
        return {
            sid,
            transport,
            url: `${url.origin}${url.pathname}`,
            displayUrl: flow.url,
            rawUrl: flow.url,
            timestamp,
            query: Object.fromEntries(url.searchParams.entries())
        };
    } catch {
        return null;
    }
}

function determineWebSocketStatus(connection) {
    if (!connection) return 'Pending';
    if (connection.type === 'socketio') {
        const info = connection.socketIo || {};
        const transports = info.transportsArray || [];
        if (info.connected) {
            return 'Connected';
        }
        if (info.lastError && info.lastError >= 400) {
            return `Error ${info.lastError}`;
        }
        if (transports.includes('websocket')) {
            return 'Upgrading';
        }
        if (transports.includes('polling')) {
            return 'Polling';
        }
        return 'Pending';
    }

    const statusCode = connection.status_code;
    if (statusCode === 101 || (connection.messageCount > 0 && !statusCode)) {
        return 'Connected';
    }
    if (statusCode && statusCode >= 400) {
        return `Error ${statusCode}`;
    }
    return 'Pending';
}

function getStatusClass(status) {
    if (!status) return 'status-unknown';
    if (status.startsWith('Error')) return 'status-4xx';
    if (status === 'Connected') return 'status-2xx';
    if (status === 'Upgrading') return 'status-3xx';
    if (status === 'Polling') return 'status-unknown';
    return 'status-unknown';
}

function formatTimestamp(ts) {
    if (!ts) return '';
    const date = new Date(ts * 1000);
    return date.toLocaleTimeString();
}

// Load WebSocket connections from flows
function loadWebSocketConnections() {
    // Start with existing connections to preserve closed WebSockets
    const connectionMap = new Map();
    
    // Add existing connections to the map to preserve them
    wsConnections.forEach(conn => {
        connectionMap.set(conn.id, { ...conn });
    });

    console.log('[WEBSOCKET] Checking', flowsData.length, 'flows for WebSocket connections');
    console.log('[WEBSOCKET] Preserving', connectionMap.size, 'existing WebSocket connections');

    // Debug: log flows with status 101
    flowsData.forEach((flow, idx) => {
        if (flow.status_code === 101) {
            console.log(`[WEBSOCKET DEBUG] Flow ${idx + 1} with status 101:`, {
                id: flow.id,
                url: flow.url,
                method: flow.method,
                status_code: flow.status_code,
                is_websocket: flow.is_websocket,
                has_messages: (flow.ws_messages || flow.messages || []).length > 0
            });
        }
    });

    flowsData.forEach(flow => {
        const isNativeWebSocket = isWebSocketFlow(flow);
        const socketIoInfo = !isNativeWebSocket ? getSocketIoInfo(flow) : null;

        if (isNativeWebSocket) {
            console.log('[WEBSOCKET] Found native WebSocket flow:', flow.id, flow.url, 'is_websocket:', flow.is_websocket, 'status:', flow.status_code);
        }

        if (!isNativeWebSocket && !socketIoInfo) {
            return;
        }

        const key = isNativeWebSocket
            ? (flow.id || flow.flow_id || `${flow.url || 'ws'}-${flow.timestamp_start || Date.now()}`)
            : (socketIoInfo.sid || socketIoInfo.url || flow.id);

        if (!connectionMap.has(key)) {
            connectionMap.set(key, {
                id: key,
                type: isNativeWebSocket ? 'native' : 'socketio',
                url: isNativeWebSocket ? (flow.url || flow.request?.url || 'Unknown URL') : socketIoInfo.url,
                displayUrl: isNativeWebSocket ? (flow.url || flow.request?.url || 'Unknown URL') : (socketIoInfo.displayUrl || socketIoInfo.rawUrl || socketIoInfo.url),
                timestamp_start: socketIoInfo?.timestamp || flow.timestamp_start || flow.request?.timestamp_start || Date.now() / 1000,
                latest_timestamp: socketIoInfo?.timestamp || flow.timestamp_start || flow.request?.timestamp_start || Date.now() / 1000,
                status_code: flow.status_code ?? flow.response?.status_code ?? null,
                messages: isNativeWebSocket ? getWebSocketMessages(flow) : [],
                socketIo: socketIoInfo
                    ? {
                        sid: socketIoInfo.sid,
                        transports: new Set([socketIoInfo.transport || 'polling']),
                        polls: [{
                            id: flow.id,
                            url: flow.url,
                            method: flow.method,
                            timestamp: socketIoInfo.timestamp,
                            status_code: flow.status_code ?? flow.response?.status_code ?? null,
                            transport: socketIoInfo.transport || 'polling'
                        }],
                        query: socketIoInfo.query,
                        connected: false,
                        lastError: null
                    }
                    : null
            });
        } else {
            const connection = connectionMap.get(key);
            const ts = socketIoInfo?.timestamp || flow.timestamp_start || flow.request?.timestamp_start || flow.timestamp || Date.now() / 1000;
            connection.timestamp_start = Math.min(connection.timestamp_start, ts);
            connection.latest_timestamp = Math.max(connection.latest_timestamp || 0, ts);

            if (!connection.displayUrl && socketIoInfo?.displayUrl) {
                connection.displayUrl = socketIoInfo.displayUrl;
            }

            const statusCandidate = flow.status_code ?? flow.response?.status_code ?? null;
            if (statusCandidate !== null && statusCandidate !== undefined) {
                connection.status_code = statusCandidate;
            }

            if (isNativeWebSocket) {
                const messages = getWebSocketMessages(flow);
                // Merge messages, keeping the most complete set
                if (messages.length > 0) {
                    // Create a map of existing messages by content to avoid duplicates
                    const existingMessagesMap = new Map();
                    (connection.messages || []).forEach(msg => {
                        const msgKey = `${msg.direction}-${msg.content}`;
                        existingMessagesMap.set(msgKey, msg);
                    });
                    
                    // Add new messages
                    messages.forEach(msg => {
                        const msgKey = `${msg.direction}-${msg.content}`;
                        if (!existingMessagesMap.has(msgKey)) {
                            existingMessagesMap.set(msgKey, msg);
                        }
                    });
                    
                    connection.messages = Array.from(existingMessagesMap.values());
                }
            } else if (connection.socketIo && socketIoInfo) {
                // Reconstruct transports Set if needed
                if (!(connection.socketIo.transports instanceof Set)) {
                    connection.socketIo.transports = new Set(connection.socketIo.transportsArray || []);
                }
                connection.socketIo.transports.add(socketIoInfo.transport || 'polling');
                
                // Check if this poll already exists
                const pollExists = connection.socketIo.polls.some(p => p.id === flow.id);
                if (!pollExists) {
                    connection.socketIo.polls.push({
                        id: flow.id,
                        url: flow.url,
                        method: flow.method,
                        timestamp: ts,
                        status_code: statusCandidate,
                        transport: socketIoInfo.transport || 'polling'
                    });
                }
                if (socketIoInfo.transport === 'websocket' && statusCandidate === 101) {
                    connection.socketIo.connected = true;
                }
                if (statusCandidate && statusCandidate >= 400) {
                    connection.socketIo.lastError = statusCandidate;
                }
            }
        }
    });

    wsConnections = Array.from(connectionMap.values())
        .map(conn => {
            conn.messageCount = conn.type === 'native'
                ? (Array.isArray(conn.messages) ? conn.messages.length : 0)
                : (conn.socketIo?.polls?.length || 0);

            if (conn.socketIo) {
                conn.socketIo.transportsArray = Array.from(conn.socketIo.transports || []);
                delete conn.socketIo.transports;
            }

            conn.status = determineWebSocketStatus(conn);
            conn.statusClass = getStatusClass(conn.status);
            conn.displayTimestamp = conn.latest_timestamp || conn.timestamp_start || 0;
            return conn;
        })
        .sort((a, b) => (b.displayTimestamp || 0) - (a.displayTimestamp || 0));

    console.log(`[WEBSOCKET] Found ${wsConnections.length} WebSocket connections (${wsConnections.length - (flowsData.filter(f => isWebSocketFlow(f) || getSocketIoInfo(f)).length)} preserved from previous session)`);
    renderWebSocketList();
}

// Render WebSocket connections list
function renderWebSocketList() {
    const wsList = document.getElementById('ws-list');
    if (!wsList) return;

    // Filter by search term
    let filtered = wsConnections;
    if (wsSearchTerm) {
        const term = wsSearchTerm.toLowerCase();
        filtered = wsConnections.filter(ws => {
            const url = (ws.url || ws.request?.url || '').toLowerCase();
            const sid = ws.socketIo?.sid ? ws.socketIo.sid.toLowerCase() : '';
            return url.includes(term) || sid.includes(term);
        });
    }

    if (filtered.length === 0) {
        wsList.innerHTML = '<div style="padding: 40px; text-align: center; color: #888;">No WebSocket connections found</div>';
        return;
    }

    wsList.innerHTML = filtered.map(ws => {
        const id = ws.id || ws.flow_id || '';
        const fullUrl = ws.displayUrl || ws.socketIo?.polls?.[0]?.url || ws.url || ws.request?.url || 'Unknown URL';
        const shortUrl = fullUrl.replace(/^https?:\/\//i, '');
        const timeStr = formatTimestamp(ws.displayTimestamp);
        const messageCount = ws.messageCount || 0;
        const status = ws.status || 'Pending';
        const statusClass = ws.statusClass || 'status-unknown';
        const typeBadge = ws.type === 'socketio'
            ? '<span style="margin-left: 6px; font-size: 10px; text-transform: uppercase; color: #ff9800; font-weight: 600;">Socket.IO</span>'
            : '';
        const isSelected = selectedWsId === id;
        const countLabel = ws.type === 'socketio'
            ? `${messageCount} ${messageCount === 1 ? 'poll' : 'polls'}`
            : `${messageCount} msg`;

        return `
            <div class="flow-item ${isSelected ? 'selected' : ''}" data-ws-id="${id}" style="background: ${isSelected ? '#e3f2fd' : 'white'};">
                <div style="text-align: center;">
                    <span class="${statusClass}" style="padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; display: inline-block;">${status}</span>
                </div>
                <div class="flow-url" title="${escapeHtml(fullUrl)}">
                    ${escapeHtml(shortUrl)}${typeBadge}
                </div>
                <div class="flow-time">${timeStr}</div>
                <div style="font-size: 12px; color: #666; text-align: right;">${countLabel}</div>
            </div>
        `;
    }).join('');

    wsList.querySelectorAll('.flow-item').forEach(item => {
        item.addEventListener('click', () => {
            const wsId = item.dataset.wsId;
            selectWebSocket(wsId);
        });
    });
}

// Select a WebSocket connection
function selectWebSocket(wsId) {
    selectedWsId = wsId;
    renderWebSocketList();
    renderWebSocketDetails(wsId);
}

// Render WebSocket details
function renderWebSocketDetails(wsId) {
    const detailContent = document.getElementById('ws-detail-content');
    if (!detailContent) return;

    const ws = wsConnections.find(w => (w.id || w.flow_id) === wsId);
    if (!ws) {
        detailContent.innerHTML = '<div style="padding: 20px; color: #666; text-align: center;">WebSocket connection not found</div>';
        return;
    }

    // Get active tab
    const activeTab = document.querySelector('[data-ws-tab].active');
    const tabName = activeTab ? activeTab.dataset.wsTab : 'overview';

    switch (tabName) {
        case 'overview':
            if (ws.type === 'socketio') {
                renderSocketIoOverview(ws, detailContent);
            } else {
                renderWebSocketOverview(ws, detailContent);
            }
            break;
        case 'messages':
            if (ws.type === 'socketio') {
                renderSocketIoMessages(ws, detailContent);
            } else {
                renderWebSocketMessages(ws, detailContent);
            }
            break;
        case 'handshake':
            if (ws.type === 'socketio') {
                renderSocketIoHandshake(ws, detailContent);
            } else {
                renderWebSocketHandshake(ws, detailContent);
            }
            break;
        case 'analysis':
            if (ws.type === 'socketio') {
                renderSocketIoAnalysis(ws, detailContent);
            } else {
                renderWebSocketAnalysis(ws, detailContent);
            }
            break;
    }
}

// Render WebSocket overview
function renderWebSocketOverview(ws, container) {
    const url = ws.displayUrl || ws.socketIo?.polls?.[0]?.url || ws.url || ws.request?.url || 'Unknown URL';
    const timestamp = ws.timestamp_start || ws.request?.timestamp_start || ws.timestamp || Date.now() / 1000;
    const date = new Date(timestamp * 1000);
    const messages = getWebSocketMessages(ws);
    const messageCount = Array.isArray(messages) ? messages.length : 0;

    let status = 'Unknown';
    let statusColor = '#666';
    const statusCode = ws.status_code ?? ws.response?.status_code;
    if (statusCode === 101 || (!statusCode && messageCount > 0)) {
        status = 'Connected';
        statusColor = '#4caf50';
    } else if (statusCode) {
        status = `Error ${statusCode}`;
        statusColor = '#f44336';
    } else {
        status = 'Pending';
        statusColor = '#ff9800';
    }

    container.innerHTML = `
        <div style="padding: 20px;">
            <h3 style="margin: 0 0 20px 0; color: #333;">WebSocket Connection Overview</h3>
            
            <div style="background: white; border-radius: 8px; padding: 16px; margin-bottom: 16px; border: 1px solid var(--border-color);">
                <div style="display: grid; grid-template-columns: 150px 1fr; gap: 12px; margin-bottom: 12px;">
                    <div style="font-weight: 600; color: #666;">URL:</div>
                    <div style="word-break: break-all; font-family: monospace; font-size: 13px;">${escapeHtml(url)}</div>
                </div>
                <div style="display: grid; grid-template-columns: 150px 1fr; gap: 12px; margin-bottom: 12px;">
                    <div style="font-weight: 600; color: #666;">Status:</div>
                    <div><span style="color: ${statusColor}; font-weight: 600;">${status}</span></div>
                </div>
                <div style="display: grid; grid-template-columns: 150px 1fr; gap: 12px; margin-bottom: 12px;">
                    <div style="font-weight: 600; color: #666;">Timestamp:</div>
                    <div>${date.toLocaleString()}</div>
                </div>
                <div style="display: grid; grid-template-columns: 150px 1fr; gap: 12px; margin-bottom: 12px;">
                    <div style="font-weight: 600; color: #666;">Messages:</div>
                    <div>${messageCount}</div>
                </div>
            </div>
            
            <div style="background: white; border-radius: 8px; padding: 16px; border: 1px solid var(--border-color);">
                <h4 style="margin: 0 0 12px 0; color: #333;">Quick Stats</h4>
                <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px;">
                    <div>
                        <div style="font-size: 12px; color: #666; margin-bottom: 4px;">Client Messages</div>
                        <div style="font-size: 18px; font-weight: 600; color: #2196f3;">
                            ${messages.filter(m => m.from_client !== false && m.direction !== 'server').length}
                        </div>
                    </div>
                    <div>
                        <div style="font-size: 12px; color: #666; margin-bottom: 4px;">Server Messages</div>
                        <div style="font-size: 18px; font-weight: 600; color: #4caf50;">
                            ${messages.filter(m => m.from_client === false || m.direction === 'server').length}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
}

// Render WebSocket messages
function renderWebSocketMessages(ws, container) {
    const messages = getWebSocketMessages(ws);

    if (!Array.isArray(messages) || messages.length === 0) {
        container.innerHTML = '<div style="padding: 40px; text-align: center; color: #888;">No messages captured</div>';
        return;
    }

    container.innerHTML = `
        <div style="padding: 20px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
                <h3 style="margin: 0; color: #333;">Messages (${messages.length})</h3>
            </div>
            <div style="display: flex; flex-direction: column; gap: 12px;">
                ${messages.map((msg, idx) => {
        const isClient = msg.from_client !== false && msg.direction !== 'server';
        const direction = isClient ? 'Client → Server' : 'Server → Client';
        const directionColor = isClient ? '#2196f3' : '#4caf50';
        const content = msg.content || msg.text || msg.data || '';
        const isText = msg.type === 'text' || typeof content === 'string';
        const timestamp = msg.timestamp || (ws.timestamp_start || 0) + (idx * 0.001);
        const date = new Date(timestamp * 1000);
        const size = typeof content === 'string' ? content.length : (content.byteLength || 0);

        // Try to parse JSON if it's text
        let parsedContent = null;
        let isJson = false;
        if (isText && typeof content === 'string' && content.trim()) {
            const trimmed = content.trim();
            if ((trimmed.startsWith('{') && trimmed.endsWith('}')) ||
                (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
                try {
                    parsedContent = JSON.parse(content);
                    isJson = true;
                } catch (e) {
                    // Not valid JSON
                }
            }
        }

        return `
                        <div style="background: white; border-radius: 8px; padding: 16px; border: 1px solid var(--border-color); border-left: 4px solid ${directionColor};">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                                <div>
                                    <span style="color: ${directionColor}; font-weight: 600; font-size: 13px;">${direction}</span>
                                    <span style="margin-left: 12px; font-size: 11px; color: #666;">${date.toLocaleTimeString()}</span>
                                </div>
                                <div style="font-size: 11px; color: #666;">
                                    ${isText ? 'Text' : 'Binary'} • ${size} bytes
                                    ${isJson ? ' • <span style="color: #4caf50; font-weight: 600;">JSON</span>' : ''}
                                </div>
                            </div>
                            <div style="background: #f5f5f5; border-radius: 4px; padding: 12px; font-family: 'Fira Code', monospace; font-size: 12px; max-height: 400px; overflow-y: auto; word-break: break-all;">
                                ${isJson && parsedContent
                ? `<pre style="margin: 0; white-space: pre-wrap; word-wrap: break-word; color: #333;">${escapeHtml(JSON.stringify(parsedContent, null, 2))}</pre>`
                : isText
                    ? `<pre style="margin: 0; white-space: pre-wrap; word-wrap: break-word; color: #333;">${escapeHtml(String(content))}</pre>`
                    : `<pre style="margin: 0; white-space: pre-wrap;">${formatBinaryData(content)}</pre>`
            }
                            </div>
                        </div>
                    `;
    }).join('')}
            </div>
        </div>
    `;
}

// Render WebSocket handshake
function renderWebSocketHandshake(ws, container) {
    const request = ws.request || {};
    const response = ws.response || {};
    let reqHeaders = request.headers || {};
    let resHeaders = response.headers || {};

    // Convert Headers object to plain object if needed
    if (reqHeaders.get && typeof reqHeaders.get === 'function') {
        const temp = {};
        reqHeaders.forEach((value, key) => {
            temp[key] = value;
        });
        reqHeaders = temp;
    }
    if (resHeaders.get && typeof resHeaders.get === 'function') {
        const temp = {};
        resHeaders.forEach((value, key) => {
            temp[key] = value;
        });
        resHeaders = temp;
    }

    const reqHeadersList = Object.entries(reqHeaders);
    const resHeadersList = Object.entries(resHeaders);

    container.innerHTML = `
        <div style="padding: 20px;">
            <h3 style="margin: 0 0 20px 0; color: #333;">WebSocket Handshake</h3>
            
            <div style="background: white; border-radius: 8px; padding: 16px; margin-bottom: 16px; border: 1px solid var(--border-color);">
                <h4 style="margin: 0 0 12px 0; color: #333;">Request Headers</h4>
                <div style="background: #f5f5f5; border-radius: 4px; padding: 12px; font-family: 'Fira Code', monospace; font-size: 12px;">
                    ${reqHeadersList.length > 0 ? reqHeadersList.map(([key, value]) =>
        `<div style="margin-bottom: 4px;"><strong>${escapeHtml(key)}:</strong> ${escapeHtml(String(value))}</div>`
    ).join('') : '<div style="color: #888;">No headers available</div>'}
                </div>
            </div>
            
            <div style="background: white; border-radius: 8px; padding: 16px; border: 1px solid var(--border-color);">
                <h4 style="margin: 0 0 12px 0; color: #333;">Response Headers</h4>
                <div style="background: #f5f5f5; border-radius: 4px; padding: 12px; font-family: 'Fira Code', monospace; font-size: 12px;">
                    ${resHeadersList.length > 0 ? resHeadersList.map(([key, value]) =>
        `<div style="margin-bottom: 4px;"><strong>${escapeHtml(key)}:</strong> ${escapeHtml(String(value))}</div>`
    ).join('') : '<div style="color: #888;">No headers available</div>'}
                </div>
            </div>
        </div>
    `;
}

// Render WebSocket analysis
function renderWebSocketAnalysis(ws, container) {
    const messages = getWebSocketMessages(ws);
    const clientMessages = messages.filter(m => m.from_client !== false && m.direction !== 'server');
    const serverMessages = messages.filter(m => m.from_client === false || m.direction === 'server');

    // Analyze for potential issues
    const issues = [];

    // Check for authentication in messages
    const hasAuth = messages.some(m => {
        const content = String(m.content || m.text || m.data || '').toLowerCase();
        return content.includes('token') || content.includes('auth') || content.includes('password') || content.includes('api_key');
    });

    if (hasAuth) {
        issues.push({
            severity: 'high',
            title: 'Potential Authentication Data',
            description: 'WebSocket messages may contain authentication tokens or credentials.'
        });
    }

    // Check for large messages
    const largeMessages = messages.filter(m => {
        const content = m.content || m.text || m.data || '';
        const size = typeof content === 'string' ? content.length : (content.byteLength || 0);
        return size > 10000;
    });

    if (largeMessages.length > 0) {
        issues.push({
            severity: 'medium',
            title: 'Large Messages Detected',
            description: `${largeMessages.length} message(s) exceed 10KB, which may indicate data exfiltration.`
        });
    }

    container.innerHTML = `
        <div style="padding: 20px;">
            <h3 style="margin: 0 0 20px 0; color: #333;">Security Analysis</h3>
            
            <div style="background: white; border-radius: 8px; padding: 16px; margin-bottom: 16px; border: 1px solid var(--border-color);">
                <h4 style="margin: 0 0 12px 0; color: #333;">Statistics</h4>
                <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px;">
                    <div>
                        <div style="font-size: 12px; color: #666; margin-bottom: 4px;">Total Messages</div>
                        <div style="font-size: 24px; font-weight: 600; color: #333;">${messages.length}</div>
                    </div>
                    <div>
                        <div style="font-size: 12px; color: #666; margin-bottom: 4px;">Client Messages</div>
                        <div style="font-size: 24px; font-weight: 600; color: #2196f3;">${clientMessages.length}</div>
                    </div>
                    <div>
                        <div style="font-size: 12px; color: #666; margin-bottom: 4px;">Server Messages</div>
                        <div style="font-size: 24px; font-weight: 600; color: #4caf50;">${serverMessages.length}</div>
                    </div>
                    <div>
                        <div style="font-size: 12px; color: #666; margin-bottom: 4px;">Issues Found</div>
                        <div style="font-size: 24px; font-weight: 600; color: ${issues.length > 0 ? '#f44336' : '#4caf50'};">${issues.length}</div>
                    </div>
                </div>
            </div>
            
            ${issues.length > 0 ? `
                <div style="background: white; border-radius: 8px; padding: 16px; border: 1px solid var(--border-color);">
                    <h4 style="margin: 0 0 12px 0; color: #333;">Potential Issues</h4>
                    <div style="display: flex; flex-direction: column; gap: 12px;">
                        ${issues.map(issue => {
        const severityColor = issue.severity === 'high' ? '#f44336' : '#ff9800';
        return `
                                <div style="border-left: 4px solid ${severityColor}; padding-left: 12px;">
                                    <div style="font-weight: 600; color: ${severityColor}; margin-bottom: 4px;">${issue.title}</div>
                                    <div style="font-size: 13px; color: #666;">${issue.description}</div>
                                </div>
                            `;
    }).join('')}
                    </div>
                </div>
            ` : ''}
        </div>
    `;
}

function renderSocketIoOverview(ws, container) {
    const info = ws.socketIo || {};
    const transports = info.transportsArray && info.transportsArray.length > 0
        ? info.transportsArray.join(', ')
        : 'Unknown';
    const pollCount = info.polls?.length || 0;
    const timestamp = ws.timestamp_start || ws.displayTimestamp || Date.now() / 1000;
    const date = new Date(timestamp * 1000);
    const sid = info.sid || 'N/A';

    container.innerHTML = `
        <div style="padding: 20px;">
            <h3 style="margin: 0 0 20px 0; color: #333;">Socket.IO Connection Overview</h3>

            <div style="background: white; border-radius: 8px; padding: 16px; margin-bottom: 16px; border: 1px solid var(--border-color);">
                <div style="display: grid; grid-template-columns: 150px 1fr; gap: 12px; margin-bottom: 12px;">
                    <div style="font-weight: 600; color: #666;">Endpoint:</div>
                    <div style="word-break: break-all; font-family: monospace; font-size: 13px;">${escapeHtml(ws.displayUrl || ws.url || 'Unknown URL')}</div>
                </div>
                <div style="display: grid; grid-template-columns: 150px 1fr; gap: 12px; margin-bottom: 12px;">
                    <div style="font-weight: 600; color: #666;">Session ID:</div>
                    <div>${escapeHtml(sid)}</div>
                </div>
                <div style="display: grid; grid-template-columns: 150px 1fr; gap: 12px; margin-bottom: 12px;">
                    <div style="font-weight: 600; color: #666;">Active transport(s):</div>
                    <div>${escapeHtml(transports)}</div>
                </div>
                <div style="display: grid; grid-template-columns: 150px 1fr; gap: 12px; margin-bottom: 12px;">
                    <div style="font-weight: 600; color: #666;">Last seen:</div>
                    <div>${date.toLocaleString()}</div>
                </div>
                <div style="display: grid; grid-template-columns: 150px 1fr; gap: 12px;">
                    <div style="font-weight: 600; color: #666;">HTTP polls:</div>
                    <div>${pollCount}</div>
                </div>
            </div>

            <div style="background: #fff7e6; border: 1px solid #ffe0b2; border-radius: 8px; padding: 16px; color: #8c6d1f;">
                <strong>Notice:</strong> this Socket.IO client is currently communicating via HTTP ${escapeHtml(transports || 'polling')}.
                WebSocket upgrades will appear automatically once the browser switches to the \`websocket\` transport.
            </div>
        </div>
    `;
}

function renderSocketIoMessages(ws, container) {
    const info = ws.socketIo || {};
    const polls = info.polls || [];

    if (!Array.isArray(polls) || polls.length === 0) {
        container.innerHTML = '<div style="padding: 40px; text-align: center; color: #888;">No Socket.IO polling requests captured yet.</div>';
        return;
    }

    container.innerHTML = `
        <div style="padding: 20px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
                <h3 style="margin: 0; color: #333;">Polling Requests (${polls.length})</h3>
                <div style="font-size: 12px; color: #666;">SID: ${escapeHtml(info.sid || 'N/A')}</div>
            </div>
            <div style="display: flex; flex-direction: column; gap: 10px;">
                ${polls.map(poll => {
        const date = poll.timestamp ? new Date(poll.timestamp * 1000) : null;
        const timeLabel = date ? date.toLocaleTimeString() : '-';
        const status = poll.status_code != null ? poll.status_code : '-';
        const statusClass = status >= 400 ? 'status-4xx' : status === 200 ? 'status-2xx' : 'status-unknown';
        return `
                        <div style="background: white; border-radius: 8px; padding: 14px; border: 1px solid var(--border-color);">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                                <div style="font-weight: 600; color: #333;">
                                    ${escapeHtml(poll.method || 'GET')} ▸ ${escapeHtml(poll.transport || 'polling')}
                                </div>
                                <div style="font-size: 12px; color: #666;">${timeLabel}</div>
                            </div>
                            <div style="font-size: 12px; color: #555; margin-bottom: 6px; word-break: break-all;">
                                ${escapeHtml(poll.url || ws.url || '')}
                            </div>
                            <div style="font-size: 12px; display: flex; align-items: center; gap: 8px;">
                                <span class="${statusClass}" style="padding: 2px 6px; border-radius: 4px;">Status ${status}</span>
                                <span style="color: #999;">Flow ID: ${poll.id}</span>
                            </div>
                        </div>
                    `;
    }).join('')}
            </div>
        </div>
    `;
}

function renderSocketIoHandshake(ws, container) {
    const info = ws.socketIo || {};
    const transports = info.transportsArray && info.transportsArray.length > 0
        ? info.transportsArray.join(', ')
        : 'Unknown';

    container.innerHTML = `
        <div style="padding: 20px;">
            <h3 style="margin: 0 0 16px 0; color: #333;">Handshake Information</h3>
            <div style="background: white; border-radius: 8px; padding: 16px; border: 1px solid var(--border-color);">
                <p style="margin: 0; color: #555;">
                    This connection is using Socket.IO with the <strong>${escapeHtml(transports)}</strong> transport.
                    When the client upgrades to the <code>websocket</code> transport, the full handshake (with HTTP 101 upgrade) will appear here automatically.
                </p>
                <p style="margin: 12px 0 0 0; font-size: 13px; color: #888;">
                    If the upgrade never happens, ensure that WebSocket traffic is allowed through the proxy and that the target application supports WebSocket mode.
                </p>
            </div>
        </div>
    `;
}

function renderSocketIoAnalysis(ws, container) {
    const info = ws.socketIo || {};
    const pollCount = info.polls?.length || 0;
    const transports = info.transportsArray || [];
    const hasWebSocketAttempt = transports.includes('websocket');
    const hasPolling = transports.includes('polling');

    container.innerHTML = `
        <div style="padding: 20px;">
            <h3 style="margin: 0 0 20px 0; color: #333;">Socket.IO Transport Analysis</h3>
            <div style="background: white; border-radius: 8px; padding: 16px; border: 1px solid var(--border-color);">
                <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px;">
                    <div>
                        <div style="font-size: 12px; color: #666; margin-bottom: 4px;">Total HTTP polls</div>
                        <div style="font-size: 20px; font-weight: 600; color: #333;">${pollCount}</div>
                    </div>
                    <div>
                        <div style="font-size: 12px; color: #666; margin-bottom: 4px;">Transports seen</div>
                        <div style="font-size: 20px; font-weight: 600; color: #333;">${escapeHtml(transports.join(', ') || 'None')}</div>
                    </div>
                    <div>
                        <div style="font-size: 12px; color: #666; margin-bottom: 4px;">WebSocket upgrade</div>
                        <div style="font-size: 20px; font-weight: 600; color: ${hasWebSocketAttempt ? '#4caf50' : '#ff9800'};">
                            ${hasWebSocketAttempt ? 'Attempted' : 'Not attempted'}
                        </div>
                    </div>
                    <div>
                        <div style="font-size: 12px; color: #666; margin-bottom: 4px;">Current mode</div>
                        <div style="font-size: 20px; font-weight: 600; color: ${hasPolling ? '#2196f3' : '#333'};">
                            ${hasPolling ? 'Polling' : 'Unknown'}
                        </div>
                    </div>
                </div>
            </div>
            <div style="margin-top: 16px; font-size: 13px; color: #555;">
                ${hasWebSocketAttempt
            ? 'A WebSocket upgrade was attempted. If it failed, check proxy TLS certificates or CSP restrictions on the target application.'
            : 'The client is still operating in long-polling mode. Some applications delay the WebSocket upgrade until certain conditions are met.'}
            </div>
        </div>
    `;
}

// Helper function to format binary data
function formatBinaryData(data) {
    if (typeof data === 'string') {
        return data;
    }
    if (data instanceof ArrayBuffer) {
        const bytes = new Uint8Array(data);
        return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(' ');
    }
    if (Array.isArray(data)) {
        return data.map(b => b.toString(16).padStart(2, '0')).join(' ');
    }
    return String(data);
}

// Initialize WebSocket view event listeners
function initWebSocketView() {
    // Search input
    const wsSearch = document.getElementById('ws-search');
    if (wsSearch) {
        wsSearch.addEventListener('input', (e) => {
            wsSearchTerm = e.target.value;
            renderWebSocketList();
        });
    }

    // Tab switching
    const wsTabs = document.querySelectorAll('[data-ws-tab]');
    wsTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            wsTabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            if (selectedWsId) {
                renderWebSocketDetails(selectedWsId);
            }
        });
    });

    // Clear button
    const wsClearBtn = document.getElementById('ws-clear-btn');
    if (wsClearBtn) {
        wsClearBtn.addEventListener('click', () => {
            wsConnections = [];
            selectedWsId = null;
            renderWebSocketList();
            const detailContent = document.getElementById('ws-detail-content');
            if (detailContent) {
                detailContent.innerHTML = '<div style="padding: 20px; color: #666; text-align: center;">Select a WebSocket connection to view details</div>';
            }
        });
    }

    // Export button
    const wsExportBtn = document.getElementById('ws-export-btn');
    if (wsExportBtn) {
        wsExportBtn.addEventListener('click', () => {
            const dataStr = JSON.stringify(wsConnections, null, 2);
            const dataBlob = new Blob([dataStr], { type: 'application/json' });
            const url = URL.createObjectURL(dataBlob);
            const link = document.createElement('a');
            link.href = url;
            link.download = `websockets_${Date.now()}.json`;
            link.click();
            URL.revokeObjectURL(url);
        });
    }
}

// === SCOPE MANAGEMENT ===
let scopeConfig = {
    enabled: false,
    mode: 'include', // 'include' or 'exclude'
    patterns: []
};

// Charger le scope depuis localStorage
function loadScope() {
    try {
        const saved = localStorage.getItem('kittyproxy_scope');
        if (saved) {
            scopeConfig = JSON.parse(saved);
            updateScopeStatus();
        }
    } catch (e) {
        console.error('[SCOPE] Error loading scope:', e);
    }
}

// Sauvegarder le scope dans localStorage
async function saveScopeConfig() {
    try {
        localStorage.setItem('kittyproxy_scope', JSON.stringify(scopeConfig));
        updateScopeStatus();
        // Envoyer le scope au serveur pour filtrage côté serveur
        await sendScopeToServer();
    } catch (e) {
        console.error('[SCOPE] Error saving scope:', e);
    }
}

// Envoyer le scope au serveur
async function sendScopeToServer() {
    try {
        const response = await fetch(`${API_BASE}/scope`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(scopeConfig)
        });
        if (!response.ok) {
            console.error('[SCOPE] Failed to send scope to server');
            return;
        }
        const data = await response.json();
        if (data.removed_flows > 0) {
            console.log(`[SCOPE] Removed ${data.removed_flows} flow(s) that don't match the scope`);
        }
        return data;
    } catch (e) {
        console.error('[SCOPE] Error sending scope to server:', e);
    }
}

// Charger le scope dans la modal
function loadScopeToModal() {
    const modeInclude = document.getElementById('scope-mode-include');
    const modeExclude = document.getElementById('scope-mode-exclude');
    const entries = document.getElementById('scope-entries');
    
    if (modeInclude && modeExclude && entries) {
        if (scopeConfig.mode === 'include') {
            modeInclude.checked = true;
        } else {
            modeExclude.checked = true;
        }
        entries.value = scopeConfig.patterns.join('\n');
        updateScopeStatus();
    }
}

// Sauvegarder le scope depuis la modal
async function saveScope() {
    const modeInclude = document.getElementById('scope-mode-include');
    const entries = document.getElementById('scope-entries');
    
    if (!entries) return;
    
    const patterns = entries.value
        .split('\n')
        .map(line => line.trim())
        .filter(line => line.length > 0);
    
    scopeConfig.mode = modeInclude && modeInclude.checked ? 'include' : 'exclude';
    scopeConfig.patterns = patterns;
    scopeConfig.enabled = patterns.length > 0;
    
    // Sauvegarder et envoyer au serveur
    await saveScopeConfig();
    
    // Le serveur supprime automatiquement les flows hors scope
    // Rafraîchir la liste des flows
    if (currentViewId === 'analyze') {
        // Recharger les flows pour refléter les changements
        await fetchFlows();
        renderFlowList();
    }
    
    closeModal('modal-scope');
    
    // Afficher un message de confirmation
    showToast(`Scope ${scopeConfig.enabled ? 'enabled' : 'disabled'}. ${patterns.length} pattern(s) configured.`, 'success');
}

// Effacer le scope
async function clearScope() {
    scopeConfig.enabled = false;
    scopeConfig.patterns = [];
    scopeConfig.mode = 'include';
    
    const entries = document.getElementById('scope-entries');
    if (entries) {
        entries.value = '';
    }
    
    // Sauvegarder et envoyer au serveur
    await saveScopeConfig();
    
    // Rafraîchir la liste des flows si on est dans la vue Analyze
    if (currentViewId === 'analyze') {
        await fetchFlows();
        renderFlowList();
    }
    
    showToast('Scope cleared', 'success');
}

// Exposer les fonctions sur window pour l'accès depuis les attributs onclick
window.saveScope = saveScope;
window.clearScope = clearScope;

// Mettre à jour le statut du scope dans la modal
function updateScopeStatus() {
    const statusDiv = document.getElementById('scope-status');
    const statusText = document.getElementById('scope-status-text');
    
    if (!statusDiv || !statusText) return;
    
    if (scopeConfig.enabled && scopeConfig.patterns.length > 0) {
        statusDiv.style.display = 'block';
        const modeText = scopeConfig.mode === 'include' ? 'Include' : 'Exclude';
        statusText.textContent = `${modeText} mode: ${scopeConfig.patterns.length} pattern(s) active`;
        statusDiv.style.background = '#e3f2fd';
    } else {
        statusDiv.style.display = 'block';
        statusText.textContent = 'Scope disabled - all requests will be recorded';
        statusDiv.style.background = '#f5f5f5';
    }
}

// Vérifier si une URL correspond au scope
function isInScope(url) {
    if (!scopeConfig.enabled || scopeConfig.patterns.length === 0) {
        return true; // Si le scope n'est pas activé, accepter toutes les requêtes
    }
    
    try {
        const urlObj = new URL(url);
        const hostname = urlObj.hostname;
        const pathname = urlObj.pathname;
        const fullUrl = url;
        
        for (const pattern of scopeConfig.patterns) {
            if (matchesPattern(pattern, hostname, pathname, fullUrl)) {
                return scopeConfig.mode === 'include';
            }
        }
        
        // Si aucun pattern ne correspond
        return scopeConfig.mode === 'exclude';
    } catch (e) {
        // Si l'URL n'est pas valide, l'accepter par défaut
        return true;
    }
}

// Vérifier si un pattern correspond à une URL
function matchesPattern(pattern, hostname, pathname, fullUrl) {
    // Convertir le pattern wildcard en regex
    let regexPattern = pattern
        .replace(/\./g, '\\.')
        .replace(/\*/g, '.*')
        .replace(/\?/g, '.');
    
    // Tester sur le hostname
    if (new RegExp(`^${regexPattern}$`).test(hostname)) {
        return true;
    }
    
    // Tester sur le pathname
    if (new RegExp(`^${regexPattern}$`).test(pathname)) {
        return true;
    }
    
    // Tester sur l'URL complète
    if (new RegExp(`^${regexPattern}$`).test(fullUrl)) {
        return true;
    }
    
    // Tester si le pattern est dans l'URL
    if (fullUrl.includes(pattern.replace(/\*/g, ''))) {
        return true;
    }
    
    return false;
}

// Initialize on page load
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initWebSocketView);
} else {
    initWebSocketView();
}

// Mettre à jour l'apparence du bouton scope selon son état
function updateScopeButton() {
    const scopeBtn = document.getElementById('scope-btn');
    if (scopeBtn) {
        if (scopeConfig.enabled && scopeConfig.patterns.length > 0) {
            scopeBtn.style.background = '#e3f2fd';
            scopeBtn.style.borderColor = '#1976d2';
            scopeBtn.title = `Scope active: ${scopeConfig.mode} mode, ${scopeConfig.patterns.length} pattern(s)`;
        } else {
            scopeBtn.style.background = '';
            scopeBtn.style.borderColor = '';
            scopeBtn.title = 'Manage scope';
        }
    }
}

// Wrapper pour saveScopeConfig qui met à jour le bouton
const originalSaveScopeConfig = saveScopeConfig;
saveScopeConfig = function() {
    originalSaveScopeConfig();
    updateScopeButton();
};

// Wrapper pour loadScope qui met à jour le bouton
const originalLoadScope = loadScope;
loadScope = function() {
    originalLoadScope();
    updateScopeButton();
};

// Charger le scope au démarrage
loadScope();

// Hook into fetchFlows to update WebSocket list when flows are updated
const originalFetchFlows = fetchFlows;
