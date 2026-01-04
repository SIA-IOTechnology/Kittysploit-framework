// Main Application Logic
// URL du serveur SaaS pour les salons, chat, édition en temps réel
// Utiliser toujours le serveur local qui fait le proxy vers le SaaS (évite CORS et problèmes de load balancer)
const SERVER_URL = window.location.origin; // Utiliser le serveur local pour toutes les requêtes API
const SAAS_URL = window.KITTYCOLLAB_SERVER_URL || "https://collab.kittysploit.com"; // URL du SaaS pour Socket.IO uniquement
// URL locale pour les modules (toujours depuis le client local)
const LOCAL_API_URL = window.location.origin;
let socket = null;
let editor = null;
let currentModulePath = null;
let currentUsername = '';
let currentRoomId = '';
let isApplyingRemoteChange = false; // Flag to prevent infinite loops when applying remote changes
let displayedMessageIds = new Set(); // Track displayed message IDs to prevent duplicates
const MAX_CHAT_MESSAGES = 200; // Maximum number of messages to keep in DOM

// Initialize Application
document.addEventListener('DOMContentLoaded', () => {
    initApp();
    initResizer();
    initDragAndDrop();
});

function initApp() {
    // Check dependencies
    if (typeof io === 'undefined' || typeof require === 'undefined') {
        setTimeout(initApp, 100);
        return;
    }

    // Get session data
    currentUsername = sessionStorage.getItem('username');
    currentRoomId = sessionStorage.getItem('currentRoomId');

    if (!currentUsername || !currentRoomId) {
        window.location.href = '/';
        return;
    }

    // Update UI
    document.getElementById('currentUser').textContent = currentUsername;
    document.getElementById('roomInfo').textContent = '#' + currentRoomId;

    // Initialize Socket
    // Utiliser SAAS_URL pour Socket.IO (connexion directe nécessaire)
    console.log('Connecting to SocketIO server:', SAAS_URL);
    socket = io(SAAS_URL, {
        reconnection: true,
        reconnectionAttempts: 5,
        reconnectionDelay: 1000,
        transports: ['websocket', 'polling']
    });
    
    socket.on('connect', () => {
        console.log('SocketIO connected successfully');
    });
    
    socket.on('connect_error', (error) => {
        console.error('SocketIO connection error:', error);
        if (error.message.includes('ERR_NAME_NOT_RESOLVED')) {
            alert('Cannot resolve domain name. Please check:\n1. DNS configuration\n2. Domain name is correct\n3. Server is accessible\n\nTrying to connect to: ' + SERVER_URL);
        }
    });
    
    setupSocketHandlers();

    // Initialize Editor
    initMonaco();
}

function initResizer() {
    // Sidebar Resizer
    const sidebar = document.querySelector('.sidebar');
    const sidebarResizer = document.getElementById('sidebarResizer');

    let isResizingSidebar = false;

    // Sidebar Events
    sidebarResizer.addEventListener('mousedown', (e) => {
        isResizingSidebar = true;
        sidebarResizer.classList.add('active');
        document.body.classList.add('is-resizing', 'col-resize');
    });

    // Global Mouse Events
    document.addEventListener('mousemove', (e) => {
        if (isResizingSidebar) {
            const newWidth = e.clientX;
            if (newWidth > 150 && newWidth < 600) {
                sidebar.style.width = newWidth + 'px';
                document.documentElement.setProperty('--sidebar-width', newWidth + 'px');
                if (editor) editor.layout();
            }
        }
    });

    document.addEventListener('mouseup', () => {
        if (isResizingSidebar) {
            isResizingSidebar = false;
            sidebarResizer.classList.remove('active');
            document.body.classList.remove('is-resizing', 'col-resize', 'row-resize');
        }
    });
}

function initDragAndDrop() {
    const dropZone = document.querySelector('.sidebar');

    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    dropZone.addEventListener('dragenter', () => dropZone.classList.add('highlight'));
    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('highlight'));

    dropZone.addEventListener('drop', (e) => {
        dropZone.classList.remove('highlight');
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            handleFiles(files);
            switchTab('files');
        }
    });
}

async function createNewPythonFile() {
    const filename = prompt('Enter filename (without .py extension):', 'new_module');
    if (!filename) return;
    
    try {
        const res = await fetch(SERVER_URL + '/api/rooms/' + currentRoomId + '/files/create', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                filename: filename,
                username: currentUsername
            })
        });
        
        const data = await res.json();
        if (data.status === 'success') {
            // Reload files list
            await loadFiles();
            // Open the newly created file
            await openFile(data.file_id, data.filename);
            switchTab('files');
        } else {
            alert('Failed to create file: ' + data.message);
        }
    } catch (e) {
        alert('Failed to create file');
        console.error(e);
    }
}

function handleFiles(files) {
    const fileUpload = document.getElementById('fileUpload');
    const label = fileUpload.previousElementSibling;

    label.innerHTML = `<i class="fas fa-circle-notch fa-spin"></i> Uploading ${files.length} file(s)...`;

    let uploadedCount = 0;

    Array.from(files).forEach(file => {
        const formData = new FormData();
        formData.append('file', file);
        formData.append('username', currentUsername);

        fetch(SERVER_URL + '/api/rooms/' + currentRoomId + '/upload', {
            method: 'POST',
            body: formData
        })
            .then(res => res.json())
            .then(data => {
                uploadedCount++;
                if (uploadedCount === files.length) {
                    label.innerHTML = `<i class="fas fa-cloud-upload-alt"></i> Upload File`;
                    switchTab('files');
                }
            })
            .catch(err => {
                console.error(err);
                uploadedCount++;
                if (uploadedCount === files.length) {
                    label.innerHTML = `<i class="fas fa-cloud-upload-alt"></i> Upload File`;
                }
            });
    });
}

function initMonaco() {
    require.config({ paths: { vs: 'https://cdn.jsdelivr.net/npm/monaco-editor@0.45.0/min/vs' } });
    require(['vs/editor/editor.main'], function () {
        editor = monaco.editor.create(document.getElementById('editor'), {
            value: '',
            language: 'python',
            theme: 'vs-dark',
            automaticLayout: true,
            minimap: { enabled: true },
            fontSize: 14,
            fontFamily: "'Consolas', 'Monaco', monospace",
            padding: { top: 20 }
        });

        // Hide editor initially
        document.getElementById('editor').style.display = 'none';

        // Editor Events
        editor.onDidChangeModelContent((e) => {
            if (!currentModulePath && !currentFileId) return;
            
            // Ignore changes that come from applying remote operations
            if (isApplyingRemoteChange) return;

            // Only emit if change is local (not from socket)
            if (!e.isFlush) {
                e.changes.forEach(change => {
                    const operation = {
                        type: change.text ? 'insert' : 'delete',
                        position: change.rangeOffset,
                        text: change.text || '',
                        length: change.rangeLength
                    };

                    if (currentModulePath) {
                        socket.emit('edit_operation', {
                            module_path: currentModulePath,
                            operation: operation
                        });
                    } else if (currentFileId) {
                        socket.emit('file_edit_operation', {
                            file_id: currentFileId,
                            operation: operation
                        });
                    }
                });
            }
        });

        // Save Shortcut
        editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS, () => {
            saveCurrentModule();
        });
    });
}


function setupSocketHandlers() {
    socket.on('connect', () => {
        const token = sessionStorage.getItem('token') || '';
        socket.emit('join_room', {
            room_id: currentRoomId,
            username: currentUsername,
            token: token
        });
        document.querySelector('.status-dot').className = 'status-dot online';
        // Load room description when connected
        loadRoomDescription();
    });

    socket.on('disconnect', () => {
        document.querySelector('.status-dot').className = 'status-dot offline';
        // Optional: Show toast
    });

    socket.on('room_joined', () => {
        loadModules();
    });

    socket.on('error', (data) => {
        alert('Error: ' + data.message);
        window.location.href = '/rooms';
    });

    socket.on('room_deleted', (data) => {
        if (data.room_id === currentRoomId) {
            alert('This session has been closed by the host. You will be redirected to the session hub.');
            window.location.href = '/rooms';
        }
    });

    socket.on('room_deleted', (data) => {
        if (data.room_id === currentRoomId) {
            alert('This session has been closed by the host. You will be redirected to the session hub.');
            window.location.href = '/rooms';
        }
    });

    socket.on('room_description_updated', (data) => {
        // Update description display
        const descriptionContainer = document.getElementById('roomDescriptionContainer');
        const descriptionText = document.getElementById('roomDescriptionText');
        if (data.description && data.description.trim()) {
            if (descriptionContainer) {
                descriptionContainer.style.display = 'block';
                if (descriptionText) {
                    descriptionText.textContent = data.description;
                }
            }
        } else {
            if (descriptionContainer) {
                descriptionContainer.style.display = 'none';
            }
        }
    });

    socket.on('file_deleted', (data) => {
        // If the deleted file was open, clear the editor
        if (currentFileId === data.file_id) {
            currentFileId = null;
            editor.setValue('');
            document.getElementById('editorTitle').textContent = 'No file selected';
            document.getElementById('saveBtn').disabled = true;
            document.getElementById('copyBtn').disabled = true;
        }
        // Reload files list
        loadFiles();
    });

    socket.on('room_update', (data) => {
        const roomInfo = document.getElementById('roomInfo');
        roomInfo.textContent = `Room: ${data.id} | Users: ${data.users ? data.users.length : data.guest_count + 1}`;

        // Update room description if it exists
        const descriptionContainer = document.getElementById('roomDescriptionContainer');
        const descriptionText = document.getElementById('roomDescriptionText');
        if (data.description && data.description.trim()) {
            if (descriptionContainer) {
                descriptionContainer.style.display = 'block';
                if (descriptionText) {
                    descriptionText.textContent = data.description;
                }
            }
        } else {
            if (descriptionContainer) {
                descriptionContainer.style.display = 'none';
            }
        }

        // Update User List in Chat Tab (if it exists) or create a new section
        let userList = document.getElementById('userList');
        if (!userList) {
            const chatTab = document.getElementById('tab-chat');
            userList = document.createElement('div');
            userList.id = 'userList';
            userList.className = 'user-list';
            chatTab.insertBefore(userList, chatTab.firstChild);
        }

        if (data.users) {
            userList.innerHTML = data.users.map(u => `
                <div class="user-item" title="${u.username}">
                    <div class="user-avatar" style="background-color: ${u.color}">${u.username.substring(0, 2).toUpperCase()}</div>
                    <span class="user-name">${u.username}</span>
                </div>
            `).join('');
        }
    });

    // Editor Sync
    socket.on('edit_operation', (data) => {
        // Vérifier que c'est pour le bon module et que ce n'est pas notre propre changement
        const senderId = data.client_id || data.user_id || data.socket_id;
        if (data.module_path === currentModulePath && senderId !== socket.id) {
            const op = data.operation;
            const model = editor.getModel();
            
            if (!model) return;
            
            // Set flag to prevent re-emitting this change
            isApplyingRemoteChange = true;
            
            try {
                // Vérifier que la position est valide
                const modelLength = model.getValueLength();
                if (op.position < 0 || op.position > modelLength) {
                    console.warn('Invalid operation position:', op.position, 'model length:', modelLength);
                    return;
                }
                
                const pos = model.getPositionAt(op.position);
                
                if (op.type === 'insert') {
                    model.applyEdits([{
                        range: new monaco.Range(pos.lineNumber, pos.column, pos.lineNumber, pos.column),
                        text: op.text,
                        forceMoveMarkers: true
                    }]);
                } else if (op.type === 'delete') {
                    const deleteLength = Math.min(op.length, modelLength - op.position);
                    if (deleteLength > 0) {
                        const endPos = model.getPositionAt(op.position + deleteLength);
                        model.applyEdits([{
                            range: new monaco.Range(pos.lineNumber, pos.column, endPos.lineNumber, endPos.column),
                            text: ''
                        }]);
                    }
                }
            } catch (error) {
                console.error('Error applying remote edit operation:', error, data);
            } finally {
                // Reset flag after a short delay to ensure the change event has been processed
                setTimeout(() => {
                    isApplyingRemoteChange = false;
                }, 10);
            }
        }
    });

    // File Edit Sync
    socket.on('file_edit_operation', (data) => {
        // Vérifier que c'est pour le bon fichier et que ce n'est pas notre propre changement
        const senderId = data.user_id || data.client_id || data.socket_id;
        if (data.file_id === currentFileId && senderId !== socket.id) {
            const op = data.operation;
            const model = editor.getModel();
            
            if (!model) return;
            
            // Set flag to prevent re-emitting this change
            isApplyingRemoteChange = true;
            
            try {
                // Vérifier que la position est valide
                const modelLength = model.getValueLength();
                if (op.position < 0 || op.position > modelLength) {
                    console.warn('Invalid operation position:', op.position, 'model length:', modelLength);
                    return;
                }
                
                const pos = model.getPositionAt(op.position);
                
                if (op.type === 'insert') {
                    model.applyEdits([{
                        range: new monaco.Range(pos.lineNumber, pos.column, pos.lineNumber, pos.column),
                        text: op.text,
                        forceMoveMarkers: true
                    }]);
                } else if (op.type === 'delete') {
                    const deleteLength = Math.min(op.length, modelLength - op.position);
                    if (deleteLength > 0) {
                        const endPos = model.getPositionAt(op.position + deleteLength);
                        model.applyEdits([{
                            range: new monaco.Range(pos.lineNumber, pos.column, endPos.lineNumber, endPos.column),
                            text: ''
                        }]);
                    }
                }
            } catch (error) {
                console.error('Error applying remote file edit operation:', error, data);
            } finally {
                // Reset flag after a short delay to ensure the change event has been processed
                setTimeout(() => {
                    isApplyingRemoteChange = false;
                }, 10);
            }
        }
    });

    // Chat
    socket.on('chat_message', (data) => {
        addChatMessage(data);
    });

    socket.on('chat_history', (data) => {
        const container = document.getElementById('chatMessages');
        container.innerHTML = '';
        displayedMessageIds.clear(); // Clear the set when loading history
        data.messages.forEach(addChatMessage);
    });

    // Notes
    socket.on('note_created', loadNotes);
    socket.on('note_updated', loadNotes);
    socket.on('note_deleted', loadNotes);

    // Files
    socket.on('file_uploaded', () => {
        if (document.getElementById('tab-files').classList.contains('active')) {
            loadFiles();
        }
    });
}

function addChatMessage(msg) {
    const chatMessages = document.getElementById('chatMessages');
    if (!chatMessages) return;
    
    // Generate a unique ID for the message to prevent duplicates
    // Use timestamp + username + message content as ID
    const messageId = `${msg.timestamp || Date.now()}_${msg.username || 'unknown'}_${msg.message || ''}`;
    
    // Check if message already exists
    if (displayedMessageIds.has(messageId)) {
        return; // Skip duplicate message
    }
    
    // Add to set of displayed messages
    displayedMessageIds.add(messageId);
    
    // Create message element
    const div = document.createElement('div');
    div.className = 'chat-message';
    div.setAttribute('data-message-id', messageId);
    
    // Format date and time
    const messageDate = new Date(msg.timestamp || Date.now());
    const dateStr = messageDate.toLocaleDateString('fr-FR', { 
        day: '2-digit', 
        month: '2-digit', 
        year: 'numeric' 
    });
    const timeStr = messageDate.toLocaleTimeString('fr-FR', { 
        hour: '2-digit', 
        minute: '2-digit' 
    });
    
    div.innerHTML = `
        <div class="username" style="color: ${msg.color || 'var(--accent)'}">${msg.username || 'Unknown'}</div>
        <div class="message-content">${escapeHtml(msg.message || '')}</div>
        <div class="timestamp">${dateStr} ${timeStr}</div>
    `;
    
    chatMessages.appendChild(div);
    
    // Limit the number of messages in DOM to prevent performance issues
    const messages = chatMessages.querySelectorAll('.chat-message');
    if (messages.length > MAX_CHAT_MESSAGES) {
        // Remove oldest messages
        const toRemove = messages.length - MAX_CHAT_MESSAGES;
        for (let i = 0; i < toRemove; i++) {
            const oldMsgId = messages[i].getAttribute('data-message-id');
            if (oldMsgId) {
                displayedMessageIds.delete(oldMsgId);
            }
            messages[i].remove();
        }
    }
    
    // Scroll to bottom
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

// Helper function to escape HTML
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// --- Modules ---
// État de l'arborescence sauvegardé
let moduleTreeState = {};

let isLoadingModules = false;
let loadModulesTimeout = null;

async function loadModules() {
    // Éviter les appels simultanés
    if (isLoadingModules) {
        console.log('loadModules already in progress, skipping');
        return;
    }
    
    // Debounce pour éviter les appels multiples rapides
    if (loadModulesTimeout) {
        clearTimeout(loadModulesTimeout);
    }
    loadModulesTimeout = setTimeout(async () => {
        await _loadModulesInternal();
    }, 100);
}

async function _loadModulesInternal() {
    if (isLoadingModules) {
        return;
    }
    isLoadingModules = true;
    
    try {
        // Les modules viennent toujours du client local
        const res = await fetch(LOCAL_API_URL + '/api/modules');
        const data = await res.json();

        if (data.status === 'success') {
            const list = document.getElementById('moduleList');
            if (!list) {
                console.warn('moduleList element not found');
                return;
            }
            
            // Sauvegarder le chemin du module actuellement sélectionné
            const previousModulePath = currentModulePath;
            
            // Construire l'arborescence de manière atomique
            list.innerHTML = '';
            const tree = buildModuleTree(data.modules);
            renderTree(tree, list);
            // Restaurer l'état de l'arborescence
            restoreTreeState();
            
            // Restaurer la sélection si un module est actuellement ouvert
            if (previousModulePath) {
                const activeModuleItem = document.querySelector(`.file-item[data-path="${previousModulePath}"]`);
                if (activeModuleItem) {
                    activeModuleItem.classList.add('active');
                }
            }
        }
    } catch (e) {
        console.error('Error loading modules:', e);
    } finally {
        isLoadingModules = false;
    }
}

function buildModuleTree(modules) {
    const root = {};
    modules.forEach(m => {
        const parts = m.path.split('/');
        let current = root;
        parts.forEach((part, i) => {
            if (!current[part]) {
                current[part] = i === parts.length - 1 ? { ...m, type: 'file' } : { type: 'folder', children: {} };
            }
            current = current[part].children || current[part];
        });
    });
    return root;
}

function renderTree(node, container, path = '') {
    const sortedKeys = Object.keys(node).sort((a, b) => {
        const nodeA = node[a];
        const nodeB = node[b];
        if (nodeA.type !== nodeB.type) return nodeA.type === 'folder' ? -1 : 1;
        return a.localeCompare(b);
    });

    sortedKeys.forEach(key => {
        const item = node[key];
        const li = document.createElement('li');
        const currentPath = path ? `${path}/${key}` : key;

        if (item.type === 'folder') {
            li.className = 'tree-folder';
            li.setAttribute('data-folder-path', currentPath);
            li.innerHTML = `
                <div class="tree-item folder-header" onclick="toggleFolder(this)">
                    <i class="fas fa-folder"></i>
                    <span>${key}</span>
                </div>
                <ul class="nested"></ul>
            `;
            renderTree(item.children, li.querySelector('.nested'), currentPath);
        } else {
            li.className = 'tree-file';
            li.innerHTML = `
                <div class="tree-item file-item" data-path="${item.path}" onclick="openModule('${item.path}')">
                    <i class="fas fa-file-code" style="color: #519aba;"></i>
                    <span>${key}</span>
                </div>
            `;
        }
        container.appendChild(li);
    });
}

function toggleFolder(element) {
    const folderLi = element.parentElement;
    const nested = folderLi.querySelector('.nested');
    const isExpanded = nested.classList.contains('active');
    
    nested.classList.toggle('active');
    const icon = element.querySelector('i');
    icon.classList.toggle('fa-folder');
    icon.classList.toggle('fa-folder-open');
    
    // Sauvegarder l'état
    const folderPath = folderLi.getAttribute('data-folder-path');
    if (folderPath) {
        if (isExpanded) {
            delete moduleTreeState[folderPath];
        } else {
            moduleTreeState[folderPath] = true;
        }
        saveTreeState();
    }
}

function saveTreeState() {
    try {
        sessionStorage.setItem('moduleTreeState', JSON.stringify(moduleTreeState));
    } catch (e) {
        console.error('Error saving tree state:', e);
    }
}

function restoreTreeState() {
    try {
        const saved = sessionStorage.getItem('moduleTreeState');
        if (saved) {
            moduleTreeState = JSON.parse(saved);
        } else {
            moduleTreeState = {};
        }
        
        // Restaurer l'état de chaque dossier
        Object.keys(moduleTreeState).forEach(folderPath => {
            if (moduleTreeState[folderPath]) {
                const folderLi = document.querySelector(`.tree-folder[data-folder-path="${folderPath}"]`);
                if (folderLi) {
                    const nested = folderLi.querySelector('.nested');
                    const header = folderLi.querySelector('.folder-header');
                    if (nested && header) {
                        nested.classList.add('active');
                        const icon = header.querySelector('i');
                        if (icon) {
                            icon.classList.remove('fa-folder');
                            icon.classList.add('fa-folder-open');
                        }
                    }
                }
            }
        });
    } catch (e) {
        console.error('Error restoring tree state:', e);
        moduleTreeState = {};
    }
}

async function openModule(path) {
    try {
        // Vérifier que l'éditeur est initialisé
        if (!editor) {
            console.error('Editor not initialized');
            alert('Editor not ready. Please wait a moment and try again.');
            return;
        }
        
        // Clear previous file cursor tracking
        if (currentFileId) {
            Object.keys(cursorDecorations || {}).forEach(userId => {
                if (cursorDecorations[userId]) {
                    editor.deltaDecorations(cursorDecorations[userId], []);
                    delete cursorDecorations[userId];
                }
            });
            cursorDecorations = {};
        }
        currentFileId = null;
        
        // Update UI
        document.querySelectorAll('.file-item').forEach(i => i.classList.remove('active'));
        const activeItem = document.querySelector(`.file-item[data-path="${path}"]`);
        if (activeItem) activeItem.classList.add('active');

        document.getElementById('editorLoading').style.display = 'block';
        document.getElementById('editor').style.display = 'none';
        document.getElementById('imagePreview').style.display = 'none';

        // Fetch Content - Les modules viennent toujours du client local
        // Flask gère les slashes dans les paths, donc on encode seulement les caractères spéciaux
        const res = await fetch(LOCAL_API_URL + '/api/modules/' + path);
        
        if (!res.ok) {
            const errorText = await res.text();
            throw new Error(`HTTP error! status: ${res.status}, message: ${errorText}`);
        }
        
        const data = await res.json();

        if (data.status === 'success') {
            currentModulePath = path;
            document.getElementById('editorTitle').textContent = path;
            document.getElementById('saveBtn').disabled = false;
            document.getElementById('shareBtn').disabled = false;
            document.getElementById('copyBtn').disabled = false;

            // Determine language
            let lang = 'python';
            if (path.endsWith('.js')) lang = 'javascript';
            else if (path.endsWith('.html')) lang = 'html';
            else if (path.endsWith('.css')) lang = 'css';
            else if (path.endsWith('.json')) lang = 'json';
            else if (path.endsWith('.md')) lang = 'markdown';

            // Update model
            const model = monaco.editor.createModel(data.content, lang);
            editor.setModel(model);

            document.getElementById('editor').style.display = 'block';
            document.getElementById('editorLoading').style.display = 'none';

            // Join editor room for sync
            socket.emit('join_editor', { module_path: path });
            
            // Setup cursor tracking for modules
            setupModuleCursorTracking();
        } else {
            alert('Failed to open module: ' + (data.message || 'Unknown error'));
            document.getElementById('editorLoading').style.display = 'none';
        }
    } catch (e) {
        console.error('Error opening module:', e);
        alert('Failed to open module: ' + e.message);
        document.getElementById('editorLoading').style.display = 'none';
    }
}

async function saveCurrentModule() {
    if (!currentModulePath && !currentFileId) return;

    const btn = document.getElementById('saveBtn');
    const status = document.getElementById('saveStatus');

    btn.disabled = true;
    status.textContent = 'Saving...';

    try {
        let res, data;

        if (currentFileId) {
            // Save file
            res = await fetch(SERVER_URL + '/api/rooms/' + currentRoomId + '/files/' + currentFileId + '/content', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    content: editor.getValue()
                })
            });
        } else {
            // Save module
            res = await fetch(LOCAL_API_URL + '/api/modules/' + currentModulePath, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    content: editor.getValue(),
                    saved_by: currentUsername
                })
            });
        }

        data = await res.json();
        if (data.status === 'success') {
            status.textContent = 'Saved!';
            setTimeout(() => status.textContent = '', 2000);
        } else {
            status.textContent = 'Error!';
        }
    } catch (e) {
        status.textContent = 'Error!';
    } finally {
        btn.disabled = false;
    }
}

document.getElementById('saveBtn').onclick = saveCurrentModule;

async function shareCurrentModule() {
    if (!currentModulePath) return;

    const btn = document.getElementById('shareBtn');
    const status = document.getElementById('saveStatus');

    if (!confirm(`Share "${currentModulePath}" to Project?`)) return;

    btn.disabled = true;
    status.textContent = 'Sharing...';

    try {
        // Récupérer le contenu du module local
        const moduleRes = await fetch(LOCAL_API_URL + '/api/modules/' + currentModulePath);
        const moduleData = await moduleRes.json();
        
        if (moduleData.status !== 'success') {
            throw new Error('Failed to read module content');
        }
        
        // Envoyer le contenu du module au SaaS
        const res = await fetch(SERVER_URL + '/api/rooms/' + currentRoomId + '/share_module', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                module_path: currentModulePath,
                content: moduleData.content,
                filename: currentModulePath.split('/').pop()
            })
        });

        const data = await res.json();
        if (data.status === 'success') {
            status.textContent = 'Shared!';
            // Afficher une popup de confirmation
            alert(`Module "${currentModulePath}" has been successfully shared to the project!`);
            setTimeout(() => {
                status.textContent = '';
                switchTab('files');
            }, 500);
        } else {
            status.textContent = 'Error!';
            alert('Failed to share module: ' + (data.message || 'Unknown error'));
        }
    } catch (e) {
        status.textContent = 'Error!';
        alert('Failed to share module: ' + e.message);
    } finally {
        btn.disabled = false;
    }
}

document.getElementById('shareBtn').onclick = shareCurrentModule;

async function copyEditorContent() {
    if (!editor) return;
    
    const content = editor.getValue();
    if (!content) {
        const status = document.getElementById('saveStatus');
        status.textContent = 'No content to copy';
        setTimeout(() => { status.textContent = ''; }, 2000);
        return;
    }
    
    try {
        await navigator.clipboard.writeText(content);
        const status = document.getElementById('saveStatus');
        status.textContent = 'Copied!';
        setTimeout(() => { status.textContent = ''; }, 2000);
    } catch (err) {
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = content;
        textArea.style.position = 'fixed';
        textArea.style.opacity = '0';
        document.body.appendChild(textArea);
        textArea.select();
        try {
            document.execCommand('copy');
            const status = document.getElementById('saveStatus');
            status.textContent = 'Copied!';
            setTimeout(() => { status.textContent = ''; }, 2000);
        } catch (e) {
            alert('Failed to copy text');
        }
        document.body.removeChild(textArea);
    }
}

document.getElementById('copyBtn').onclick = copyEditorContent;

// --- Chat ---
function sendChatMessage() {
    const input = document.getElementById('chatInput');
    const message = input.value.trim();
    if (message && socket) {
        socket.emit('chat_message', { message: message });
        input.value = '';
    }
}

// --- Tabs ---
function switchTab(tabName, eventElement) {
    // Update Buttons
    document.querySelectorAll('.sidebar-tab').forEach(t => t.classList.remove('active'));
    // Si un élément d'événement est fourni, l'utiliser, sinon trouver le bouton correspondant
    if (eventElement && eventElement.currentTarget) {
        eventElement.currentTarget.classList.add('active');
    } else {
        // Trouver le bouton correspondant à l'onglet en cherchant dans les attributs onclick
        const tabButtons = document.querySelectorAll('.sidebar-tab');
        tabButtons.forEach(btn => {
            const onclickAttr = btn.getAttribute('onclick');
            if (onclickAttr && onclickAttr.includes(`'${tabName}'`)) {
                btn.classList.add('active');
            }
        });
    }

    // Update Views
    document.querySelectorAll('.sidebar-view').forEach(v => v.classList.remove('active'));
    document.getElementById('tab-' + tabName).classList.add('active');

    // Load Data
    if (tabName === 'chat') socket.emit('get_chat_history');
    else if (tabName === 'notes') loadNotes();
    else if (tabName === 'files') loadFiles();
    else if (tabName === 'modules') loadModules();
}

// --- Notes ---
let currentNoteId = null;

async function loadNotes() {
    try {
        const res = await fetch(SERVER_URL + '/api/rooms/' + currentRoomId + '/notes');
        const data = await res.json();
        if (data.status === 'success') {
            const list = document.getElementById('notesList');
            list.innerHTML = Object.entries(data.notes).map(([id, note]) => {
                const title = note.title || 'Untitled Note';
                return `
                <li class="note-item" onclick="viewNote('${id}')">
                    <div style="flex:1">
                        <div class="note-title">${title}</div>
                        <div class="note-preview">${(note.content || '').substring(0, 50)}${note.content && note.content.length > 50 ? '...' : ''}</div>
                    </div>
                    <i class="fas fa-trash" style="color: var(--error)" onclick="event.stopPropagation(); deleteNote('${id}')"></i>
                </li>
            `}).join('');
        }
    } catch (e) { console.error(e); }
}

function createNote() {
    currentNoteId = null;
    document.getElementById('noteTitle').value = '';
    document.getElementById('noteContent').value = '';
    document.getElementById('noteModal').style.display = 'flex';
}

function viewNote(id) {
    fetch(SERVER_URL + '/api/rooms/' + currentRoomId + '/notes')
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success' && data.notes[id]) {
                currentNoteId = id;
                const note = data.notes[id];
                document.getElementById('noteTitle').value = note.title || '';
                document.getElementById('noteContent').value = note.content || '';
                document.getElementById('noteModal').style.display = 'flex';
            }
        });
}

function saveNote() {
    const title = document.getElementById('noteTitle').value.trim();
    const content = document.getElementById('noteContent').value.trim();

    if (!title) {
        alert('Please enter a title');
        return;
    }

    const endpoint = currentNoteId
        ? '/api/rooms/' + currentRoomId + '/notes'
        : '/api/rooms/' + currentRoomId + '/notes';

    const method = currentNoteId ? 'PUT' : 'POST';
    const body = currentNoteId
        ? { note_id: currentNoteId, title, content }
        : { title, content };

    fetch(SERVER_URL + endpoint, {
        method: method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    })
        .then(() => {
            closeNoteModal();
            loadNotes();
        })
        .catch(err => {
            console.error(err);
            alert('Failed to save note');
        });
}

function closeNoteModal() {
    document.getElementById('noteModal').style.display = 'none';
    currentNoteId = null;
}

function deleteNote(id) {
    if (confirm('Delete note?')) {
        fetch(SERVER_URL + '/api/rooms/' + currentRoomId + '/notes?note_id=' + id, {
            method: 'DELETE'
        }).then(() => loadNotes());
    }
}

// --- Files ---
let currentFileId = null;
let cursorDecorations = {}; // Track cursor decorations by user_id

let isLoadingFiles = false;
let loadFilesTimeout = null;
let filesLoadedOnce = false; // Pour éviter les chargements multiples au démarrage
let loadFilesRequestId = 0; // Compteur pour ignorer les réponses obsolètes
let currentFilesAbortController = null; // Pour annuler les requêtes en cours

async function loadFiles() {
    // Annuler la requête précédente si elle est en cours
    if (currentFilesAbortController) {
        currentFilesAbortController.abort();
    }
    
    // Éviter les appels simultanés
    if (isLoadingFiles) {
        console.log('loadFiles already in progress, will retry after current load');
        // Programmer un nouveau chargement après le chargement en cours
        if (loadFilesTimeout) {
            clearTimeout(loadFilesTimeout);
        }
        loadFilesTimeout = setTimeout(() => {
            loadFiles();
        }, 200);
        return;
    }
    
    // Debounce pour éviter les appels multiples rapides
    if (loadFilesTimeout) {
        clearTimeout(loadFilesTimeout);
    }
    loadFilesTimeout = setTimeout(async () => {
        await _loadFilesInternal();
    }, 150); // Augmenté à 150ms pour mieux grouper les appels
}

async function _loadFilesInternal() {
    if (isLoadingFiles) {
        return;
    }
    
    // Créer un nouvel AbortController pour cette requête
    currentFilesAbortController = new AbortController();
    const requestId = ++loadFilesRequestId;
    isLoadingFiles = true;
    
    try {
        const res = await fetch(SERVER_URL + '/api/rooms/' + currentRoomId + '/files', {
            signal: currentFilesAbortController.signal
        });
        
        // Vérifier si cette requête est toujours la plus récente
        if (requestId !== loadFilesRequestId) {
            console.log(`Ignoring stale loadFiles response (requestId: ${requestId}, current: ${loadFilesRequestId})`);
            return;
        }
        
        const data = await res.json();
        if (data.status === 'success') {
            const list = document.getElementById('filesList');
            if (!list) {
                console.warn('filesList element not found');
                return;
            }
            
            // Vérifier à nouveau que la requête est toujours valide avant de mettre à jour le DOM
            if (requestId !== loadFilesRequestId) {
                console.log(`Ignoring stale loadFiles response before DOM update (requestId: ${requestId}, current: ${loadFilesRequestId})`);
                return;
            }
            
            // Sauvegarder l'ID du fichier actuellement sélectionné
            const previousFileId = currentFileId;
            
            // Trier les fichiers par nom pour un affichage cohérent
            const sortedFiles = [...data.files].sort((a, b) => a.name.localeCompare(b.name));
            
            // Construire le HTML de manière atomique
            const filesHtml = sortedFiles.map(f => `
                <li class="file-item" data-file-id="${f.id}">
                    <i class="fas fa-file"></i>
                    <span style="flex:1; cursor:pointer;" onclick="openFile('${f.id}', '${f.name}')">${f.name}</span>
                    <span style="font-size:10px; color:var(--text-secondary); margin-right: 8px;">${f.uploaded_by}</span>
                    <button class="icon-btn" onclick="event.stopPropagation(); downloadFile('${f.id}', '${f.name}')" title="Download file" style="padding: 4px 8px; color: var(--primary); margin-right: 4px;">
                        <i class="fas fa-download"></i>
                    </button>
                    <button class="icon-btn" onclick="event.stopPropagation(); deleteFile('${f.id}', '${f.name}')" title="Delete file" style="padding: 4px 8px; color: var(--error);">
                        <i class="fas fa-trash"></i>
                    </button>
                </li>
            `).join('');
            
            // Vérifier une dernière fois avant la mise à jour du DOM
            if (requestId !== loadFilesRequestId) {
                console.log(`Ignoring stale loadFiles response at DOM update (requestId: ${requestId}, current: ${loadFilesRequestId})`);
                return;
            }
            
            // Mettre à jour le DOM de manière atomique
            list.innerHTML = filesHtml;
            
            // Restaurer la sélection si un fichier est actuellement ouvert
            if (previousFileId) {
                const activeFileItem = document.querySelector(`.file-item[data-file-id="${previousFileId}"]`);
                if (activeFileItem) {
                    activeFileItem.classList.add('active');
                }
            }
            
            filesLoadedOnce = true;
            console.log(`Loaded ${sortedFiles.length} files (requestId: ${requestId})`);
        }
    } catch (e) {
        // Ignorer les erreurs d'annulation
        if (e.name === 'AbortError') {
            console.log('loadFiles request was aborted');
            return;
        }
        console.error('Error loading files:', e);
    } finally {
        // Ne réinitialiser que si c'est toujours la requête en cours
        if (requestId === loadFilesRequestId) {
            isLoadingFiles = false;
            currentFilesAbortController = null;
        }
    }
}

async function openFile(fileId, filename) {
    try {
        // Leave previous file session if any
        if (currentFileId) {
            socket.emit('leave_file_editor', { file_id: currentFileId });
        }

        // Clear module cursor tracking
        if (currentModulePath) {
            Object.keys(cursorDecorations || {}).forEach(userId => {
                if (cursorDecorations[userId]) {
                    editor.deltaDecorations(cursorDecorations[userId], []);
                    delete cursorDecorations[userId];
                }
            });
            cursorDecorations = {};
        }
        currentModulePath = null;
        currentFileId = fileId;

        // Update UI - Retirer la sélection des modules locaux et fichiers partagés
        document.querySelectorAll('.file-item').forEach(i => i.classList.remove('active'));
        // Ajouter la classe active au fichier sélectionné
        const activeFileItem = document.querySelector(`.file-item[data-file-id="${fileId}"]`);
        if (activeFileItem) {
            activeFileItem.classList.add('active');
        }

        document.getElementById('editorLoading').style.display = 'block';
        document.getElementById('editor').style.display = 'none';
        document.getElementById('imagePreview').style.display = 'none';
        document.getElementById('editorTitle').textContent = filename;
        document.getElementById('saveBtn').disabled = false;
        document.getElementById('shareBtn').disabled = true; // Can't share uploaded files
        document.getElementById('copyBtn').disabled = false;

        // Vérifier si c'est une image
        const imageExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg', '.ico'];
        const isImage = imageExtensions.some(ext => filename.toLowerCase().endsWith(ext));

        if (isImage) {
            // Afficher l'image
            const imageUrl = SERVER_URL + '/api/rooms/' + currentRoomId + '/files/' + fileId;
            document.getElementById('previewImage').src = imageUrl;
            document.getElementById('imagePreview').style.display = 'block';
            document.getElementById('editorLoading').style.display = 'none';
            // Désactiver les boutons pour les images
            document.getElementById('saveBtn').disabled = true;
            document.getElementById('copyBtn').disabled = true;
        } else {
            // Fetch file content pour les fichiers texte
            const res = await fetch(SERVER_URL + '/api/rooms/' + currentRoomId + '/files/' + fileId + '/content');
            const data = await res.json();

            if (data.status === 'success') {
                // Determine language from filename
                let lang = 'plaintext';
                if (filename.endsWith('.js')) lang = 'javascript';
                else if (filename.endsWith('.py')) lang = 'python';
                else if (filename.endsWith('.html')) lang = 'html';
                else if (filename.endsWith('.css')) lang = 'css';
                else if (filename.endsWith('.json')) lang = 'json';
                else if (filename.endsWith('.md')) lang = 'markdown';

                // Update editor model
                const model = monaco.editor.createModel(data.content, lang);
                editor.setModel(model);

                document.getElementById('editor').style.display = 'block';
                document.getElementById('editorLoading').style.display = 'none';

                // Join file editing session
                socket.emit('join_file_editor', { file_id: fileId });

                // Setup cursor tracking
                setupFileCursorTracking();
            }
        }
    } catch (e) {
        alert('Failed to open file');
        console.error(e);
    }
}

function setupFileCursorTracking() {
    // Clear existing decorations
    cursorDecorations = {};

    // Send cursor position on change
    const cursorListener = editor.onDidChangeCursorPosition((e) => {
        if (!currentFileId) return;

        const position = e.position;
        socket.emit('file_cursor_move', {
            file_id: currentFileId,
            position: {
                lineNumber: position.lineNumber,
                column: position.column
            }
        });
    });

    // Listen for other users' cursors
    // Utiliser une fonction nommée pour pouvoir la supprimer proprement
    const handleFileCursorUpdate = (data) => {
        if (data.file_id !== currentFileId) return;

        const userId = data.user_id || data.client_id || data.socket_id;
        if (userId === socket.id) return; // Ignorer notre propre curseur
        
        const position = data.position;
        const color = data.color || '#00ffff';
        const username = data.username || 'Unknown';

        // Remove old decoration for this user
        if (cursorDecorations[userId]) {
            cursorDecorations[userId] = editor.deltaDecorations(cursorDecorations[userId], []);
        }

        // Add new decoration with color
        const decorationId = `cursor-${userId.substring(0, 8)}`;
        cursorDecorations[userId] = editor.deltaDecorations([], [{
            range: new monaco.Range(position.lineNumber, position.column, position.lineNumber, position.column + 1),
            options: {
                className: 'remote-cursor',
                glyphMarginClassName: 'remote-cursor-glyph',
                glyphMarginHoverMessage: { value: username },
                stickiness: monaco.editor.TrackedRangeStickiness.NeverGrowsWhenTypingAtEdges,
                zIndex: 100,
                inlineClassName: decorationId,
                before: {
                    content: username,
                    inlineClassName: 'remote-cursor-label',
                    inlineClassNameAffectsLetterSpacing: true
                }
            }
        }]);

        // Apply color via CSS
        const style = document.createElement('style');
        style.id = `cursor-style-${userId}`;
        style.textContent = `
            .monaco-editor .${decorationId} {
                border-left-color: ${color} !important;
            }
            .monaco-editor .remote-cursor-label {
                background: ${color} !important;
            }
        `;
        const existingStyle = document.getElementById(style.id);
        if (existingStyle) existingStyle.remove();
        document.head.appendChild(style);
    };
    
    // Supprimer l'ancien listener s'il existe
    socket.off('cursor_update', handleFileCursorUpdate);
    socket.on('cursor_update', handleFileCursorUpdate);

    // Remove cursor when user leaves
    const handleUserLeftFile = (data) => {
        const userId = data.user_id || data.client_id || data.socket_id;
        if (cursorDecorations[userId]) {
            editor.deltaDecorations(cursorDecorations[userId], []);
            delete cursorDecorations[userId];
            // Remove style
            const style = document.getElementById(`cursor-style-${userId}`);
            if (style) style.remove();
        }
    };
    
    socket.off('user_left_file', handleUserLeftFile);
    socket.on('user_left_file', handleUserLeftFile);
}

function setupModuleCursorTracking() {
    // Clear existing decorations
    if (!cursorDecorations) cursorDecorations = {};
    Object.keys(cursorDecorations).forEach(userId => {
        if (cursorDecorations[userId]) {
            editor.deltaDecorations(cursorDecorations[userId], []);
            delete cursorDecorations[userId];
        }
    });

    // Send cursor position on change for modules
    const cursorListener = editor.onDidChangeCursorPosition((e) => {
        if (!currentModulePath) return;

        const position = e.position;
        socket.emit('module_cursor_move', {
            module_path: currentModulePath,
            position: {
                lineNumber: position.lineNumber,
                column: position.column
            }
        });
    });

    // Listen for other users' cursors in modules
    const handleModuleCursorUpdate = (data) => {
        if (data.module_path !== currentModulePath) return;

        const userId = data.client_id || data.user_id || data.socket_id;
        if (userId === socket.id) return; // Ignorer notre propre curseur
        
        const position = data.position;
        const color = data.color || '#00ffff';
        const username = data.username || 'Unknown';

        // Remove old decoration for this user
        if (cursorDecorations[userId]) {
            editor.deltaDecorations(cursorDecorations[userId], []);
        }

        // Add new decoration with color
        const decorationId = `cursor-${userId.substring(0, 8)}`;
        cursorDecorations[userId] = editor.deltaDecorations([], [{
            range: new monaco.Range(position.lineNumber, position.column, position.lineNumber, position.column + 1),
            options: {
                className: 'remote-cursor',
                glyphMarginClassName: 'remote-cursor-glyph',
                glyphMarginHoverMessage: { value: username },
                stickiness: monaco.editor.TrackedRangeStickiness.NeverGrowsWhenTypingAtEdges,
                zIndex: 100,
                inlineClassName: decorationId,
                before: {
                    content: username,
                    inlineClassName: 'remote-cursor-label',
                    inlineClassNameAffectsLetterSpacing: true
                }
            }
        }]);

        // Apply color via CSS variable
        const style = document.createElement('style');
        style.id = `cursor-style-${userId}`;
        style.textContent = `
            .monaco-editor .${decorationId} {
                border-left-color: ${color} !important;
            }
            .monaco-editor .remote-cursor-label[data-user="${userId}"] {
                background: ${color} !important;
            }
        `;
        const existingStyle = document.getElementById(style.id);
        if (existingStyle) existingStyle.remove();
        document.head.appendChild(style);
    };
    
    socket.off('module_cursor_update', handleModuleCursorUpdate);
    socket.on('module_cursor_update', handleModuleCursorUpdate);

    // Remove cursor when user leaves module
    const handleUserLeftModule = (data) => {
        const userId = data.client_id || data.user_id || data.socket_id;
        if (cursorDecorations[userId]) {
            editor.deltaDecorations(cursorDecorations[userId], []);
            delete cursorDecorations[userId];
            // Remove style
            const style = document.getElementById(`cursor-style-${userId}`);
            if (style) style.remove();
        }
    };
    
    socket.off('user_left_module', handleUserLeftModule);
    socket.on('user_left_module', handleUserLeftModule);
}

// File Upload
document.getElementById('fileUpload').addEventListener('change', function (e) {
    const files = e.target.files;
    if (files.length > 0) {
        handleFiles(files);
    }
});

// --- Room Description ---
function editRoomDescription() {
    // First, try to get description from the displayed text
    const descriptionText = document.getElementById('roomDescriptionText');
    let currentDesc = '';
    
    if (descriptionText && descriptionText.textContent) {
        currentDesc = descriptionText.textContent.trim();
    }
    
    // If not found in DOM, fetch from API
    if (!currentDesc) {
        const token = sessionStorage.getItem('token') || '';
        const url = SERVER_URL + '/api/rooms' + (token ? '?token=' + encodeURIComponent(token) : '');
        
        fetch(url)
            .then(res => res.json())
            .then(data => {
                if (data.status === 'success') {
                    const room = data.rooms.find(r => r.id === currentRoomId);
                    const currentDesc = room ? (room.description || '') : '';
                    const textarea = document.getElementById('roomDescription');
                    if (textarea) {
                        textarea.value = currentDesc;
                    }
                    const modal = document.getElementById('descriptionModal');
                    if (modal) {
                        modal.style.display = 'flex';
                    }
                } else {
                    // Fallback: show modal with empty textarea
                    const textarea = document.getElementById('roomDescription');
                    if (textarea) {
                        textarea.value = '';
                    }
                    const modal = document.getElementById('descriptionModal');
                    if (modal) {
                        modal.style.display = 'flex';
                    }
                }
            })
            .catch(err => {
                console.error('Error fetching room description:', err);
                // Fallback: show modal with empty textarea
                const textarea = document.getElementById('roomDescription');
                if (textarea) {
                    textarea.value = '';
                }
                const modal = document.getElementById('descriptionModal');
                if (modal) {
                    modal.style.display = 'flex';
                }
            });
    } else {
        // Use description from DOM
        const textarea = document.getElementById('roomDescription');
        if (textarea) {
            textarea.value = currentDesc;
        }
        const modal = document.getElementById('descriptionModal');
        if (modal) {
            modal.style.display = 'flex';
        }
    }
}

function closeDescriptionModal() {
    document.getElementById('descriptionModal').style.display = 'none';
}

async function saveRoomDescription() {
    const description = document.getElementById('roomDescription').value;
    
    try {
        const res = await fetch(SERVER_URL + '/api/rooms/' + currentRoomId + '/description', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ description: description })
        });
        
        const data = await res.json();
        if (data.status === 'success') {
            closeDescriptionModal();
            // Update description display
            const descriptionContainer = document.getElementById('roomDescriptionContainer');
            const descriptionText = document.getElementById('roomDescriptionText');
            if (description && description.trim()) {
                if (descriptionContainer) {
                    descriptionContainer.style.display = 'block';
                    if (descriptionText) {
                        descriptionText.textContent = description;
                    }
                }
            } else {
                if (descriptionContainer) {
                    descriptionContainer.style.display = 'none';
                }
            }
        } else {
            alert('Failed to update description: ' + data.message);
        }
    } catch (e) {
        alert('Failed to update description');
        console.error(e);
    }
}

// Load room description from API
async function loadRoomDescription() {
    if (!currentRoomId) return;
    
    try {
        const token = sessionStorage.getItem('token') || '';
        const url = SERVER_URL + '/api/rooms' + (token ? '?token=' + encodeURIComponent(token) : '');
        const res = await fetch(url);
        const data = await res.json();
        if (data.status === 'success') {
            const room = data.rooms.find(r => r.id === currentRoomId);
            if (room) {
                // Update description if exists
                if (room.description && room.description.trim()) {
                    const descriptionContainer = document.getElementById('roomDescriptionContainer');
                    const descriptionText = document.getElementById('roomDescriptionText');
                    if (descriptionContainer) {
                        descriptionContainer.style.display = 'block';
                        if (descriptionText) {
                            descriptionText.textContent = room.description;
                        }
                    }
                }
                
                // Show delete button if user is the host
                const deleteBtn = document.getElementById('deleteRoomBtn');
                if (deleteBtn && room.host_username === currentUsername) {
                    deleteBtn.style.display = 'inline-block';
                } else if (deleteBtn) {
                    deleteBtn.style.display = 'none';
                }
            }
        }
    } catch (e) {
        console.error('Error loading room description:', e);
    }
}

// Delete current room (host only)
async function deleteCurrentRoom() {
    if (!currentRoomId) return;
    
    if (!confirm('Are you sure you want to delete/close this session? This action cannot be undone and all participants will be disconnected.')) {
        return;
    }
    
    try {
        const res = await fetch(SERVER_URL + '/api/rooms/' + currentRoomId + '?username=' + encodeURIComponent(currentUsername), {
            method: 'DELETE'
        });
        
        const data = await res.json();
        
        if (data.status === 'success') {
            alert('Session deleted successfully. You will be redirected to the session hub.');
            // Redirect to rooms page
            window.location.href = '/rooms';
        } else {
            alert('Error deleting session: ' + (data.message || 'Unknown error'));
        }
    } catch (e) {
        console.error('Error deleting room:', e);
        alert('Failed to delete session: ' + e.message);
    }
}

// --- Download File ---
function downloadFile(fileId, filename) {
    // Créer un lien de téléchargement avec le paramètre download=true pour forcer le téléchargement
    const downloadUrl = SERVER_URL + '/api/rooms/' + currentRoomId + '/files/' + fileId + '?download=true';
    
    // Créer un élément <a> temporaire pour déclencher le téléchargement
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.download = filename;
    link.style.display = 'none';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// --- Delete File ---
async function deleteFile(fileId, filename) {
    if (!confirm(`Delete file "${filename}"?`)) return;
    
    try {
        const res = await fetch(SERVER_URL + '/api/rooms/' + currentRoomId + '/files/' + fileId, {
            method: 'DELETE'
        });
        
        const data = await res.json();
        if (data.status === 'success') {
            // If the deleted file was open, clear the editor
            if (currentFileId === fileId) {
                currentFileId = null;
                // Retirer la sélection visuelle
                document.querySelectorAll('.file-item').forEach(i => i.classList.remove('active'));
                editor.setValue('');
                document.getElementById('editorTitle').textContent = 'No file selected';
                document.getElementById('saveBtn').disabled = true;
                document.getElementById('copyBtn').disabled = true;
            }
            // Reload files list
            await loadFiles();
        } else {
            alert('Failed to delete file: ' + data.message);
        }
    } catch (e) {
        alert('Failed to delete file');
        console.error(e);
    }
}
