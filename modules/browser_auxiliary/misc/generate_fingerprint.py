from kittysploit import *
import json
import hashlib
from datetime import datetime

class Module(BrowserAuxiliary):

    __info__ = {
        "name": "Generate Fingerprint",
        "description": "Generate a unique fingerprint hash from browser properties for session matching",
        "author": "KittySploit Team",
        "browser": Browser.ALL,
        "platform": Platform.ALL,
        "session_type": SessionType.BROWSER,
    }

    def run(self):
        """Generate fingerprint from browser properties (auto-detects if needed)"""
        # Ensure browser server is available
        self._ensure_browser_server()
        
        if not self.browser_server:
            print_error("Browser server not available. Please start the browser server first with 'browser_server start'")
            return False
        
        if not self.session_id:
            print_error("Session ID not set. Please set the session_id option.")
            return False
        
        session = self.browser_server.get_session(self.session_id)
        if not session:
            print_error(f"Session {self.session_id[:8]}... not found")
            return False
        
        # Check if session has properties, if not, detect them automatically
        properties = None
        if session.fingerprint:
            properties = session.fingerprint.get('properties', {})
        
        # If no properties found, detect them automatically
        if not properties:
            print_info("[*] No properties found in session. Detecting browser properties...")
            properties = self._detect_properties()
            if not properties:
                print_error("Failed to detect browser properties")
                return False
            
            # Store properties in session
            if session.fingerprint is None:
                session.fingerprint = {}
            session.fingerprint['properties'] = properties
            session.fingerprint['timestamp'] = datetime.now().isoformat()
            print_success("Browser properties detected and stored")
        
        # Generate fingerprint hash
        fingerprint_hash = self._generate_fingerprint(properties)
        
        # Update fingerprint in session
        session.fingerprint['hash'] = fingerprint_hash
        session.fingerprint['timestamp'] = datetime.now().isoformat()
        
        print_info("\n" + "="*80)
        print_success("Fingerprint Generation")
        print_info("="*80)
        print_info(f"[Fingerprint Hash] {fingerprint_hash}")
        print_info(f"[Session ID] {self.session_id[:8]}...")
        print_info("[Fingerprint Components]")
        print_info(f"  User Agent: {properties.get('userAgent', 'N/A')[:60]}...")
        print_info(f"  Platform: {properties.get('platform', 'N/A')}")
        print_info(f"  Screen: {properties.get('screen', {}).get('width', 'N/A')}x{properties.get('screen', {}).get('height', 'N/A')}")
        print_info(f"  Timezone: {properties.get('timezone', 'N/A')}")
        print_info(f"  Language: {properties.get('language', 'N/A')}")
        
        hardware = properties.get('hardware', {})
        if hardware:
            print_info(f"  Hardware: {hardware.get('hardwareConcurrency', 'N/A')} cores, {hardware.get('deviceMemory', 'N/A')} GB")
        
        features = properties.get('features', {})
        enabled_features = [k for k, v in features.items() if v]
        print_info(f"  Enabled Features: {len(enabled_features)}")
        
        plugins = properties.get('plugins', [])
        print_info(f"  Plugins: {len(plugins)}")
        
        print_info("="*80)
        print_success(f"[+] Fingerprint generated and stored for session {self.session_id[:8]}...")
        print_info("="*80)
        
        return True
    
    def _generate_fingerprint(self, properties: dict) -> str:
        """
        Generate a fingerprint hash from browser properties
        
        The fingerprint is based on stable properties that identify a browser configuration:
        - User Agent (normalized)
        - Platform
        - Screen resolution
        - Color depth
        - Timezone
        - Language
        - Hardware (CPU cores, memory)
        - WebGL vendor/renderer
        - Canvas fingerprint
        - Available features
        
        Returns:
            str: SHA256 hash of the fingerprint
        """
        # Extract key properties for fingerprinting
        fingerprint_data = {
            'user_agent': properties.get('userAgent', ''),
            'platform': properties.get('platform', ''),
            'language': properties.get('language', ''),
            'timezone': properties.get('timezone', ''),
            'timezone_offset': properties.get('timezoneOffset', 0),
        }
        
        # Screen properties
        screen = properties.get('screen', {})
        if screen:
            fingerprint_data['screen'] = {
                'width': screen.get('width', 0),
                'height': screen.get('height', 0),
                'color_depth': screen.get('colorDepth', 0),
                'pixel_depth': screen.get('pixelDepth', 0)
            }
        
        # Hardware
        hardware = properties.get('hardware', {})
        if hardware:
            fingerprint_data['hardware'] = {
                'cores': hardware.get('hardwareConcurrency', 0),
                'memory': hardware.get('deviceMemory', 0),
                'touch_points': hardware.get('maxTouchPoints', 0)
            }
        
        # WebGL info
        webgl = properties.get('webgl')
        if webgl and isinstance(webgl, dict):
            fingerprint_data['webgl'] = {
                'vendor': webgl.get('vendor', ''),
                'renderer': webgl.get('renderer', '')
            }
        
        # Canvas fingerprint
        if 'canvasFingerprint' in properties:
            fingerprint_data['canvas'] = properties.get('canvasFingerprint', '')
        
        # Features (as a sorted list for consistency)
        features = properties.get('features', {})
        if features:
            # Sort features for consistent hashing
            enabled_features = sorted([k for k, v in features.items() if v])
            fingerprint_data['features'] = enabled_features
        
        # Plugins (just names, sorted)
        plugins = properties.get('plugins', [])
        if plugins:
            plugin_names = sorted([p.get('name', '') for p in plugins if p.get('name')])
            fingerprint_data['plugins'] = plugin_names
        
        # Create a normalized JSON string (sorted keys for consistency)
        fingerprint_json = json.dumps(fingerprint_data, sort_keys=True, separators=(',', ':'))
        
        # Generate SHA256 hash
        fingerprint_hash = hashlib.sha256(fingerprint_json.encode('utf-8')).hexdigest()
        
        return fingerprint_hash
    
    def _detect_properties(self) -> dict:
        """
        Automatically detect browser properties (same logic as detect_properties module)
        
        Returns:
            dict: Browser properties dictionary, or None if detection fails
        """
        code_js = """
        (function() {
            const info = {
                // Basic browser info
                userAgent: navigator.userAgent,
                platform: navigator.platform,
                language: navigator.language,
                languages: navigator.languages || [navigator.language],
                cookieEnabled: navigator.cookieEnabled,
                onLine: navigator.onLine,
                
                // Screen properties
                screen: {
                    width: screen.width,
                    height: screen.height,
                    availWidth: screen.availWidth,
                    availHeight: screen.availHeight,
                    colorDepth: screen.colorDepth,
                    pixelDepth: screen.pixelDepth
                },
                
                // Window properties
                window: {
                    innerWidth: window.innerWidth,
                    innerHeight: window.innerHeight,
                    outerWidth: window.outerWidth,
                    outerHeight: window.outerHeight
                },
                
                // Timezone
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                timezoneOffset: new Date().getTimezoneOffset(),
                
                // Features detection
                features: {
                    java: window.navigator.javaEnabled ? window.navigator.javaEnabled() : false,
                    flash: !!(navigator.mimeTypes && navigator.mimeTypes["application/x-shockwave-flash"]),
                    quicktime: false,
                    vbscript: false,
                    activeX: false,
                    webgl: !!window.WebGLRenderingContext,
                    canvas: !!document.createElement('canvas').getContext,
                    localStorage: !!window.localStorage,
                    sessionStorage: !!window.sessionStorage,
                    indexedDB: !!window.indexedDB,
                    geolocation: !!navigator.geolocation,
                    mediaDevices: !!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia),
                    serviceWorker: 'serviceWorker' in navigator,
                    webWorker: typeof Worker !== 'undefined',
                    websocket: typeof WebSocket !== 'undefined',
                    webRTC: !!(window.RTCPeerConnection || window.mozRTCPeerConnection || window.webkitRTCPeerConnection)
                },
                
                // Plugins
                plugins: [],
                
                // MIME types
                mimeTypes: [],
                
                // Hardware
                hardware: {
                    hardwareConcurrency: navigator.hardwareConcurrency || 'unknown',
                    deviceMemory: navigator.deviceMemory || 'unknown',
                    maxTouchPoints: navigator.maxTouchPoints || 0
                },
                
                // Connection info (if available)
                connection: null
            };
            
            // Detect QuickTime
            if (navigator.plugins) {
                for (let i = 0; i < navigator.plugins.length; i++) {
                    if (navigator.plugins[i].name.indexOf("QuickTime") >= 0) {
                        info.features.quicktime = true;
                        break;
                    }
                }
            }
            if ((navigator.appVersion.indexOf("Mac") > 0) && 
                (navigator.appName.substring(0, 9) == "Microsoft") && 
                (parseInt(navigator.appVersion) < 5)) {
                info.features.quicktime = true;
            }
            
            // Detect VBScript
            if ((navigator.userAgent.indexOf('MSIE') != -1) && 
                (navigator.userAgent.indexOf('Win') != -1)) {
                info.features.vbscript = true;
            }
            
            // Detect ActiveX
            try {
                const test = new ActiveXObject("WbemScripting.SWbemLocator");
                info.features.activeX = true;
            } catch (ex) {
                info.features.activeX = false;
            }
            
            // List all plugins
            if (navigator.plugins && navigator.plugins.length > 0) {
                for (let i = 0; i < navigator.plugins.length; i++) {
                    const plugin = navigator.plugins[i];
                    const pluginInfo = {
                        name: plugin.name,
                        description: plugin.description,
                        filename: plugin.filename,
                        length: plugin.length
                    };
                    
                    // Get MIME types for this plugin
                    if (plugin.length > 0) {
                        pluginInfo.mimeTypes = [];
                        for (let j = 0; j < plugin.length; j++) {
                            const mimeType = plugin[j];
                            pluginInfo.mimeTypes.push({
                                type: mimeType.type,
                                description: mimeType.description,
                                suffixes: mimeType.suffixes
                            });
                        }
                    }
                    
                    info.plugins.push(pluginInfo);
                }
            }
            
            // List all MIME types
            if (navigator.mimeTypes && navigator.mimeTypes.length > 0) {
                for (let i = 0; i < navigator.mimeTypes.length; i++) {
                    const mimeType = navigator.mimeTypes[i];
                    info.mimeTypes.push({
                        type: mimeType.type,
                        description: mimeType.description,
                        suffixes: mimeType.suffixes,
                        enabledPlugin: mimeType.enabledPlugin ? mimeType.enabledPlugin.name : null
                    });
                }
            }
            
            // Connection API
            if (navigator.connection || navigator.mozConnection || navigator.webkitConnection) {
                const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
                info.connection = {
                    effectiveType: conn.effectiveType,
                    downlink: conn.downlink,
                    rtt: conn.rtt,
                    saveData: conn.saveData
                };
            }
            
            // Canvas fingerprinting (simple hash)
            if (info.features.canvas) {
                try {
                    const canvas = document.createElement('canvas');
                    const ctx = canvas.getContext('2d');
                    ctx.textBaseline = 'top';
                    ctx.font = '14px Arial';
                    ctx.textBaseline = 'alphabetic';
                    ctx.fillStyle = '#f60';
                    ctx.fillRect(125, 1, 62, 20);
                    ctx.fillStyle = '#069';
                    ctx.fillText('KittySploit', 2, 15);
                    info.canvasFingerprint = canvas.toDataURL().substring(0, 50);
                } catch (e) {
                    info.canvasFingerprint = 'error';
                }
            }
            
            // WebGL fingerprinting
            if (info.features.webgl) {
                try {
                    const canvas = document.createElement('canvas');
                    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
                    if (gl) {
                        const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                        if (debugInfo) {
                            info.webgl = {
                                vendor: gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL),
                                renderer: gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL)
                            };
                        }
                    }
                } catch (e) {
                    info.webgl = 'error';
                }
            }
            
            return JSON.stringify(info, null, 2);
        })();
        """
        
        # Execute JavaScript and get result
        result = self.send_js_and_wait_for_response(code_js, timeout=15.0)
        
        if not result:
            return None
        
        try:
            # Parse JSON result
            data = json.loads(result)
            return data
        except json.JSONDecodeError:
            return None

