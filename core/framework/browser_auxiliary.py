from core.framework.base_module import BaseModule
from core.framework.option.option_string import OptString
from core.framework.option.option_integer import OptInteger
from core.output_handler import print_error, print_info, print_debug, print_status, print_warning
import time
import uuid
import functools
from difflib import SequenceMatcher

class BrowserAuxiliary(BaseModule):

    TYPE_MODULE = "browserauxiliary"

    session_id = OptString("", "Target browser session ID", required=True)
    fingerprint_match = OptInteger(0, "Similarity threshold for fingerprint matching (0-100, default: 0 = no matching)", required=False, advanced=True)
    fingerprint_target = OptString("", "Target fingerprint hash or session ID to match against (empty = use current session)", required=False, advanced=True)

    encode = OptString("", "Encoder module to use", required=False, advanced=True)

    def __init__(self, framework=None):
        super().__init__(framework)

        self.browser_server = None
        if framework and hasattr(framework, 'browser_server') and framework.browser_server:
            self.browser_server = framework.browser_server
        
        # Initialize for auto-return handling
        self._last_js_result = None
        self._execute_js_called = False  # Flag to track if execute_js was called
    
    def check(self):
        raise NotImplementedError("BrowserAuxiliary modules must implement the check() method")

    def run(self):
        raise NotImplementedError("BrowserAuxiliary modules must implement the run() method")

    def _reset_auto_return_flags(self):
        """Reset auto-return flags - called by framework before each run()"""
        self._last_js_result = None
        self._execute_js_called = False
    
    def _auto_return_js(self, javascript_code: str):
        """
        Internal method that executes JS and automatically returns the result.
        This is used internally to ensure return values are properly handled.
        """
        return self.send_js(javascript_code)
    
    def _ensure_browser_server(self):
        """Ensure browser server is set from framework if available"""
        if not self.browser_server and self.framework and hasattr(self.framework, 'browser_server') and self.framework.browser_server:
            self.browser_server = self.framework.browser_server
    
    def _check_fingerprint_match(self) -> bool:
        """
        Check if the current session matches the fingerprint requirements
        
        Returns:
            bool: True if fingerprint match passes (or not required), False otherwise
        """
        # If fingerprint_match is 0 or not set, skip check
        # Ensure fingerprint_match is an integer for comparison
        try:
            fingerprint_match_int = int(self.fingerprint_match) if self.fingerprint_match else 0
        except (ValueError, TypeError):
            fingerprint_match_int = 0
        
        if fingerprint_match_int <= 0:
            return True
        
        self._ensure_browser_server()
        if not self.browser_server:
            return True  # Can't check, but don't block execution
        
        if not self.session_id:
            return True  # Can't check, but don't block execution
        
        # Get current session
        current_session = self.browser_server.get_session(self.session_id)
        if not current_session:
            print_warning(f"[!] Session {self.session_id[:8]}... not found, skipping fingerprint check")
            return True  # Don't block if session doesn't exist yet
        
        # Check if current session has fingerprint, if not, generate it automatically
        if not current_session.fingerprint:
            print_info(f"[*] Session {self.session_id[:8]}... has no fingerprint. Generating automatically...")
            if not self._auto_generate_fingerprint(current_session):
                print_warning(f"[!] Failed to generate fingerprint for session {self.session_id[:8]}...")
                return False
        
        current_props = current_session.fingerprint.get('properties', {})
        if not current_props:
            print_info(f"[*] Session {self.session_id[:8]}... has no properties. Detecting automatically...")
            if not self._auto_detect_properties(current_session):
                print_warning(f"[!] Failed to detect properties for session {self.session_id[:8]}...")
                return False
            current_props = current_session.fingerprint.get('properties', {})
        
        # Determine target fingerprint
        target_props = None
        target_session_id = None
        
        if self.fingerprint_target:
            # Check if it's a session ID (UUID format) or a fingerprint hash
            if len(self.fingerprint_target) == 36 and '-' in self.fingerprint_target:
                # Likely a session ID
                target_session = self.browser_server.get_session(self.fingerprint_target)
                if target_session and target_session.fingerprint:
                    target_props = target_session.fingerprint.get('properties', {})
                    target_session_id = self.fingerprint_target
            else:
                # Likely a fingerprint hash - find session with matching hash
                all_sessions = self.browser_server.get_sessions()
                for sid, session in all_sessions.items():
                    if session.fingerprint:
                        if session.fingerprint.get('hash') == self.fingerprint_target:
                            target_props = session.fingerprint.get('properties', {})
                            target_session_id = sid
                            break
        else:
            # No target specified - use current session (always matches 100%)
            return True
        
        if not target_props:
            print_warning(f"[!] Target fingerprint '{self.fingerprint_target[:16]}...' not found")
            return False
        
        # Calculate similarity
        similarity = self._calculate_similarity(current_props, target_props)
        similarity_pct = similarity * 100
        # Ensure threshold is an integer (options might be stored as strings)
        try:
            threshold_pct = int(self.fingerprint_match) if self.fingerprint_match else 0
        except (ValueError, TypeError):
            threshold_pct = 0
        
        if similarity_pct >= threshold_pct:
            print_debug(f"[+] Fingerprint match: {similarity_pct:.1f}% >= {threshold_pct}% (target: {target_session_id[:8] if target_session_id else 'hash'}...)")
            return True
        else:
            print_warning(f"[!] Fingerprint match failed: {similarity_pct:.1f}% < {threshold_pct}% (target: {target_session_id[:8] if target_session_id else 'hash'}...)")
            print_warning(f"[!] Module execution blocked due to fingerprint mismatch")
            return False
    
    def _calculate_similarity(self, props1: dict, props2: dict) -> float:
        """
        Calculate similarity between two browser property sets
        (Same logic as in find_similar_sessions module)
        
        Returns:
            float: Similarity score between 0.0 and 1.0
        """
        if not props1 or not props2:
            return 0.0
        
        scores = []
        weights = []
        
        # 1. User Agent similarity (weight: 0.15)
        ua1 = props1.get('userAgent', '')
        ua2 = props2.get('userAgent', '')
        if ua1 and ua2:
            ua_sim = SequenceMatcher(None, ua1, ua2).ratio()
            scores.append(ua_sim)
            weights.append(0.15)
        
        # 2. Platform match (weight: 0.10)
        platform1 = props1.get('platform', '')
        platform2 = props2.get('platform', '')
        platform_match = 1.0 if platform1 == platform2 else 0.0
        scores.append(platform_match)
        weights.append(0.10)
        
        # 3. Screen properties (weight: 0.15)
        screen1 = props1.get('screen', {})
        screen2 = props2.get('screen', {})
        if screen1 and screen2:
            screen_scores = []
            for key in ['width', 'height', 'colorDepth', 'pixelDepth']:
                val1 = screen1.get(key, 0)
                val2 = screen2.get(key, 0)
                if val1 == val2 and val1 != 0:
                    screen_scores.append(1.0)
                elif val1 != 0 and val2 != 0:
                    diff = abs(val1 - val2) / max(val1, val2)
                    screen_scores.append(max(0.0, 1.0 - diff))
            screen_sim = sum(screen_scores) / len(screen_scores) if screen_scores else 0.0
            scores.append(screen_sim)
            weights.append(0.15)
        
        # 4. Hardware similarity (weight: 0.10)
        hw1 = props1.get('hardware', {})
        hw2 = props2.get('hardware', {})
        if hw1 and hw2:
            hw_scores = []
            for key in ['hardwareConcurrency', 'deviceMemory', 'maxTouchPoints']:
                val1 = hw1.get(key, 0)
                val2 = hw2.get(key, 0)
                if val1 == val2 and val1 != 0:
                    hw_scores.append(1.0)
                elif val1 != 0 and val2 != 0:
                    diff = abs(val1 - val2) / max(val1, val2)
                    hw_scores.append(max(0.0, 1.0 - diff))
            hw_sim = sum(hw_scores) / len(hw_scores) if hw_scores else 0.0
            scores.append(hw_sim)
            weights.append(0.10)
        
        # 5. Timezone match (weight: 0.10)
        tz1 = props1.get('timezone', '')
        tz2 = props2.get('timezone', '')
        tz_match = 1.0 if tz1 == tz2 else 0.0
        scores.append(tz_match)
        weights.append(0.10)
        
        # 6. Language match (weight: 0.05)
        lang1 = props1.get('language', '')
        lang2 = props2.get('language', '')
        lang_match = 1.0 if lang1 == lang2 else 0.0
        scores.append(lang_match)
        weights.append(0.05)
        
        # 7. Features similarity (weight: 0.15)
        features1 = props1.get('features', {})
        features2 = props2.get('features', {})
        if features1 and features2:
            all_features = set(list(features1.keys()) + list(features2.keys()))
            if all_features:
                matches = sum(1 for f in all_features if features1.get(f) == features2.get(f))
                features_sim = matches / len(all_features)
                scores.append(features_sim)
                weights.append(0.15)
        
        # 8. WebGL similarity (weight: 0.10)
        webgl1 = props1.get('webgl')
        webgl2 = props2.get('webgl')
        if webgl1 and webgl2 and isinstance(webgl1, dict) and isinstance(webgl2, dict):
            webgl_scores = []
            for key in ['vendor', 'renderer']:
                val1 = webgl1.get(key, '')
                val2 = webgl2.get(key, '')
                if val1 == val2:
                    webgl_scores.append(1.0)
                elif val1 and val2:
                    webgl_scores.append(SequenceMatcher(None, val1, val2).ratio())
            webgl_sim = sum(webgl_scores) / len(webgl_scores) if webgl_scores else 0.0
            scores.append(webgl_sim)
            weights.append(0.10)
        
        # Calculate weighted average
        if scores and weights:
            total_weight = sum(weights)
            if total_weight > 0:
                weighted_sum = sum(score * weight for score, weight in zip(scores, weights))
                return weighted_sum / total_weight
        
        return 0.0
    
    def _auto_detect_properties(self, session) -> bool:
        """
        Automatically detect browser properties for a session
        
        Returns:
            bool: True if properties were detected successfully, False otherwise
        """
        code_js = """
        (function() {
            const info = {
                userAgent: navigator.userAgent,
                platform: navigator.platform,
                language: navigator.language,
                languages: navigator.languages || [navigator.language],
                cookieEnabled: navigator.cookieEnabled,
                onLine: navigator.onLine,
                screen: {
                    width: screen.width,
                    height: screen.height,
                    availWidth: screen.availWidth,
                    availHeight: screen.availHeight,
                    colorDepth: screen.colorDepth,
                    pixelDepth: screen.pixelDepth
                },
                window: {
                    innerWidth: window.innerWidth,
                    innerHeight: window.innerHeight,
                    outerWidth: window.outerWidth,
                    outerHeight: window.outerHeight
                },
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                timezoneOffset: new Date().getTimezoneOffset(),
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
                plugins: [],
                mimeTypes: [],
                hardware: {
                    hardwareConcurrency: navigator.hardwareConcurrency || 'unknown',
                    deviceMemory: navigator.deviceMemory || 'unknown',
                    maxTouchPoints: navigator.maxTouchPoints || 0
                },
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
            
            // Canvas fingerprinting
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
        
        # Execute JavaScript to detect properties
        result = self.send_js_and_wait_for_response(code_js, timeout=15.0)
        if not result:
            return False
        
        try:
            import json
            from datetime import datetime
            properties = json.loads(result)
            
            # Store properties in session
            if session.fingerprint is None:
                session.fingerprint = {}
            session.fingerprint['properties'] = properties
            session.fingerprint['timestamp'] = datetime.now().isoformat()
            
            return True
        except Exception:
            return False
    
    def _auto_generate_fingerprint(self, session) -> bool:
        """
        Automatically generate fingerprint hash from session properties
        
        Returns:
            bool: True if fingerprint was generated successfully, False otherwise
        """
        # First ensure we have properties
        if not session.fingerprint or not session.fingerprint.get('properties'):
            if not self._auto_detect_properties(session):
                return False
        
        properties = session.fingerprint.get('properties', {})
        if not properties:
            return False
        
        # Generate fingerprint hash
        fingerprint_hash = self._generate_fingerprint_hash(properties)
        
        # Store fingerprint in session
        if session.fingerprint is None:
            session.fingerprint = {}
        session.fingerprint['hash'] = fingerprint_hash
        from datetime import datetime
        session.fingerprint['timestamp'] = datetime.now().isoformat()
        
        return True
    
    def _generate_fingerprint_hash(self, properties: dict) -> str:
        """
        Generate a fingerprint hash from browser properties (same logic as generate_fingerprint module)
        
        Returns:
            str: SHA256 hash of the fingerprint
        """
        import json
        import hashlib
        
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
    
    def _encode_javascript(self, javascript_code: str) -> str:
        """
        Encode JavaScript code using the specified encoder module if encode option is set
        
        Args:
            javascript_code: Raw JavaScript code to encode
            
        Returns:
            str: Encoded JavaScript code, or original code if no encoder is specified
        """
        # Check if encoder is specified
        if not hasattr(self, 'encode') or not self.encode:
            return javascript_code
        
        encoder_path = self.encode.value if hasattr(self.encode, 'value') else str(self.encode)
        if not encoder_path:
            return javascript_code
        
        try:
            import importlib
            from core.utils.function import pythonize_path
            
            # Load encoder module
            encoder_path_normalized = pythonize_path(encoder_path)
            encoder_full_path = ".".join(("modules", encoder_path_normalized))
            encoder_module = getattr(importlib.import_module(encoder_full_path), "Module")()
            
            # Set framework reference if available
            if self.framework:
                encoder_module.framework = self.framework
            
            # Apply encoding
            if hasattr(encoder_module, 'encode'):
                encoded_code = encoder_module.encode(javascript_code)
                print_debug(f"Applied encoder: {encoder_path}")
                return encoded_code
            else:
                print_warning(f"Encoder module {encoder_path} does not have encode() method")
                return javascript_code
                
        except ImportError as e:
            print_warning(f"Failed to import encoder module {encoder_path}: {e}")
            return javascript_code
        except Exception as e:
            print_warning(f"Failed to apply encoder: {e}")
            return javascript_code
    
    def _execute(self, command: dict):
        """Execute a command on the target browser session"""
        # Check fingerprint match before executing
        if not self._check_fingerprint_match():
            return False
        
        self._ensure_browser_server()
        if not self.browser_server:
            print_error("Browser server not available. Please start the browser server first with 'browser_server start'")
            return False
        
        if not self.session_id:
            print_error("Session ID not set. Please set the session_id option.")
            return False
        
        try:
            result = self.browser_server.send_command_to_session(self.session_id, command)
            if not result:
                print_error(f"Failed to send command to session {self.session_id[:8]}... (session not found)")
            return result
        except Exception as e:
            print_error(f"Error sending command to session: {e}")
            return False
    
    def send_js(self, javascript_code: str):
        """Send JavaScript code to execute on the target browser session (fire and forget)"""
        # Encode JavaScript if encoder is specified
        encoded_code = self._encode_javascript(javascript_code)
        return self._execute({"type": "execute_js", "code": encoded_code})
    
    def execute_js(self, javascript_code: str):
        """
        Execute JavaScript code on the target browser session.
        
        IMPORTANT: This method automatically handles return values!
        You can use it in two ways:
        
        1. Explicit return (recommended for clarity):
           def run(self):
               return self.execute_js("alert('Hello')")
        
        2. Automatic return (no need for 'return' keyword):
           def run(self):
               self.execute_js("alert('Hello')")  # Framework automatically returns True/False
        
        The framework will automatically detect if run() returns None and use the result
        from execute_js() instead. This prevents forgetting to return the result.
        
        Args:
            javascript_code: JavaScript code to execute
            
        Returns:
            bool: True if command was sent successfully, False otherwise
            
        Example:
            def run(self):
                # Both work the same way:
                self.execute_js("alert('Hello')")  # ✅ Auto-return
                # OR
                return self.execute_js("alert('Hello')")  # ✅ Explicit return
        """
        result = self.send_js(javascript_code)
        # Store result for potential automatic return (always store, even if False)
        # This allows the framework to detect if execute_js was called
        self._last_js_result = result
        self._execute_js_called = True  # Mark that execute_js was called
        return result
    
    def send_js_and_wait_for_response(self, javascript_code: str, timeout: float = 10.0):
        """
        Send JavaScript code and wait for the response
        
        Args:
            javascript_code: JavaScript code to execute (must return a value, e.g., "document.title" or "JSON.stringify({key: 'value'})")
            timeout: Maximum time to wait for response in seconds (default: 10.0)
            
        Returns:
            The result of the JavaScript execution, or None if timeout or error
            
        Example:
            # Get page title
            title = self.send_js_and_wait_for_response("document.title")
            
            # Get cookies
            cookies = self.send_js_and_wait_for_response("document.cookie")
            
            # Execute complex JavaScript and get result
            result = self.send_js_and_wait_for_response("JSON.stringify({url: window.location.href, title: document.title})")
        """
        self._ensure_browser_server()
        if not self.browser_server:
            print_error("Browser server not available. Please start the browser server first with 'browser_server start'")
            return None
        
        if not self.session_id:
            print_error("Session ID not set. Please set the session_id option.")
            return None
        
        # Generate unique command ID
        command_id = str(uuid.uuid4())
        
        # Get session to track responses
        session = self.browser_server.get_session(self.session_id)
        if not session:
            print_error(f"Session {self.session_id[:8]}... not found")
            return None
        
        # Clear any old responses for this command (shouldn't happen, but just in case)
        initial_response_count = len(session.responses)
        
        # Encode JavaScript if encoder is specified
        encoded_code = self._encode_javascript(javascript_code)
        
        # Send command with unique ID
        command = {
            "type": "execute_js",
            "code": encoded_code,
            "id": command_id,
            "timestamp": time.time()
        }
        
        try:
            self.browser_server.send_command_to_session(self.session_id, command)
            print_status(f"Sent JavaScript command (ID: {command_id[:8]}...), waiting for response...")
        except Exception as e:
            print_error(f"Error sending command: {e}")
            return None
        
        # Wait for response
        start_time = time.time()
        poll_interval = 0.5  # Check every 0.5 seconds
        
        while time.time() - start_time < timeout:
            # Check if we have a new response
            if len(session.responses) > initial_response_count:
                # Check the most recent responses for our command_id
                for response in reversed(session.responses):
                    if response.get('command_id') == command_id:
                        result = response.get('result')
                        print_debug(f"Received response: {result}")
                        return result
            
            time.sleep(poll_interval)
        
        # Timeout
        print_error(f"Timeout waiting for response (>{timeout}s)")
        return None