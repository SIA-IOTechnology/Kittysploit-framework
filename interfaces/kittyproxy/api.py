from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from flow_manager import flow_manager
from proxy_core import plugin_manager
from endpoint_extractor import endpoint_extractor
from performance_monitor import performance_monitor
from collaboration_manager import collaboration_manager, Collaborator
from tech_detector import tech_detector
from mitmproxy.http import HTTPFlow, Request, Response
import os
from typing import Dict, List, Optional
import requests
import sys
import threading
import io
import contextlib
import json
import asyncio
import time
import uuid
import random
import string
from core.config import Config

# Framework will be initialized by main.py
framework = None

# Cache for modules (loaded once at startup)
modules_cache = None
modules_cache_lock = threading.Lock()

def set_framework(fw):
    """Set the framework instance"""
    global framework
    framework = fw
    # Set framework in flow_manager and endpoint_extractor
    flow_manager.framework = fw
    endpoint_extractor.framework = fw
    # Load modules cache on framework initialization
    load_modules_cache()
    # Load flows and endpoints from database for current workspace
    if fw:
        current_workspace = fw.get_current_workspace_name()
        if current_workspace and current_workspace != "default":
            try:
                flow_manager.load_flows_from_db(current_workspace)
                endpoint_extractor.load_endpoints_from_db(current_workspace)
            except Exception as e:
                print(f"[API] Error loading flows/endpoints from database: {e}")

app = FastAPI()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/flows")
def get_flows(page: int = 1, size: int = 50, search: Optional[str] = None):
    return flow_manager.get_flows_paginated(page, size, search)

@app.get("/api/flows/{flow_id}")
def get_flow_detail(flow_id: str):
    try:
        flow = flow_manager.get_flow(flow_id)
        if not flow:
            raise HTTPException(status_code=404, detail="Flow not found")
        return flow
    except Exception as e:
        print(f"[ERROR] Error getting flow detail {flow_id}: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error getting flow detail: {str(e)}")

@app.post("/api/clear")
def clear_flows():
    flow_manager.clear()
    try:
        endpoint_extractor.reset()
    except Exception as e:
        print(f"[WARN] Failed to reset endpoint extractor on clear: {e}")
    return {"status": "ok"}

from pydantic import BaseModel

class ProxyRequest(BaseModel):
    url: str
    method: str = "GET"

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import threading

def fetch_resources(base_url, content, proxies):
    try:
        soup = BeautifulSoup(content, 'html.parser')
        resources = []
        
        # Find all linked resources
        for link in soup.find_all('link', href=True):
            resources.append(urljoin(base_url, link['href']))
        for script in soup.find_all('script', src=True):
            resources.append(urljoin(base_url, script['src']))
        for img in soup.find_all('img', src=True):
            resources.append(urljoin(base_url, img['src']))
            
        # Deduplicate
        resources = list(set(resources))
        
        print(f"Found {len(resources)} resources to fetch for {base_url}")
        
        for res_url in resources:
            try:
                requests.get(
                    res_url,
                    proxies=proxies,
                    verify=False,
                    timeout=5
                )
            except Exception as e:
                print(f"Failed to fetch resource {res_url}: {e}")
                
    except Exception as e:
        print(f"Error parsing resources: {e}")

@app.post("/api/request")
def trigger_request(req: ProxyRequest):
    try:
        # Proxy settings - assuming default port 8080
        proxies = {
            "http": "http://127.0.0.1:8080",
            "https": "http://127.0.0.1:8080",
        }
        
        # Make the request through the proxy
        # verify=False because we are using a self-signed cert proxy (mitmproxy)
        resp = requests.request(
            method=req.method,
            url=req.url,
            proxies=proxies,
            verify=False,
            timeout=10
        )
        
        # If HTML, fetch resources in background
        content_type = resp.headers.get('Content-Type', '')
        if 'text/html' in content_type and resp.status_code == 200:
            threading.Thread(
                target=fetch_resources,
                args=(req.url, resp.content, proxies),
                daemon=True
            ).start()
        
        return {
            "status": "success",
            "status_code": resp.status_code,
            "reason": resp.reason
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/replay/{flow_id}")
def replay_flow(flow_id: str):
    flow_data = flow_manager.get_flow(flow_id)
    if not flow_data:
        raise HTTPException(status_code=404, detail="Flow not found")
    
    try:
        # Extract request details
        req_data = flow_data['request']
        import base64
        content = base64.b64decode(req_data['content_bs64'])
        
        # Proxy settings
        proxies = {
            "http": "http://127.0.0.1:8080",
            "https": "http://127.0.0.1:8080",
        }
        
        # Re-send request
        requests.request(
            method=flow_data['method'],
            url=flow_data['url'],
            headers=req_data['headers'],
            data=content,
            proxies=proxies,
            verify=False,
            timeout=10
        )
        
        return {"status": "replayed"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Replay failed: {str(e)}")

def _create_flow_from_request_response(method: str, url: str, request_headers: Dict, request_body: bytes, 
                                       response_status: int, response_reason: str, response_headers: Dict, 
                                       response_body: bytes, start_time: float, end_time: float):
    """Create a mitmproxy HTTPFlow from a request/response pair."""
    try:
        parsed_url = urlparse(url)
        
        # Create request
        req = Request(
            host=parsed_url.hostname or '',
            port=parsed_url.port or (443 if parsed_url.scheme == 'https' else 80),
            method=method,
            scheme=parsed_url.scheme or 'http',
            authority=f"{parsed_url.hostname}:{parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)}",
            path=parsed_url.path + ('?' + parsed_url.query if parsed_url.query else ''),
            http_version=b"HTTP/1.1",
            headers=[],
            content=request_body,
            timestamp_start=start_time,
            trailers=[],
            timestamp_end=start_time
        )
        
        # Set request headers
        for key, value in request_headers.items():
            req.headers.add(key.encode('utf-8'), str(value).encode('utf-8'))
        
        # Add custom header to mark as API Tester request only if not already set (e.g., by Intruder)
        if 'X-KittyProxy-Source' not in request_headers and 'x-kittyproxy-source' not in request_headers:
            req.headers.add(b'X-KittyProxy-Source', b'api_tester')
        
        # Create response
        resp = Response(
            http_version=b"HTTP/1.1",
            status_code=response_status,
            reason=response_reason.encode('utf-8') if response_reason else b"OK",
            headers=[],
            content=response_body,
            trailers=[],
            timestamp_start=start_time,
            timestamp_end=end_time
        )
        
        # Set response headers
        for key, value in response_headers.items():
            resp.headers.add(key.encode('utf-8'), str(value).encode('utf-8'))
        
        # Create flow
        flow = HTTPFlow(None, req)
        flow.response = resp
        flow.id = str(uuid.uuid4())
        
        # Mark as API request - the header X-KittyProxy-Source is already set in the request
        # We'll also try to set it as a custom attribute if possible
        try:
            if not hasattr(flow, 'metadata'):
                flow.metadata = {}
            flow.metadata['source'] = 'api_tester'
        except:
            pass  # If metadata can't be set, the header will be used instead
        
        return flow
    except Exception as e:
        print(f"[ERROR] Failed to create flow from request/response: {e}")
        import traceback
        traceback.print_exc()
        return None

@app.post("/api/send_custom")
def send_custom(request: Dict):
    try:
        import base64
        
        method = request.get('method', 'GET')
        url = request.get('url')
        headers = request.get('headers', {})
        body_bs64 = request.get('body_bs64', '')
        
        if not url:
            raise HTTPException(status_code=400, detail="URL is required")
        
        print(f"[API TESTER] Sending {method} request to {url}")
        print(f"[API TESTER] Headers ({len(headers)}): {headers}")
        
        content = b""
        if body_bs64:
            try:
                content = base64.b64decode(body_bs64)
                print(f"[API TESTER] Body size: {len(content)} bytes")
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Invalid base64 body: {str(e)}")
        
        # Preserve the X-KittyProxy-Source header for filtering
        source_header = headers.get('X-KittyProxy-Source') or headers.get('x-kittyproxy-source')
        
        # Clean headers - ensure they are strings
        # Exclude internal KittyProxy headers from HTTP sending
        cleaned_headers = {}
        for key, value in headers.items():
            # Skip internal headers for HTTP sending (but keep them for the flow)
            if key.lower() in ['x-kittyproxy-source']:
                continue
            # Convert values to string if necessary
            if not isinstance(value, str):
                cleaned_headers[key] = str(value)
            else:
                cleaned_headers[key] = value
        
        # Proxy settings
        proxies = {
            "http": "http://127.0.0.1:8080",
            "https": "http://127.0.0.1:8080",
        }
        
        start_time = time.time()
        
        # Send request and capture response
        try:
            print(f"[API TESTER] Attempting request through proxy at 127.0.0.1:8080")
            response = requests.request(
                method=method,
                url=url,
                headers=cleaned_headers,
                data=content,
                proxies=proxies,
                verify=False,
                timeout=10,
                allow_redirects=True
            )
            
            print(f"[API TESTER] Response: {response.status_code} {response.reason}")
            print(f"[API TESTER] Response headers: {dict(response.headers)}")
        except requests.exceptions.ProxyError as e:
            error_msg = f"Proxy connection failed. Is the proxy running on port 8080? Error: {str(e)}"
            print(f"[API TESTER ERROR] {error_msg}")
            print(f"[API TESTER] Attempting direct request (without proxy)...")
            try:
                # Try without proxy as fallback
                response = requests.request(
                    method=method,
                    url=url,
                    headers=cleaned_headers,
                    data=content,
                    verify=False,
                    timeout=10,
                    allow_redirects=True
                )
                print(f"[API TESTER] Direct request succeeded: {response.status_code} {response.reason}")
            except Exception as direct_error:
                error_msg = f"Both proxy and direct connection failed. Proxy error: {str(e)}. Direct error: {str(direct_error)}"
                print(f"[API TESTER ERROR] {error_msg}")
                raise HTTPException(status_code=500, detail=error_msg)
        except requests.exceptions.Timeout as e:
            error_msg = f"Request timeout: {str(e)}"
            print(f"[API TESTER ERROR] {error_msg}")
            raise HTTPException(status_code=500, detail=error_msg)
        except requests.exceptions.ConnectionError as e:
            error_msg = f"Connection error: {str(e)}"
            print(f"[API TESTER ERROR] {error_msg}")
            raise HTTPException(status_code=500, detail=error_msg)
        except Exception as e:
            error_msg = f"Request failed: {str(e)}"
            print(f"[API TESTER ERROR] {error_msg}")
            import traceback
            traceback.print_exc()
            raise HTTPException(status_code=500, detail=error_msg)
        
        end_time = time.time()
        
        # Create and add flow to flow_manager
        try:
            # Restaurer le header source dans les headers du flow pour le filtrage
            flow_headers = cleaned_headers.copy()
            if source_header:
                flow_headers['X-KittyProxy-Source'] = source_header
            
            flow = _create_flow_from_request_response(
                method=method,
                url=url,
                request_headers=flow_headers,
                request_body=content,
                response_status=response.status_code,
                response_reason=response.reason or 'OK',
                response_headers=dict(response.headers),
                response_body=response.content or b'',
                start_time=start_time,
                end_time=end_time
            )
            
            if flow:
                # Ne pas ajouter les flows de l'Intruder au flow_manager pour éviter de polluer
                # la navigation tree, le graph des dépendances, etc.
                if source_header and source_header.lower() == 'intruder':
                    print(f"[INTRUDER] Flow {flow.id} created but not added to flow_manager (to avoid polluting navigation tree)")
                else:
                    # Add flow to flow_manager so it appears in Analyze view
                    flow_manager.add_flow(flow)
                    print(f"[API TESTER] Flow {flow.id} added to flow_manager")
        except Exception as e:
            print(f"[API TESTER WARNING] Failed to create flow: {e}")
            import traceback
            traceback.print_exc()
            # Continue anyway, don't fail the request
        
        # Return response details
        response_content_bs64 = base64.b64encode(response.content).decode('utf-8') if response.content else ''
        
        return {
            "status": "ok",
            "status_code": response.status_code,
            "reason": response.reason,
            "headers": dict(response.headers),
            "content_bs64": response_content_bs64,
            "url": response.url
        }
    except HTTPException:
        raise
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        print(f"[API TESTER ERROR] {error_msg}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=error_msg)

@app.post("/api/intercept/toggle")
def toggle_intercept(data: Dict):
    enabled = data.get('enabled', False)
    flow_manager.toggle_intercept(enabled)
    return {"status": "ok", "enabled": enabled}

@app.get("/api/performance/fast-mode")
def get_fast_mode():
    """Get current fast mode settings."""
    return {
        "fast_mode": flow_manager.fast_mode,
        "threshold_kb": flow_manager.fast_mode_threshold_kb
    }

@app.post("/api/performance/fast-mode")
def set_fast_mode(data: Dict):
    """Set fast mode settings."""
    enabled = data.get("enabled", True)
    threshold_kb = data.get("threshold_kb", 100)
    flow_manager.set_fast_mode(enabled, threshold_kb)
    return {
        "status": "ok",
        "fast_mode": flow_manager.fast_mode,
        "threshold_kb": flow_manager.fast_mode_threshold_kb
    }

@app.post("/api/scope")
def set_scope(data: Dict):
    """Set scope configuration for filtering flows."""
    try:
        scope_config = {
            "enabled": data.get("enabled", False),
            "mode": data.get("mode", "include"),
            "patterns": data.get("patterns", [])
        }
        flow_manager.set_scope(scope_config)
        
        # Remove flows that don't match the new scope
        removed_count = flow_manager.remove_flows_out_of_scope()
        
        return {
            "status": "ok",
            "scope": scope_config,
            "removed_flows": removed_count
        }
    except Exception as e:
        print(f"[API] Error setting scope: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error setting scope: {str(e)}")

@app.get("/api/scope")
def get_scope():
    """Get current scope configuration."""
    return {
        "status": "ok",
        "scope": flow_manager.scope_config
    }

@app.get("/api/intercept/pending")
def get_pending_intercepts():
    pending = []
    for flow_id, flow in flow_manager.pending_intercepts.items():
        pending.append(flow_manager._serialize_flow(flow, detail=True))
    return pending

@app.post("/api/intercept/{flow_id}/resume")
def resume_intercept(flow_id: str, data: Dict):
    flow_manager.resume_intercept(flow_id, data)
    return {"status": "resumed"}

import subprocess
import shutil
import tempfile

@app.get("/api/detected_browsers")
def get_detected_browsers():
    """Retourne la liste des navigateurs détectés sur le système"""
    try:
        is_windows = os.name == "nt"
        is_mac = sys.platform == "darwin"
        is_linux = sys.platform.startswith("linux")
        
        detected = []
        
        # Function to find Chromium
        def find_chromium():
            paths = []
            if is_windows:
                paths += [
                    r"C:\Program Files\Chromium\Application\chrome.exe",
                    r"C:\Program Files\Chromium\Application\chromium.exe",
                    r"C:\Program Files (x86)\Chromium\Application\chrome.exe",
                    r"C:\Program Files (x86)\Chromium\Application\chromium.exe",
                    os.path.expanduser(r"~\AppData\Local\Chromium\Application\chrome.exe"),
                    os.path.expanduser(r"~\AppData\Local\Chromium\Application\chromium.exe"),
                ]
            if is_mac:
                paths += [
                    "/Applications/Chromium.app/Contents/MacOS/Chromium",
                ]
            if is_linux:
                paths += [
                    "/usr/bin/chromium",
                    "/usr/bin/chromium-browser",
                    "/snap/bin/chromium",
                    "/usr/local/bin/chromium",
                    "/usr/local/bin/chromium-browser",
                ]
            for path in paths:
                if os.path.exists(path):
                    return path
            return shutil.which("chromium") or shutil.which("chromium-browser")
        
        # Function to find Chrome
        def find_chrome():
            paths = []
            if is_windows:
                paths += [
                    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
                    os.path.expanduser(r"~\AppData\Local\Google\Chrome\Application\chrome.exe")
                ]
            if is_mac:
                paths += [
                    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                ]
            if is_linux:
                paths += [
                    "/usr/bin/google-chrome",
                    "/usr/bin/google-chrome-stable",
                    "/snap/bin/chromium",
                ]
            for path in paths:
                if os.path.exists(path):
                    return path
            return shutil.which("chrome") or shutil.which("google-chrome") or shutil.which("google-chrome-stable")
        
        # Function to find Edge
        def find_edge():
            paths = []
            if is_windows:
                paths += [
                    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
                    os.path.expanduser(r"~\AppData\Local\Microsoft\Edge\Application\msedge.exe")
                ]
            if is_mac:
                paths += [
                    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
                ]
            if is_linux:
                paths += [
                    "/usr/bin/microsoft-edge",
                    "/usr/bin/microsoft-edge-stable",
                    "/usr/bin/microsoft-edge-beta",
                    "/usr/bin/microsoft-edge-dev",
                    "/snap/bin/microsoft-edge",
                ]
            for path in paths:
                if os.path.exists(path):
                    return path
            return shutil.which("msedge") or shutil.which("microsoft-edge") or shutil.which("microsoft-edge-stable")
        
        # Function to find Firefox
        def find_firefox():
            paths = []
            if is_windows:
                paths += [
                    r"C:\Program Files\Mozilla Firefox\firefox.exe",
                    r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe",
                    os.path.expanduser(r"~\AppData\Local\Mozilla Firefox\firefox.exe")
                ]
            if is_mac:
                paths += [
                    "/Applications/Firefox.app/Contents/MacOS/firefox",
                ]
            if is_linux:
                paths += [
                    "/usr/bin/firefox",
                    "/snap/bin/firefox",
                ]
            for path in paths:
                if os.path.exists(path):
                    return path
            return shutil.which("firefox")
        
        # Detect each browser
        if find_chromium():
            detected.append({"value": "chromium", "label": "Chromium"})
        if find_chrome():
            detected.append({"value": "chrome", "label": "Google Chrome"})
        if find_edge():
            detected.append({"value": "edge", "label": "Microsoft Edge"})
        if find_firefox():
            detected.append({"value": "firefox", "label": "Mozilla Firefox"})
        
        return {"browsers": detected}
    except Exception as e:
        print(f"[ERROR] Error detecting browsers: {e}")
        # In case of error, return an empty list
        return {"browsers": []}

@app.post("/api/launch_browser")
def launch_browser(request: Dict = None):
    try:
        if request is None:
            request = {}
        
        browser_choice = request.get("browser", "auto")
        browser_path = None
        browser_name = None
        
        is_windows = os.name == "nt"
        is_mac = sys.platform == "darwin"
        is_linux = sys.platform.startswith("linux")

        # Function to find Chromium (portable or installed)
        def find_chromium():
            paths = []
            if is_windows:
                paths += [
                    r"C:\Program Files\Chromium\Application\chrome.exe",
                    r"C:\Program Files\Chromium\Application\chromium.exe",
                    r"C:\Program Files (x86)\Chromium\Application\chrome.exe",
                    r"C:\Program Files (x86)\Chromium\Application\chromium.exe",
                    os.path.expanduser(r"~\AppData\Local\Chromium\Application\chrome.exe"),
                    os.path.expanduser(r"~\AppData\Local\Chromium\Application\chromium.exe"),
                ]
            if is_mac:
                paths += [
                    "/Applications/Chromium.app/Contents/MacOS/Chromium",
                ]
            if is_linux:
                paths += [
                    "/usr/bin/chromium",
                    "/usr/bin/chromium-browser",
                    "/snap/bin/chromium",
                ]
            for path in paths:
                if os.path.exists(path):
                    return path
            return shutil.which("chromium") or shutil.which("chromium-browser")
        
        # Function to find Chrome
        def find_chrome():
            paths = []
            if is_windows:
                paths += [
                    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
                    os.path.expanduser(r"~\AppData\Local\Google\Chrome\Application\chrome.exe")
                ]
            if is_mac:
                paths += [
                    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                ]
            if is_linux:
                paths += [
                    "/usr/bin/google-chrome",
                    "/usr/bin/google-chrome-stable",
                    "/snap/bin/chromium",
                ]
            for path in paths:
                if os.path.exists(path):
                    return path
            return shutil.which("chrome") or shutil.which("google-chrome") or shutil.which("google-chrome-stable")
        
        # Function to find Edge
        def find_edge():
            paths = []
            if is_windows:
                paths += [
                    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
                    os.path.expanduser(r"~\AppData\Local\Microsoft\Edge\Application\msedge.exe")
                ]
            if is_mac:
                paths += [
                    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
                ]
            if is_linux:
                paths += [
                    "/usr/bin/microsoft-edge",
                    "/usr/bin/microsoft-edge-stable",
                ]
            for path in paths:
                if os.path.exists(path):
                    return path
            return shutil.which("msedge") or shutil.which("microsoft-edge") or shutil.which("microsoft-edge-stable")
        
        # Function to find Firefox
        def find_firefox():
            paths = []
            if is_windows:
                paths += [
                    r"C:\Program Files\Mozilla Firefox\firefox.exe",
                    r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe",
                    os.path.expanduser(r"~\AppData\Local\Mozilla Firefox\firefox.exe")
                ]
            if is_mac:
                paths += [
                    "/Applications/Firefox.app/Contents/MacOS/firefox",
                ]
            if is_linux:
                paths += [
                    "/usr/bin/firefox",
                    "/snap/bin/firefox",
                ]
            for path in paths:
                if os.path.exists(path):
                    return path
            return shutil.which("firefox")
        
        # Select browser according to choice
        if browser_choice == "chromium":
            browser_path = find_chromium()
            browser_name = "Chromium"
        elif browser_choice == "chrome":
            browser_path = find_chrome()
            browser_name = "Chrome"
        elif browser_choice == "edge":
            browser_path = find_edge()
            browser_name = "Edge"
        elif browser_choice == "firefox":
            browser_path = find_firefox()
            browser_name = "Firefox"
        else:  # auto
            # Try in order: Chromium, Chrome, Edge, Firefox
            browser_path = find_chromium()
            if browser_path:
                browser_name = "Chromium"
            else:
                browser_path = find_chrome()
                if browser_path:
                    browser_name = "Chrome"
                else:
                    browser_path = find_edge()
                    if browser_path:
                        browser_name = "Edge"
                    else:
                        browser_path = find_firefox()
                        if browser_path:
                            browser_name = "Firefox"
        
        if not browser_path:
            raise HTTPException(
                status_code=500,
                detail=f"Could not find {browser_name or 'any supported browser'} installation. Please install Chrome, Edge, or Firefox."
            )
        
        # Create temp user data dir
        user_data_dir = tempfile.mkdtemp(prefix="kittyproxy_browser_")
        
        # Launch args according to browser
        if browser_name == "Firefox":
            # Firefox requires proxy configuration via a preferences file
            # Create profile directory if it doesn't exist
            os.makedirs(user_data_dir, exist_ok=True)
            
            # Create user.js file with proxy preferences
            user_js_path = os.path.join(user_data_dir, "user.js")
            with open(user_js_path, 'w', encoding='utf-8') as f:
                f.write("""// Proxy configuration for KittyProxy
user_pref("network.proxy.type", 1);
user_pref("network.proxy.http", "127.0.0.1");
user_pref("network.proxy.http_port", 8080);
user_pref("network.proxy.ssl", "127.0.0.1");
user_pref("network.proxy.ssl_port", 8080);
user_pref("network.proxy.share_proxy_settings", true);
user_pref("network.proxy.no_proxies_on", "localhost, 127.0.0.1");

// Accept self-signed certificates (for mitmproxy)
// Note: You may still need to accept the certificate manually the first time
user_pref("security.tls.insecure_fallback_hosts", "127.0.0.1,localhost");
user_pref("security.tls.unrestricted_rc4_fallback", true);
user_pref("security.enterprise_roots.enabled", true);
user_pref("security.ssl.errorReporting.enabled", false);
user_pref("security.ssl.treat_unsafe_negotiation_as_broken", false);
// Allow invalid certificates for localhost (less secure but works for testing)
user_pref("security.tls.version.min", 1);
user_pref("security.tls.version.max", 4);
""")
            
            # Try to find and install the mitmproxy CA certificate
            # The certificate is usually located in ~/.mitmproxy/
            mitmproxy_cert_paths = [
                os.path.join(os.path.expanduser("~"), ".mitmproxy", "mitmproxy-ca-cert.pem"),
                os.path.join(os.path.expanduser("~"), ".mitmproxy", "mitmproxy-ca-cert.cer"),
            ]
            
            # Note: Firefox requires manual certificate installation via about:preferences#privacy
            # We cannot install it automatically via user.js
            # But we can at least create a help message
            
            # Firefox uses different arguments
            # Open mitm.it to install the CA certificate
            # Note: The user will need to accept the certificate the first time they visit an HTTPS site
            # or install the CA certificate from http://mitm.it
            args = [
                browser_path,
                "-new-instance",
                "-profile", user_data_dir,
                "http://mitm.it"  # Page pour installer le certificat CA de mitmproxy
            ]
            subprocess.Popen(args)
        else:
            # Chrome/Edge (Chromium-based)
            args = [
                browser_path,
                "--proxy-server=127.0.0.1:8080",
                "--ignore-certificate-errors",
                f"--user-data-dir={user_data_dir}",
                "--no-first-run",
                "--no-default-browser-check",
                "http://example.com"
            ]
            subprocess.Popen(args)
        
        return {"status": "success", "browser": browser_path, "browser_name": browser_name}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# === MODULES ENDPOINTS ===
# Store output for module execution
module_outputs = {}

def _extract_tags_from_source(file_path: str) -> list:
    """Extract tags from module source file without loading the module"""
    import ast
    import os
    
    if not os.path.exists(file_path):
        return []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            source = f.read()
        
        # Parse the AST
        tree = ast.parse(source)
        
        # Look for __info__ dictionary
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                # Check class attributes
                for item in node.body:
                    if isinstance(item, ast.Assign):
                        for target in item.targets:
                            if isinstance(target, ast.Name) and target.id == '__info__':
                                # Found __info__ assignment
                                if isinstance(item.value, ast.Dict):
                                    # Extract tags from dict
                                    keys = [ast.literal_eval(k) if isinstance(k, (ast.Str, ast.Constant)) else None 
                                            for k in item.value.keys]
                                    values = item.value.values
                                    
                                    for key, value in zip(keys, values):
                                        if key == 'tags':
                                            # Extract tags list
                                            if isinstance(value, ast.List):
                                                tags = []
                                                for elt in value.elts:
                                                    if isinstance(elt, (ast.Str, ast.Constant)):
                                                        tag_val = elt.s if isinstance(elt, ast.Str) else elt.value
                                                        if isinstance(tag_val, str):
                                                            tags.append(tag_val)
                                                return tags
                                            elif isinstance(value, (ast.Str, ast.Constant)):
                                                tag_val = value.s if isinstance(value, ast.Str) else value.value
                                                if isinstance(tag_val, str):
                                                    return [tag_val]
                                        elif key == 'plugins':
                                            # Extract plugins (alias for tags)
                                            if isinstance(value, ast.List):
                                                tags = []
                                                for elt in value.elts:
                                                    if isinstance(elt, (ast.Str, ast.Constant)):
                                                        tag_val = elt.s if isinstance(elt, ast.Str) else elt.value
                                                        if isinstance(tag_val, str):
                                                            tags.append(tag_val)
                                                return tags
                                            elif isinstance(value, (ast.Str, ast.Constant)):
                                                tag_val = value.s if isinstance(value, ast.Str) else value.value
                                                if isinstance(tag_val, str):
                                                    return [tag_val]
    except Exception as e:
        # If AST parsing fails, fall back to regex (less reliable but more forgiving)
        import re
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                source = f.read()
            
            # Try to find __info__ with tags using regex
            # Look for 'tags': [...] or 'tags': '...'
            tags_pattern = r"['\"]tags['\"]\s*:\s*\[([^\]]+)\]"
            match = re.search(tags_pattern, source)
            if match:
                # Extract tags from list
                tags_str = match.group(1)
                # Simple extraction of quoted strings
                tag_matches = re.findall(r"['\"]([^'\"]+)['\"]", tags_str)
                if tag_matches:
                    return tag_matches
            
            # Try plugins as fallback
            plugins_pattern = r"['\"]plugins['\"]\s*:\s*\[([^\]]+)\]"
            match = re.search(plugins_pattern, source)
            if match:
                plugins_str = match.group(1)
                tag_matches = re.findall(r"['\"]([^'\"]+)['\"]", plugins_str)
                if tag_matches:
                    return tag_matches
        except:
            pass
    
    return []

def load_modules_cache():
    """Load and cache all modules with 'web' tag (called once at startup)"""
    global modules_cache
    
    if not framework:
        print("[WARNING] Framework not initialized, cannot load modules cache")
        return
    
    print("[+] Loading modules cache...")
    try:
        with modules_cache_lock:
            # Discover all modules
            discovered_modules = framework.module_loader.discover_modules()
            print(f"[+] Discovered {len(discovered_modules)} modules")
            
            modules_list = []
            modules_with_web_tag = 0
            modules_loaded = 0
            modules_skipped = 0
            
            # Iterate through discovered modules
            for module_path, file_path in discovered_modules.items():
                try:
                    # First, check tags from source file without loading the module
                    tags = _extract_tags_from_source(file_path)
                    
                    # Skip modules without "web" tag (don't load them at all)
                    if "web" not in tags:
                        modules_skipped += 1
                        continue
                    
                    modules_with_web_tag += 1
                    
                    # Load modules with "web" tag and cache them for immediate use
                    # Use load_only=False to actually cache the module in the framework
                    module = framework.load_module(module_path, load_only=False)
                    if not module:
                        modules_skipped += 1
                        continue
                    
                    modules_loaded += 1
                    
                    # Get module info
                    info = framework.get_module_info(module_path)
                    
                    # Extract category from path
                    category = module_path.split('/')[0] if '/' in module_path else 'misc'
                    
                    # Extract tags if present in __info__
                    raw_tags = []
                    if info and isinstance(info, dict):
                        raw_tags = info.get('tags') or info.get('Tags') or []
                        if isinstance(raw_tags, str):
                            raw_tags = [raw_tags]
                        elif not isinstance(raw_tags, list):
                            raw_tags = []

                    # Format for frontend
                    module_data = {
                        'name': module_path,
                        'description': info.get('Description', info.get('description', 'No description')) if info else 'No description',
                        'author': info.get('Author', info.get('author', 'Unknown')) if info else 'Unknown',
                        'category': category,
                        'options': [],
                        'tags': raw_tags
                    }
                    
                    # Get options
                    try:
                        if module and hasattr(module, 'get_options'):
                            options = module.get_options()
                            if isinstance(options, dict):
                                for opt_name, opt_obj in options.items():
                                    if hasattr(opt_obj, 'description'):
                                        module_data['options'].append({
                                            'name': opt_name,
                                            'description': opt_obj.description,
                                            'required': getattr(opt_obj, 'required', False),
                                            'default': getattr(opt_obj, 'value', None)
                                        })
                    except Exception as e:
                        pass
                    
                    modules_list.append(module_data)
                except Exception as e:
                    print(f"[DEBUG] Error processing module {module_path}: {e}")
                    modules_skipped += 1
                    continue
            
            modules_cache = modules_list
            print(f"[+] Modules cache loaded: {len(modules_list)} modules with 'web' tag")
            print(f"    - Modules with 'web' tag found: {modules_with_web_tag}")
            print(f"    - Modules loaded: {modules_loaded}")
            print(f"    - Modules skipped (no 'web' tag or load error): {modules_skipped}")
            
    except Exception as e:
        import traceback
        print(f"[ERROR] Error loading modules cache: {str(e)}")
        print(f"[ERROR] Traceback: {traceback.format_exc()}")
        modules_cache = []
module_outputs_lock = threading.Lock()

def capture_module_output(module_name: str):
    """Capture stdout/stderr for module execution"""
    output_buffer = io.StringIO()
    
    class OutputCapture:
        def __init__(self, buffer):
            self.buffer = buffer
            self.original_stdout = sys.stdout
            self.original_stderr = sys.stderr
        
        def __enter__(self):
            sys.stdout = self.buffer
            sys.stderr = self.buffer
            return self
        
        def __exit__(self, *args):
            sys.stdout = self.original_stdout
            sys.stderr = self.original_stderr
            with module_outputs_lock:
                module_outputs[module_name] = self.buffer.getvalue()
    
    return OutputCapture(output_buffer)

@app.get("/api/modules/debug")
def get_modules_debug():
    """Debug endpoint to check module discovery"""
    if not framework:
        return {"error": "Framework not initialized", "framework": None}
    
    try:
        discovered = framework.module_loader.discover_modules()
        lfi_module = 'auxiliary/scanner/http/lfi_fuzzer'
        
        result = {
            "total_discovered": len(discovered),
            "lfi_module_exists": lfi_module in discovered,
            "framework_initialized": framework is not None
        }
        
        if lfi_module in discovered:
            # Try to load it
            module = framework.load_module(lfi_module, load_only=True)
            result["lfi_module_loaded"] = module is not None
            
            # Try to import it
            import importlib
            try:
                mod = importlib.import_module(f"modules.{lfi_module.replace('/', '.')}")
                result["lfi_module_imported"] = True
                result["lfi_has_info"] = hasattr(mod, '__info__')
                if hasattr(mod, '__info__'):
                    result["lfi_tags"] = mod.__info__.get('tags', [])
                    result["lfi_has_web_tag"] = 'web' in mod.__info__.get('tags', [])
            except Exception as e:
                result["lfi_import_error"] = str(e)
        
        return result
    except Exception as e:
        import traceback
        return {"error": str(e), "traceback": traceback.format_exc()}

@app.get("/api/modules")
def get_modules():
    """List all available modules (from cache)"""
    if not framework:
        raise HTTPException(status_code=500, detail="Framework not initialized")
    
    with modules_cache_lock:
        if modules_cache is None:
            # Cache not loaded yet, load it now
            load_modules_cache()
        
        return modules_cache if modules_cache is not None else []

@app.post("/api/modules/refresh")
def refresh_modules_cache():
    """Refresh the modules cache (manual refresh)"""
    if not framework:
        raise HTTPException(status_code=500, detail="Framework not initialized")
    
    try:
        load_modules_cache()
        return {
            "status": "success",
            "message": f"Modules cache refreshed: {len(modules_cache) if modules_cache else 0} modules",
            "count": len(modules_cache) if modules_cache else 0
        }
    except Exception as e:
        import traceback
        print(f"[ERROR] Error refreshing modules cache: {str(e)}")
        print(f"[ERROR] Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Error refreshing modules cache: {str(e)}")

@app.get("/api/modules/{module_path:path}")
def get_module_info(module_path: str):
    """Get information about a specific module"""
    if not framework:
        raise HTTPException(status_code=500, detail="Framework not initialized")
    
    try:
        # Get module info
        info = framework.get_module_info(module_path)
        if not info:
            raise HTTPException(status_code=404, detail="Module not found")
        
        # Load module to get options
        module = framework.load_module(module_path, load_only=True)
        if not module:
            raise HTTPException(status_code=404, detail="Module not found")
        
        # Get options
        options = []
        if hasattr(module, 'get_options'):
            opts = module.get_options()
            if isinstance(opts, dict):
                for opt_name, opt_obj in opts.items():
                    if hasattr(opt_obj, 'description'):
                        options.append({
                            'name': opt_name,
                            'description': opt_obj.description,
                            'required': getattr(opt_obj, 'required', False),
                            'default': getattr(opt_obj, 'value', None)
                        })
        
        return {
            'name': module_path,
            'description': info.get('Description', info.get('description', 'No description')),
            'author': info.get('Author', info.get('author', 'Unknown')),
            'options': options
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting module info: {str(e)}")

@app.post("/api/execute_module_from_flow")
def execute_module_from_flow(request: Dict):
    """Execute a module with auto-configuration from flow data"""
    if not framework:
        raise HTTPException(status_code=500, detail="Framework not initialized")
    
    try:
        module_name = request.get('module_name')
        flow_id = request.get('flow_id')
        
        if not module_name:
            raise HTTPException(status_code=400, detail="module_name is required")
        if not flow_id:
            raise HTTPException(status_code=400, detail="flow_id is required")
        
        # Get the flow
        flow = flow_manager.flows.get(flow_id)
        if not flow:
            raise HTTPException(status_code=404, detail="Flow not found")
        
        # Extract configuration from flow
        if not flow.request:
            raise HTTPException(status_code=400, detail="Flow request not available")
        
        from urllib.parse import urlparse
        # Use flow.request.url instead of flow.url
        flow_url = flow.request.url
        parsed_url = urlparse(flow_url)
        
        # Auto-configure options from request
        auto_options = {}
        
        # Extract host and port - use flow.request.host directly
        # HTTP modules use 'target' and 'port', not 'RHOST' and 'RPORT'
        host = flow.request.host or parsed_url.hostname or 'localhost'
        
        # Determine port from parsed URL or default based on scheme
        if parsed_url.port:
            port = parsed_url.port
        else:
            # Default port based on scheme
            port = 443 if flow.request.scheme == 'https' else 80
        
        # Build target URL (modules may use 'target' for full URL or just hostname)
        # Try both formats to support different module types
        if flow.request.scheme == 'https':
            target_url = f"https://{host}:{port}"
        else:
            target_url = f"http://{host}:{port}"
        
        # Set options - try both naming conventions
        auto_options['target'] = target_url  # HTTP modules use 'target'
        auto_options['port'] = port  # HTTP modules use 'port'
        auto_options['RHOST'] = host  # Some modules might use RHOST
        auto_options['RPORT'] = port  # Some modules might use RPORT
        
        # SSL
        auto_options['ssl'] = flow.request.scheme == 'https'  # HTTP modules use lowercase 'ssl'
        
        # Target URI - use flow.request.path directly
        auto_options['TARGETURI'] = flow.request.path or '/'
        
        # Method
        auto_options['METHOD'] = flow.request.method or 'GET'
        
        # Headers (convert to string or dict based on module needs)
        if flow.request and flow.request.headers:
            # Some modules might expect headers in a specific format
            pass
        
        # Body/Data
        if flow.request and flow.request.content:
            try:
                # flow.request.content is already bytes, decode it
                body_content = flow.request.content.decode('utf-8', errors='ignore')
                if body_content:
                    auto_options['DATA'] = body_content
            except:
                pass
        
        # Load module
        module = framework.load_module(module_name)
        if not module:
            raise HTTPException(status_code=404, detail="Module not found")
        
        # Set auto-configured options
        for opt_name, opt_value in auto_options.items():
            try:
                module.set_option(opt_name, opt_value)
            except:
                # Option might not exist in this module, skip it
                pass
        
        # Check required options
        if not module.check_options():
            missing = []
            # Use the framework's built-in method to get missing options
            if hasattr(module, 'get_missing_options'):
                missing = module.get_missing_options()
            else:
                # Fallback: manually check options
                if hasattr(module, 'get_options'):
                    opts = module.get_options()
                    if isinstance(opts, dict):
                        for opt_name, opt_obj in opts.items():
                            if getattr(opt_obj, 'required', False):
                                # Check if value is None or empty string
                                opt_value = getattr(opt_obj, 'value', None)
                                if opt_value is None or opt_value == '':
                                    missing.append(opt_name)
            
            missing_str = ', '.join(missing) if missing else 'unknown'
            raise HTTPException(status_code=400, detail=f"Missing required options: {missing_str}")
        
        # Execute module in a thread with output capture
        execution_id = f"{module_name}_{int(time.time() * 1000)}"
        
        # Initialize output
        with module_outputs_lock:
            module_outputs[execution_id] = "Module execution started...\n"
        
        module_result = {'value': None}

        def run_with_capture():
            try:
                # Create a custom StringIO that updates module_outputs in real-time
                class RealtimeStringIO(io.StringIO):
                    def __init__(self, execution_id):
                        super().__init__()
                        self.execution_id = execution_id
                        self._buffer = []
                    
                    def write(self, s):
                        if s:
                            super().write(s)
                            self._buffer.append(s)
                            # Update output in real-time
                            with module_outputs_lock:
                                current = module_outputs.get(self.execution_id, "")
                                module_outputs[self.execution_id] = current + s
                        return len(s)
                    
                    def flush(self):
                        # Force update
                        with module_outputs_lock:
                            current = module_outputs.get(self.execution_id, "")
                            full_output = ''.join(self._buffer)
                            if full_output != current:
                                module_outputs[self.execution_id] = full_output
                        super().flush()
                
                output_buffer = RealtimeStringIO(execution_id)
                old_stdout = sys.stdout
                old_stderr = sys.stderr
                
                sys.stdout = output_buffer
                sys.stderr = output_buffer
                
                # Patch ALL possible locations where print functions might be imported
                patches_applied = {}
                original_funcs = {}
                
                def create_patched_func(func_name, prefix=""):
                    """Create a patched function that writes to buffer"""
                    def patched(*args, **kwargs):
                        message = ' '.join(str(arg) for arg in args) if args else ""
                        formatted = f"{prefix}{message}\n" if prefix else f"{message}\n"
                        output_buffer.write(formatted)
                        output_buffer.flush()
                    return patched
                
                # Patch core.output_handler module
                try:
                    import core.output_handler as output_handler_module
                    for func_name in ['print_info', 'print_status', 'print_success', 'print_error', 'print_warning']:
                        if hasattr(output_handler_module, func_name):
                            original_funcs[func_name] = getattr(output_handler_module, func_name)
                            prefix_map = {
                                'print_info': '',
                                'print_status': '[*] ',
                                'print_success': '[+] ',
                                'print_error': '[!] ',
                                'print_warning': '[~] '
                            }
                            patched = create_patched_func(func_name, prefix_map.get(func_name, ''))
                            setattr(output_handler_module, func_name, patched)
                            patches_applied[f'core.output_handler.{func_name}'] = (output_handler_module, func_name, original_funcs[func_name])
                except Exception as e:
                    output_buffer.write(f"Warning: Could not patch core.output_handler: {e}\n")
                
                # Patch kittysploit.__init__ module (where modules import from)
                try:
                    if 'kittysploit' in sys.modules:
                        kittysploit_module = sys.modules['kittysploit']
                        for func_name in ['print_info', 'print_status', 'print_success', 'print_error', 'print_warning']:
                            if hasattr(kittysploit_module, func_name):
                                if func_name not in original_funcs:
                                    original_funcs[func_name] = getattr(kittysploit_module, func_name)
                                prefix_map = {
                                    'print_info': '',
                                    'print_status': '[*] ',
                                    'print_success': '[+] ',
                                    'print_error': '[!] ',
                                    'print_warning': '[~] '
                                }
                                patched = create_patched_func(func_name, prefix_map.get(func_name, ''))
                                setattr(kittysploit_module, func_name, patched)
                                patches_applied[f'kittysploit.{func_name}'] = (kittysploit_module, func_name, original_funcs[func_name])
                except Exception as e:
                    output_buffer.write(f"Warning: Could not patch kittysploit module: {e}\n")
                
                # Also patch in sys.modules
                for module_name in ['core.output_handler', 'kittysploit']:
                    if module_name in sys.modules:
                        module = sys.modules[module_name]
                        for func_name in ['print_info', 'print_status', 'print_success', 'print_error', 'print_warning']:
                            if hasattr(module, func_name):
                                if func_name not in original_funcs:
                                    original_funcs[func_name] = getattr(module, func_name)
                                prefix_map = {
                                    'print_info': '',
                                    'print_status': '[*] ',
                                    'print_success': '[+] ',
                                    'print_error': '[!] ',
                                    'print_warning': '[~] '
                                }
                                patched = create_patched_func(func_name, prefix_map.get(func_name, ''))
                                setattr(module, func_name, patched)
                                patches_applied[f'{module_name}.{func_name}'] = (module, func_name, original_funcs[func_name])
                
                try:
                    # Execute module
                    result = framework.execute_module(use_runtime_kernel=True)
                    module_result['value'] = result
                    
                    # Final flush
                    output_buffer.flush()
                    output_text = output_buffer.getvalue()
                    
                    with module_outputs_lock:
                        module_outputs[execution_id] = output_text
                        # Add result to output (True/False indicates completion)
                        module_outputs[execution_id] += f"\nResult: {result}"
                        # Mark as completed in a way the frontend can detect
                        module_outputs[execution_id] += "\n[MODULE_COMPLETED]"
                finally:
                    sys.stdout = old_stdout
                    sys.stderr = old_stderr
                    
                    # Restore all patched functions
                    for key, (module_obj, func_name, original_func) in patches_applied.items():
                        try:
                            setattr(module_obj, func_name, original_func)
                        except:
                            pass
                    
            except Exception as e:
                import traceback
                error_msg = f"Error executing module: {str(e)}\n{traceback.format_exc()}"
                with module_outputs_lock:
                    module_outputs[execution_id] = error_msg
        
        thread = threading.Thread(target=run_with_capture, daemon=True)
        thread.start()
        
        # Wait for module to complete (with reasonable timeout)
        thread.join(timeout=30)  # Wait up to 30 seconds
        
        # Get output
        with module_outputs_lock:
            output_text = module_outputs.get(execution_id, "Module execution started...")
        
        # Check if thread is still alive
        is_running = thread.is_alive()

        # If finished but result not captured, try to extract from output
        if not is_running and module_result.get('value') is None and output_text:
            import re
            match = re.search(r"Result:\s*(True|False|null|None)", output_text, re.IGNORECASE)
            if match:
                val = match.group(1).lower()
                if val == 'true':
                    module_result['value'] = True
                elif val == 'false':
                    module_result['value'] = False
                else:
                    module_result['value'] = None
        
        return {
            'status': 'success' if not is_running else 'running',
            'execution_id': execution_id,
            'output': output_text,
            'configured_options': auto_options,
            'is_running': is_running,
            'result': module_result.get('value')
        }
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        raise HTTPException(status_code=500, detail=f"Error executing module: {str(e)}\n{traceback.format_exc()}")


@app.post("/api/modules/suggestions")
def get_module_suggestions(payload: Dict):
    """
    Return a list of suggested modules based on detected technologies/configurations.
    Expected payload:
    {
        "technologies": ["nginx", "wordpress", ...],
        "configurations": ["cors", "nginx_config", ...]
    }
    """
    if not framework:
        raise HTTPException(status_code=500, detail="Framework not initialized")

    techs = payload.get("technologies", []) or []
    configs = payload.get("configurations", []) or []

    # Normalize to lowercase sets
    tech_set = set([t.lower() for t in techs if isinstance(t, str)])
    config_set = set([c.lower() for c in configs if isinstance(c, str)])

    with modules_cache_lock:
        if modules_cache is None:
            load_modules_cache()

        suggestions = []
        for mod in modules_cache or []:
            name = mod.get('name', '')
            name_lower = name.lower()
            tags = [t.lower() for t in mod.get('tags', []) if isinstance(t, str)]
            category = (mod.get('category') or '').lower()

            score = 0
            reasons = []

            # Tech/tag matches
            for t in tech_set:
                if t in tags or t in name_lower or t in category:
                    score += 3
                    reasons.append(f"Tech match: {t}")

            # Configuration matches
            for cfg in config_set:
                if cfg in tags or cfg in name_lower:
                    score += 2
                    reasons.append(f"Config match: {cfg}")

            # Simple heuristics by module path
            if 'nginx' in name_lower and 'nginx' in tech_set:
                score += 2
                reasons.append("Heuristic: nginx module for nginx server")
            if 'cors' in name_lower and any('cors' in t for t in tech_set):
                score += 2
                reasons.append("Heuristic: CORS-related")
            if 'wordpress' in name_lower and any('wordpress' in t for t in tech_set):
                score += 2
                reasons.append("Heuristic: WordPress related")

            if score > 0:
                priority = 'high' if score >= 6 else 'medium' if score >= 3 else 'low'
                suggestions.append({
                    "module": name,
                    "score": score,
                    "priority": priority,
                    "reasons": reasons
                })

        # Sort by score desc, then by name
        suggestions = sorted(suggestions, key=lambda x: (-x["score"], x["module"]))[:15]
        return suggestions
@app.post("/api/auto_configure_module_from_url")
def auto_configure_module_from_url(request: Dict):
    """Auto-configure module options from a URL (without executing)"""
    if not framework:
        raise HTTPException(status_code=500, detail="Framework not initialized")
    
    try:
        module_name = request.get('module_name')
        url = request.get('url')
        
        if not module_name:
            raise HTTPException(status_code=400, detail="module_name is required")
        if not url:
            raise HTTPException(status_code=400, detail="url is required")
        
        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        
        # Validate URL
        if not parsed_url.scheme or not parsed_url.hostname:
            raise HTTPException(status_code=400, detail="Invalid URL format")
        
        # Auto-configure options from URL (same logic as execute_module_from_flow)
        auto_options = {}
        
        host = parsed_url.hostname or 'localhost'
        
        # Determine port from parsed URL or default based on scheme
        if parsed_url.port:
            port = parsed_url.port
            port_suffix = f":{port}"
        else:
            # Default port based on scheme
            port = 443 if parsed_url.scheme == 'https' else 80
            port_suffix = ""  # do not append default port in URL display
        
        # Build target base (host only for kittysploit modules) and URL (for display)
        target_host = host
        target_url = f"{parsed_url.scheme}://{host}{port_suffix}"
        
        # Set options - try both naming conventions
        auto_options['target'] = target_host  # HTTP modules expect host without scheme
        auto_options['port'] = port  # HTTP modules use 'port'
        auto_options['RHOST'] = host  # Some modules might use RHOST
        auto_options['RPORT'] = port  # Some modules might use RPORT
        
        # SSL
        auto_options['ssl'] = parsed_url.scheme == 'https'
        auto_options['SSL'] = parsed_url.scheme == 'https'  # Some modules use uppercase
        
        # Target URI
        auto_options['TARGETURI'] = parsed_url.path or '/'
        auto_options['URI'] = parsed_url.path or '/'  # Alternative naming
        
        # Query string
        if parsed_url.query:
            auto_options['QUERY'] = parsed_url.query
        
        # Full URL for modules that need it
        auto_options['URL'] = url
        
        return {
            'status': 'success',
            'options': auto_options,
            'parsed': {
                'scheme': parsed_url.scheme,
                'hostname': host,
                'port': port,
                'path': parsed_url.path or '/',
                'query': parsed_url.query
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error auto-configuring module: {str(e)}")

@app.post("/api/modules/run")
def run_module(request: Dict):
    """Execute a module"""
    if not framework:
        raise HTTPException(status_code=500, detail="Framework not initialized")
    
    try:
        module_name = request.get('module_name')
        options = request.get('options', {})
        
        if not module_name:
            raise HTTPException(status_code=400, detail="module_name is required")
        
        # Load module
        module = framework.load_module(module_name)
        if not module:
            raise HTTPException(status_code=404, detail="Module not found")
        
        # Set options
        for opt_name, opt_value in options.items():
            module.set_option(opt_name, opt_value)
        
        # Check required options
        if not module.check_options():
            missing = []
            # Use the framework's built-in method to get missing options
            if hasattr(module, 'get_missing_options'):
                missing = module.get_missing_options()
            else:
                # Fallback: manually check options
                if hasattr(module, 'get_options'):
                    opts = module.get_options()
                    if isinstance(opts, dict):
                        for opt_name, opt_obj in opts.items():
                            if getattr(opt_obj, 'required', False):
                                # Check if value is None or empty string
                                opt_value = getattr(opt_obj, 'value', None)
                                if opt_value is None or opt_value == '':
                                    missing.append(opt_name)
            
            missing_str = ', '.join(missing) if missing else 'unknown'
            raise HTTPException(status_code=400, detail=f"Missing required options: {missing_str}")
        
        # Execute module in a thread with output capture
        execution_id = f"{module_name}_{int(time.time() * 1000)}"
        
        # Initialize output
        with module_outputs_lock:
            module_outputs[execution_id] = "Module execution started...\n"
        
        def run_with_capture():
            try:
                # Create a custom StringIO that updates module_outputs in real-time
                class RealtimeStringIO(io.StringIO):
                    def __init__(self, execution_id):
                        super().__init__()
                        self.execution_id = execution_id
                        self._buffer = []
                    
                    def write(self, s):
                        if s:
                            self._buffer.append(s)
                            # Update output in real-time
                            with module_outputs_lock:
                                current = module_outputs.get(self.execution_id, "")
                                module_outputs[self.execution_id] = current + s
                        return len(s)
                    
                    def flush(self):
                        # Force update
                        with module_outputs_lock:
                            current = module_outputs.get(self.execution_id, "")
                            full_output = ''.join(self._buffer)
                            if full_output != current:
                                module_outputs[self.execution_id] = full_output
                        super().flush()
                
                output_buffer = RealtimeStringIO(execution_id)
                old_stdout = sys.stdout
                old_stderr = sys.stderr
                
                sys.stdout = output_buffer
                sys.stderr = output_buffer
                
                # Patch ALL possible locations where print functions might be imported
                patches_applied = {}
                original_funcs = {}
                
                def create_patched_func(func_name, prefix=""):
                    """Create a patched function that writes to buffer"""
                    def patched(*args, **kwargs):
                        message = ' '.join(str(arg) for arg in args) if args else ""
                        formatted = f"{prefix}{message}\n" if prefix else f"{message}\n"
                        output_buffer.write(formatted)
                        output_buffer.flush()
                    return patched
                
                # Patch core.output_handler module
                try:
                    import core.output_handler as output_handler_module
                    for func_name in ['print_info', 'print_status', 'print_success', 'print_error', 'print_warning']:
                        if hasattr(output_handler_module, func_name):
                            original_funcs[func_name] = getattr(output_handler_module, func_name)
                            prefix_map = {
                                'print_info': '',
                                'print_status': '[*] ',
                                'print_success': '[+] ',
                                'print_error': '[!] ',
                                'print_warning': '[~] '
                            }
                            patched = create_patched_func(func_name, prefix_map.get(func_name, ''))
                            setattr(output_handler_module, func_name, patched)
                            patches_applied[f'core.output_handler.{func_name}'] = (output_handler_module, func_name, original_funcs[func_name])
                except Exception as e:
                    output_buffer.write(f"Warning: Could not patch core.output_handler: {e}\n")
                
                # Patch kittysploit.__init__ module (where modules import from)
                try:
                    if 'kittysploit' in sys.modules:
                        kittysploit_module = sys.modules['kittysploit']
                        for func_name in ['print_info', 'print_status', 'print_success', 'print_error', 'print_warning']:
                            if hasattr(kittysploit_module, func_name):
                                if func_name not in original_funcs:
                                    original_funcs[func_name] = getattr(kittysploit_module, func_name)
                                prefix_map = {
                                    'print_info': '',
                                    'print_status': '[*] ',
                                    'print_success': '[+] ',
                                    'print_error': '[!] ',
                                    'print_warning': '[~] '
                                }
                                patched = create_patched_func(func_name, prefix_map.get(func_name, ''))
                                setattr(kittysploit_module, func_name, patched)
                                patches_applied[f'kittysploit.{func_name}'] = (kittysploit_module, func_name, original_funcs[func_name])
                except Exception as e:
                    output_buffer.write(f"Warning: Could not patch kittysploit module: {e}\n")
                
                # Also patch in sys.modules
                for module_name in ['core.output_handler', 'kittysploit']:
                    if module_name in sys.modules:
                        module = sys.modules[module_name]
                        for func_name in ['print_info', 'print_status', 'print_success', 'print_error', 'print_warning']:
                            if hasattr(module, func_name):
                                if func_name not in original_funcs:
                                    original_funcs[func_name] = getattr(module, func_name)
                                prefix_map = {
                                    'print_info': '',
                                    'print_status': '[*] ',
                                    'print_success': '[+] ',
                                    'print_error': '[!] ',
                                    'print_warning': '[~] '
                                }
                                patched = create_patched_func(func_name, prefix_map.get(func_name, ''))
                                setattr(module, func_name, patched)
                                patches_applied[f'{module_name}.{func_name}'] = (module, func_name, original_funcs[func_name])
                
                try:
                    # Execute module
                    result = framework.execute_module(use_runtime_kernel=True)
                    
                    # Final flush
                    output_buffer.flush()
                    captured_output = output_buffer.getvalue()
                    
                    with module_outputs_lock:
                        output_text = captured_output if captured_output.strip() else module_outputs.get(execution_id, "")
                        if not output_text.strip():
                            output_text = "Module executed successfully.\n"
                        module_outputs[execution_id] = output_text
                        
                        # Add result to output (True/False indicates completion)
                        # Always add result to indicate completion (even if False or None)
                        module_outputs[execution_id] += f"\nResult: {result}"
                        # Mark as completed in a way the frontend can detect
                        module_outputs[execution_id] += "\n[MODULE_COMPLETED]"
                finally:
                    sys.stdout = old_stdout
                    sys.stderr = old_stderr
                    
                    # Restore all patched functions
                    for key, (module_obj, func_name, original_func) in patches_applied.items():
                        try:
                            setattr(module_obj, func_name, original_func)
                        except:
                            pass
                    
            except Exception as e:
                import traceback
                error_msg = f"Error executing module: {str(e)}\n{traceback.format_exc()}"
                with module_outputs_lock:
                    module_outputs[execution_id] = error_msg
        
        thread = threading.Thread(target=run_with_capture, daemon=True)
        thread.start()
        
        # Wait for module to complete (with reasonable timeout)
        thread.join(timeout=30)  # Wait up to 30 seconds
        
        # Get output
        with module_outputs_lock:
            output_text = module_outputs.get(execution_id, "Module execution started...")
        
        # Check if thread is still alive
        is_running = thread.is_alive()
        
        return {
            'status': 'success' if not is_running else 'running',
            'output': output_text,
            'result': None,
            'is_running': is_running,
            'execution_id': execution_id
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error executing module: {str(e)}")

import time

# === MODULE OUTPUT ENDPOINT ===
@app.get("/api/module-output/{execution_id}")
def get_module_output(execution_id: str):
    """Get module output by execution ID"""
    with module_outputs_lock:
        output_text = module_outputs.get(execution_id, "Module execution not found or completed.")
    
    return {
        'status': 'success',
        'output': output_text,
        'execution_id': execution_id
    }

# === INTERCEPTION PLUGINS ENDPOINTS ===
@app.get("/api/plugins")
def get_plugins():
    """Get all interception plugins"""
    try:
        plugins = plugin_manager.get_all_plugins()
        return plugins
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting plugins: {str(e)}")

@app.get("/api/plugins/{plugin_name}")
def get_plugin_info(plugin_name: str):
    """Get information about a specific plugin"""
    try:
        plugin = plugin_manager.get_plugin(plugin_name)
        if not plugin:
            raise HTTPException(status_code=404, detail="Plugin not found")
        
        return {
            "name": plugin.name,
            "description": plugin.description,
            "enabled": plugin.enabled,
            "config": plugin.config
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting plugin info: {str(e)}")

@app.post("/api/plugins/{plugin_name}/enable")
def enable_plugin(plugin_name: str):
    """Enable a plugin"""
    try:
        plugin_manager.enable_plugin(plugin_name)
        return {"status": "success", "message": f"Plugin {plugin_name} enabled"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error enabling plugin: {str(e)}")

@app.post("/api/plugins/{plugin_name}/disable")
def disable_plugin(plugin_name: str):
    """Disable a plugin"""
    try:
        plugin_manager.disable_plugin(plugin_name)
        return {"status": "success", "message": f"Plugin {plugin_name} disabled"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error disabling plugin: {str(e)}")

@app.post("/api/plugins/{plugin_name}/config")
def update_plugin_config(plugin_name: str, config: Dict):
    """Update plugin configuration"""
    try:
        plugin_manager.update_plugin_config(plugin_name, config)
        return {"status": "success", "message": f"Plugin {plugin_name} configuration updated"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error updating plugin config: {str(e)}")

# === ENDPOINT EXTRACTION ENDPOINTS ===
@app.get("/api/endpoints")
def get_discovered_endpoints():
    """Get all discovered endpoints and links"""
    try:
        # Ne plus logger à chaque appel pour éviter le spam
        # print(f"[API ENDPOINT] /api/endpoints called")
        all_endpoints = endpoint_extractor.get_all_discovered()
        
        react_apis = all_endpoints.get('react_api_endpoints', [])
        # Ne plus logger à chaque appel
        # print(f"[API ENDPOINT] Returning {len(react_apis)} React API endpoints")
        
        # Compter par catégorie depuis les données déjà extraites (pas besoin de réanalyser)
        category_counts = {
            'html_links': len(endpoint_extractor.discovered_links),
            'javascript_endpoints': len([e for e in endpoint_extractor.discovered_endpoints if any(ext in e for ext in ['.js', 'javascript'])]),
            'api_endpoints': len([e for e in endpoint_extractor.discovered_endpoints if '/api/' in e or '/graphql' in e.lower()]),
            'form_actions': 0,  # Non stocké séparément pour le moment
            'json_urls': len([e for e in endpoint_extractor.discovered_endpoints if '.json' in e or '/api/' in e]),
            'css_urls': len([e for e in endpoint_extractor.discovered_links if '.css' in e]),
            'other_resources': 0,
            'react_api_endpoints': len(react_apis),
        }
        
        # Calculer other_resources
        category_counts['other_resources'] = len(endpoint_extractor.discovered_endpoints) - category_counts['api_endpoints'] - category_counts['json_urls']
        
        result = {
            "total": all_endpoints['total'],
            "endpoints": all_endpoints['endpoints'],
            "links": all_endpoints['links'],
            "react_api_endpoints": react_apis,
            "graphql_queries": all_endpoints.get('graphql_queries', {}),
            "category_counts": category_counts
        }
        
        # Ne plus logger à chaque appel pour éviter le spam
        # print(f"[API ENDPOINT] Returning result with {len(react_apis)} React APIs and {len(all_endpoints.get('graphql_queries', {}))} GraphQL endpoints with queries")
        return result
    except Exception as e:
        import traceback
        print(f"[API ENDPOINT] Error: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error getting endpoints: {str(e)}")

# === PERFORMANCE MONITORING ENDPOINTS ===
@app.get("/api/performance")
def get_performance_stats():
    """Get performance monitoring statistics"""
    try:
        stats = performance_monitor.get_stats()
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting performance stats: {str(e)}")

# === COLLABORATION ENDPOINTS ===
# Stocker les connexions WebSocket actives
active_websockets: Dict[str, WebSocket] = {}
websocket_lock = threading.Lock()

# === FLOW UPDATES WEBSOCKET ===
active_flow_websockets: List[WebSocket] = []
flow_ws_lock = threading.Lock()

async def broadcast_new_flow(flow_data: Dict):
    """Broadcast a new flow to all connected clients."""
    to_remove = []
    with flow_ws_lock:
        for ws in active_flow_websockets:
            try:
                await ws.send_json({
                    "type": "new_flow",
                    "flow": flow_data
                })
            except Exception as e:
                to_remove.append(ws)
        
        # Remove disconnected clients
        for ws in to_remove:
            if ws in active_flow_websockets:
                active_flow_websockets.remove(ws)

def on_flow_added(flow_data: Dict):
    """Callback from FlowManager. Bridges sync to async."""
    # We need to run the async broadcast in the event loop
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # Broadcast to regular flow websockets
            asyncio.run_coroutine_threadsafe(broadcast_new_flow(flow_data), loop)
            # Also broadcast to collaboration sessions
            asyncio.run_coroutine_threadsafe(broadcast_flow_to_all_collaboration_sessions(flow_data), loop)
        else:
            # Should not happen in normal operation as uvicorn runs an event loop
            pass
    except RuntimeError:
        # No event loop in this thread
        pass

async def broadcast_flow_to_all_collaboration_sessions(flow_data: Dict):
    """Diffuse un flow à toutes les sessions collaboratives actives"""
    try:
        sessions = collaboration_manager.list_sessions()
        for session_info in sessions:
            session_id = session_info['id']
            connections = collaboration_manager.get_active_connections(session_id)
            
            if connections:
                await broadcast_to_session(session_id, None, {
                    'type': 'flow_added',
                    'flow': flow_data
                })
    except Exception as e:
        print(f"[ERROR] Error broadcasting flow to collaboration sessions: {e}")

# Register callback
flow_manager.register_callback(on_flow_added)

@app.websocket("/ws/flows")
async def websocket_flows(websocket: WebSocket):
    """WebSocket for real-time flow updates."""
    await websocket.accept()
    with flow_ws_lock:
        active_flow_websockets.append(websocket)
    
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        with flow_ws_lock:
            if websocket in active_flow_websockets:
                active_flow_websockets.remove(websocket)


@app.websocket("/ws/collaboration/{session_id}")
async def websocket_collaboration(websocket: WebSocket, session_id: str):
    """WebSocket pour la collaboration en temps réel"""
    await websocket.accept()
    websocket_id = str(uuid.uuid4())
    
    try:
        # Recevoir les informations du collaborateur
        data = await websocket.receive_json()
        collaborator_name = data.get('name', 'Anonymous')
        collaborator_color = data.get('color', '#2196f3')
        
        # Create or retrieve the session
        session = collaboration_manager.get_session(session_id)
        if not session:
            # Create a new session if it doesn't exist
            session = collaboration_manager.create_session(
                name=f"Session {session_id[:8]}",
                owner_id=websocket_id,
                target_url=data.get('target_url', '')
            )
            session_id = session.id
        
        # Create the collaborator
        collaborator = Collaborator(
            id=websocket_id,
            name=collaborator_name,
            color=collaborator_color,
            connected_at=time.time(),
            last_seen=time.time()
        )
        
        # Rejoindre la session
        session = collaboration_manager.join_session(session_id, collaborator, websocket_id)
        
        with websocket_lock:
            active_websockets[websocket_id] = websocket
        
        # Envoyer l'état initial
        await websocket.send_json({
            'type': 'session_joined',
            'session': {
                'id': session.id,
                'name': session.name,
                'target_url': session.target_url,
                'collaborators': [
                    {
                        'id': c.id,
                        'name': c.name,
                        'color': c.color,
                        'selected_flow': session.selected_flows.get(c.id)
                    }
                    for c in session.collaborators.values()
                ],
                'annotations': {
                    flow_id: [
                        {
                            'id': a.id,
                            'author_id': a.author_id,
                            'author_name': a.author_name,
                            'content': a.content,
                            'created_at': a.created_at
                        }
                        for a in annotations
                    ]
                    for flow_id, annotations in session.annotations.items()
                }
            }
        })
        
        # Notifier les autres collaborateurs
        await broadcast_to_session(session_id, websocket_id, {
            'type': 'collaborator_joined',
            'collaborator': {
                'id': collaborator.id,
                'name': collaborator.name,
                'color': collaborator.color
            }
        })
        
        # Boucle principale pour recevoir les messages
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_json(), timeout=30.0)
                await handle_collaboration_message(session_id, websocket_id, data)
            except asyncio.TimeoutError:
                # Envoyer un ping pour maintenir la connexion
                await websocket.send_json({'type': 'ping'})
            except WebSocketDisconnect:
                break
    
    except Exception as e:
        print(f"[ERROR] WebSocket error: {e}")
    finally:
        # Clean up
        collaboration_manager.leave_session(websocket_id)
        with websocket_lock:
            active_websockets.pop(websocket_id, None)
        
        # Notifier les autres collaborateurs
        await broadcast_to_session(session_id, websocket_id, {
            'type': 'collaborator_left',
            'collaborator_id': websocket_id
        })


@app.websocket("/ws/collaboration/{session_id}/mirror")
async def websocket_mirror(websocket: WebSocket, session_id: str):
    """WebSocket pour le live browser mirroring"""
    await websocket.accept()
    websocket_id = str(uuid.uuid4())
    user_id = None
    
    try:
        # Recevoir les informations initiales
        data = await websocket.receive_json()
        
        if data.get('type') == 'mirror_start':
            user_id = data.get('user_id')
            if not user_id:
                await websocket.close(code=1008, reason="user_id required")
                return
            
            with websocket_lock:
                active_websockets[websocket_id] = websocket
            
            # Notifier les autres participants qu'un mirroring a démarré
            print(f"[DEBUG] Broadcasting mirror_started for user_id: {user_id} in session: {session_id}")
            await broadcast_to_session(session_id, None, {
                'type': 'mirror_started',
                'user_id': user_id
            })
            print(f"[DEBUG] Mirror_started message broadcasted")
            
            # Envoyer la configuration
            await websocket.send_json({
                'type': 'mirror_config',
                'config': {
                    'screenshotInterval': 1000,
                    'quality': 0.7
                }
            })
            
            # Boucle principale pour recevoir les données de mirroring
            while True:
                try:
                    data = await asyncio.wait_for(websocket.receive_json(), timeout=60.0)
                    
                    # Diffuser les données aux autres participants
                    if data.get('type') in ['dom_snapshot', 'dom_diff', 'screenshot']:
                        await broadcast_to_session(session_id, websocket_id, {
                            'type': 'mirror_data',
                            'user_id': user_id,
                            'data': data
                        }, exclude_websocket_id=websocket_id)
                    
                except asyncio.TimeoutError:
                    # Envoyer un ping pour maintenir la connexion
                    await websocket.send_json({'type': 'ping'})
                except WebSocketDisconnect:
                    break
        else:
            await websocket.close(code=1008, reason="Invalid initial message")
    
    except Exception as e:
        print(f"[ERROR] Mirror WebSocket error: {e}")
    finally:
        # Clean up
        with websocket_lock:
            active_websockets.pop(websocket_id, None)
        
        # Notifier que le mirroring s'est arrêté
        if user_id:
            await broadcast_to_session(session_id, None, {
                'type': 'mirror_stopped',
                'user_id': user_id
            })


async def handle_collaboration_message(session_id: str, websocket_id: str, data: Dict):
    """Gère les messages de collaboration"""
    msg_type = data.get('type')
    
    if msg_type == 'flow_selected':
        flow_id = data.get('flow_id')
        collaborator_id = collaboration_manager.get_collaborator_for_websocket(websocket_id)
        if collaborator_id:
            collaboration_manager.set_selected_flow(session_id, collaborator_id, flow_id)
            await broadcast_to_session(session_id, websocket_id, {
                'type': 'flow_selected',
                'collaborator_id': collaborator_id,
                'flow_id': flow_id
            })
    
    elif msg_type == 'annotation_added':
        flow_id = data.get('flow_id')
        content = data.get('content')
        collaborator_id = collaboration_manager.get_collaborator_for_websocket(websocket_id)
        session = collaboration_manager.get_session(session_id)
        
        if session and collaborator_id:
            collaborator = session.collaborators.get(collaborator_id)
            if collaborator:
                annotation = collaboration_manager.add_annotation(
                    session_id, flow_id, collaborator_id, collaborator.name, content
                )
                if annotation:
                    await broadcast_to_session(session_id, None, {
                        'type': 'annotation_added',
                        'annotation': {
                            'id': annotation.id,
                            'flow_id': annotation.flow_id,
                            'author_id': annotation.author_id,
                            'author_name': annotation.author_name,
                            'content': annotation.content,
                            'created_at': annotation.created_at
                        }
                    })
    
    elif msg_type == 'annotation_updated':
        annotation_id = data.get('annotation_id')
        content = data.get('content')
        collaborator_id = collaboration_manager.get_collaborator_for_websocket(websocket_id)
        
        if collaborator_id:
            annotation = collaboration_manager.update_annotation(
                session_id, annotation_id, collaborator_id, content
            )
            if annotation:
                await broadcast_to_session(session_id, None, {
                    'type': 'annotation_updated',
                    'annotation': {
                        'id': annotation.id,
                        'flow_id': annotation.flow_id,
                        'content': annotation.content,
                        'updated_at': annotation.updated_at
                    }
                })
    
    elif msg_type == 'annotation_deleted':
        annotation_id = data.get('annotation_id')
        collaborator_id = collaboration_manager.get_collaborator_for_websocket(websocket_id)
        
        if collaborator_id:
            if collaboration_manager.delete_annotation(session_id, annotation_id, collaborator_id):
                await broadcast_to_session(session_id, None, {
                    'type': 'annotation_deleted',
                    'annotation_id': annotation_id
                })
    
    elif msg_type == 'flow_added':
        # Notifier quand un nouveau flow est ajouté
        flow = data.get('flow')
        collaborator_id = collaboration_manager.get_collaborator_for_websocket(websocket_id)
        
        if flow:
            # Transmettre le flow complet avec l'ID du collaborateur
            message = {
                'type': 'flow_added',
                'flow': flow
            }
            # Ajouter user_id seulement si collaborator_id est disponible
            if collaborator_id:
                message['user_id'] = collaborator_id
                message['userId'] = collaborator_id  # Alias pour compatibilité
            
            await broadcast_to_session(session_id, websocket_id, message)
    
    elif msg_type in ['screenshot', 'dom_snapshot', 'dom_diff']:
        # Messages de mirroring - les rediffuser comme mirror_data
        collaborator_id = collaboration_manager.get_collaborator_for_websocket(websocket_id)
        if collaborator_id:
            print(f"[DEBUG] Mirror data received: type={msg_type}, websocket_id={websocket_id}, collaborator_id={collaborator_id}")
            await broadcast_to_session(session_id, websocket_id, {
                'type': 'mirror_data',
                'user_id': collaborator_id,
                'data': data
            }, exclude_websocket_id=websocket_id)
        else:
            print(f"[WARNING] No collaborator_id found for websocket_id={websocket_id} when receiving mirror data")
    
    elif msg_type == 'mirror_start':
        # Démarrer le mirroring via le WebSocket de collaboration
        collaborator_id = collaboration_manager.get_collaborator_for_websocket(websocket_id)
        if collaborator_id:
            await broadcast_to_session(session_id, None, {
                'type': 'mirror_started',
                'user_id': collaborator_id
            })
    
    elif msg_type == 'mirror_stop':
        # Arrêter le mirroring
        collaborator_id = collaboration_manager.get_collaborator_for_websocket(websocket_id)
        if collaborator_id:
            await broadcast_to_session(session_id, None, {
                'type': 'mirror_stopped',
                'user_id': collaborator_id
            })
    
    elif msg_type == 'chat_message':
        # Message de chat
        content = data.get('content')
        collaborator_id = collaboration_manager.get_collaborator_for_websocket(websocket_id)
        session = collaboration_manager.get_session(session_id)
        
        if session and collaborator_id and content:
            collaborator = session.collaborators.get(collaborator_id)
            if collaborator:
                message = {
                    'id': str(uuid.uuid4()),
                    'session_id': session_id,
                    'user_id': collaborator_id,
                    'username': collaborator.name,
                    'content': content,
                    'created_at': time.time()
                }
                await broadcast_to_session(session_id, None, {
                    'type': 'chat_message',
                    'message': message
                })
    
    elif msg_type == 'cursor_position':
        # Position du curseur pour le suivi en temps réel
        flow_id = data.get('flow_id')
        position = data.get('position')
        collaborator_id = collaboration_manager.get_collaborator_for_websocket(websocket_id)
        
        if collaborator_id:
            await broadcast_to_session(session_id, websocket_id, {
                'type': 'cursor_position',
                'collaborator_id': collaborator_id,
                'flow_id': flow_id,
                'position': position
            })

async def broadcast_to_session(session_id: str, exclude_websocket_id: Optional[str], message: Dict):
    """Diffuse un message à tous les collaborateurs d'une session"""
    connections = collaboration_manager.get_active_connections(session_id)
    
    with websocket_lock:
        for websocket_id in connections:
            if websocket_id != exclude_websocket_id:
                websocket = active_websockets.get(websocket_id)
                if websocket:
                    try:
                        await websocket.send_json(message)
                    except Exception as e:
                        print(f"[ERROR] Error sending to websocket {websocket_id}: {e}")

# Stocker la référence à l'event loop principal pour les broadcasts
main_event_loop = None

def set_main_event_loop(loop):
    """Définit l'event loop principal pour les broadcasts"""
    global main_event_loop
    main_event_loop = loop

def broadcast_flow_to_collaborators(flow):
    """Notifie tous les collaborateurs actifs d'un nouveau flow (appelé depuis proxy_core)"""
    # Cette fonction sera appelée de manière synchrone depuis mitmproxy
    # On doit utiliser asyncio pour envoyer aux WebSockets
    try:
        # Récupérer toutes les sessions actives
        sessions = collaboration_manager.list_sessions()
        for session_info in sessions:
            session_id = session_info['id']
            connections = collaboration_manager.get_active_connections(session_id)
            
            if connections:
                # Sérialiser le flow
                flow_data = flow_manager._serialize_flow(flow, detail=False)
                
                # Envoyer via asyncio (dans un thread séparé)
                try:
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        asyncio.create_task(broadcast_to_session(session_id, None, {
                            'type': 'flow_added',
                            'flow': flow_data
                        }))
                    else:
                        asyncio.run_coroutine_threadsafe(
                            broadcast_to_session(session_id, None, {
                                'type': 'flow_added',
                                'flow': flow_data
                            }),
                            loop
                        )
                except RuntimeError:
                    # Pas d'event loop, utiliser le thread principal
                    if main_event_loop:
                        asyncio.run_coroutine_threadsafe(
                            broadcast_to_session(session_id, None, {
                                'type': 'flow_added',
                                'flow': flow_data
                            }),
                            main_event_loop
                        )
    except Exception as e:
        # Ignorer les erreurs pour ne pas bloquer le proxy
        print(f"[WARNING] Error broadcasting flow: {e}")
        pass

@app.post("/api/collaboration/sessions")
def create_session(request: Dict):
    """Crée une nouvelle session collaborative"""
    name = request.get('name', 'New Session')
    target_url = request.get('target_url', '')
    owner_id = str(uuid.uuid4())
    
    session = collaboration_manager.create_session(name, owner_id, target_url)
    
    return {
        'session_id': session.id,
        'name': session.name,
        'target_url': session.target_url,
        'owner_id': owner_id
    }

@app.get("/api/collaboration/sessions")
def list_sessions():
    """Liste toutes les sessions disponibles"""
    return collaboration_manager.list_sessions()

@app.get("/api/collaboration/sessions/{session_id}")
def get_session(session_id: str):
    """Récupère les détails d'une session"""
    session = collaboration_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    return {
        'id': session.id,
        'name': session.name,
        'owner_id': session.owner_id,
        'target_url': session.target_url,
        'created_at': session.created_at,
        'collaborators': [
            {
                'id': c.id,
                'name': c.name,
                'color': c.color,
                'connected_at': c.connected_at
            }
            for c in session.collaborators.values()
        ],
        'annotations_count': sum(len(annos) for annos in session.annotations.values())
    }

@app.get("/api/collaboration/sessions/{session_id}/annotations")
def get_session_annotations(session_id: str):
    """Récupère toutes les annotations d'une session"""
    session = collaboration_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    return {
        'annotations': {
            flow_id: [
                {
                    'id': a.id,
                    'author_id': a.author_id,
                    'author_name': a.author_name,
                    'content': a.content,
                    'created_at': a.created_at,
                    'updated_at': a.updated_at
                }
                for a in annotations
            ]
            for flow_id, annotations in session.annotations.items()
        }
    }

# === WORKSPACE MANAGEMENT ENDPOINTS ===
@app.get("/api/workspaces")
def get_workspaces():
    """Get list of available workspaces"""
    if not framework:
        raise HTTPException(status_code=503, detail="Framework not initialized")
    try:
        workspaces = framework.get_workspaces()
        current = framework.get_current_workspace_name()
        return {
            "workspaces": workspaces,
            "current": current
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting workspaces: {str(e)}")

@app.get("/api/workspaces/current")
def get_current_workspace():
    """Get current workspace information"""
    if not framework:
        raise HTTPException(status_code=503, detail="Framework not initialized")
    try:
        current = framework.get_current_workspace_name()
        # Try to get workspace description from database
        description = f"Workspace: {current}"
        try:
            session = framework.db_manager.get_session("default")
            if session:
                from core.models.models import Workspace
                workspace = session.query(Workspace).filter(Workspace.name == current).first()
                if workspace:
                    description = workspace.description or f"Workspace: {current}"
        except:
            pass
        
        return {
            "name": current,
            "description": description
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting current workspace: {str(e)}")

class WorkspaceCreateRequest(BaseModel):
    name: str
    description: Optional[str] = ""

@app.post("/api/workspaces")
def create_workspace(request: WorkspaceCreateRequest):
    """Create a new workspace"""
    if not framework:
        raise HTTPException(status_code=503, detail="Framework not initialized")
    try:
        if not request.name:
            raise HTTPException(status_code=400, detail="Workspace name is required")
        
        success = framework.create_workspace(request.name, request.description or "")
        if success:
            return {"status": "ok", "name": request.name}
        else:
            raise HTTPException(status_code=400, detail="Failed to create workspace")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating workspace: {str(e)}")

@app.post("/api/workspaces/{workspace_name}/switch")
def switch_workspace(workspace_name: str):
    """Switch to a different workspace"""
    if not framework:
        raise HTTPException(status_code=503, detail="Framework not initialized")
    try:
        success = framework.set_workspace(workspace_name)
        if success:
            # Load flows and endpoints from database for the new workspace
            if hasattr(flow_manager, 'load_flows_from_db'):
                flow_manager.framework = framework
                flow_manager.load_flows_from_db(workspace_name)
            if hasattr(endpoint_extractor, 'load_endpoints_from_db'):
                endpoint_extractor.framework = framework
                endpoint_extractor.load_endpoints_from_db(workspace_name)
            return {"status": "ok", "workspace": workspace_name}
        else:
            raise HTTPException(status_code=400, detail=f"Failed to switch to workspace: {workspace_name}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error switching workspace: {str(e)}")

@app.get("/api/workspaces/{workspace_name}")
def get_workspace_info(workspace_name: str):
    """Get information about a specific workspace"""
    if not framework:
        raise HTTPException(status_code=503, detail="Framework not initialized")
    try:
        session = framework.db_manager.get_session("default")
        if session:
            from core.models.models import Workspace
            workspace = session.query(Workspace).filter(Workspace.name == workspace_name).first()
            if workspace:
                return {
                    "name": workspace.name,
                    "description": workspace.description or "",
                    "created_at": workspace.created_at.isoformat() if workspace.created_at else None
                }
        raise HTTPException(status_code=404, detail="Workspace not found")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting workspace info: {str(e)}")

@app.delete("/api/workspaces/{workspace_name}")
def delete_workspace(workspace_name: str, force: bool = Query(False, description="Force deletion even if workspace contains data")):
    """Delete a workspace"""
    if not framework:
        raise HTTPException(status_code=503, detail="Framework not initialized")
    try:
        # Check if it's the current workspace
        current = framework.get_current_workspace_name()
        if current == workspace_name:
            raise HTTPException(status_code=400, detail="Cannot delete current workspace. Switch to another workspace first.")
        
        success = framework.delete_workspace(workspace_name, force=force)
        if success:
            return {"status": "ok", "name": workspace_name}
        else:
            raise HTTPException(status_code=400, detail=f"Failed to delete workspace: {workspace_name}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error deleting workspace: {str(e)}")

# Serve logo and favicon from interfaces/static/img/
# These routes must be defined before the static files mount to take precedence
static_img_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static", "img")

@app.get("/logo.png")
def get_logo():
    """Serve logo from interfaces/static/img/"""
    logo_path = os.path.join(static_img_dir, "logo.png")
    if os.path.exists(logo_path):
        return FileResponse(logo_path, media_type="image/png")
    raise HTTPException(status_code=404, detail="Logo not found")

@app.get("/favicon.ico")
def get_favicon():
    """Serve favicon from interfaces/static/img/"""
    favicon_path = os.path.join(static_img_dir, "favicon.ico")
    if os.path.exists(favicon_path):
        return FileResponse(favicon_path, media_type="image/x-icon")
    raise HTTPException(status_code=404, detail="Favicon not found")

# Serve browser icons from core/browser_static/icons/browsers/
browser_icons_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "core", "browser_static", "icons", "browsers")

@app.get("/browser-icons/{browser_name}")
def get_browser_icon(browser_name: str):
    """Serve browser icon from core/browser_static/icons/browsers/"""
    icon_path = os.path.join(browser_icons_dir, f"{browser_name}.svg")
    if os.path.exists(icon_path):
        return FileResponse(icon_path, media_type="image/svg+xml")
    # Fallback to unknown icon
    unknown_path = os.path.join(browser_icons_dir, "unknown.svg")
    if os.path.exists(unknown_path):
        return FileResponse(unknown_path, media_type="image/svg+xml")
    raise HTTPException(status_code=404, detail="Browser icon not found")

# ===================== Collaboration Pro (API key gating) =====================
COLLAB_SAAS_URL = "https://proxy.kittysploit.com"

def _load_collab_api_key() -> str:
    """Load API key from env or config.toml"""
    env_key = os.getenv("COLLABORATION_API_KEY") or os.getenv("KITTYSPLOIT_API_KEY")
    if env_key:
        key = env_key.strip()
        print(f"[COLLAB] Using API key from env: {_mask_key(key)}", flush=True)
        return key
    # Try via Config (which searches in CWD and parents)
    try:
        cfg = Config.get_instance().config
        framework_cfg = cfg.get("FRAMEWORK") or cfg.get("framework") or {}
        key = (framework_cfg.get("api_key") or "").strip()
        print(f"[COLLAB] Using API key from Config: {_mask_key(key)}", flush=True)
        if key:
            return key
    except Exception:
        pass

    # Fallback: read config.toml explicitly at project root
    try:
        import tomllib  # Python 3.11+
    except ImportError:
        try:
            import tomli as tomllib  # compat
        except ImportError:
            tomllib = None

    if tomllib:
        try:
            project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
            candidate = os.path.join(project_root, "config.toml")
            print(f"[COLLAB] Fallback config path: {candidate}", flush=True)
            if os.path.exists(candidate):
                with open(candidate, "rb") as f:
                    data = tomllib.load(f)
                    framework_cfg = data.get("FRAMEWORK") or data.get("framework") or {}
                    key = (framework_cfg.get("api_key") or "").strip()
                    print(f"[COLLAB] Using API key from fallback config: {_mask_key(key)}", flush=True)
                    if key:
                        return key
        except Exception:
            pass

    print("[COLLAB] No API key found", flush=True)
    return ""

def _validate_collab_api_key(api_key: str):
    """Validate API key with SaaS and return full response if valid"""
    if not api_key:
        raise HTTPException(status_code=401, detail="API key missing. Set [FRAMEWORK].api_key in config.toml.")
    url = f"{COLLAB_SAAS_URL}/api/auth/validate-api-key"
    try:
        resp = requests.get(url, headers={"X-API-Key": api_key, "User-Agent": "Kittysploit-Framework/2.0"}, timeout=10)
        try:
            body_preview = resp.text[:300]
            print(f"[COLLAB] SaaS validate status={resp.status_code} body={body_preview}", flush=True)
        except Exception:
            pass
        if resp.status_code != 200:
            raise HTTPException(status_code=401, detail=f"Validation failed (HTTP {resp.status_code})")
        try:
            data = resp.json()
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"SaaS response not JSON: {e}")
        if data.get("valid") is True and data.get("token"):
            return data
        raise HTTPException(status_code=401, detail=data.get("message") or "API key invalide")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Erreur de validation de l'API key: {e}")

def _mask_key(key: str) -> str:
    if not key:
        return ""
    if len(key) <= 8:
        return "*" * len(key)
    return f"{key[:4]}...{key[-4:]}"

@app.get("/api/collab/auth")
def collab_auth():
    """Validate API key (Pro) and return token if valid"""
    print(f"[COLLAB] Validating API key", flush=True)
    api_key = _load_collab_api_key()
    try:
        print(f"[COLLAB] Using API key: {_mask_key(api_key)}", flush=True)
    except Exception:
        pass
    data = _validate_collab_api_key(api_key)
    # Add server_url for front
    data["server_url"] = COLLAB_SAAS_URL
    return data

# === SIDECHANNEL ENDPOINTS ===
# SideChannel uses the same API key and SaaS as Collaboration

class SideChannelTestRequest(BaseModel):
    flow_id: str
    attack_type: str

@app.post("/api/sidechannel/test")
def sidechannel_test(request: SideChannelTestRequest):
    """Test an attack of type XXE, SSRF, etc. on a flow"""
    # Load API key from config (same source as collaboration)
    api_key = _load_collab_api_key()
    if not api_key:
        raise HTTPException(status_code=401, detail="API key not configured. Please set [FRAMEWORK].api_key in config.toml or KITTYSPLOIT_API_KEY environment variable.")
    
    try:
        # Get flow
        flow = flow_manager.get_flow(request.flow_id)
        if not flow:
            raise HTTPException(status_code=404, detail="Flow not found")
        
        # Prepare flow data for analysis
        flow_data = {
            "request": {
                "method": flow.get("request", {}).get("method", "GET"),
                "url": flow.get("request", {}).get("url", ""),
                "headers": flow.get("request", {}).get("headers", {}),
                "content": flow.get("request", {}).get("content", ""),
            },
            "response": {
                "status_code": flow.get("response", {}).get("status_code", 0),
                "headers": flow.get("response", {}).get("headers", {}),
                "content": flow.get("response", {}).get("content", ""),
            }
        }
        
        # Step 1: Ask SaaS to generate a unique URL and create the modified payload
        url = f"{COLLAB_SAAS_URL}/api/sidechannel/prepare"
        payload = {
            "api_key": api_key,
            "attack_type": request.attack_type,
            "flow": flow_data
        }
        
        resp = requests.post(url, json=payload, timeout=30)
        
        if resp.status_code != 200:
            try:
                error_data = resp.json()
                raise HTTPException(status_code=resp.status_code, detail=error_data.get("message", "Failed to prepare attack"))
            except:
                raise HTTPException(status_code=resp.status_code, detail=f"Failed to prepare attack (HTTP {resp.status_code})")
        
        prepare_data = resp.json()
        sidechannel_url = prepare_data.get("sidechannel_url")  # Unique URL generated
        modified_request = prepare_data.get("modified_request")  # Request with injected payload
        test_id = prepare_data.get("test_id")  # ID du test pour le polling
        
        if not sidechannel_url or not modified_request or not test_id:
            raise HTTPException(status_code=500, detail="Invalid response from SaaS: missing required fields")
        
        # Step 2: Send the modified request to the target
        import base64
        target_url = modified_request.get("url")
        target_method = modified_request.get("method", "GET")
        target_headers = modified_request.get("headers", {})
        target_body_b64 = modified_request.get("body_bs64", "")
        
        # Clean headers for HTTP send
        cleaned_headers = {}
        for key, value in target_headers.items():
            if key.lower() not in ['x-kittyproxy-source']:
                cleaned_headers[key] = str(value) if not isinstance(value, str) else value
        
        # Decode body if present
        body_content = b""
        if target_body_b64:
            try:
                body_content = base64.b64decode(target_body_b64)
            except Exception as e:
                print(f"[SIDECHANNEL] Error decoding body: {e}", flush=True)
        
        # Send request via proxy
        proxies = {
            "http": "http://127.0.0.1:8080",
            "https": "http://127.0.0.1:8080",
        }
        
        start_time = time.time()
        try:
            if target_method.upper() == "GET":
                target_resp = requests.get(target_url, headers=cleaned_headers, proxies=proxies, timeout=30, allow_redirects=False)
            elif target_method.upper() == "POST":
                target_resp = requests.post(target_url, headers=cleaned_headers, data=body_content, proxies=proxies, timeout=30, allow_redirects=False)
            elif target_method.upper() == "PUT":
                target_resp = requests.put(target_url, headers=cleaned_headers, data=body_content, proxies=proxies, timeout=30, allow_redirects=False)
            elif target_method.upper() == "PATCH":
                target_resp = requests.patch(target_url, headers=cleaned_headers, data=body_content, proxies=proxies, timeout=30, allow_redirects=False)
            else:
                target_resp = requests.request(target_method, target_url, headers=cleaned_headers, data=body_content, proxies=proxies, timeout=30, allow_redirects=False)
        except Exception as e:
            print(f"[SIDECHANNEL] Error sending request to target: {e}", flush=True)
            # Continue anyway to check if a request has been received
        
        request_duration = int((time.time() - start_time) * 1000)
        
        # Step 3: Check if a request has been received on the SideChannel URL
        # Wait a little bit to let the request arrive at the SaaS
        import time as time_module
        time_module.sleep(2)
        
        check_url = f"{COLLAB_SAAS_URL}/api/sidechannel/check/{test_id}"
        check_resp = requests.get(check_url, headers={"X-API-Key": api_key}, timeout=10)
        
        if check_resp.status_code == 200:
            check_data = check_resp.json()
            detected = check_data.get("detected", False)
            request_details = check_data.get("request_details", {})
            
            return {
                "flow_id": request.flow_id,
                "attack_type": request.attack_type,
                "test_id": test_id,
                "sidechannel_url": sidechannel_url,
                "detected": detected,
                "request_duration": request_duration,
                "target_response_status": target_resp.status_code if 'target_resp' in locals() else None,
                "details": {
                    "message": "Vulnerability detected!" if detected else "No vulnerability detected",
                    "evidence": request_details if detected else None,
                    "recommendations": [
                        "Disable external entity processing in XML parsers",
                        "Use whitelist for allowed URLs in SSRF",
                        "Implement proper input validation"
                    ] if detected else None
                }
            }
        else:
            # If we cannot verify, return an undetermined status
            return {
                "flow_id": request.flow_id,
                "attack_type": request.attack_type,
                "test_id": test_id,
                "sidechannel_url": sidechannel_url,
                "detected": False,
                "request_duration": request_duration,
                "target_response_status": target_resp.status_code if 'target_resp' in locals() else None,
                "details": {
                    "message": "Unable to verify vulnerability. Please check manually.",
                    "evidence": None,
                    "recommendations": None
                }
            }
                
    except HTTPException:
        raise
    except Exception as e:
        print(f"[SIDECHANNEL] Error testing attack: {e}", flush=True)
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to test attack: {str(e)}")

@app.get("/api/sidechannel/check/{test_id}")
def sidechannel_check_test(test_id: str):
    """Vérifie le statut d'un test SideChannel (polling)"""
    api_key = _load_collab_api_key()
    if not api_key:
        raise HTTPException(status_code=401, detail="API key not configured")
    
    try:
        # Check with SaaS if a request was received
        url = f"{COLLAB_SAAS_URL}/api/sidechannel/check/{test_id}"
        resp = requests.get(url, headers={"X-API-Key": api_key}, timeout=10)
        
        if resp.status_code == 200:
            data = resp.json()
            request_details = data.get("request_details", {})
            detected = data.get("detected", False)
            return {
                "test_id": test_id,
                "detected": detected,
                "details": {
                    "message": "Vulnerability detected!" if detected else "No request received yet",
                    "evidence": request_details if detected and request_details else None,
                    "recommendations": [
                        "Disable external entity processing in XML parsers",
                        "Use whitelist for allowed URLs in SSRF",
                        "Implement proper input validation"
                    ] if detected else None
                }
            }
        elif resp.status_code == 404:
            # Test non trouvé ou expiré
            return {
                "test_id": test_id,
                "detected": False,
                "details": {},
                "message": "Test not found or expired"
            }
        else:
            try:
                error_data = resp.json()
                raise HTTPException(status_code=resp.status_code, detail=error_data.get("message", "Check failed"))
            except:
                raise HTTPException(status_code=resp.status_code, detail=f"Check failed (HTTP {resp.status_code})")
                
    except HTTPException:
        raise
    except Exception as e:
        print(f"[SIDECHANNEL] Error checking test {test_id}: {e}", flush=True)
        raise HTTPException(status_code=500, detail=f"Failed to check test: {str(e)}")

class SideChannelGenerateUrlRequest(BaseModel):
    attack_type: str

@app.post("/api/sidechannel/generate-url")
def sidechannel_generate_url(request: SideChannelGenerateUrlRequest):
    """Génère une URL SideChannel unique pour injection manuelle
    
    Le SaaS génère un sous-domaine disponible au format abc.proxy.kittysploit.com
    """
    api_key = _load_collab_api_key()
    if not api_key:
        raise HTTPException(status_code=401, detail="API key not configured")
    
    try:
        # Demander au SaaS de générer une URL unique
        # Le SaaS s'occupe de générer un sous-domaine disponible au format abc.proxy.kittysploit.com
        url = f"{COLLAB_SAAS_URL}/api/sidechannel/generate-url"
        payload = {
            "api_key": api_key,
            "attack_type": request.attack_type
        }
        
        resp = requests.post(url, json=payload, timeout=30)
        
        if resp.status_code == 200:
            data = resp.json()
            sidechannel_url = data.get("sidechannel_url", "")
            
            # Normaliser l'URL pour utiliser HTTPS et le domaine proxy.kittysploit.com
            if sidechannel_url:
                try:
                    from urllib.parse import urlparse, urlunparse
                    parsed = urlparse(sidechannel_url)
                    
                    # Extraire le sous-domaine (ex: "i94hme2kilqk" depuis "i94hme2kilqk.sidechannel.kittysploit.com")
                    hostname = parsed.hostname or ""
                    if hostname:
                        # Find the subdomain (first part before the first dot)
                        parts = hostname.split('.')
                        if len(parts) > 0:
                            subdomain = parts[0]
                            # Rebuild URL with HTTPS and proxy.kittysploit.com
                            normalized_hostname = f"{subdomain}.proxy.kittysploit.com"
                            normalized_url = urlunparse((
                                "https",  # Forcer HTTPS
                                normalized_hostname,
                                parsed.path,
                                parsed.params,
                                parsed.query,
                                parsed.fragment
                            ))
                            sidechannel_url = normalized_url
                except Exception as e:
                    print(f"[SIDECHANNEL] Warning: Failed to normalize URL {sidechannel_url}: {e}", flush=True)
                    # In case of error, try a simple correction
                    if sidechannel_url.startswith("http://"):
                        sidechannel_url = sidechannel_url.replace("http://", "https://")
                    if "sidechannel.kittysploit.com" in sidechannel_url:
                        sidechannel_url = sidechannel_url.replace("sidechannel.kittysploit.com", "proxy.kittysploit.com")
            
            return {
                "test_id": data.get("test_id"),
                "sidechannel_url": sidechannel_url,
                "attack_type": request.attack_type
            }
        else:
            try:
                error_data = resp.json()
                raise HTTPException(status_code=resp.status_code, detail=error_data.get("message", "Failed to generate URL"))
            except:
                raise HTTPException(status_code=resp.status_code, detail=f"Failed to generate URL (HTTP {resp.status_code})")
                
    except HTTPException:
        raise
    except Exception as e:
        print(f"[SIDECHANNEL] Error generating URL: {e}", flush=True)
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to generate URL: {str(e)}")

# Serve static files (Frontend) — mounted after API routes to avoid shadowing /api/*
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")
