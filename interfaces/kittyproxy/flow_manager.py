import uuid
import copy
import threading
import queue
import json
import base64
from datetime import datetime
from typing import List, Dict, Optional, Callable
from collections import OrderedDict

from mitmproxy.http import HTTPFlow

from flow_utils import safe_response_content as _safe_response_content, safe_response_size as _safe_response_size

from tech_detector import tech_detector
from fingerprint_engine import fingerprint_engine
from module_suggester import module_suggester
from endpoint_extractor import endpoint_extractor

class FlowManager:
    def __init__(self, max_flows: int = 5000, fast_mode: bool = False, fast_mode_threshold_kb: int = 100, framework=None):
        self.flows: OrderedDict[str, 'HTTPFlow'] = OrderedDict()
        self.flow_cache: Dict[str, Dict] = {}  # Cache for serialized flows
        self.flow_analysis_cache: Dict[str, Dict] = {}  # Cache for heavy analysis results
        self.max_flows = max_flows
        self.intercept_enabled: bool = False
        self.intercept_queue: Dict[str, threading.Event] = {}
        self.pending_intercepts: Dict[str, 'HTTPFlow'] = {}
        self._lock = threading.RLock()
        self.callbacks: List[Callable[[Dict], None]] = []
        self.framework = framework  # Framework instance for database access
        
        # Fast mode: skip heavy analysis for large responses
        self.fast_mode = fast_mode
        self.fast_mode_threshold_kb = fast_mode_threshold_kb  # Skip analysis if response > X KB
        
        # Scope configuration
        self.scope_config = {
            'enabled': False,
            'mode': 'include',  # 'include' or 'exclude'
            'patterns': []
        }

        # Flows imported from PCAP (id -> full flow dict)
        self.imported_pcap_flows: Dict[str, Dict] = {}
        
        # Worker thread for heavy analysis
        self.analysis_queue = queue.Queue()
        self.analysis_worker_running = True
        self.analysis_worker = threading.Thread(target=self._analysis_worker, daemon=True)
        self.analysis_worker.start()
        print(f"[FLOW MANAGER] Analysis worker thread started (fast_mode={self.fast_mode}, threshold={self.fast_mode_threshold_kb}KB)")

    def register_callback(self, callback):
        """Register a callback to be called when a new flow is added."""
        self.callbacks.append(callback)

    def set_scope(self, scope_config: Dict):
        """Set the scope configuration for filtering flows."""
        with self._lock:
            self.scope_config = scope_config.copy()
            print(f"[FLOW MANAGER] Scope updated: enabled={scope_config.get('enabled', False)}, mode={scope_config.get('mode', 'include')}, patterns={len(scope_config.get('patterns', []))}")
    
    def _is_in_scope(self, flow) -> bool:
        """Check if a flow matches the scope configuration."""
        if not self.scope_config.get('enabled', False) or not self.scope_config.get('patterns'):
            return True  # If scope is disabled, accept all flows
        
        try:
            url = flow.request.url if hasattr(flow.request, 'url') else None
            if not url:
                return True  # If URL is not available, accept by default
            
            hostname = flow.request.host if hasattr(flow.request, 'host') else None
            path = flow.request.path if hasattr(flow.request, 'path') else None
            
            import re
            mode = self.scope_config.get('mode', 'include')
            patterns = self.scope_config.get('patterns', [])
            
            # Check if any pattern matches
            pattern_matched = False
            for pattern in patterns:
                if self._matches_pattern(pattern, url, hostname, path):
                    pattern_matched = True
                    break
            
            # In include mode: return True if pattern matched, False otherwise
            # In exclude mode: return False if pattern matched, True otherwise
            if mode == 'include':
                return pattern_matched
            else:  # exclude mode
                return not pattern_matched
        except Exception as e:
            print(f"[FLOW MANAGER] Error checking scope: {e}")
            import traceback
            traceback.print_exc()
            return True  # On error, accept the flow
    
    def _matches_pattern(self, pattern: str, url: str, hostname: Optional[str], path: Optional[str]) -> bool:
        """Check if a pattern matches a URL."""
        try:
            import re
            from urllib.parse import urlparse
            
            # Normalize pattern and URL for comparison
            pattern_lower = pattern.lower()
            url_lower = url.lower() if url else ''
            hostname_lower = hostname.lower() if hostname else ''
            path_lower = path.lower() if path else ''
            
            # Convert wildcard pattern to regex (escape dots, convert * to .*, ? to .)
            regex_pattern = pattern.replace('.', r'\.').replace('*', '.*').replace('?', '.')
            
            # Test 1: Exact match on hostname (most common case for domain patterns)
            if hostname:
                if re.match(f'^{regex_pattern}$', hostname, re.IGNORECASE):
                    return True
                # For patterns like "example.com", also check if hostname ends with it
                if '/' not in pattern and not pattern.startswith('*'):
                    if hostname_lower == pattern_lower or hostname_lower.endswith('.' + pattern_lower):
                        return True
            
            # Test 2: Wildcard subdomain pattern (e.g., *.example.com)
            # This pattern should match:
            # - example.com (exact domain)
            # - www.example.com (any subdomain)
            # - api.example.com (any subdomain)
            if hostname and pattern.startswith('*.'):
                domain = pattern[2:].lower()  # Remove "*." to get "kittysploit.com"
                
                # Match exact domain (kittysploit.com)
                if hostname_lower == domain:
                    return True
                
                # Match subdomains (www.kittysploit.com, api.kittysploit.com, etc.)
                # The hostname must end with ".kittysploit.com"
                if hostname_lower.endswith('.' + domain):
                    return True
                
                # Also try regex matching: any subdomain + domain
                # This matches: *.kittysploit.com -> ^.+\\.kittysploit\\.com$
                regex_wildcard = r'^.+\.' + re.escape(domain) + r'$'
                if re.match(regex_wildcard, hostname_lower):
                    return True
                
                # Debug: log when pattern doesn't match
                # print(f"[DEBUG] Pattern '{pattern}' (domain: '{domain}') did not match hostname '{hostname_lower}'")
            
            # Test 3: Match on path
            if path:
                if re.match(f'^{regex_pattern}$', path, re.IGNORECASE):
                    return True
                # Test if pattern matches path prefix
                pattern_clean = pattern.replace('*', '').replace('?', '')
                if pattern_clean and path_lower.startswith(pattern_clean.lower()):
                    return True
            
            # Test 4: Match on full URL
            if re.match(f'^{regex_pattern}$', url, re.IGNORECASE):
                return True
            
            # Test 5: Pattern contained in URL (for partial matches like "api" matching "/api/v1/...")
            pattern_clean = pattern.replace('*', '').replace('?', '')
            if pattern_clean and pattern_clean.lower() in url_lower:
                return True
            
            return False
        except Exception as e:
            print(f"[FLOW MANAGER] Error matching pattern '{pattern}' against URL '{url}': {e}")
            import traceback
            traceback.print_exc()
            return False

    def add_flow(self, flow):
        """Adds a flow to the list with memory limit and pre-caching."""
        # Check scope before adding
        if not self._is_in_scope(flow):
            print(f"[FLOW MANAGER] Flow {flow.id} excluded by scope: {flow.request.url}")
            return
        
        serialized_flow = None
        with self._lock:
            # Add or update flow
            self.flows[flow.id] = flow
            self.flows.move_to_end(flow.id)  # Move to end (newest)
            
            # Enforce limit
            if len(self.flows) > self.max_flows:
                oldest_id, _ = self.flows.popitem(last=False)
                if oldest_id in self.flow_cache:
                    del self.flow_cache[oldest_id]
                if oldest_id in self.flow_analysis_cache:
                    del self.flow_analysis_cache[oldest_id]
            
            # Use minimal serialization for fast path (only method, URL, status, size)
            serialized_flow = self._serialize_flow_minimal(flow)
            self.flow_cache[flow.id] = serialized_flow
            
            # Queue heavy analysis in background if needed
            # Only analyze when response is available (not in request() hook)
            if flow.response and flow.id not in self.flow_analysis_cache:
                # Check if we should skip analysis (fast mode + large response)
                should_skip = False
                if self.fast_mode:
                    response_size = _safe_response_size(flow.response) or 0
                    if response_size > (self.fast_mode_threshold_kb * 1024):
                        should_skip = True
                        print(f"[FLOW MANAGER] Skipping heavy analysis for flow {flow.id} (response size: {response_size} bytes > {self.fast_mode_threshold_kb}KB threshold)")
                
                if not should_skip:
                    # Queue for background analysis
                    try:
                        self.analysis_queue.put_nowait((flow.id, flow))
                        print(f"[FLOW MANAGER] Queued flow {flow.id} for heavy analysis (fast_mode={self.fast_mode})")
                    except queue.Full:
                        print(f"[FLOW MANAGER] Analysis queue full, skipping analysis for flow {flow.id}")
            elif not flow.response:
                # Flow added in request() hook, will be analyzed when response arrives
                print(f"[FLOW MANAGER] Flow {flow.id} added without response, will analyze when response arrives")
            
        # Notify callbacks (outside lock to avoid deadlocks if callback does something slow)
        if serialized_flow:
            for callback in self.callbacks:
                try:
                    callback(serialized_flow)
                except Exception as e:
                    print(f"[ERROR] Error in flow callback: {e}")
            
            # Save to database if workspace is not "default"
            self._save_flow_to_db(flow, serialized_flow)

    def get_flows(self) -> List[Dict]:
        """Returns all flows (legacy method)."""
        with self._lock:
            # Return flows in reverse order (newest first)
            return list(reversed(list(self.flow_cache.values())))

    def add_imported_pcap_flows(self, flows: List[Dict]) -> int:
        """Add flows imported from a PCAP file. Returns count added."""
        with self._lock:
            n = 0
            for f in flows:
                fid = f.get("id")
                if not fid:
                    continue
                self.imported_pcap_flows[fid] = f
                n += 1
            if n:
                print(f"[FLOW MANAGER] Added {n} flow(s) from PCAP import")
            return n

    def get_flows_paginated(self, page: int = 1, size: int = 50, search: str = None) -> Dict:
        """Returns a paginated slice of flows."""
        with self._lock:
            all_flows = list(reversed(list(self.flow_cache.values())))
            # Merge imported PCAP flows (minimal view for list: no request/response bodies)
            for fid, f in self.imported_pcap_flows.items():
                minimal = {k: v for k, v in f.items() if k not in ("request", "response")}
                all_flows.append(minimal)
            # Keep newest first (imported are appended last; we could sort by timestamp)
            all_flows.sort(key=lambda x: x.get("timestamp_start") or 0, reverse=True)
            
            # Filter by scope if enabled
            if self.scope_config.get('enabled', False) and self.scope_config.get('patterns'):
                scope_filtered_flows = []
                for flow_data in all_flows:
                    try:
                        url = flow_data.get('url', '')
                        if not url:
                            continue
                        
                        # Parse URL to get hostname
                        from urllib.parse import urlparse
                        parsed = urlparse(url)
                        hostname = parsed.hostname
                        path = parsed.path
                        
                        # Check if flow matches scope
                        matches = False
                        mode = self.scope_config.get('mode', 'include')
                        patterns = self.scope_config.get('patterns', [])
                        
                        for pattern in patterns:
                            if self._matches_pattern(pattern, url, hostname, path):
                                matches = True
                                break
                        
                        # In include mode: keep if matches, in exclude mode: keep if doesn't match
                        if (mode == 'include' and matches) or (mode == 'exclude' and not matches):
                            scope_filtered_flows.append(flow_data)
                    except Exception as e:
                        # On error, exclude the flow to be safe
                        print(f"[FLOW MANAGER] Error filtering flow by scope: {e}")
                        continue
                
                all_flows = scope_filtered_flows
            
            # Filter if search term provided (URL, method, status_code, or flow id)
            if search:
                search_lower = search.lower()
                filtered_flows = [
                    f for f in all_flows
                    if search_lower in (f.get('id') or '').lower()
                    or search_lower in f.get('url', '').lower()
                    or search_lower in f.get('method', '').lower()
                    or search_lower in str(f.get('status_code', '')).lower()
                ]
            else:
                filtered_flows = all_flows
            
            total = len(filtered_flows)
            start_idx = (page - 1) * size
            end_idx = start_idx + size
            
            items = filtered_flows[start_idx:end_idx]
            
            return {
                "items": items,
                "total": total,
                "page": page,
                "size": size,
                "pages": max(1, (total + size - 1) // size)
            }

    def get_flow(self, flow_id: str) -> Optional[Dict]:
        """Returns full details of a specific flow."""
        with self._lock:
            imported = self.imported_pcap_flows.get(flow_id)
            if imported is not None:
                return imported
            flow = self.flows.get(flow_id)
            if not flow:
                return None
            
            # Get minimal data from cache
            minimal_data = self.flow_cache.get(flow_id, {})
            
            # Get or compute heavy analysis
            analysis_data = self.flow_analysis_cache.get(flow_id)
            if analysis_data is None:
                # Compute analysis synchronously if not cached (for detail view)
                analysis_data = self._perform_heavy_analysis(flow)
                self.flow_analysis_cache[flow_id] = analysis_data
            
            # Merge minimal + analysis + detail
            result = {**minimal_data, **analysis_data}
            
            # Add full request/response content for detail view
            import base64
            req_content = flow.request.content or b""
            result["request"] = {
                "headers": dict(flow.request.headers),
                "content_bs64": base64.b64encode(req_content).decode('utf-8'),
                "content_length": len(req_content)
            }
            
            if flow.response:
                res_content = _safe_response_content(flow.response)
                result["response"] = {
                    "headers": dict(flow.response.headers),
                    "content_bs64": base64.b64encode(res_content).decode('utf-8'),
                    "content_length": len(res_content),
                    "reason": getattr(flow.response, 'reason', '') or ''
                }
            else:
                result["response"] = None
            
            return result

    def toggle_intercept(self, enabled: bool):
        self.intercept_enabled = enabled
        
    def intercept_request(self, flow):
        """Blocks execution if interception is enabled."""
        if not self.intercept_enabled:
            return
            
        event = threading.Event()
        with self._lock:
            self.intercept_queue[flow.id] = event
            self.pending_intercepts[flow.id] = flow
        
        # Wait for resume
        event.wait()
        
        # Cleanup
        with self._lock:
            if flow.id in self.intercept_queue:
                del self.intercept_queue[flow.id]
            if flow.id in self.pending_intercepts:
                del self.pending_intercepts[flow.id]

    def resume_intercept(self, flow_id: str, modified_flow: Optional[Dict] = None):
        with self._lock:
            if flow_id in self.intercept_queue:
                # Apply modifications if any
                if modified_flow:
                    flow = self.flows.get(flow_id)
                    if flow:
                        # Update request details
                        if 'method' in modified_flow:
                            flow.request.method = modified_flow['method']
                        if 'url' in modified_flow:
                            flow.request.url = modified_flow['url']
                        if 'headers' in modified_flow:
                            for k, v in modified_flow['headers'].items():
                                flow.request.headers[k] = v
                        if 'body_bs64' in modified_flow:
                            import base64
                            try:
                                flow.request.content = base64.b64decode(modified_flow['body_bs64'])
                            except:
                                pass
                
                self.intercept_queue[flow_id].set()

    def _serialize_flow_minimal(self, flow) -> Dict:
        """Minimal serialization: only method, URL, status, size, duration."""
        duration = None
        duration_ms = None
        
        # Calculate duration
        if flow.response:
            if hasattr(flow.response, 'timestamp_end') and flow.response.timestamp_end:
                duration = flow.response.timestamp_end - flow.request.timestamp_start
                duration_ms = int(duration * 1000) if duration else None
            elif hasattr(flow.response, 'timestamp_start') and flow.response.timestamp_start:
                duration = flow.response.timestamp_start - flow.request.timestamp_start
                duration_ms = int(duration * 1000) if duration else None
            elif hasattr(flow, 'timestamp_end') and flow.timestamp_end:
                duration = flow.timestamp_end - flow.request.timestamp_start
                duration_ms = int(duration * 1000) if duration else None
            elif flow.request.timestamp_start:
                import time
                current_time = time.time()
                duration = current_time - flow.request.timestamp_start
                duration_ms = int(duration * 1000) if duration else None
        
        # Calculate response size (avoid flow.response.content when Content-Encoding is gzip but body is not)
        response_size = _safe_response_size(flow.response) if flow.response else None
        
        # Check if flow is from API Tester
        source = None
        if hasattr(flow, 'metadata') and isinstance(flow.metadata, dict):
            source = flow.metadata.get('source')
        if not source and hasattr(flow, 'request') and hasattr(flow.request, 'headers'):
            if b'X-KittyProxy-Source' in flow.request.headers:
                source = flow.request.headers[b'X-KittyProxy-Source'].decode('utf-8')
        
        # Get WebSocket messages from the addon if available
        ws_messages = []
        try:
            # Try to get WebSocket messages from mitmproxy flow directly
            # For HTTPFlow with WebSocket upgrade, check if it has websocket attribute
            if hasattr(flow, 'websocket') and flow.websocket:
                if hasattr(flow.websocket, 'messages') and flow.websocket.messages:
                    for msg in flow.websocket.messages:
                        try:
                            from mitmproxy import websocket as ws
                            msg_type = 'text' if msg.type == ws.MessageType.TEXT else 'binary'
                        except:
                            msg_type = 'text' if hasattr(msg, 'type') and msg.type == 1 else 'binary'
                        
                        ws_messages.append({
                            'from_client': msg.from_client,
                            'content': msg.content.decode('utf-8', errors='replace') if isinstance(msg.content, bytes) else str(msg.content),
                            'type': msg_type,
                            'timestamp': flow.request.timestamp_start if hasattr(flow.request, 'timestamp_start') else None,
                            'direction': 'client' if msg.from_client else 'server'
                        })
            # For WebSocketFlow (direct WebSocket flow, not HTTP upgrade)
            elif hasattr(flow, 'messages') and flow.messages:
                # This is a WebSocketFlow, not an HTTPFlow
                for msg in flow.messages:
                    try:
                        from mitmproxy import websocket as ws
                        msg_type = 'text' if msg.type == ws.MessageType.TEXT else 'binary'
                    except:
                        msg_type = 'text' if hasattr(msg, 'type') and msg.type == 1 else 'binary'
                    
                    timestamp = None
                    if hasattr(flow, 'handshake_flow') and flow.handshake_flow:
                        timestamp = flow.handshake_flow.request.timestamp_start if hasattr(flow.handshake_flow.request, 'timestamp_start') else None
                    
                    ws_messages.append({
                        'from_client': msg.from_client,
                        'content': msg.content.decode('utf-8', errors='replace') if isinstance(msg.content, bytes) else str(msg.content),
                        'type': msg_type,
                        'timestamp': timestamp,
                        'direction': 'client' if msg.from_client else 'server'
                    })
            # Try to get from addon's websocket_messages dict
            try:
                from proxy_core import interceptor_addon_instance
                if interceptor_addon_instance and flow.id in interceptor_addon_instance.websocket_messages:
                    addon_messages = interceptor_addon_instance.websocket_messages[flow.id]
                    if addon_messages:
                        ws_messages = addon_messages
                        print(f"[FLOW MANAGER] Retrieved {len(ws_messages)} WebSocket messages from addon for flow {flow.id}")
            except Exception as e:
                # Silently fail if can't access addon
                pass
        except Exception as e:
            # Silently fail if WebSocket messages can't be extracted
            print(f"[DEBUG] Could not extract WebSocket messages: {e}")
        
        # Check if this is a WebSocket flow
        is_websocket = False
        if flow.response and flow.response.status_code == 101:
            is_websocket = True
            print(f"[FLOW MANAGER] Flow {flow.id} detected as WebSocket (status 101)")
        elif flow.request and flow.request.headers:
            upgrade_header = None
            if hasattr(flow.request.headers, 'get'):
                upgrade_header = flow.request.headers.get(b'Upgrade') or flow.request.headers.get('Upgrade')
            elif isinstance(flow.request.headers, dict):
                upgrade_header = flow.request.headers.get(b'Upgrade') or flow.request.headers.get('Upgrade') or flow.request.headers.get('upgrade')
            
            if upgrade_header:
                if isinstance(upgrade_header, bytes):
                    upgrade_header = upgrade_header.decode('utf-8', errors='ignore')
                if 'websocket' in upgrade_header.lower():
                    is_websocket = True
                    print(f"[FLOW MANAGER] Flow {flow.id} detected as WebSocket (Upgrade header)")
            
            # Check for Sec-WebSocket-Key
            if not is_websocket:
                sec_ws_key = None
                if hasattr(flow.request.headers, 'get'):
                    sec_ws_key = flow.request.headers.get(b'Sec-WebSocket-Key') or flow.request.headers.get('Sec-WebSocket-Key')
                elif isinstance(flow.request.headers, dict):
                    sec_ws_key = flow.request.headers.get(b'Sec-WebSocket-Key') or flow.request.headers.get('Sec-WebSocket-Key')
                
                if sec_ws_key:
                    is_websocket = True
                    print(f"[FLOW MANAGER] Flow {flow.id} detected as WebSocket (Sec-WebSocket-Key header)")
            # Check if flow is known in proxy core as a WebSocket (source of truth)
            try:
                from proxy_core import interceptor_addon_instance
                if interceptor_addon_instance:
                    if flow.id in interceptor_addon_instance.websocket_messages:
                        is_websocket = True
                        # print(f"[FLOW MANAGER] Flow {flow.id} is a WebSocket (present in addon messages dict)")
                    elif flow.id in interceptor_addon_instance.websocket_flows:
                        is_websocket = True
                        # print(f"[FLOW MANAGER] Flow {flow.id} is a WebSocket (present in addon flows dict)")
            except Exception:
                pass

            # Also check if we have WebSocket messages (redundant but safe)
            if ws_messages:
                is_websocket = True
                print(f"[FLOW MANAGER] Flow {flow.id} detected as WebSocket (has messages: {len(ws_messages)})")
        
        return {
            "id": flow.id,
            "method": flow.request.method,
            "scheme": flow.request.scheme,
            "host": flow.request.host,
            "path": flow.request.path,
            "url": flow.request.url,
            "timestamp_start": flow.request.timestamp_start,
            "status_code": flow.response.status_code if flow.response else None,
            "duration": duration,
            "duration_ms": duration_ms,
            "intercepted": flow.intercepted,
            "source": source,
            "response_size": response_size,
            # WebSocket messages
            "ws_messages": ws_messages,
            "messages": ws_messages,  # Alias for compatibility
            "is_websocket": is_websocket,  # Flag to easily identify WebSocket flows
            # Placeholders for heavy analysis (will be filled by background worker)
            "technologies": {},
            "fingerprint": {},
            "module_suggestions": [],
            "endpoints": {},
            "discovered_endpoints": [],
        }
    
    def _perform_heavy_analysis(self, flow) -> Dict:
        """Perform heavy analysis: tech detection, fingerprinting, module suggestions, endpoint extraction."""
        # Détecter les technologies
        try:
            detected_techs = tech_detector.detect(flow)
        except Exception as e:
            print(f"[ERROR] Error detecting technologies: {e}")
            detected_techs = {
                'frameworks': [],
                'cms': [],
                'servers': [],
                'languages': [],
                'security': [],
            }
        
        # Fingerprinting avancé
        try:
            fingerprint = fingerprint_engine.fingerprint(flow, detected_techs)
        except Exception as e:
            print(f"[ERROR] Error fingerprinting: {e}")
            fingerprint = {
                'versions': {},
                'configurations': [],
                'services': [],
                'security_features': [],
                'vulnerabilities': [],
            }
        
        # Suggestions de modules
        try:
            module_suggestions = module_suggester.suggest_modules(
                detected_techs, 
                fingerprint,
                fingerprint.get('vulnerabilities', [])
            )
        except Exception as e:
            print(f"[ERROR] Error suggesting modules: {e}")
            module_suggestions = []
        
        # Ajout ciblé : bypass 404 si la réponse est 404
        try:
            status_code = flow.response.status_code if flow.response else None
            if status_code == 404:
                module_path = 'auxiliary/scanner/http/bypass_404'
                already_suggested = any(sug.get('module') == module_path for sug in module_suggestions)
                if not already_suggested:
                    module_suggestions.append({
                        'module': module_path,
                        'score': 12,
                        'reasons': ['Response status is 404 - test for soft/hard 404 bypass'],
                        'priority': 'medium'
                    })
        except Exception as e:
            print(f"[ERROR] Error adding 404 bypass suggestion: {e}")
        
        # Extraire les endpoints et liens
        try:
            extracted_endpoints = endpoint_extractor.extract(flow, detected_techs)
            total_extracted = sum(len(urls) for urls in extracted_endpoints.values())
            if total_extracted > 0:
                print(f"[FLOW MANAGER] Extracted {total_extracted} endpoints from {flow.request.url if flow.request else 'unknown'}")
        except Exception as e:
            print(f"[ERROR] Error extracting endpoints: {e}")
            import traceback
            traceback.print_exc()
            extracted_endpoints = {
                'html_links': [],
                'form_actions': [],
                'javascript_endpoints': [],
                'json_urls': [],
                'css_urls': [],
                'api_endpoints': [],
                'other_resources': [],
                'react_api_endpoints': [],
            }
        
        # Ajouter aux endpoints découverts globaux
        try:
            for category, urls in extracted_endpoints.items():
                for url in urls:
                    if hasattr(endpoint_extractor, 'discovered_endpoints'):
                        endpoint_extractor.discovered_endpoints.add(url)
                    if hasattr(endpoint_extractor, 'discovered_links'):
                        endpoint_extractor.discovered_links.add(url)
                    # Save to database if workspace is not "default"
                    if category in ['api_endpoints', 'html_links', 'javascript_endpoints', 'react_api_endpoints']:
                        endpoint_extractor._save_endpoint_to_db(url, category, flow)
        except Exception as e:
            print(f"[ERROR] Error adding to discovered endpoints: {e}")
        
        # SSRF/redirect parameter discovery from request (query + body)
        ssrf_redirect_candidates = []
        try:
            ssrf_redirect_candidates = endpoint_extractor.extract_ssrf_redirect_candidates_from_flow(flow)
            for c in ssrf_redirect_candidates:
                if c not in endpoint_extractor.ssrf_redirect_candidates:
                    endpoint_extractor.ssrf_redirect_candidates.append(c)
        except Exception as e:
            print(f"[ERROR] Error extracting SSRF/redirect candidates: {e}")
        
        return {
            "technologies": detected_techs,
            "fingerprint": fingerprint,
            "module_suggestions": module_suggestions,
            "endpoints": extracted_endpoints,
            "discovered_endpoints": sorted(list(set([url for urls in extracted_endpoints.values() for url in urls]))),
            "ssrf_redirect_candidates": ssrf_redirect_candidates,
        }
    
    def _analysis_worker(self):
        """Background worker thread that performs heavy analysis on queued flows."""
        print("[FLOW MANAGER] Analysis worker thread started")
        while self.analysis_worker_running:
            try:
                flow_id, flow = self.analysis_queue.get(timeout=1)
                print(f"[FLOW MANAGER] Processing analysis for flow {flow_id}")
                
                # Perform heavy analysis
                analysis_data = self._perform_heavy_analysis(flow)
                print(f"[FLOW MANAGER] Analysis completed for flow {flow_id}: {len(analysis_data.get('technologies', {}).get('frameworks', []))} frameworks, {len(analysis_data.get('discovered_endpoints', []))} endpoints")
                
                # Update cache with analysis results
                with self._lock:
                    if flow_id in self.flow_cache:
                        # Merge analysis into cached flow
                        self.flow_cache[flow_id].update(analysis_data)
                        self.flow_analysis_cache[flow_id] = analysis_data
                        print(f"[FLOW MANAGER] Updated cache for flow {flow_id}")
                    else:
                        print(f"[FLOW MANAGER] WARNING: Flow {flow_id} not in cache, cannot update")
                
                self.analysis_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[ERROR] Error in analysis worker: {e}")
                import traceback
                traceback.print_exc()
    
    def set_fast_mode(self, enabled: bool, threshold_kb: int = 100):
        """Enable/disable fast mode and set threshold."""
        old_fast_mode = self.fast_mode
        self.fast_mode = enabled
        self.fast_mode_threshold_kb = threshold_kb
        print(f"[FLOW MANAGER] Fast mode changed: {old_fast_mode} -> {enabled}, threshold: {threshold_kb}KB")
        
        # If fast mode was disabled, trigger re-analysis of flows that were skipped
        if old_fast_mode and not enabled:
            print("[FLOW MANAGER] Fast mode disabled, flows will be analyzed on next add_flow() call")
    
    def _serialize_flow(self, flow, detail: bool = False) -> Dict:
        """Legacy method - kept for compatibility. Uses optimized minimal serialization + heavy analysis."""
        # Use minimal serialization
        data = self._serialize_flow_minimal(flow)
        
        # Get or compute heavy analysis
        analysis_data = self.flow_analysis_cache.get(flow.id)
        if analysis_data is None:
            # Compute synchronously if not cached (for legacy compatibility)
            analysis_data = self._perform_heavy_analysis(flow)
            with self._lock:
                self.flow_analysis_cache[flow.id] = analysis_data
        
        # Merge analysis data
        data.update(analysis_data)
        
        # Add detail if requested
        if detail:
            import base64
            req_content = flow.request.content or b""
            data["request"] = {
                "headers": dict(flow.request.headers),
                "content_bs64": base64.b64encode(req_content).decode('utf-8'),
                "content_length": len(req_content)
            }
            
            if flow.response:
                res_content = _safe_response_content(flow.response)
                data["response"] = {
                    "headers": dict(flow.response.headers),
                    "content_bs64": base64.b64encode(res_content).decode('utf-8'),
                    "content_length": len(res_content),
                    "reason": getattr(flow.response, 'reason', '') or ''
                }
            else:
                data["response"] = None
                
        return data

    def clear(self):
        with self._lock:
            self.flows.clear()
            self.flow_cache.clear()
            self.flow_analysis_cache.clear()
            self.imported_pcap_flows.clear()
            self.pending_intercepts.clear()
            self.intercept_queue.clear()
    
    def remove_flows_out_of_scope(self) -> int:
        """Remove all flows that don't match the current scope configuration."""
        if not self.scope_config.get('enabled', False) or not self.scope_config.get('patterns'):
            return 0  # Scope is disabled, nothing to remove
        
        removed_count = 0
        flows_to_remove = []
        mode = self.scope_config.get('mode', 'include')
        patterns = self.scope_config.get('patterns', [])
        
        print(f"[FLOW MANAGER] Checking scope: mode={mode}, patterns={patterns}, total_flows={len(self.flows)}")
        
        with self._lock:
            # Collect flows that are out of scope
            matched_count = 0
            for flow_id, flow in self.flows.items():
                try:
                    url = flow.request.url if hasattr(flow.request, 'url') else None
                    hostname = flow.request.host if hasattr(flow.request, 'host') else None
                    is_in_scope = self._is_in_scope(flow)
                    
                    if is_in_scope:
                        matched_count += 1
                    else:
                        flows_to_remove.append(flow_id)
                        if url and hostname:
                            print(f"[FLOW MANAGER] Flow {flow_id[:8]}... OUT OF SCOPE: {hostname} - {url}")
                except Exception as e:
                    print(f"[FLOW MANAGER] Error checking flow {flow_id}: {e}")
                    import traceback
                    traceback.print_exc()
                    # On error, keep the flow (safer to keep than remove on error)
            
            print(f"[FLOW MANAGER] Scope check: {matched_count} flows IN scope, {len(flows_to_remove)} flows OUT of scope")
            
            # Remove flows
            for flow_id in flows_to_remove:
                if flow_id in self.flows:
                    del self.flows[flow_id]
                if flow_id in self.flow_cache:
                    del self.flow_cache[flow_id]
                if flow_id in self.flow_analysis_cache:
                    del self.flow_analysis_cache[flow_id]
                if flow_id in self.pending_intercepts:
                    del self.pending_intercepts[flow_id]
                removed_count += 1
        
        remaining = len(self.flows) if hasattr(self, 'flows') else 0
        if removed_count > 0:
            print(f"[FLOW MANAGER] Removed {removed_count} flow(s) that don't match the scope. Remaining: {remaining}")
        else:
            print(f"[FLOW MANAGER] No flows removed. All {remaining} flows match the scope.")
        
        return removed_count
    
    def shutdown(self):
        """Shutdown the analysis worker thread."""
        self.analysis_worker_running = False
        if self.analysis_worker.is_alive():
            self.analysis_worker.join(timeout=2)
    
    def _save_flow_to_db(self, flow: 'HTTPFlow', serialized_flow: Dict):
        """Save flow to database if workspace is not 'default'"""
        if not self.framework:
            return
        
        try:
            current_workspace = self.framework.get_current_workspace_name()
            if current_workspace == "default":
                return  # Don't save flows for default workspace
            
            # Get database session
            db_session = self.framework.get_db_session()
            if not db_session:
                return
            
            from core.models.models import ProxyFlow, Workspace
            
            # Get workspace ID
            workspace = db_session.query(Workspace).filter(Workspace.name == current_workspace).first()
            if not workspace:
                return
            
            # Check if flow already exists
            existing_flow = db_session.query(ProxyFlow).filter(
                ProxyFlow.flow_id == flow.id,
                ProxyFlow.workspace_id == workspace.id
            ).first()
            
            # Prepare flow data
            req_content = flow.request.content or b""
            req_headers = dict(flow.request.headers) if flow.request.headers else {}
            
            res_content = b""
            res_headers = {}
            if flow.response:
                res_content = _safe_response_content(flow.response)
                res_headers = dict(flow.response.headers) if flow.response.headers else {}
            
            # Get analysis data
            analysis_data = self.flow_analysis_cache.get(flow.id, {})
            
            if existing_flow:
                # Update existing flow
                existing_flow.method = flow.request.method
                existing_flow.scheme = flow.request.scheme
                existing_flow.host = flow.request.host
                existing_flow.path = flow.request.path
                existing_flow.url = flow.request.url
                existing_flow.request_headers = json.dumps(req_headers)
                existing_flow.request_content = base64.b64encode(req_content).decode('utf-8')
                existing_flow.request_content_length = len(req_content)
                
                if flow.response:
                    existing_flow.status_code = flow.response.status_code
                    existing_flow.response_headers = json.dumps(res_headers)
                    existing_flow.response_content = base64.b64encode(res_content).decode('utf-8')
                    existing_flow.response_content_length = len(res_content)
                    existing_flow.response_reason = getattr(flow.response, 'reason', '') or ''
                else:
                    existing_flow.status_code = None
                    existing_flow.response_headers = None
                    existing_flow.response_content = None
                    existing_flow.response_content_length = 0
                    existing_flow.response_reason = None
                
                existing_flow.timestamp_start = flow.request.timestamp_start
                existing_flow.duration = serialized_flow.get('duration')
                existing_flow.duration_ms = serialized_flow.get('duration_ms')
                existing_flow.response_size = serialized_flow.get('response_size')
                existing_flow.intercepted = flow.intercepted
                existing_flow.source = serialized_flow.get('source')
                existing_flow.is_websocket = serialized_flow.get('is_websocket', False)
                existing_flow.ws_messages = json.dumps(serialized_flow.get('ws_messages', []))
                
                # Update analysis data
                existing_flow.technologies = json.dumps(analysis_data.get('technologies', {}))
                existing_flow.fingerprint = json.dumps(analysis_data.get('fingerprint', {}))
                existing_flow.module_suggestions = json.dumps(analysis_data.get('module_suggestions', []))
                existing_flow.endpoints = json.dumps(analysis_data.get('endpoints', {}))
                existing_flow.discovered_endpoints = json.dumps(analysis_data.get('discovered_endpoints', []))
                existing_flow.updated_at = datetime.utcnow()
            else:
                # Create new flow
                db_flow = ProxyFlow(
                    flow_id=flow.id,
                    workspace_id=workspace.id,
                    method=flow.request.method,
                    scheme=flow.request.scheme,
                    host=flow.request.host,
                    path=flow.request.path,
                    url=flow.request.url,
                    request_headers=json.dumps(req_headers),
                    request_content=base64.b64encode(req_content).decode('utf-8'),
                    request_content_length=len(req_content),
                    status_code=flow.response.status_code if flow.response else None,
                    response_headers=json.dumps(res_headers) if flow.response else None,
                    response_content=base64.b64encode(res_content).decode('utf-8') if flow.response else None,
                    response_content_length=len(res_content) if flow.response else 0,
                    response_reason=getattr(flow.response, 'reason', '') or '' if flow.response else None,
                    timestamp_start=flow.request.timestamp_start,
                    duration=serialized_flow.get('duration'),
                    duration_ms=serialized_flow.get('duration_ms'),
                    response_size=serialized_flow.get('response_size'),
                    intercepted=flow.intercepted,
                    source=serialized_flow.get('source'),
                    is_websocket=serialized_flow.get('is_websocket', False),
                    ws_messages=json.dumps(serialized_flow.get('ws_messages', [])),
                    technologies=json.dumps(analysis_data.get('technologies', {})),
                    fingerprint=json.dumps(analysis_data.get('fingerprint', {})),
                    module_suggestions=json.dumps(analysis_data.get('module_suggestions', [])),
                    endpoints=json.dumps(analysis_data.get('endpoints', {})),
                    discovered_endpoints=json.dumps(analysis_data.get('discovered_endpoints', []))
                )
                db_session.add(db_flow)
            
            db_session.commit()
        except Exception as e:
            print(f"[FLOW MANAGER] Error saving flow to database: {e}")
            import traceback
            traceback.print_exc()
            try:
                if db_session:
                    db_session.rollback()
            except:
                pass
    
    def load_flows_from_db(self, workspace_name: str = None):
        """Load flows from database for the current workspace"""
        if not self.framework:
            return
        
        try:
            if workspace_name is None:
                workspace_name = self.framework.get_current_workspace_name()
            
            if workspace_name == "default":
                return  # Don't load flows for default workspace
            
            # Get database session
            db_session = self.framework.get_db_session()
            if not db_session:
                return
            
            from core.models.models import ProxyFlow, Workspace
            
            # Get workspace ID
            workspace = db_session.query(Workspace).filter(Workspace.name == workspace_name).first()
            if not workspace:
                return
            
            # Load flows from database
            db_flows = db_session.query(ProxyFlow).filter(
                ProxyFlow.workspace_id == workspace.id
            ).order_by(ProxyFlow.timestamp_start.desc()).limit(self.max_flows).all()
            
            print(f"[FLOW MANAGER] Loading {len(db_flows)} flows from database for workspace '{workspace_name}'")
            
            with self._lock:
                # Clear existing flows
                self.flows.clear()
                self.flow_cache.clear()
                self.flow_analysis_cache.clear()
                
                # Load flows into cache
                for db_flow in db_flows:
                    flow_dict = db_flow.to_dict()
                    self.flow_cache[db_flow.flow_id] = flow_dict
                    
                    # Load analysis data
                    if db_flow.technologies or db_flow.fingerprint or db_flow.module_suggestions:
                        self.flow_analysis_cache[db_flow.flow_id] = {
                            'technologies': json.loads(db_flow.technologies) if db_flow.technologies else {},
                            'fingerprint': json.loads(db_flow.fingerprint) if db_flow.fingerprint else {},
                            'module_suggestions': json.loads(db_flow.module_suggestions) if db_flow.module_suggestions else [],
                            'endpoints': json.loads(db_flow.endpoints) if db_flow.endpoints else {},
                            'discovered_endpoints': json.loads(db_flow.discovered_endpoints) if db_flow.discovered_endpoints else [],
                        }
            
            print(f"[FLOW MANAGER] Successfully loaded {len(self.flow_cache)} flows from database")
        except Exception as e:
            print(f"[FLOW MANAGER] Error loading flows from database: {e}")
            import traceback
            traceback.print_exc()

# Global instance
flow_manager = FlowManager()
