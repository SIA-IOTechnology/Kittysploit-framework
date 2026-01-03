import uuid
import copy
import threading
import queue
from typing import List, Dict, Optional, Callable
from collections import OrderedDict

from mitmproxy.http import HTTPFlow

from tech_detector import tech_detector
from fingerprint_engine import fingerprint_engine
from module_suggester import module_suggester
from endpoint_extractor import endpoint_extractor

class FlowManager:
    def __init__(self, max_flows: int = 5000, fast_mode: bool = False, fast_mode_threshold_kb: int = 100):
        self.flows: OrderedDict[str, 'HTTPFlow'] = OrderedDict()
        self.flow_cache: Dict[str, Dict] = {}  # Cache for serialized flows
        self.flow_analysis_cache: Dict[str, Dict] = {}  # Cache for heavy analysis results
        self.max_flows = max_flows
        self.intercept_enabled: bool = False
        self.intercept_queue: Dict[str, threading.Event] = {}
        self.pending_intercepts: Dict[str, 'HTTPFlow'] = {}
        self._lock = threading.RLock()
        self.callbacks: List[Callable[[Dict], None]] = []
        
        # Fast mode: skip heavy analysis for large responses
        self.fast_mode = fast_mode
        self.fast_mode_threshold_kb = fast_mode_threshold_kb  # Skip analysis if response > X KB
        
        # Worker thread for heavy analysis
        self.analysis_queue = queue.Queue()
        self.analysis_worker_running = True
        self.analysis_worker = threading.Thread(target=self._analysis_worker, daemon=True)
        self.analysis_worker.start()
        print(f"[FLOW MANAGER] Analysis worker thread started (fast_mode={self.fast_mode}, threshold={self.fast_mode_threshold_kb}KB)")

    def register_callback(self, callback):
        """Register a callback to be called when a new flow is added."""
        self.callbacks.append(callback)

    def add_flow(self, flow):
        """Adds a flow to the list with memory limit and pre-caching."""
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
                    response_size = 0
                    if hasattr(flow.response, 'content') and flow.response.content:
                        response_size = len(flow.response.content)
                    elif hasattr(flow.response, 'headers') and flow.response.headers:
                        content_length_header = flow.response.headers.get(b'Content-Length') or flow.response.headers.get('Content-Length')
                        if content_length_header:
                            try:
                                if isinstance(content_length_header, bytes):
                                    content_length_header = content_length_header.decode('utf-8')
                                response_size = int(content_length_header)
                            except (ValueError, TypeError):
                                pass
                    
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

    def get_flows(self) -> List[Dict]:
        """Returns all flows (legacy method)."""
        with self._lock:
            # Return flows in reverse order (newest first)
            return list(reversed(list(self.flow_cache.values())))

    def get_flows_paginated(self, page: int = 1, size: int = 50, search: str = None) -> Dict:
        """Returns a paginated slice of flows."""
        with self._lock:
            all_flows = list(reversed(list(self.flow_cache.values())))
            
            # Filter if search term provided
            if search:
                search = search.lower()
                filtered_flows = [
                    f for f in all_flows 
                    if search in f.get('url', '').lower() or 
                       search in f.get('method', '').lower() or 
                       str(f.get('status_code', '')).lower() in search
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
                res_content = flow.response.content or b""
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
        
        # Calculate response size
        response_size = None
        if flow.response:
            if hasattr(flow.response, 'content') and flow.response.content:
                response_size = len(flow.response.content)
            elif hasattr(flow.response, 'headers') and flow.response.headers:
                content_length_header = flow.response.headers.get(b'Content-Length') or flow.response.headers.get('Content-Length')
                if content_length_header:
                    try:
                        if isinstance(content_length_header, bytes):
                            content_length_header = content_length_header.decode('utf-8')
                        response_size = int(content_length_header)
                    except (ValueError, TypeError):
                        pass
        
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
        except Exception as e:
            print(f"[ERROR] Error adding to discovered endpoints: {e}")
        
        return {
            "technologies": detected_techs,
            "fingerprint": fingerprint,
            "module_suggestions": module_suggestions,
            "endpoints": extracted_endpoints,
            "discovered_endpoints": sorted(list(set([url for urls in extracted_endpoints.values() for url in urls]))),
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
                res_content = flow.response.content or b""
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
            self.pending_intercepts.clear()
            self.intercept_queue.clear()
    
    def shutdown(self):
        """Shutdown the analysis worker thread."""
        self.analysis_worker_running = False
        if self.analysis_worker.is_alive():
            self.analysis_worker.join(timeout=2)

# Global instance
flow_manager = FlowManager()
