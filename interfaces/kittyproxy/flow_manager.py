import uuid
import copy
import threading
from typing import List, Dict, Optional, Callable
from collections import OrderedDict

from mitmproxy.http import HTTPFlow

from tech_detector import tech_detector
from fingerprint_engine import fingerprint_engine
from module_suggester import module_suggester
from endpoint_extractor import endpoint_extractor

class FlowManager:
    def __init__(self, max_flows: int = 1000):
        self.flows: OrderedDict[str, 'HTTPFlow'] = OrderedDict()
        self.flow_cache: Dict[str, Dict] = {}  # Cache for serialized flows
        self.max_flows = max_flows
        self.intercept_enabled: bool = False
        self.intercept_queue: Dict[str, threading.Event] = {}
        self.pending_intercepts: Dict[str, 'HTTPFlow'] = {}
        self._lock = threading.RLock()
        self.callbacks: List[Callable[[Dict], None]] = []

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
            
            # Pre-calculate and cache the serialized version
            serialized_flow = self._serialize_flow(flow)
            self.flow_cache[flow.id] = serialized_flow
            
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
            return self._serialize_flow(flow, detail=True)

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

    def _serialize_flow(self, flow, detail: bool = False) -> Dict:
        """Helper to convert mitmproxy flow to dict."""
        duration = None
        duration_ms = None
        
        # Calculer la durée de différentes manières selon ce qui est disponible
        if flow.response:
            # Méthode 1: Utiliser timestamp_end de la réponse (le plus précis)
            if hasattr(flow.response, 'timestamp_end') and flow.response.timestamp_end:
                duration = flow.response.timestamp_end - flow.request.timestamp_start
                duration_ms = int(duration * 1000) if duration else None
            # Méthode 2: Utiliser timestamp_start de la réponse
            elif hasattr(flow.response, 'timestamp_start') and flow.response.timestamp_start:
                duration = flow.response.timestamp_start - flow.request.timestamp_start
                duration_ms = int(duration * 1000) if duration else None
            # Méthode 3: Utiliser le timestamp_end du flow
            elif hasattr(flow, 'timestamp_end') and flow.timestamp_end:
                duration = flow.timestamp_end - flow.request.timestamp_start
                duration_ms = int(duration * 1000) if duration else None
            # Méthode 4: Utiliser time.time() si les timestamps ne sont pas disponibles
            # (fallback, moins précis)
            elif flow.request.timestamp_start:
                import time
                current_time = time.time()
                duration = current_time - flow.request.timestamp_start
                duration_ms = int(duration * 1000) if duration else None
        
        # Only perform heavy analysis if not already done or if detail is requested
        # Note: For the list view (detail=False), we rely on the cache in add_flow calling this
        
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
            # Log du résultat de l'extraction
            total_extracted = sum(len(urls) for urls in extracted_endpoints.values())
            if total_extracted > 0:
                print(f"[FLOW MANAGER] Extracted {total_extracted} endpoints from {flow.request.url if flow.request else 'unknown'}")
            else:
                print(f"[FLOW MANAGER] No endpoints extracted from {flow.request.url if flow.request else 'unknown'}")
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
        
        # Check if flow is from API Tester
        source = None
        if hasattr(flow, 'metadata') and isinstance(flow.metadata, dict):
            source = flow.metadata.get('source')
        # Also check in request headers as fallback
        if not source and hasattr(flow, 'request') and hasattr(flow.request, 'headers'):
            if b'X-KittyProxy-Source' in flow.request.headers:
                source = flow.request.headers[b'X-KittyProxy-Source'].decode('utf-8')
        
        # Calculate response size even without detail
        response_size = None
        if flow.response:
            # Try to get content length from response
            if hasattr(flow.response, 'content') and flow.response.content:
                response_size = len(flow.response.content)
            # Fallback: try to get from Content-Length header
            elif hasattr(flow.response, 'headers') and flow.response.headers:
                content_length_header = flow.response.headers.get(b'Content-Length') or flow.response.headers.get('Content-Length')
                if content_length_header:
                    try:
                        if isinstance(content_length_header, bytes):
                            content_length_header = content_length_header.decode('utf-8')
                        response_size = int(content_length_header)
                    except (ValueError, TypeError):
                        pass
        
        data = {
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
            "source": source,  # 'api_tester' if from API Tester, None otherwise
            "technologies": detected_techs,  # Technologies détectées
            "fingerprint": fingerprint,  # Fingerprinting avancé
            "module_suggestions": module_suggestions,  # Suggestions de modules
            "endpoints": extracted_endpoints,  # Endpoints extraits (categorized)
            "discovered_endpoints": sorted(list(set([url for urls in extracted_endpoints.values() for url in urls]))),  # Flattened list for UI
            "response_size": response_size,  # Response size for list view
        }
        
        # Log pour vérifier que les endpoints sont bien stockés
        discovered_count = len(data["discovered_endpoints"])
        if discovered_count > 0:
            print(f"[FLOW MANAGER] Stored {discovered_count} discovered_endpoints in flow data for {data['url']}")
        else:
            print(f"[FLOW MANAGER] No discovered_endpoints stored in flow data for {data['url']} (extracted_endpoints had {sum(len(urls) for urls in extracted_endpoints.values())} total)")
        
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
            self.pending_intercepts.clear()
            self.intercept_queue.clear()

# Global instance
flow_manager = FlowManager()
