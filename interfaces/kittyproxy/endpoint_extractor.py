#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Endpoint Extractor - Extrait les endpoints et liens depuis les réponses HTTP
"""

import re
import json
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse, urlunparse

from mitmproxy import http

class EndpointExtractor:
    """Extrait les endpoints, liens et URLs depuis les réponses HTTP"""
    
    def __init__(self, framework=None):
        self.discovered_endpoints: Set[str] = set()
        self.discovered_links: Set[str] = set()
        self.react_api_endpoints: Set[str] = set()  # Endpoints spécifiques extraits depuis React
        self.react_domains: Set[str] = set()  # Domaines où React a été détecté
        self.js_files_to_fetch: Set[str] = set()  # Fichiers JS à télécharger pour analyse
        self.fetched_js_files: Set[str] = set()  # Fichiers JS déjà téléchargés
        self.analyzed_js_files: Set[str] = set()  # Fichiers JS déjà analysés pour extraction React/GraphQL
        self.graphql_queries: Dict[str, List[Dict]] = {}  # Endpoint GraphQL -> Liste de requêtes
        self.analyzed_flows: Set[str] = set()  # URLs de flows déjà analysés (pour éviter la réanalyse)
        self.cached_endpoints: Dict[str, Dict[str, List[str]]] = {}  # Cache des endpoints extraits par flow_id
        self.framework = framework  # Framework instance for database access
        # JS → creds/secrets (type, name, context, source_url - no raw values logged)
        self.discovered_secrets: List[Dict] = []
        # SSRF/redirect candidate params: { flow_id, url, param_name, location, candidate_type }
        self.ssrf_redirect_candidates: List[Dict] = []

    def reset(self):
        """Réinitialise tous les jeux de données extraits (utile après un clear)"""
        self.discovered_endpoints.clear()
        self.discovered_links.clear()
        self.react_api_endpoints.clear()
        self.react_domains.clear()
        self.js_files_to_fetch.clear()
        self.fetched_js_files.clear()
        self.analyzed_js_files.clear()
        self.graphql_queries.clear()
        self.analyzed_flows.clear()
        self.cached_endpoints.clear()
        self.discovered_secrets.clear()
        self.ssrf_redirect_candidates.clear()

    # Parameter names often used for SSRF or open redirect (case-insensitive match)
    SSRF_REDIRECT_PARAM_NAMES = frozenset([
        'url', 'uri', 'target', 'dest', 'destination', 'redirect', 'redirect_uri', 'redirect_url',
        'return', 'returnurl', 'return_url', 'next', 'next_url', 'continue', 'goto', 'out', 'view',
        'link', 'href', 'callback', 'cb', 'forward', 'redirect_to', 'redir', 'rurl', 'page',
        'path', 'file', 'document', 'folder', 'img', 'image', 'load', 'fetch', 'request', 'proxy',
        'data', 'ref', 'reference', 'host', 'domain', 'site', 'address', 'from', 'to', 'src',
        'open', 'window', 'popup', 'jump', 'jump_to', 'return_to', 'back', 'ret', 'returnTo',
    ])

    def _extract_secrets_from_js(self, js: str, base_url: str) -> List[Dict]:
        """Extract potential credentials/secrets from JavaScript (variable names + context, no raw values)."""
        from urllib.parse import urlparse
        results = []
        seen_keys = set()  # (source_url, type, name_lower) to avoid duplicates

        # Patterns: (regex, secret_type). Capture variable/key name and optional context.
        # We do NOT capture the actual secret value in logs; we only report "potential secret found".
        patterns = [
            # apiKey, API_KEY, api_key, etc.
            (r'(?:const|let|var)\s+([a-zA-Z_$][\w$]*)\s*=\s*["\'][^"\']{8,}["\']\s*(?:;|\n|$)', 'api_key'),
            (r'(?:api[_-]?key|apikey|API[_-]?KEY)\s*[:=]\s*["\']([^"\']+)["\']', 'api_key'),
            (r'["\'](?:api[_-]?key|apikey)["\']\s*:\s*["\']([^"\']+)["\']', 'api_key'),
            # secret
            (r'(?:const|let|var)\s+([a-zA-Z_$][\w$]*[sS]ecret[a-zA-Z_$]*)\s*=\s*["\'][^"\']+["\']', 'secret'),
            (r'["\'](?:secret|client_secret)["\']\s*:\s*["\']([^"\']+)["\']', 'secret'),
            (r'(?:secret|client_secret)\s*[:=]\s*["\']([^"\']+)["\']', 'secret'),
            # password
            (r'(?:const|let|var)\s+([a-zA-Z_$][\w$]*[pP]assword[a-zA-Z_$]*)\s*=\s*["\'][^"\']+["\']', 'password'),
            (r'["\'](?:password|passwd|pwd)["\']\s*:\s*["\']([^"\']+)["\']', 'password'),
            (r'(?:password|passwd)\s*[:=]\s*["\']([^"\']+)["\']', 'password'),
            # token, access_token, bearer
            (r'(?:const|let|var)\s+([a-zA-Z_$][\w$]*[tT]oken[a-zA-Z_$]*)\s*=\s*["\'][^"\']+["\']', 'token'),
            (r'["\'](?:access_token|refresh_token|auth_token|token|bearer)["\']\s*:\s*["\']([^"\']+)["\']', 'token'),
            (r'(?:access_token|token|auth_token)\s*[:=]\s*["\']([^"\']+)["\']', 'token'),
            # auth
            (r'(?:const|let|var)\s+([a-zA-Z_$][\w$]*[aA]uth[a-zA-Z_$]*)\s*=\s*["\'][^"\']+["\']', 'auth'),
            (r'["\'](?:authorization|auth|basic)["\']\s*:\s*["\']([^"\']+)["\']', 'auth'),
            # credential
            (r'(?:const|let|var)\s+([a-zA-Z_$][\w$]*[cC]redential[a-zA-Z_$]*)\s*=\s*["\'][^"\']+["\']', 'credential'),
            (r'["\'](?:credential|credentials)["\']\s*:\s*["\']([^"\']+)["\']', 'credential'),
        ]

        for pattern, secret_type in patterns:
            for m in re.finditer(pattern, js, re.IGNORECASE | re.MULTILINE):
                try:
                    # First group is usually the variable name or a placeholder; we use it for dedup
                    name = (m.group(1) or '').strip()[:80]
                    if not name or name.startswith('{{'):
                        continue
                    key = (base_url, secret_type, name.lower())
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    # Context: 50 chars around match (no raw value in snippet)
                    start = max(0, m.start() - 20)
                    end = min(len(js), m.end() + 30)
                    context = js[start:end].replace('\n', ' ').strip()[:100]
                    # Redact potential value in context (replace quoted strings with ***)
                    context = re.sub(r'["\'][^"\']{4,}["\']', '"***"', context)
                    results.append({
                        'type': secret_type,
                        'name': name,
                        'context': context,
                        'source_url': base_url,
                    })
                except (IndexError, Exception):
                    continue

        return results

    def extract_ssrf_redirect_candidates_from_flow(self, flow) -> List[Dict]:
        """Extract parameter names from flow request that look like SSRF/redirect candidates."""
        from urllib.parse import urlparse, parse_qs
        candidates = []
        if not flow or not getattr(flow, 'request', None):
            return candidates

        try:
            url = flow.request.url or ''
            path = getattr(flow.request, 'path', '') or ''
            flow_id = getattr(flow, 'id', None) or url

            # Query string params
            parsed = urlparse(url)
            if parsed.query:
                for param_name in parse_qs(parsed.query, keep_blank_values=True).keys():
                    if param_name and param_name.lower() in self.SSRF_REDIRECT_PARAM_NAMES:
                        candidates.append({
                            'flow_id': flow_id,
                            'url': url,
                            'param_name': param_name,
                            'location': 'query',
                            'candidate_type': 'redirect' if any(x in param_name.lower() for x in ('redirect', 'return', 'next', 'url', 'goto', 'callback', 'returnurl', 'next_url')) else 'ssrf',
                        })

            # Body: form or JSON
            content = flow.request.content or b''
            if not content:
                return candidates

            ct_raw = flow.request.headers.get('Content-Type') or b''
            if isinstance(ct_raw, bytes):
                ct = ct_raw.decode('utf-8', errors='ignore').lower()
            else:
                ct = str(ct_raw).lower()
            try:
                body_str = content.decode('utf-8', errors='replace') if isinstance(content, bytes) else str(content)
            except Exception:
                return candidates

            if 'application/x-www-form-urlencoded' in ct:
                for part in body_str.split('&'):
                    if '=' in part:
                        param_name = part.split('=')[0].strip()
                        if param_name and param_name.lower() in self.SSRF_REDIRECT_PARAM_NAMES:
                            candidates.append({
                                'flow_id': flow_id,
                                'url': url,
                                'param_name': param_name,
                                'location': 'body_form',
                                'candidate_type': 'redirect' if any(x in param_name.lower() for x in ('redirect', 'return', 'next', 'url', 'goto', 'callback')) else 'ssrf',
                            })
            elif 'application/json' in ct:
                try:
                    data = json.loads(body_str)
                    if isinstance(data, dict):
                        for key in data.keys():
                            if isinstance(key, str) and key.lower() in self.SSRF_REDIRECT_PARAM_NAMES:
                                candidates.append({
                                    'flow_id': flow_id,
                                    'url': url,
                                    'param_name': key,
                                    'location': 'body_json',
                                    'candidate_type': 'redirect' if any(x in key.lower() for x in ('redirect', 'return', 'next', 'url', 'goto', 'callback')) else 'ssrf',
                                })
                except (json.JSONDecodeError, TypeError):
                    pass
        except Exception as e:
            print(f"[ENDPOINT EXTRACTION] Error extracting SSRF/redirect candidates: {e}")
        return candidates

    def extract(self, flow, detected_technologies: Dict = None) -> Dict[str, List[str]]:
        """Extrait tous les endpoints et liens depuis un flow
        
        Args:
            flow: Le flow HTTP à analyser
            detected_technologies: Dict des technologies détectées (optionnel)
        """
        endpoints = {
            'html_links': [],
            'javascript_endpoints': [],
            'api_endpoints': [],
            'form_actions': [],
            'json_urls': [],
            'css_urls': [],
            'image_urls': [],
            'other_resources': [],
            'react_api_endpoints': [],
        }
        
        if not flow.response or not flow.response.content:
            print(f"[ENDPOINT EXTRACTION] Skipping flow {flow.request.url if flow.request else 'unknown'}: no response or empty content")
            return endpoints
        
        # Vérifier si le flow a une réponse (nécessaire pour l'extraction)
        if not flow.response or not flow.response.content:
            # Pas de réponse disponible, retourner des endpoints vides
            return endpoints
        
        try:
            content = flow.response.content.decode('utf-8', errors='ignore')
            content_type = flow.response.headers.get('Content-Type', '').lower()
            base_url = flow.request.url
            
            # Utiliser l'URL de la requête comme identifiant unique
            flow_id = base_url
            
            # Vérifier si ce flow a déjà été analysé avec une réponse complète
            # Si le flow a déjà été analysé ET qu'on a un cache, on peut le retourner
            # Mais si le flow a été analysé sans réponse (lors de la requête), on doit réanalyser
            if flow_id in self.analyzed_flows and flow_id in self.cached_endpoints:
                # Flow déjà analysé avec réponse, retourner les endpoints mis en cache
                print(f"[ENDPOINT EXTRACTION] Flow {flow_id} already analyzed, returning {sum(len(urls) for urls in self.cached_endpoints[flow_id].values())} cached endpoints")
                return self.cached_endpoints[flow_id].copy()
            
            # Marquer ce flow comme analysé AVANT l'extraction pour éviter les doublons
            # (ou réanalyser si le cache n'existe pas, ce qui signifie qu'il a été analysé sans réponse)
            self.analyzed_flows.add(flow_id)
            print(f"[ENDPOINT EXTRACTION] Analyzing flow {flow_id}, content_type: {content_type}, content_length: {len(content)}")
            
            # Extraire le domaine pour la détection au niveau domaine
            try:
                from urllib.parse import urlparse
                parsed_url = urlparse(base_url)
                domain = f"{parsed_url.scheme}://{parsed_url.netloc}"
            except:
                domain = None
            
            # Vérifier si React est détecté
            is_react = False
            if detected_technologies:
                frameworks = detected_technologies.get('frameworks', [])
                if 'React' in frameworks:
                    is_react = True
                    if domain:
                        self.react_domains.add(domain)
            
            # Vérifier aussi dans le contenu si pas déjà détecté
            if not is_react:
                react_indicators = ['react', 'React', '__REACT_DEVTOOLS', 'React.createElement', 'data-reactroot', 'react-dom']
                if any(indicator in content for indicator in react_indicators):
                    is_react = True
                    if domain:
                        self.react_domains.add(domain)
            
            # Vérifier aussi si le domaine a déjà été identifié comme React
            if not is_react and domain and domain in self.react_domains:
                is_react = True
            
            # Extraire depuis HTML
            if 'text/html' in content_type:
                endpoints['html_links'].extend(self._extract_html_links(content, base_url))
                endpoints['form_actions'].extend(self._extract_form_actions(content, base_url))
                
                # Si React est détecté, extraire les fichiers JS référencés et les télécharger pour analyse
                if is_react:
                    print(f"[REACT DETECTION] React detected on {base_url}, extracting JS files...")
                    js_files = self._extract_js_files_from_html(content, base_url)
                    print(f"[REACT DETECTION] Found {len(js_files)} JS file(s) to analyze: {js_files}")
                    for js_url in js_files:
                        # Vérifier si le fichier JS a déjà été analysé
                        if js_url in self.analyzed_js_files:
                            print(f"[REACT DETECTION] JS file already analyzed: {js_url}, skipping")
                            continue
                        
                        # Marquer pour téléchargement si pas déjà fait
                        if js_url in self.fetched_js_files:
                            # Si déjà téléchargé mais pas encore analysé, marquer comme analysé et passer
                            print(f"[REACT DETECTION] JS file already fetched: {js_url}, marking as analyzed")
                            self.analyzed_js_files.add(js_url)
                            continue
                        elif js_url in self.js_files_to_fetch:
                            print(f"[REACT DETECTION] JS file already queued (but not fetched yet): {js_url}, skipping")
                            # Ne pas forcer le téléchargement si déjà en queue
                            continue
                        else:
                            self.js_files_to_fetch.add(js_url)
                            print(f"[REACT DETECTION] Queueing JS file for download: {js_url}")
                            # Télécharger en arrière-plan
                            print(f"[REACT DETECTION] Calling _fetch_js_file_async for {js_url}")
                            self._fetch_js_file_async(js_url, domain)
                            print(f"[REACT DETECTION] _fetch_js_file_async returned for {js_url}")
            
            # Extraire depuis JavaScript
            if 'javascript' in content_type or 'application/javascript' in content_type or '.js' in flow.request.path:
                # Vérifier si ce fichier JS a déjà été analysé
                if base_url not in self.analyzed_js_files:
                    endpoints['javascript_endpoints'].extend(self._extract_js_endpoints(content, base_url))
                    
                    # JS → creds/secrets: extract potential secrets (no raw values)
                    try:
                        secrets = self._extract_secrets_from_js(content, base_url)
                        for s in secrets:
                            if s not in self.discovered_secrets:
                                self.discovered_secrets.append(s)
                    except Exception as e:
                        print(f"[ENDPOINT EXTRACTION] Error extracting secrets from JS: {e}")
                    
                    # Si React est détecté, extraire spécifiquement les API React
                    if is_react:
                        react_apis = self.extract_react_api_endpoints(content, base_url)
                        endpoints['javascript_endpoints'].extend(react_apis)
                        endpoints['react_api_endpoints'] = react_apis
                    
                    # Marquer ce fichier JS comme analysé
                    self.analyzed_js_files.add(base_url)
                else:
                    print(f"[REACT API EXTRACTION] JS file already analyzed: {base_url}, skipping extraction")
            
            # Extraire depuis JSON
            if 'application/json' in content_type:
                endpoints['json_urls'].extend(self._extract_json_urls(content, base_url))
            
            # Extraire depuis CSS
            if 'text/css' in content_type:
                endpoints['css_urls'].extend(self._extract_css_urls(content, base_url))
            
            # Extraire depuis n'importe quel contenu texte
            endpoints['api_endpoints'].extend(self._extract_api_patterns(content, base_url))
            endpoints['other_resources'].extend(self._extract_generic_urls(content, base_url))
            
            # IMPORTANT: Extraire aussi les API depuis les requêtes réseau réelles
            # Si la requête elle-même ressemble à une API (ex: /graphql, /api/...)
            # Ne pas ajouter les requêtes issues du fuzzing (XSS/SQLi) aux Discovered APIs
            if flow.request:
                _source = None
                if hasattr(flow, 'metadata') and isinstance(getattr(flow, 'metadata'), dict):
                    _source = flow.metadata.get('source')
                if not _source and hasattr(flow.request, 'headers') and flow.request.headers:
                    _h = flow.request.headers.get(b'X-KittyProxy-Source') or flow.request.headers.get('X-KittyProxy-Source')
                    if _h:
                        _source = _h.decode('utf-8', errors='replace') if isinstance(_h, bytes) else str(_h)
                if _source and _source.lower() == 'fuzzing':
                    pass  # Ne pas ajouter l'URL de la requête fuzzing aux Discovered APIs
                else:
                    request_path = flow.request.path.split('?')[0]  # Enlever les query params
                    request_url_full = flow.request.url
                    request_url_clean = request_url_full.split('?')[0]  # Enlever les query params pour la détection
                    
                    # Extraire le domaine de la requête
                    try:
                        from urllib.parse import urlparse
                        parsed_req = urlparse(request_url_full)
                        request_domain = f"{parsed_req.scheme}://{parsed_req.netloc}"
                    except:
                        request_domain = None
                    
                    # Vérifier le Content-Type pour exclure les pages HTML
                    is_html_page = False
                    if flow.response:
                        response_content_type = flow.response.headers.get('Content-Type', '').lower()
                        if 'text/html' in response_content_type:
                            is_html_page = True
                    
                    # Exclure la racine et les pages HTML normales
                    path_lower = request_path.lower()
                    is_root_or_html = (
                        request_path == '/' or 
                        request_path == '' or
                        is_html_page or
                        path_lower.endswith('.html') or
                        path_lower.endswith('.htm') or
                        ('.' not in path_lower.split('/')[-1] and not any(indicator in path_lower for indicator in ['/api/', '/v', '/graphql', '/rest/', '/rpc/', '/webhook', '/callback', '/oauth', '/auth', '/login', '/logout', '/token']))
                    )
                    
                    # Vérifier si la requête elle-même est une API (et n'est pas une page HTML)
                    if not is_root_or_html and (self._looks_like_api_endpoint(request_path) or self._looks_like_api_endpoint(request_url_clean)):
                        # Si React est détecté sur ce domaine (actuel ou déjà détecté), ajouter aux API React
                        is_react_for_request = is_react or (request_domain and request_domain in self.react_domains)
                        
                        if is_react_for_request:
                            if request_url_full not in endpoints['react_api_endpoints']:
                                endpoints['react_api_endpoints'].append(request_url_full)
                                self.react_api_endpoints.add(request_url_full)
                        # Ajouter aussi aux endpoints généraux
                        if request_url_full not in endpoints['api_endpoints']:
                            endpoints['api_endpoints'].append(request_url_full)
            
            # Filtrer et normaliser
            for key in endpoints:
                endpoints[key] = list(set(endpoints[key]))  # Dédupliquer
                endpoints[key] = [url for url in endpoints[key] if self._is_valid_url(url)]
            
            # Mettre en cache les endpoints extraits
            self.cached_endpoints[flow_id] = {k: v.copy() for k, v in endpoints.items()}
            
            # Log du résumé de l'extraction
            total_endpoints = sum(len(urls) for urls in endpoints.values())
            if total_endpoints > 0:
                print(f"[ENDPOINT EXTRACTION] Found {total_endpoints} endpoints for {base_url}:")
                for category, urls in endpoints.items():
                    if urls:
                        print(f"  - {category}: {len(urls)}")
            else:
                print(f"[ENDPOINT EXTRACTION] No endpoints found for {base_url} (content_type: {content_type}, content_length: {len(content)})")
        
        except Exception as e:
            print(f"[ERROR] Error extracting endpoints: {e}")
            import traceback
            traceback.print_exc()
        
        return endpoints
    
    def _extract_html_links(self, html: str, base_url: str) -> List[str]:
        """Extrait les liens depuis le HTML"""
        links = []
        
        # Fonction helper pour filtrer les faux positifs JavaScript
        def is_valid_link(url: str) -> bool:
            if not url:
                return False
            url_lower = url.lower().strip()
            # Exclure les faux positifs JavaScript courants
            if url_lower in ['javascript:;', 'javascript:void(0)', 'javascript:void(0);', 'javascript:', 'javascript: ']:
                return False
            if url_lower.startswith('javascript:'):
                return False
            return True
        
        # Liens href
        href_pattern = r'href=["\']([^"\']+)["\']'
        for match in re.finditer(href_pattern, html, re.IGNORECASE):
            url = match.group(1)
            if url and not url.startswith('#') and is_valid_link(url):
                links.append(urljoin(base_url, url))
        
        # Liens src (images, scripts, etc.)
        src_pattern = r'src=["\']([^"\']+)["\']'
        for match in re.finditer(src_pattern, html, re.IGNORECASE):
            url = match.group(1)
            if url and is_valid_link(url):
                links.append(urljoin(base_url, url))
        
        # Liens data-src (lazy loading)
        data_src_pattern = r'data-src=["\']([^"\']+)["\']'
        for match in re.finditer(data_src_pattern, html, re.IGNORECASE):
            url = match.group(1)
            if url and is_valid_link(url):
                links.append(urljoin(base_url, url))
        
        # Liens dans les meta tags
        meta_pattern = r'<meta[^>]+(?:content|url)=["\']([^"\']+)["\']'
        for match in re.finditer(meta_pattern, html, re.IGNORECASE):
            url = match.group(1)
            if url and (url.startswith('http') or url.startswith('/')) and is_valid_link(url):
                links.append(urljoin(base_url, url))
        
        return links
    
    def _extract_form_actions(self, html: str, base_url: str) -> List[str]:
        """Extrait les actions des formulaires"""
        actions = []
        form_pattern = r'<form[^>]+action=["\']([^"\']+)["\']'
        for match in re.finditer(form_pattern, html, re.IGNORECASE):
            action = match.group(1)
            if action:
                actions.append(urljoin(base_url, action))
        return actions
    
    def _extract_js_endpoints(self, js: str, base_url: str) -> List[str]:
        """Extrait les endpoints depuis le JavaScript"""
        endpoints = []
        
        # Patterns pour fetch
        fetch_patterns = [
            r'fetch\(["\']([^"\']+)["\']',
            r'fetch\(`([^`]+)`',
            r"fetch\(['\"]([^'\"]+)['\"]",
        ]
        
        # Patterns pour XMLHttpRequest
        xhr_patterns = [
            r'\.open\(["\'](?:GET|POST|PUT|DELETE|PATCH)["\'],\s*["\']([^"\']+)["\']',
            r'\.open\(["\'](?:GET|POST|PUT|DELETE|PATCH)["\'],\s*`([^`]+)`',
        ]
        
        # Patterns pour axios
        axios_patterns = [
            r'axios\.(?:get|post|put|delete|patch)\(["\']([^"\']+)["\']',
            r'axios\.(?:get|post|put|delete|patch)\(`([^`]+)`',
            r'axios\(["\']([^"\']+)["\']',
        ]
        
        # Patterns pour $.ajax / $.get / $.post
        jquery_patterns = [
            r'\$\.(?:ajax|get|post|put|delete)\(["\']([^"\']+)["\']',
            r'\$\.(?:ajax|get|post|put|delete)\(`([^`]+)`',
            r'url:\s*["\']([^"\']+)["\']',
            r'url:\s*`([^`]+)`',
        ]
        
        # Patterns génériques pour URLs dans les strings
        url_string_patterns = [
            r'["\'](https?://[^"\']+)["\']',
            r'["\'](/[^"\']+)["\']',
            r'`(https?://[^`]+)`',
            r'`(/[^`]+)`',
        ]
        
        all_patterns = fetch_patterns + xhr_patterns + axios_patterns + jquery_patterns + url_string_patterns
        
        for pattern in all_patterns:
            for match in re.finditer(pattern, js, re.IGNORECASE):
                url = match.group(1)
                if url and len(url) > 1 and not url.startswith('#'):
                    # Filtrer les URLs qui ressemblent à des endpoints
                    if self._looks_like_endpoint(url):
                        # Vérifier aussi le ratio de caractères encodés pour les chemins
                        if url.startswith('/'):
                            encoded_ratio = len(re.findall(r'%[0-9A-Fa-f]{2}', url)) / max(len(url), 1)
                            if encoded_ratio < 0.5:  # Moins de 50% de caractères encodés
                                endpoints.append(urljoin(base_url, url))
                        else:
                            endpoints.append(urljoin(base_url, url))
        
        return endpoints
    
    def extract_react_api_endpoints(self, js: str, base_url: str) -> List[str]:
        """Extrait spécifiquement les endpoints API depuis du code React"""
        endpoints = []
        
        # Patterns spécifiques React pour fetch (dans useEffect, handlers, etc.)
        react_fetch_patterns = [
            # fetch dans useEffect
            r'useEffect\([^)]*fetch\(["\']([^"\']+)["\']',
            r'useEffect\([^)]*fetch\(`([^`]+)`',
            # fetch dans des fonctions async
            r'(?:const|let|var)\s+\w+\s*=\s*async\s*\([^)]*\)\s*=>\s*\{[^}]*fetch\(["\']([^"\']+)["\']',
            r'(?:const|let|var)\s+\w+\s*=\s*async\s*\([^)]*\)\s*=>\s*\{[^}]*fetch\(`([^`]+)`',
            # fetch avec await
            r'await\s+fetch\(["\']([^"\']+)["\']',
            r'await\s+fetch\(`([^`]+)`',
        ]
        
        # Patterns pour axios dans React
        react_axios_patterns = [
            r'useEffect\([^)]*axios\.(?:get|post|put|delete|patch)\(["\']([^"\']+)["\']',
            r'useEffect\([^)]*axios\.(?:get|post|put|delete|patch)\(`([^`]+)`',
            r'await\s+axios\.(?:get|post|put|delete|patch)\(["\']([^"\']+)["\']',
            r'await\s+axios\.(?:get|post|put|delete|patch)\(`([^`]+)`',
        ]
        
        # Patterns pour les constantes d'API (API_BASE, API_URL, etc.)
        api_constant_patterns = [
            r'(?:const|let|var)\s+(?:API_?(?:BASE|URL|ENDPOINT|ROOT)|BASE_?URL|API_?PATH)\s*=\s*["\']([^"\']+)["\']',
            r'(?:const|let|var)\s+(?:API_?(?:BASE|URL|ENDPOINT|ROOT)|BASE_?URL|API_?PATH)\s*=\s*`([^`]+)`',
        ]
        
        # Patterns for API calls with variables (e.g., `${API_BASE}/users`)
        # NOTE: We exclude these patterns because they generate too many false positives
        # api_template_patterns = [
        #     r'`\$\{[^}]+\}(/[^`]+)`',  # Template literals avec variables
        #     r'["\']\$\{[^}]+\}(/[^"\']+)["\']',  # Template strings dans quotes
        # ]
        api_template_patterns = []  # Disabled to avoid false positives
        
        # Patterns for API configuration objects
        api_config_patterns = [
            r'(?:baseURL|base_url|apiUrl|api_url|endpoint|url):\s*["\']([^"\']+)["\']',
            r'(?:baseURL|base_url|apiUrl|api_url|endpoint|url):\s*`([^`]+)`',
        ]
        
        # Patterns for API calls in React Query / SWR hooks
        react_query_patterns = [
            r'useQuery\([^)]*["\']([^"\']+)["\']',
            r'useQuery\([^)]*`([^`]+)`',
            r'useSWR\([^)]*["\']([^"\']+)["\']',
            r'useSWR\([^)]*`([^`]+)`',
        ]
        
        all_react_patterns = (
            react_fetch_patterns + react_axios_patterns + 
            api_constant_patterns + 
            api_config_patterns + react_query_patterns
            # api_template_patterns excluded to avoid false positives
        )
        
        matches_found = 0
        for pattern in all_react_patterns:
            for match in re.finditer(pattern, js, re.IGNORECASE | re.MULTILINE | re.DOTALL):
                url = match.group(1)
                matches_found += 1
                if url and len(url) > 1 and not url.startswith('#'):
                    # Filtrer les template literals avec variables (ex: ${l}/${r})
                    if '${' in url or '$' in url:
                        print(f"[REACT API EXTRACTION] Skipping template literal with variables: {url}")
                        continue
                    
                    # Filtrer les URLs qui ressemblent à des endpoints API
                    if self._looks_like_api_endpoint(url):
                        full_url = urljoin(base_url, url)
                        if full_url not in endpoints:
                            endpoints.append(full_url)
                            self.react_api_endpoints.add(full_url)
                            print(f"[REACT API EXTRACTION] Found API endpoint: {full_url} (from pattern match)")
        
        # Extraire les endpoints GraphQL depuis le contenu
        graphql_endpoints = self._extract_graphql_endpoints(js, base_url)
        for graphql_url in graphql_endpoints:
            # Normaliser l'URL pour éviter les doublons
            normalized_url = self._normalize_graphql_url(graphql_url)
            if normalized_url not in endpoints:
                endpoints.append(normalized_url)
                self.react_api_endpoints.add(normalized_url)
                print(f"[REACT API EXTRACTION] Found GraphQL endpoint: {normalized_url}")
        
        # Extraire les requêtes GraphQL elles-mêmes
        graphql_queries = self._extract_graphql_queries(js, base_url)
        for graphql_url, queries in graphql_queries.items():
            # Normaliser l'URL de l'endpoint GraphQL
            normalized_url = self._normalize_graphql_url(graphql_url)
            
            if normalized_url not in self.graphql_queries:
                self.graphql_queries[normalized_url] = []
            
            # Dédupliquer les requêtes avant de les ajouter
            existing_queries = self.graphql_queries[normalized_url]
            existing_query_contents = {q.get('full_content', q.get('content', '')) for q in existing_queries}
            
            new_queries = []
            for query in queries:
                query_content = query.get('full_content', query.get('content', ''))
                if query_content and query_content not in existing_query_contents:
                    new_queries.append(query)
                    existing_query_contents.add(query_content)
            
            if new_queries:
                self.graphql_queries[normalized_url].extend(new_queries)
                print(f"[REACT API EXTRACTION] Found {len(new_queries)} new GraphQL query(ies) for {normalized_url} (total: {len(self.graphql_queries[normalized_url])})")
        
        print(f"[REACT API EXTRACTION] Pattern matching: {matches_found} matches, {len(endpoints)} valid API endpoints")
        return endpoints
    
    def _extract_graphql_endpoints(self, js: str, base_url: str) -> List[str]:
        """Extrait les endpoints GraphQL depuis le code JavaScript"""
        endpoints = []
        
        # Patterns pour détecter les requêtes GraphQL
        graphql_query_patterns = [
            r'query\s*\{',  # query {
            r'mutation\s*\{',  # mutation {
            r'subscription\s*\{',  # subscription {
        ]
        
        has_graphql = False
        for pattern in graphql_query_patterns:
            if re.search(pattern, js, re.IGNORECASE | re.MULTILINE):
                has_graphql = True
                print(f"[REACT API EXTRACTION] GraphQL query/mutation detected in JS")
                break
        
        if not has_graphql:
            return endpoints
        
        # Si GraphQL est détecté, chercher l'endpoint GraphQL
        # Patterns communs pour les endpoints GraphQL
        graphql_endpoint_patterns = [
            # fetch('/graphql', ...)
            r'fetch\(["\']([^"\']*graphql[^"\']*)["\']',
            r'fetch\(`([^`]*graphql[^`]*)`',
            # axios.post('/graphql', ...)
            r'axios\.(?:get|post|put)\(["\']([^"\']*graphql[^"\']*)["\']',
            r'axios\.(?:get|post|put)\(`([^`]*graphql[^`]*)`',
            # Variables d'environnement ou constantes
            r'(?:GRAPHQL|GQL|API)_?(?:URL|ENDPOINT|BASE)\s*[:=]\s*["\']([^"\']*graphql[^"\']*)["\']',
            r'(?:GRAPHQL|GQL|API)_?(?:URL|ENDPOINT|BASE)\s*[:=]\s*`([^`]*graphql[^`]*)`',
            # Dans les objets de configuration
            r'(?:endpoint|url|uri):\s*["\']([^"\']*graphql[^"\']*)["\']',
            r'(?:endpoint|url|uri):\s*`([^`]*graphql[^`]*)`',
        ]
        
        found_endpoints = set()
        for pattern in graphql_endpoint_patterns:
            for match in re.finditer(pattern, js, re.IGNORECASE | re.MULTILINE | re.DOTALL):
                endpoint = match.group(1)
                if endpoint and '${' not in endpoint:  # Exclude template literals with variables
                    # Clean the endpoint
                    endpoint = endpoint.strip().strip('"').strip("'").strip('`')
                    if endpoint:
                        # Si c'est un chemin relatif, construire l'URL complète
                        if endpoint.startswith('/'):
                            full_url = urljoin(base_url, endpoint)
                        elif endpoint.startswith('http'):
                            full_url = endpoint
                        else:
                            # Probablement un chemin relatif
                            full_url = urljoin(base_url, '/' + endpoint)
                        
                        if full_url not in found_endpoints:
                            found_endpoints.add(full_url)
                            endpoints.append(full_url)
                            print(f"[REACT API EXTRACTION] Found GraphQL endpoint pattern: {endpoint} -> {full_url}")
        
        # If no specific endpoint is found but GraphQL is present,
        # try to guess the common endpoint
        if not endpoints:
            # Endpoints GraphQL communs
            common_graphql_endpoints = ['/graphql', '/api/graphql', '/gql', '/query']
            for common_endpoint in common_graphql_endpoints:
                full_url = urljoin(base_url, common_endpoint)
                endpoints.append(full_url)
                print(f"[REACT API EXTRACTION] Guessed GraphQL endpoint: {full_url}")
        
        return endpoints
    
    def _extract_graphql_queries(self, js: str, base_url: str) -> Dict[str, List[Dict]]:
        """Extrait les requêtes GraphQL depuis le code JavaScript"""
        queries_by_endpoint = {}
        
        # Patterns pour détecter les requêtes GraphQL (query, mutation, subscription)
        graphql_patterns = [
            # query { ... } ou query Name { ... } ou query ($var: Type) { ... }
            (r'(query\s+(?:\w+\s*)?(?:\([^)]*\)\s*)?\{[^}]+\})', 'query'),
            # mutation { ... }
            (r'(mutation\s+(?:\w+\s*)?(?:\([^)]*\)\s*)?\{[^}]+\})', 'mutation'),
            # subscription { ... }
            (r'(subscription\s+(?:\w+\s*)?(?:\([^)]*\)\s*)?\{[^}]+\})', 'subscription'),
        ]
        
        # Chercher toutes les requêtes GraphQL dans le code
        all_queries = []
        
        # Pattern amélioré pour capturer les requêtes GraphQL multilignes avec imbrication
        # On cherche d'abord "query", "mutation" ou "subscription" puis on capture jusqu'à la fin de la requête
        # Utiliser une approche avec comptage de braces pour gérer l'imbrication
        def extract_graphql_with_braces(text, start_pos):
            """Extrait une requête GraphQL en comptant les braces"""
            pos = start_pos
            brace_count = 0
            in_query = False
            query_start = None
            
            while pos < len(text):
                if pos + 5 < len(text) and text[pos:pos+5].lower() in ['query', 'mutat', 'subsc']:
                    # Vérifier si c'est vraiment query/mutation/subscription
                    match = re.match(r'(query|mutation|subscription)', text[pos:], re.IGNORECASE)
                    if match:
                        query_start = pos
                        in_query = True
                        pos += len(match.group(0))
                        continue
                
                if in_query:
                    if text[pos] == '{':
                        brace_count += 1
                    elif text[pos] == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            # Fin de la requête
                            return text[query_start:pos+1], pos+1
                
                pos += 1
            
            return None, pos
        
        # D'abord, extraire les template literals JavaScript (backticks)
        # Pattern pour détecter les template literals: `...` ou g.J1`...` ou variable`...`
        template_literal_pattern = r'[a-zA-Z_$][\w$]*\.J1\s*`([^`]*)`|`([^`]*)`'
        
        # Chercher tous les template literals
        template_matches = list(re.finditer(template_literal_pattern, js, re.DOTALL))
        
        # Extraire les requêtes GraphQL depuis les template literals
        for tmpl_match in template_matches:
            # Get template literal content (group 1 or 2 depending on pattern)
            template_content = tmpl_match.group(1) or tmpl_match.group(2) or ''
            if not template_content:
                continue
            
            # Chercher les requêtes GraphQL dans ce template literal
            tmpl_pos = 0
            while tmpl_pos < len(template_content):
                # Chercher le prochain query/mutation/subscription
                match = re.search(r'\b(query|mutation|subscription)\b', template_content[tmpl_pos:], re.IGNORECASE)
                if not match:
                    break
                
                query_start_in_tmpl = tmpl_pos + match.start()
                query_type = match.group(1).lower()
                
                # Extraire la requête complète depuis le template literal
                query_content, next_pos_in_tmpl = extract_graphql_with_braces(template_content, query_start_in_tmpl)
                
                if query_content:
                    # Clean the query (already in template literal, no need to remove backticks)
                    query_content = query_content.strip()
                    
                    # Extraire le nom de la requête si présent
                    name_match = re.search(rf'{query_type}\s+(\w+)', query_content, re.IGNORECASE)
                    query_name = name_match.group(1) if name_match else None
                    
                    # Extraire les variables si présentes
                    vars_match = re.search(r'\(([^)]+)\)', query_content)
                    variables = vars_match.group(1) if vars_match else None
                    
                    # Extraire les champs principaux (première ligne après {)
                    fields_match = re.search(r'\{\s*(\w+)', query_content)
                    main_field = fields_match.group(1) if fields_match else None
                    
                    if query_content and len(query_content) > 10:  # Filtrer les trop courts
                        all_queries.append({
                            'type': query_type,
                            'name': query_name,
                            'variables': variables,
                            'main_field': main_field,
                            'content': query_content[:500],  # Limiter la taille pour l'affichage
                            'full_content': query_content  # Version complète
                        })
                        print(f"[REACT API EXTRACTION] Found GraphQL {query_type} in template literal: {query_name or 'unnamed'} -> {main_field or 'unknown field'}")
                
                tmpl_pos = next_pos_in_tmpl
        
        # Aussi chercher directement dans le code JavaScript (pour les cas où les requêtes ne sont pas dans des template literals)
        pos = 0
        while pos < len(js):
            # Chercher le prochain query/mutation/subscription (mais pas dans un template literal déjà traité)
            match = re.search(r'\b(query|mutation|subscription)\b', js[pos:], re.IGNORECASE)
            if not match:
                break
            
            query_start = pos + match.start()
            
            # Vérifier si cette position est dans un template literal déjà traité
            in_processed_template = False
            for tmpl_match in template_matches:
                if tmpl_match.start() <= query_start <= tmpl_match.end():
                    in_processed_template = True
                    break
            
            if in_processed_template:
                pos = query_start + 1
                continue
            
            query_type = match.group(1).lower()
            
            # Extraire la requête complète
            query_content, next_pos = extract_graphql_with_braces(js, query_start)
            
            if query_content:
                # Clean the query
                query_content = query_content.strip().strip('`').strip('"').strip("'")
                
                # Extraire le nom de la requête si présent
                name_match = re.search(rf'{query_type}\s+(\w+)', query_content, re.IGNORECASE)
                query_name = name_match.group(1) if name_match else None
                
                # Extraire les variables si présentes
                vars_match = re.search(r'\(([^)]+)\)', query_content)
                variables = vars_match.group(1) if vars_match else None
                
                # Extraire les champs principaux (première ligne après {)
                fields_match = re.search(r'\{\s*(\w+)', query_content)
                main_field = fields_match.group(1) if fields_match else None
                
                if query_content and len(query_content) > 10:  # Filtrer les trop courts
                    all_queries.append({
                        'type': query_type,
                        'name': query_name,
                        'variables': variables,
                        'main_field': main_field,
                        'content': query_content[:500],  # Limiter la taille pour l'affichage
                        'full_content': query_content  # Version complète
                    })
                    print(f"[REACT API EXTRACTION] Found GraphQL {query_type}: {query_name or 'unnamed'} -> {main_field or 'unknown field'}")
            
            pos = next_pos
        
        # Try to find the associated GraphQL endpoint
        # If we found queries, search for the endpoint
        if all_queries:
            # Search for GraphQL endpoint in code around queries
            graphql_endpoint = None
            
            # Patterns to find the endpoint
            endpoint_patterns = [
                r'["\']([^"\']*graphql[^"\']*)["\']',
                r'`([^`]*graphql[^`]*)`',
                r'(?:endpoint|url|uri):\s*["\']([^"\']*graphql[^"\']*)["\']',
            ]
            
            for pattern in endpoint_patterns:
                for match in re.finditer(pattern, js, re.IGNORECASE):
                    endpoint = match.group(1)
                    if endpoint and '${' not in endpoint:
                        endpoint = endpoint.strip().strip('"').strip("'").strip('`')
                        if endpoint.startswith('/'):
                            graphql_endpoint = urljoin(base_url, endpoint)
                        elif endpoint.startswith('http'):
                            graphql_endpoint = endpoint
                        else:
                            graphql_endpoint = urljoin(base_url, '/' + endpoint)
                        break
                if graphql_endpoint:
                    break
            
            # Si aucun endpoint trouvé, utiliser un endpoint par défaut
            if not graphql_endpoint:
                graphql_endpoint = urljoin(base_url, '/graphql')
            
            # Normaliser l'endpoint pour éviter les doublons
            normalized_endpoint = self._normalize_graphql_url(graphql_endpoint)
            
            # Dédupliquer les requêtes localement (dans ce fichier JS)
            # La déduplication globale se fera dans extract_react_api_endpoints
            existing_query_contents = set()
            unique_queries = []
            for query in all_queries:
                query_content = query.get('full_content', query.get('content', ''))
                if query_content and query_content not in existing_query_contents:
                    unique_queries.append(query)
                    existing_query_contents.add(query_content)
            
            queries_by_endpoint[normalized_endpoint] = unique_queries
            print(f"[REACT API EXTRACTION] Extracted {len(unique_queries)} GraphQL queries for endpoint {normalized_endpoint}")
        
        return queries_by_endpoint
    
    def _looks_like_api_endpoint(self, url: str) -> bool:
        """Vérifie si une URL ressemble à un endpoint API (plus strict que _looks_like_endpoint)"""
        if not url or len(url) < 2:
            return False
        
        # Exclure les fragments, data URIs, mailto, etc.
        if url.startswith('#') or url.startswith('data:') or url.startswith('mailto:') or url.startswith('javascript:'):
            return False
        
        url_lower = url.lower().strip()
        if url_lower.startswith('javascript:'):
            return False
        
        # Extraire le chemin (sans query params et fragment)
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            path = parsed.path
        except:
            path = url.split('?')[0].split('#')[0]
        
        path_lower = path.lower()
        
        # EXCLURE la racine et les chemins vides
        if path == '/' or path == '' or path_lower == '/':
            return False
        
        # EXCLURE les pages HTML
        if path_lower.endswith('.html') or path_lower.endswith('.htm'):
            return False
        
        # Prioriser les patterns d'API - liste étendue
        api_indicators = [
            '/api/', '/v1/', '/v2/', '/v3/', '/v4/', '/v5/',
            '/rest/', '/graphql', '/rpc/', '/rpc',
            '/oauth/', '/auth/', '/login', '/logout', '/token', '/refresh',
            '/webhook/', '/callback/', '/webhooks/', '/callbacks/',
            '/endpoint', '/endpoints', '/service', '/services',
        ]
        if any(indicator in path_lower for indicator in api_indicators):
            return True
        
        # Patterns GraphQL spécifiques
        if '/graphql' in path_lower or path_lower.endswith('/graphql'):
            return True
        
        # Accepter les chemins qui commencent par / et ne sont pas des fichiers statiques
        # MAIS seulement s'ils contiennent des indicateurs d'API ou ont une extension JSON/XML
        if path.startswith('/'):
            excluded_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.css', '.woff', '.ttf', '.eot', '.js', '.html', '.htm', '.map']
            if not any(path_lower.endswith(ext) for ext in excluded_extensions):
                # Vérifier que ce n'est pas un chemin de fichier statique
                last_part = path.split('/')[-1]
                # Accepter seulement si c'est un fichier JSON/XML/TXT ou si le chemin contient des indicateurs d'API
                if '.' in last_part and last_part.split('.')[-1] in ['json', 'xml', 'txt']:
                    return True
                # Si pas d'extension, vérifier qu'il y a des indicateurs d'API dans le chemin
                if '.' not in last_part:
                    # Ne pas accepter les chemins simples sans indicateurs d'API
                    return False
        
        # Accepter les URLs complètes HTTP/HTTPS qui contiennent des patterns d'API
        if url.startswith('http://') or url.startswith('https://'):
            if any(indicator in url_lower for indicator in api_indicators):
                return True
        
        return False
    
    def _extract_api_patterns(self, content: str, base_url: str) -> List[str]:
        """Extrait les patterns d'API depuis n'importe quel contenu"""
        endpoints = []
        
        # Patterns d'API REST - améliorés pour capturer plus de variantes
        api_patterns = [
            r'/api/[^\s"\'<>\)\?]+',  # /api/endpoint (sans query params dans le pattern)
            r'/v\d+/[^\s"\'<>\)\?]+',  # /v1/endpoint
            r'/v\d+\.\d+/[^\s"\'<>\)\?]+',  # /v1.0/endpoint
            r'/rest/[^\s"\'<>\)\?]+',
            r'/graphql(?:\?[^\s"\'<>\)]*)?',  # /graphql avec ou sans query params
            r'/graphql/[^\s"\'<>\)\?]+',
            r'/rpc/[^\s"\'<>\)\?]+',
            r'/webhook/[^\s"\'<>\)\?]+',
            r'/callback/[^\s"\'<>\)\?]+',
            r'/oauth/[^\s"\'<>\)\?]+',  # OAuth endpoints
            r'/auth/[^\s"\'<>\)\?]+',  # Auth endpoints
            r'/login[^\s"\'<>\)]*',  # Login endpoints
            r'/logout[^\s"\'<>\)]*',  # Logout endpoints
            r'/token[^\s"\'<>\)]*',  # Token endpoints
            r'/refresh[^\s"\'<>\)]*',  # Refresh token endpoints
        ]
        
        for pattern in api_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                endpoint = match.group(0)
                if endpoint and len(endpoint) > 1:
                    # Clean the endpoint (remove unwanted trailing characters)
                    endpoint = endpoint.rstrip('.,;:!?')
                    full_url = urljoin(base_url, endpoint)
                    if self._looks_like_api_endpoint(full_url):
                        endpoints.append(full_url)
        
        return endpoints
    
    def _extract_json_urls(self, json_str: str, base_url: str) -> List[str]:
        """Extrait les URLs depuis JSON"""
        urls = []
        
        try:
            data = json.loads(json_str)
            urls.extend(self._extract_urls_from_dict(data, base_url))
        except:
            # Si ce n'est pas du JSON valide, chercher des patterns
            url_pattern = r'https?://[^\s"\'<>\)]+|/[^\s"\'<>\)]+'
            for match in re.finditer(url_pattern, json_str):
                url = match.group(0)
                if self._looks_like_endpoint(url):
                    urls.append(urljoin(base_url, url))
        
        return urls
    
    def _extract_urls_from_dict(self, data: any, base_url: str) -> List[str]:
        """Extrait récursivement les URLs depuis un dictionnaire"""
        urls = []
        
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(key, str) and ('url' in key.lower() or 'endpoint' in key.lower() or 'link' in key.lower()):
                    if isinstance(value, str) and (value.startswith('http') or value.startswith('/')):
                        urls.append(urljoin(base_url, value))
                urls.extend(self._extract_urls_from_dict(value, base_url))
        elif isinstance(data, list):
            for item in data:
                urls.extend(self._extract_urls_from_dict(item, base_url))
        elif isinstance(data, str):
            if (data.startswith('http') or data.startswith('/')) and self._looks_like_endpoint(data):
                urls.append(urljoin(base_url, data))
        
        return urls
    
    def _extract_css_urls(self, css: str, base_url: str) -> List[str]:
        """Extrait les URLs depuis CSS"""
        urls = []
        url_pattern = r'url\(["\']?([^"\'()]+)["\']?\)'
        for match in re.finditer(url_pattern, css, re.IGNORECASE):
            url = match.group(1)
            if url and not url.startswith('data:'):
                urls.append(urljoin(base_url, url))
        return urls
    
    def _extract_generic_urls(self, content: str, base_url: str) -> List[str]:
        """Extrait les URLs génériques depuis n'importe quel contenu"""
        urls = []
        
        # Pattern pour URLs complètes
        full_url_pattern = r'https?://[^\s"\'<>\)]+'
        for match in re.finditer(full_url_pattern, content):
            url = match.group(0)
            if self._is_valid_url(url):
                urls.append(url)
        
        # Pattern pour chemins relatifs/absolus - être plus restrictif
        # Chercher des chemins qui ressemblent à des endpoints valides
        # Exclure les chemins avec trop de caractères spéciaux encodés
        path_pattern = r'["\'](/[^\s"\'<>\)]+)["\']'
        for match in re.finditer(path_pattern, content):
            path = match.group(1)
            if len(path) > 1:
                # Vérifier avant d'ajouter
                if self._looks_like_endpoint(path):
                    # Vérifier aussi que le chemin n'est pas principalement des caractères encodés
                    encoded_ratio = len(re.findall(r'%[0-9A-Fa-f]{2}', path)) / max(len(path), 1)
                    if encoded_ratio < 0.5:  # Moins de 50% de caractères encodés
                        urls.append(urljoin(base_url, path))
        
        return urls
    
    def _looks_like_endpoint(self, url: str) -> bool:
        """Vérifie si une URL ressemble à un endpoint"""
        if not url or len(url) < 2:
            return False
        
        # Exclure les fragments, data URIs, mailto, etc.
        if url.startswith('#') or url.startswith('data:') or url.startswith('mailto:') or url.startswith('javascript:'):
            return False
        
        # Exclure spécifiquement les faux positifs JavaScript courants
        url_lower = url.lower().strip()
        if url_lower in ['javascript:;', 'javascript:void(0)', 'javascript:void(0);', 'javascript:', 'javascript: ']:
            return False
        
        # Inclure les chemins qui ressemblent à des endpoints
        if url.startswith('/') or url.startswith('http'):
            # Exclure les extensions de fichiers communs (sauf .json, .xml, etc.)
            excluded_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.css', '.woff', '.ttf', '.eot']
            if any(url.lower().endswith(ext) for ext in excluded_extensions):
                return False
            
            # Filtrer les chemins qui contiennent trop de caractères spéciaux encodés
            # Un endpoint valide devrait avoir une structure raisonnable
            if url.startswith('/'):
                # Exclure les chemins trop courts (moins de 3 caractères après le /)
                # Sauf pour les chemins racine comme /api, /v1, etc.
                path_part = url.lstrip('/').split('?')[0].split('#')[0]
                if len(path_part) < 2 and path_part not in ['', 'api', 'v1', 'v2', 'v3', 'v4', 'v5']:
                    return False
                
                # Décoder l'URL pour vérifier
                try:
                    from urllib.parse import unquote
                    decoded = unquote(url)
                    
                    # Vérifier si le chemin décodé contient trop de caractères non-ASCII ou spéciaux
                    # Un endpoint valide devrait principalement contenir des caractères alphanumériques,
                    # des tirets, underscores, slashes, points, etc.
                    if len(decoded) > 1:
                        # Exclure les chemins qui commencent par des caractères suspects
                        # Comme /-u, /[QÜV, etc.
                        path_after_slash = decoded.lstrip('/')
                        if path_after_slash:
                            # Vérifier si le premier caractère est suspect (non-alphanumérique sauf _-.)
                            first_char = path_after_slash[0]
                            if not (first_char.isalnum() or first_char in '._-'):
                                return False
                            
                            # Exclure les chemins qui contiennent des caractères de contrôle ou non-printables
                            if any(ord(c) < 32 or (ord(c) > 126 and ord(c) < 160) for c in path_after_slash if c not in '/._-'):
                                # Vérifier si c'est vraiment un caractère de contrôle
                                control_chars = sum(1 for c in path_after_slash if ord(c) < 32 and c not in '\t\n\r')
                                if control_chars > 0:
                                    return False
                        
                        # Compter les caractères "normaux" vs spéciaux
                        normal_chars = sum(1 for c in decoded if c.isalnum() or c in '/._-')
                        special_chars = len(decoded) - normal_chars
                        
                        # Si plus de 30% de caractères spéciaux, c'est probablement un faux positif
                        if special_chars > len(decoded) * 0.3:
                            return False
                except:
                    # Si le décodage échoue, être plus strict
                    pass
            
            # Vérifier que l'URL ne contient pas de séquences suspectes de caractères encodés
            # Par exemple, des patterns comme %XX%XX%XX répétés (plus de 3 fois)
            import re
            encoded_pattern = r'%[0-9A-Fa-f]{2}'
            encoded_matches = len(re.findall(encoded_pattern, url))
            if encoded_matches > 3:
                # Si plus de 3 caractères encodés consécutifs, c'est suspect
                # Sauf si c'est un chemin valide avec quelques caractères encodés
                if re.search(r'%[0-9A-Fa-f]{2}%[0-9A-Fa-f]{2}%[0-9A-Fa-f]{2}%[0-9A-Fa-f]{2}', url):
                    return False
            
            return True
        
        return False
    
    def _extract_js_files_from_html(self, html: str, base_url: str) -> List[str]:
        """Extrait les URLs des fichiers JavaScript depuis le HTML"""
        js_files = []
        
        try:
            from urllib.parse import urlparse
            base_parsed = urlparse(base_url)
            base_domain = base_parsed.netloc.lower()
        except:
            base_domain = None
        
        # Patterns pour les balises <script src="...">
        script_patterns = [
            r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
            r'<script[^>]+src=["\']([^"\']+\.mjs[^"\']*)["\']',
            # Aussi les scripts inline avec type="module" qui peuvent charger d'autres modules
            r'import\s+.*?from\s+["\']([^"\']+\.js[^"\']*)["\']',
        ]
        
        for pattern in script_patterns:
            for match in re.finditer(pattern, html, re.IGNORECASE):
                js_url = match.group(1)
                if js_url and not js_url.startswith('data:') and not js_url.startswith('javascript:'):
                    full_url = urljoin(base_url, js_url)
                    
                    # Filtrer : on veut surtout les fichiers du même domaine (pas les CDN)
                    try:
                        parsed = urlparse(full_url)
                        if parsed.netloc:
                            # Prioriser les fichiers du même domaine
                            if base_domain and parsed.netloc.lower() == base_domain:
                                js_files.append(full_url)
                            # Mais aussi accepter les sous-domaines (ex: assets.example.com)
                            elif base_domain and base_domain in parsed.netloc.lower():
                                js_files.append(full_url)
                            # Et les fichiers relatifs qui deviennent du même domaine
                            elif not parsed.netloc or parsed.netloc.lower() == base_domain:
                                js_files.append(full_url)
                    except:
                        # Si le parsing échoue, ajouter quand même (peut être un chemin relatif)
                        if not js_url.startswith('http'):
                            js_files.append(full_url)
        
        return list(set(js_files))  # Dédupliquer
    
    def _fetch_js_file_async(self, js_url: str, domain: str):
        """Télécharge un fichier JS en arrière-plan et extrait les API"""
        import threading
        import requests
        
        # Vérifier si ce fichier JS a déjà été analysé
        if js_url in self.analyzed_js_files:
            print(f"[REACT API EXTRACTION] JS file already analyzed: {js_url}, skipping")
            return
        
        print(f"[REACT API EXTRACTION] _fetch_js_file_async called for {js_url}")
        
        def fetch_and_extract():
            try:
                # Vérifier à nouveau au début du thread (au cas où plusieurs threads tentent en même temps)
                if js_url in self.analyzed_js_files:
                    print(f"[REACT API EXTRACTION] JS file already analyzed (thread check): {js_url}, skipping")
                    return
                
                print(f"[REACT API EXTRACTION] Thread started, downloading {js_url}")
                # Télécharger le fichier JS
                response = requests.get(js_url, timeout=10, verify=False)
                print(f"[REACT API EXTRACTION] Download response: {response.status_code} for {js_url}")
                if response.status_code == 200:
                    js_content = response.text
                    print(f"[REACT API EXTRACTION] Downloaded {len(js_content)} characters from {js_url}")
                    self.fetched_js_files.add(js_url)
                    
                    # Marquer comme analysé AVANT l'extraction pour éviter les doublons si plusieurs threads
                    self.analyzed_js_files.add(js_url)
                    
                    # Extraire les API React depuis le contenu
                    print(f"[REACT API EXTRACTION] Extracting APIs from {js_url}...")
                    react_apis = self.extract_react_api_endpoints(js_content, js_url)
                    print(f"[REACT API EXTRACTION] Extracted {len(react_apis)} API(s) from {js_url}: {react_apis}")
                    
                    # JS → creds/secrets from fetched JS
                    try:
                        secrets = self._extract_secrets_from_js(js_content, js_url)
                        for s in secrets:
                            if s not in self.discovered_secrets:
                                self.discovered_secrets.append(s)
                    except Exception as e:
                        print(f"[REACT API EXTRACTION] Error extracting secrets from JS: {e}")
                    
                    # Ajouter aux endpoints React
                    for api_url in react_apis:
                        self.react_api_endpoints.add(api_url)
                        print(f"[REACT API EXTRACTION] Added API: {api_url}")
                    
                    print(f"[REACT API EXTRACTION] Total React APIs now: {len(self.react_api_endpoints)}")
                else:
                    print(f"[REACT API EXTRACTION] Failed to download {js_url}: HTTP {response.status_code}")
            except Exception as e:
                import traceback
                print(f"[REACT API EXTRACTION] Error fetching {js_url}: {e}")
                traceback.print_exc()
        
        # Lancer en arrière-plan
        try:
            print(f"[REACT API EXTRACTION] Creating thread for {js_url}")
            thread = threading.Thread(target=fetch_and_extract, daemon=True)
            thread.start()
            print(f"[REACT API EXTRACTION] Thread started for {js_url}")
        except Exception as e:
            import traceback
            print(f"[REACT API EXTRACTION] Error creating thread for {js_url}: {e}")
            traceback.print_exc()
    
    def _normalize_graphql_url(self, url: str) -> str:
        """Normalise une URL GraphQL pour éviter les doublons"""
        if not url:
            return url
        
        try:
            parsed = urlparse(url)
            # Normaliser le chemin : enlever le trailing slash sauf pour la racine
            path = parsed.path.rstrip('/') or '/'
            
            # Pour les endpoints GraphQL, on ignore les query params et fragments
            # car ils ne changent pas l'endpoint lui-même
            normalized = urlunparse((
                parsed.scheme,
                parsed.netloc,
                path,
                parsed.params,  # On garde les params du chemin (rare)
                '',  # On ignore les query params
                ''   # On ignore les fragments
            ))
            
            return normalized
        except Exception as e:
            # Si la normalisation échoue, retourner l'URL originale
            print(f"[REACT API EXTRACTION] Error normalizing URL {url}: {e}")
            return url
    
    def _is_valid_url(self, url: str) -> bool:
        """Vérifie si une URL est valide"""
        if not url:
            return False
        
        # Exclure les faux positifs JavaScript courants
        url_lower = url.lower().strip()
        if url_lower in ['javascript:;', 'javascript:void(0)', 'javascript:void(0);', 'javascript:', 'javascript: ']:
            return False
        
        # Exclure les URLs JavaScript en général
        if url_lower.startswith('javascript:'):
            return False
        
        try:
            parsed = urlparse(url)
            return bool(parsed.netloc) or bool(parsed.path)
        except:
            return False
    
    def get_all_discovered(self) -> Dict[str, List[str]]:
        """Retourne tous les endpoints découverts"""
        # Filtrer les faux positifs JavaScript avant de retourner
        def filter_javascript_false_positives(urls: Set[str]) -> List[str]:
            filtered = []
            for url in urls:
                url_lower = url.lower().strip()
                # Exclure les faux positifs JavaScript
                if url_lower in ['javascript:;', 'javascript:void(0)', 'javascript:void(0);', 'javascript:', 'javascript: ']:
                    continue
                if url_lower.startswith('javascript:'):
                    continue
                filtered.append(url)
            return sorted(filtered)
        
        filtered_endpoints = filter_javascript_false_positives(self.discovered_endpoints)
        filtered_links = filter_javascript_false_positives(self.discovered_links)
        filtered_react_apis = filter_javascript_false_positives(self.react_api_endpoints)
        
        # Inclure aussi les requêtes GraphQL
        graphql_data = {}
        for endpoint, queries in self.graphql_queries.items():
            # Normaliser l'endpoint pour la correspondance
            normalized_endpoint = self._normalize_graphql_url(endpoint)
            # Filtrer les endpoints qui sont dans les React APIs (vérifier les deux versions)
            if endpoint in filtered_react_apis or normalized_endpoint in filtered_react_apis:
                # Utiliser l'endpoint normalisé comme clé pour éviter les doublons
                if normalized_endpoint not in graphql_data:
                    graphql_data[normalized_endpoint] = []
                # Dédupliquer les requêtes par contenu
                existing_contents = {q.get('full_content', q.get('content', '')) for q in graphql_data[normalized_endpoint]}
                for query in queries:
                    query_content = query.get('full_content', query.get('content', ''))
                    if query_content and query_content not in existing_contents:
                        graphql_data[normalized_endpoint].append(query)
                        existing_contents.add(query_content)
        
        return {
            'total': len(filtered_endpoints),
            'endpoints': filtered_endpoints,
            'links': filtered_links,
            'react_api_endpoints': filtered_react_apis,
            'graphql_queries': graphql_data,  # Endpoint -> Liste de requêtes
            'discovered_secrets': list(self.discovered_secrets),
            'ssrf_redirect_candidates': list(self.ssrf_redirect_candidates),
        }
    
    def _save_endpoint_to_db(self, url: str, category: str, flow):
        """Save endpoint to database if workspace is not 'default'"""
        if not self.framework:
            return
        
        try:
            current_workspace = self.framework.get_current_workspace_name()
            if current_workspace == "default":
                return  # Don't save endpoints for default workspace
            
            # Get database session
            db_session = self.framework.get_db_session()
            if not db_session:
                return
            
            from core.models.models import ProxyEndpoint, Workspace
            
            # Get workspace ID
            workspace = db_session.query(Workspace).filter(Workspace.name == current_workspace).first()
            if not workspace:
                return
            
            # Determine endpoint type based on category
            endpoint_type = 'api_endpoint' if category == 'api_endpoints' else \
                          'html_link' if category == 'html_links' else \
                          'javascript_endpoint' if category == 'javascript_endpoints' else \
                          'react_api_endpoint' if category == 'react_api_endpoints' else \
                          'other'
            
            # Check if endpoint already exists
            # Note: Since url is encrypted, we need to load all endpoints and check in memory
            # This is less efficient but necessary for encrypted fields
            existing_endpoints = db_session.query(ProxyEndpoint).filter(
                ProxyEndpoint.workspace_id == workspace.id,
                ProxyEndpoint.endpoint_type == endpoint_type
            ).all()
            
            # Check if URL already exists (decrypt and compare)
            existing = None
            for ep in existing_endpoints:
                if ep.url == url:  # Decryption happens automatically via EncryptedText
                    existing = ep
                    break
            
            if not existing:
                # Create new endpoint
                db_endpoint = ProxyEndpoint(
                    workspace_id=workspace.id,
                    url=url,
                    endpoint_type=endpoint_type,
                    category=category,
                    source_flow_id=flow.id if hasattr(flow, 'id') else None,
                    source_url=flow.request.url if hasattr(flow, 'request') and hasattr(flow.request, 'url') else None
                )
                db_session.add(db_endpoint)
                db_session.commit()
        except Exception as e:
            print(f"[ENDPOINT EXTRACTOR] Error saving endpoint to database: {e}")
            import traceback
            traceback.print_exc()
            try:
                if db_session:
                    db_session.rollback()
            except:
                pass
    
    def load_endpoints_from_db(self, workspace_name: str = None):
        """Load endpoints from database for the current workspace"""
        if not self.framework:
            return
        
        try:
            if workspace_name is None:
                workspace_name = self.framework.get_current_workspace_name()
            
            if workspace_name == "default":
                return  # Don't load endpoints for default workspace
            
            # Get database session
            db_session = self.framework.get_db_session()
            if not db_session:
                return
            
            from core.models.models import ProxyEndpoint, Workspace
            
            # Get workspace ID
            workspace = db_session.query(Workspace).filter(Workspace.name == workspace_name).first()
            if not workspace:
                return
            
            # Load endpoints from database
            db_endpoints = db_session.query(ProxyEndpoint).filter(
                ProxyEndpoint.workspace_id == workspace.id
            ).all()
            
            print(f"[ENDPOINT EXTRACTOR] Loading {len(db_endpoints)} endpoints from database for workspace '{workspace_name}'")
            
            # Clear existing endpoints
            self.discovered_endpoints.clear()
            self.discovered_links.clear()
            self.react_api_endpoints.clear()
            
            # Load endpoints into sets
            for db_endpoint in db_endpoints:
                if db_endpoint.endpoint_type == 'react_api_endpoint':
                    self.react_api_endpoints.add(db_endpoint.url)
                elif db_endpoint.endpoint_type == 'html_link':
                    self.discovered_links.add(db_endpoint.url)
                else:
                    self.discovered_endpoints.add(db_endpoint.url)
            
            print(f"[ENDPOINT EXTRACTOR] Successfully loaded {len(self.discovered_endpoints)} endpoints, {len(self.discovered_links)} links, {len(self.react_api_endpoints)} React APIs from database")
        except Exception as e:
            print(f"[ENDPOINT EXTRACTOR] Error loading endpoints from database: {e}")
            import traceback
            traceback.print_exc()

# Instance globale
endpoint_extractor = EndpointExtractor()

