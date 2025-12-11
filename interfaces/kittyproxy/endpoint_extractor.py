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
    
    def __init__(self):
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
        
        try:
            content = flow.response.content.decode('utf-8', errors='ignore')
            content_type = flow.response.headers.get('Content-Type', '').lower()
            base_url = flow.request.url
            
            # Vérifier si ce flow a déjà été analysé
            # Utiliser l'URL de la requête comme identifiant unique
            flow_id = base_url
            if flow_id in self.analyzed_flows:
                # Flow déjà analysé, retourner les endpoints mis en cache
                if flow_id in self.cached_endpoints:
                    print(f"[ENDPOINT EXTRACTION] Flow {flow_id} already analyzed, returning {sum(len(urls) for urls in self.cached_endpoints[flow_id].values())} cached endpoints")
                    return self.cached_endpoints[flow_id].copy()
                else:
                    print(f"[ENDPOINT EXTRACTION] Flow {flow_id} already analyzed but no cache found, returning empty")
                    return endpoints
            
            # Marquer ce flow comme analysé AVANT l'extraction pour éviter les doublons
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
            if flow.request:
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
        
        # Patterns pour les appels API avec des variables (ex: `${API_BASE}/users`)
        # NOTE: On exclut ces patterns car ils génèrent trop de faux positifs
        # api_template_patterns = [
        #     r'`\$\{[^}]+\}(/[^`]+)`',  # Template literals avec variables
        #     r'["\']\$\{[^}]+\}(/[^"\']+)["\']',  # Template strings dans quotes
        # ]
        api_template_patterns = []  # Désactivé pour éviter les faux positifs
        
        # Patterns pour les objets de configuration API
        api_config_patterns = [
            r'(?:baseURL|base_url|apiUrl|api_url|endpoint|url):\s*["\']([^"\']+)["\']',
            r'(?:baseURL|base_url|apiUrl|api_url|endpoint|url):\s*`([^`]+)`',
        ]
        
        # Patterns pour les appels API dans les hooks React Query / SWR
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
            # api_template_patterns exclu pour éviter les faux positifs
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
                if endpoint and '${' not in endpoint:  # Exclure les template literals avec variables
                    # Nettoyer l'endpoint
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
        
        # Si aucun endpoint spécifique n'est trouvé mais que GraphQL est présent,
        # essayer de deviner l'endpoint commun
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
            # Récupérer le contenu du template literal (groupe 1 ou 2 selon le pattern)
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
                    # Nettoyer la requête (déjà dans le template literal, pas besoin de retirer les backticks)
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
                # Nettoyer la requête
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
        
        # Essayer de trouver l'endpoint GraphQL associé
        # Si on a trouvé des requêtes, chercher l'endpoint
        if all_queries:
            # Chercher l'endpoint GraphQL dans le code autour des requêtes
            graphql_endpoint = None
            
            # Patterns pour trouver l'endpoint
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
                    # Nettoyer l'endpoint (enlever les caractères de fin indésirables)
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
        }

# Instance globale
endpoint_extractor = EndpointExtractor()

