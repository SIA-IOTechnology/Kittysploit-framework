#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Technology Detector - Détecte automatiquement les technologies utilisées
"""

import re
from typing import Dict, List, Set

from mitmproxy import http

class TechnologyDetector:
    """Détecte les technologies, frameworks, CMS, etc. à partir des requêtes/réponses"""
    
    def __init__(self):
        """Initialise le détecteur avec un cache par domaine"""
        # Cache par domaine pour améliorer les performances (30x plus rapide)
        self.domain_cache: Dict[str, Dict[str, List[str]]] = {}
        # Précompile toutes les regex pour accélérer la détection
        self.compiled_patterns = self._compile_patterns()
        self.compiled_cookie_patterns = self._compile_patterns(cookie=True)
    
    # Signatures de technologies (ordre de priorité important)
    SIGNATURES = {
        'frameworks': {
            # Backend frameworks (priorité haute)
            'Flask': [
                r'flask',
                r'werkzeug',
                r'X-Powered-By:\s*Flask',
                r'Server:\s*Werkzeug',
            ],
            'Django': [
                r'django',
                r'X-Django',
                r'csrftoken',
                r'sessionid',
            ],
            'Express.js': [
                r'express',
                r'X-Powered-By:\s*Express',
            ],
            'FastAPI': [
                r'fastapi',
                r'X-Powered-By:\s*FastAPI',
            ],
            'Laravel': [
                r'laravel_session',
                r'X-Powered-By:\s*Laravel',
                r'X-Laravel',
            ],
            'Ruby on Rails': [
                r'_rails_session',
                r'Ruby',
                r'X-Runtime',
            ],
            'Spring Boot': [
                r'X-Application-Context',
                r'springframework',
            ],
            'AspNetCore': [
                r'\.AspNetCore\.',
                r'X-Powered-By:\s*ASP\.NET',
            ],
            # Frontend frameworks (low priority - require more specific patterns)
            'React': [
                r'__REACT_DEVTOOLS',
                r'react-dom',
                r'React\.createElement',
                r'data-reactroot',
            ],
            'Vue.js': [
                r'__VUE__',
                r'v-if=',
                r'v-for=',
                r'vue\.js',
            ],
            'Angular': [
                r'ng-app',
                r'ng-controller',
                r'@angular',
                r'angular\.js',
            ],
            'jQuery': [
                r'jquery',
                r'\$\.ajax',
                r'jQuery\.',
            ],
            'Bootstrap': [
                r'bootstrap',
                r'\.container-fluid',
                r'btn btn-',
            ],
            'Next.js': [
                r'__next',
                r'_next/static',
                r'next-data',
                r'X-Powered-By:\s*Next\.js',
            ],
            'Nuxt.js': [
                r'__NUXT__',
                r'nuxt',
                r'_nuxt/',
                r'X-Powered-By:\s*Nuxt\.js',
            ],
            'Svelte': [
                r'svelte',
                r'data-sveltekit-',
                r'sveltekit',
            ],
            'SolidJS': [
                r'solid-js',
                r'data-solid-start',
                r'solidStart',
            ],
            'Remix': [
                r'data-remix-run',
                r'remix:',
                r'X-Powered-By:\s*Remix',
            ],
        },
        'cms': {
            'WordPress': [
                r'wp-content',
                r'wp-includes',
                r'wordpress',
                r'/wp-admin/',
            ],
            'Drupal': [
                r'drupal',
                r'/sites/default/',
            ],
            'Joomla': [
                r'joomla',
                r'/administrator/',
            ],
            'Magento': [
                r'magento',
                r'/skin/',
            ],
            'Strapi': [
                r'strapi',
                r'X-Powered-By:\s*Strapi',
            ],
            'Contentful': [
                r'contentful',
                r'cdn\.contentful\.com',
            ],
            'Sanity': [
                r'sanity',
                r'sanity\.io',
                r'cdn\.sanity\.io',
            ],
        },
        'commerce': {
            'Shopify': [
                r'x-shopify',
                r'Server:\s*Shopify',
                r'shopify\.com',
                r'\.myshopify\.com',
            ],
            'WooCommerce': [
                r'woocommerce',
                r'wc-api',
                r'woo-commerce',
            ],
        },
        'analytics': {
            'Google Analytics': [
                r'google-analytics\.com/analytics\.js',
                r'www\.googletagmanager\.com/gtag/js',
                r'gtag\(',
                r'ga\(',
            ],
            'Mixpanel': [
                r'mixpanel',
                r'cdn\.mxpnl\.com',
                r'api\.mixpanel\.com',
            ],
            'Segment': [
                r'cdn\.segment\.com',
                r'analytics\.js',
                r'segment\.com',
            ],
        },
        'servers': {
            'Apache': [
                r'Apache',
                r'Server:\s*Apache',
            ],
            'Nginx': [
                r'nginx',
                r'Server:\s*nginx',
            ],
            'IIS': [
                r'Microsoft-IIS',
                r'Server:\s*Microsoft-IIS',
            ],
        },
        'languages': {
            'PHP': [
                r'X-Powered-By:\s*PHP',
                r'PHPSESSID',
                r'\.php\?',
                r'\.php"',
            ],
            'ASP.NET': [
                r'X-AspNet-Version',
                r'ASP\.NET',
                r'\.aspx',
                r'ViewState',
            ],
            'Python': [
                r'X-Powered-By:\s*Python',
                r'werkzeug',
                r'gunicorn',
                r'uwsgi',
            ],
            'Java': [
                r'JSESSIONID',
                r'\.jsp',
                r'X-Powered-By:\s*Java',
                r'Tomcat',
            ],
            'Node.js': [
                r'X-Powered-By:\s*Express',
                r'Server:\s*.*node',
                r'X-Powered-By:\s*.*node',
                # Patterns plus stricts pour éviter les faux positifs
                r'process\.env\.NODE_ENV',
                r'require\(["\']node:',
                r'__dirname',
                r'__filename',
            ],
        },
        'security': {
            'Cloudflare': [
                r'cf-ray',
                r'cloudflare',
            ],
            'AWS': [
                r'x-amz-',
                r'amazonaws',
            ],
            'WAF': [
                r'x-waf',
                r'waf',
            ],
            'Fastly': [
                r'fastly',
                r'via:\s*.*fastly',
            ],
            'Akamai': [
                r'akamai',
                r'ghost',
            ],
            'Firebase Hosting': [
                r'x-firebase',
                r'firebase',
            ],
            'Vercel': [
                r'server:\s*vercel',
                r'x-vercel-id',
            ],
            'Netlify': [
                r'x-nf-request-id',
                r'netlify',
            ],
            'Heroku': [
                r'server:\s*heroku',
                r'herokuapp\.com',
                r'x-heroku-queue-wait-time',
            ],
            'Railway': [
                r'railway\.app',
                r'x-railway-region',
            ],
            'Render': [
                r'ondigitalocean',
                r'onrender\.com',
                r'x-render',
            ],
        },
    }

    # Signatures basées sur les cookies (plus fiables pour certaines stacks)
    COOKIE_SIGNATURES = {
        'frameworks': {
            'Django': [
                r'^sessionid$',
                r'^csrftoken$',
            ],
            'Laravel': [
                r'^laravel_session$',
            ],
            'Ruby on Rails': [
                r'_rails_session',
            ],
            'Express.js': [
                r'^connect\.sid$',
                r'^express:sess',
            ],
            'Next.js': [
                r'^next-auth\.session-token',
                r'^__Secure-next-auth\.session-token',
                r'^next-auth\.csrf-token',
            ],
            'Nuxt.js': [
                r'^nuxt-session',
            ],
        },
        'cms': {
            'WordPress': [
                r'^wordpress_',
                r'^wp-settings-',
                r'^wp-postpass_',
                r'^wordpress_logged_in_',
            ],
            'WooCommerce': [
                r'^woocommerce_',
                r'^wp_woocommerce_session_',
            ],
        },
        'commerce': {
            'Shopify': [
                r'^_shopify_',
                r'^_shopify_sa_',
                r'^_shopify_y$',
                r'^_shopify_s$',
                r'^_shopify_fs$',
                r'^_shopify_tw$',
            ],
        },
        'analytics': {
            'Google Analytics': [
                r'^_ga$',
                r'^_gid$',
                r'^_gat',
                r'^_gcl_',
            ],
            'Mixpanel': [
                r'^mp_',
            ],
            'Segment': [
                r'^ajs_anonymous_id$',
                r'^ajs_user_id$',
                r'^ajs_group_id$',
            ],
        },
        'languages': {
            'ASP.NET': [
                r'^ASP\.NET_SessionId$',
            ],
            'Java': [
                r'^JSESSIONID$',
            ],
            'PHP': [
                r'^PHPSESSID$',
            ],
        },
    }

    def _compile_patterns(self, cookie: bool = False) -> Dict[str, Dict[str, List[re.Pattern]]]:
        """Pré-compile tous les patterns regex (signatures et cookies)"""
        source = self.COOKIE_SIGNATURES if cookie else self.SIGNATURES
        compiled: Dict[str, Dict[str, List[re.Pattern]]] = {}
        for category, technologies in source.items():
            compiled[category] = {}
            for tech_name, patterns in technologies.items():
                compiled[category][tech_name] = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
        return compiled
    
    def detect(self, flow) -> Dict[str, List[str]]:
        """Détecte les technologies à partir d'un flow"""
        detected = {
            'frameworks': [],
            'cms': [],
            'commerce': [],
            'analytics': [],
            'servers': [],
            'languages': [],
            'security': [],
        }
        
        # Extraire le hostname pour le cache
        hostname = flow.request.host
        
        # Déterminer si c'est une requête principale (HTML) ou une ressource externe
        is_main_request = self._is_main_request(flow)
        
        # Vérifier le cache pour les requêtes principales (technologies d'un domaine ne changent pas)
        if is_main_request and hostname in self.domain_cache:
            return self.domain_cache[hostname].copy()
        
        # Analyser la requête
        request_text = self._get_request_text(flow)
        
        # Analyser la réponse
        response_text = self._get_response_text(flow)
        
        # Extraire les headers de réponse pour une détection plus précise
        response_headers = {}
        if flow.response:
            response_headers = {k.lower(): v.lower() for k, v in flow.response.headers.items()}
        
        # Extraire les noms de cookies (requête + réponse)
        cookie_names = self._extract_cookie_names(flow)
        
        # Extraire le contenu HTML/JS séparément (safe: évite BadGzipFile si Content-Encoding gzip mais corps brut)
        html_content = ""
        js_content = ""
        content_type = ""
        if flow.response:
            try:
                from .flow_utils import safe_response_content
                res_content = safe_response_content(flow.response)
                if res_content:
                    content = res_content.decode('utf-8', errors='ignore')
                    content_type = flow.response.headers.get('Content-Type', '').lower()
                    if 'text/html' in content_type:
                        html_content = content
                    elif 'javascript' in content_type or 'application/javascript' in content_type:
                        js_content = content
            except Exception:
                pass
        
        # Système de scores pour réduire les faux positifs
        scores = {cat: {} for cat in detected.keys()}
        
        # Détecter chaque catégorie avec système de scores
        for category, technologies in self.compiled_patterns.items():
            for tech_name, patterns in technologies.items():
                for pattern in patterns:
                    match_found = False
                    
                    # Vérifier dans les headers d'abord (plus fiable, score plus élevé)
                    if category in ['servers', 'languages', 'frameworks'] and response_headers:
                        for header_name, header_value in response_headers.items():
                            if pattern.search(f"{header_name}: {header_value}"):
                                match_found = True
                                # Headers = score +2 (plus fiable)
                                scores[category].setdefault(tech_name, 0)
                                scores[category][tech_name] += 2
                                break
                    
                    # Check in HTML/JS content according to type
                    if not match_found:
                        if tech_name in ['React', 'Vue.js', 'Angular', 'jQuery', 'Bootstrap']:
                            # Frontend frameworks: ONLY on main requests (HTML)
                            if is_main_request and html_content and pattern.search(html_content):
                                # Check that it's not a false positive
                                if self._is_valid_frontend_detection(tech_name, html_content, pattern.pattern):
                                    match_found = True
                                    scores[category].setdefault(tech_name, 0)
                                    scores[category][tech_name] += 1
                        else:
                            # Backend/others: search in content
                            if pattern.search(response_text):
                                # Check that it's not a false positive
                                if self._is_valid_detection(pattern.pattern, response_text, tech_name):
                                    match_found = True
                                    # Node.js requires a higher score because often false positive
                                    score_increment = 2 if tech_name == 'Node.js' else 1
                                    scores[category].setdefault(tech_name, 0)
                                    scores[category][tech_name] += score_increment

        # Détection spécifique basée sur les cookies
        if cookie_names:
            for category, technologies in self.compiled_cookie_patterns.items():
                for tech_name, patterns in technologies.items():
                    for pattern in patterns:
                        if any(pattern.search(cookie) for cookie in cookie_names):
                            scores[category].setdefault(tech_name, 0)
                            # Les cookies sont assez fiables : +2
                            scores[category][tech_name] += 2
        
        # Détection basée sur heuristiques DOM (hautement fiable, score élevé)
        frontend_dom = self._detect_dom_features(html_content)
        for item in frontend_dom:
            # La détection DOM est très fiable, donc score élevé
            scores['frameworks'].setdefault(item, 0)
            scores['frameworks'][item] += 3
        
        # Ne garder que les technologies avec score >= 2 (score >= 3 pour Node.js pour éviter faux positifs)
        for category, tech_scores in scores.items():
            for tech, score in tech_scores.items():
                # Node.js nécessite un score plus élevé pour éviter les faux positifs
                min_score = 3 if tech == 'Node.js' else 2
                if score >= min_score:
                    if tech not in detected[category]:
                        detected[category].append(tech)
        
        # Appliquer des règles de priorité pour éviter les conflits
        detected = self._apply_priority_rules(detected, response_headers, html_content)
        
        # Mettre en cache le résultat pour les requêtes principales (améliore les performances)
        if is_main_request:
            self.domain_cache[hostname] = detected.copy()
        
        return detected
    
    def _is_main_request(self, flow) -> bool:
        """Détermine si c'est une requête principale (page HTML) ou une ressource externe"""
        if not flow.response:
            return False
        
        # Vérifier le Content-Type
        content_type = flow.response.headers.get('Content-Type', '').lower()
        if 'text/html' in content_type:
            return True
        
        # Vérifier l'extension du fichier dans l'URL
        path = flow.request.path.lower()
        # Ignorer les ressources statiques
        static_extensions = ['.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', 
                            '.woff', '.woff2', '.ttf', '.eot', '.json', '.xml', '.pdf']
        for ext in static_extensions:
            if path.endswith(ext):
                return False
        
        # Si c'est une requête vers la racine ou sans extension, c'est probablement une page principale
        if path == '/' or path.endswith('/') or '.' not in path.split('/')[-1]:
            return True
        
        # Par défaut, considérer comme ressource externe si ce n'est pas clairement HTML
        return False
    
    def _detect_dom_features(self, html: str) -> Set[str]:
        """Détecte les frameworks frontend via des heuristiques DOM (hautement fiable)"""
        found = set()
        if not html:
            return found
        
        # React typique
        if 'id="root"' in html or 'id="app"' in html:
            found.add('React')
        
        # Vue composition API / templates
        if 'id="vue"' in html or 'v-cloak' in html:
            found.add('Vue.js')
        
        # Angular runtime bootstrap
        if 'ng-version="' in html:
            found.add('Angular')

        # Next.js renders into __next container
        if 'id="__next"' in html:
            found.add('Next.js')

        # Nuxt apps often render into __nuxt container
        if 'id="__nuxt"' in html or '__NUXT__' in html:
            found.add('Nuxt.js')

        # SvelteKit adds data-sveltekit markers
        if 'data-sveltekit-' in html:
            found.add('Svelte')
        
        return found
    
    def _is_valid_detection(self, pattern: str, text: str, tech_name: str) -> bool:
        """Vérifie si une détection est valide (évite les faux positifs)"""
        # Ignorer les commentaires HTML/JS
        text = re.sub(r'<!--.*?-->', '', text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'//.*?$|/\*.*?\*/', '', text, flags=re.MULTILINE | re.DOTALL)
        
        # Patterns qui doivent être évités (faux positifs communs)
        false_positive_patterns = {
            'React': [
                r'react\s*=',  # Variable nommée "react"
                r'react\s*:',  # Propriété nommée "react"
            ],
            'Angular': [
                r'angular\s*=',  # Variable
                r'angular\s*:',  # Propriété
            ],
            'Node.js': [
                # Éviter les faux positifs sur sites statiques
                r'["\'].*node\.js.*["\']',  # Chaîne de caractères contenant "node.js"
                r'["\'].*npm.*["\']',  # Chaîne de caractères contenant "npm"
                r'node\.js\s*=',  # Variable nommée "node.js"
                r'node\.js\s*:',  # Propriété nommée "node.js"
                r'npm\s*=',  # Variable nommée "npm"
                r'npm\s*:',  # Propriété nommée "npm"
            ],
        }
        
        # Vérifier les faux positifs
        if tech_name in false_positive_patterns:
            for fp_pattern in false_positive_patterns[tech_name]:
                if re.search(fp_pattern, text, re.IGNORECASE):
                    return False
        
        # Règles spéciales pour Node.js : nécessite des preuves backend
        if tech_name == 'Node.js':
            # Si on trouve "node.js" ou "npm" dans le contenu, vérifier qu'il y a des preuves backend
            if re.search(r'node\.js|npm', text, re.IGNORECASE):
                # Vérifier qu'il y a des patterns backend (pas juste du texte)
                backend_indicators = [
                    r'process\.env',
                    r'require\(["\']node:',
                    r'__dirname',
                    r'__filename',
                    r'module\.exports',
                    r'exports\.',
                ]
                has_backend_indicator = any(re.search(indicator, text, re.IGNORECASE) for indicator in backend_indicators)
                if not has_backend_indicator:
                    # Si c'est juste "node.js" ou "npm" sans indicateurs backend, c'est probablement un faux positif
                    return False
        
        return True
    
    def _is_valid_frontend_detection(self, tech_name: str, content: str, pattern: str) -> bool:
        """Vérifie si une détection frontend est valide (patterns stricts)"""
        # Retirer les commentaires
        content = re.sub(r'<!--.*?-->', '', content, flags=re.DOTALL | re.IGNORECASE)
        content = re.sub(r'//.*?$|/\*.*?\*/', '', content, flags=re.MULTILINE | re.DOTALL)
        
        # Patterns stricts pour chaque framework
        strict_patterns = {
            'React': [
                r'__REACT_DEVTOOLS',
                r'React\.createElement',
                r'data-reactroot',
                r'react-dom',
                r'from\s+["\']react["\']',
            ],
            'Angular': [
                r'ng-app',
                r'ng-controller',
                r'@angular',
                r'angular\.js',
                r'angular\.module',
            ],
            'Vue.js': [
                r'__VUE__',
                r'v-if=',
                r'v-for=',
                r'new\s+Vue\(',
            ],
            'jQuery': [
                r'\$\.ajax',
                r'jQuery\.',
                r'\$\(document\)',
            ],
        }
        
        # Si on a des patterns stricts pour ce framework, les utiliser
        if tech_name in strict_patterns:
            for strict_pattern in strict_patterns[tech_name]:
                if re.search(strict_pattern, content, re.IGNORECASE):
                    return True
            # Si aucun pattern strict ne match, c'est probablement un faux positif
            return False
        
        # Pour les autres, accepter si le pattern match
        return True
    
    def _apply_priority_rules(self, detected: Dict[str, List[str]], headers: Dict, html: str) -> Dict[str, List[str]]:
        """Applique des règles de priorité pour éviter les conflits"""
        # Si Flask est détecté, retirer React/Angular sauf si vraiment présent
        if 'Flask' in detected['frameworks']:
            # Vérifier si React/Angular sont vraiment présents (pas juste le mot dans un commentaire)
            if 'React' in detected['frameworks']:
                if not (re.search(r'__REACT_DEVTOOLS|React\.createElement|data-reactroot', html, re.IGNORECASE) if html else False):
                    detected['frameworks'].remove('React')
            
            if 'Angular' in detected['frameworks']:
                if not (re.search(r'ng-app|ng-controller|@angular', html, re.IGNORECASE) if html else False):
                    detected['frameworks'].remove('Angular')
        
        # Si Django est détecté, retirer Flask (incompatibles)
        if 'Django' in detected['frameworks'] and 'Flask' in detected['frameworks']:
            # Django a priorité si csrftoken est présent
            if 'csrftoken' in str(headers).lower():
                detected['frameworks'].remove('Flask')
            else:
                detected['frameworks'].remove('Django')
        
        # Si Python est détecté via Flask/Django, ne pas ajouter "Python" séparément
        if 'Flask' in detected['frameworks'] or 'Django' in detected['frameworks']:
            if 'Python' in detected['languages']:
                detected['languages'].remove('Python')
        
        # Vérifier si c'est un site statique (HTML/JS/CSS uniquement)
        # Si oui, retirer Node.js sauf si on a des preuves backend solides
        if 'Node.js' in detected['languages']:
            # Vérifier les preuves backend solides
            has_express_header = any('express' in str(v).lower() for v in headers.values())
            has_node_header = any('node' in str(k).lower() or 'node' in str(v).lower() for k, v in headers.items())
            has_backend_code = False
            if html:
                # Chercher des patterns backend réels dans le code
                backend_patterns = [
                    r'process\.env\.',
                    r'require\(["\']node:',
                    r'__dirname',
                    r'__filename',
                    r'module\.exports\s*=',
                    r'exports\.\w+\s*=',
                ]
                has_backend_code = any(re.search(pattern, html, re.IGNORECASE) for pattern in backend_patterns)
            
            # Si pas de preuves backend solides, retirer Node.js (probablement site statique)
            if not (has_express_header or has_node_header or has_backend_code):
                detected['languages'].remove('Node.js')
        
        # Si Node.js/Express est détecté, retirer React/Angular sauf si vraiment présents
        if 'Express.js' in detected['frameworks'] or 'Node.js' in detected['languages']:
            if 'React' in detected['frameworks']:
                if not (re.search(r'__REACT_DEVTOOLS|React\.createElement', html, re.IGNORECASE) if html else False):
                    detected['frameworks'].remove('React')
        
        return detected
    
    def _get_request_text(self, flow) -> str:
        """Extrait le texte de la requête"""
        text = f"{flow.request.method} {flow.request.url}\n"
        text += "\n".join([f"{k}: {v}" for k, v in flow.request.headers.items()])
        if flow.request.content:
            try:
                text += "\n" + flow.request.content.decode('utf-8', errors='ignore')
            except:
                pass
        return text
    
    def _get_response_text(self, flow) -> str:
        """Extrait le texte de la réponse"""
        if not flow.response:
            return ""
        try:
            from .flow_utils import safe_response_content
            res_content = safe_response_content(flow.response)
        except Exception:
            res_content = b""
        text = f"HTTP/{flow.response.http_version} {flow.response.status_code}\n"
        text += "\n".join([f"{k}: {v}" for k, v in flow.response.headers.items()])
        if res_content:
            text += "\n" + res_content.decode('utf-8', errors='ignore')
        return text

    def _extract_cookie_names(self, flow) -> Set[str]:
        """Retourne l'ensemble des noms de cookies vus dans la requête et la réponse"""
        names: Set[str] = set()

        # Cookies côté requête (envoyés par le client)
        try:
            for cookie_name in flow.request.cookies.keys():
                names.add(str(cookie_name).lower())
        except Exception:
            pass

        # Cookies côté réponse (définis par le serveur)
        if flow.response:
            try:
                for cookie_name in flow.response.cookies.keys():
                    names.add(str(cookie_name).lower())
            except Exception:
                pass

            # Par sécurité, parser aussi les headers Set-Cookie bruts si disponibles
            try:
                set_cookie_headers = []
                if hasattr(flow.response.headers, "get_all"):
                    set_cookie_headers = flow.response.headers.get_all("set-cookie")
                else:
                    header_val = flow.response.headers.get("set-cookie")
                    if header_val:
                        set_cookie_headers = [header_val]
                for header_val in set_cookie_headers or []:
                    parts = header_val.split(";")[0]
                    if "=" in parts:
                        cookie_name = parts.split("=", 1)[0].strip().lower()
                        if cookie_name:
                            names.add(cookie_name)
            except Exception:
                pass

        return names
    
    def get_summary(self, detected: Dict[str, List[str]]) -> str:
        """Retourne un résumé des technologies détectées"""
        all_techs = []
        for category, techs in detected.items():
            all_techs.extend(techs)
        
        if not all_techs:
            return "Aucune technologie détectée"
        
        return ", ".join(all_techs)

# Instance globale
tech_detector = TechnologyDetector()

