#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
import re
import urllib.parse
import json


class Module(Auxiliary, Http_client):

    __info__ = {
        'name': 'SPA Scanner',
        'description': 'Scans for vulnerabilities and misconfigurations in Single Page Applications including exposed API endpoints, authentication issues, and client-side vulnerabilities',
        'author': 'KittySploit Team',
        'tags': ['web', 'spa', 'scanner', 'security', 'api'],
        'references': [
            'https://owasp.org/www-project-web-security-testing-guide/',
            'https://portswigger.net/web-security',
        ],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 2,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals', 'endpoints', 'params'],
        'cost': 1.0,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
         'min_params': 0,
         'tech_hints_any': [],
         'tech_hints_all': [],
         'specializations_any': [],
         'risk_signals_any': [],
         'auth_session': False,
         'capabilities_any': [],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'ssrf_primitive', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    # Common SPA frameworks
    SPA_FRAMEWORKS = ['react', 'angular', 'vue', 'ember', 'backbone', 'knockout']

    # Common API endpoints in SPAs
    API_ENDPOINTS = [
        '/api',
        '/api/v1',
        '/api/v2',
        '/rest',
        '/rest/api',
        '/graphql',
        '/auth',
        '/auth/login',
        '/auth/register',
        '/auth/token',
        '/auth/refresh',
        '/user',
        '/users',
        '/profile',
        '/admin',
        '/config',
        '/settings',
    ]

    # Sensitive files that might be exposed
    SENSITIVE_FILES = [
        '/.env',
        '/.env.local',
        '/.env.production',
        '/.env.development',
        '/config.js',
        '/config.json',
        '/settings.js',
        '/settings.json',
        '/package.json',
        '/package-lock.json',
        '/yarn.lock',
        '/.git/config',
        '/.git/HEAD',
        '/.gitignore',
        '/webpack.config.js',
        '/.htaccess',
        '/web.config',
    ]

    FRAMEWORK_STRONG_MARKERS = {
        "React": [
            r"data-reactroot\b",
            r"data-reactid\b",
            r"__react(?:fiber|props|container)?\b",
            r"_reactrootcontainer",
            r"\breact-dom\b",
            r"\breact(?:\.production|\.development|\.min){0,2}\.js\b",
            r"\breact/jsx-runtime\b",
            r"__next_data__",
            r"id=[\"']__next[\"']",
            r"id=[\"']___gatsby[\"']",
            r"gatsby-",
        ],
        "Angular": [
            r"\bng-version\b",
            r"\bng-app\b",
            r"\bng-controller\b",
            r"\bng-view\b",
            r"_ngcontent-",
            r"angular(?:\.min)?\.js",
            r"platform-browser",
            r"zone\.js",
        ],
        "Vue.js": [
            r"\bdata-v-[a-f0-9]{4,}",
            r"\bdata-v-app\b",
            r"__vue__",
            r"\bv-(?:if|for|bind|model|show|on)\b",
            r"vue(?:\.runtime)?(?:\.global|\.esm-browser|\.min)?\.js",
            r"__nuxt__",
            r"id=[\"']__nuxt[\"']",
        ],
        "Ember.js": [
            r"ember-application",
            r"ember-view",
            r"ember(?:\.min)?\.js",
            r"data-ember-",
        ],
        "Backbone.js": [
            r"backbone(?:\.min)?\.js",
            r"backbone\.history",
            r"backbone\.router",
        ],
        "Knockout.js": [
            r"knockout(?:\.min)?\.js",
            r"\bko\.applybindings\b",
            r"data-bind=[\"']",
        ],
    }

    GENERIC_SPA_MARKERS = [
        r"id=[\"'](?:app|root|__next|__nuxt|___gatsby)[\"']",
        r"/(?:static/js|assets)/[^\"']+\.(?:js|mjs)",
        r"(?:app|main|bundle|chunk|runtime)[._-][^\"']*\.(?:js|mjs)",
        r"webpackjsonp",
        r"window\.__initial_state__",
        r"vite/client",
        r"type=[\"']module[\"'][^>]+src=[\"'][^\"']+\.(?:js|mjs)",
    ]

    DOM_XSS_SOURCE_PATTERNS = [
        r"location\.(?:hash|search|href|pathname)",
        r"document\.url",
        r"document\.location",
        r"document\.referrer",
        r"window\.name",
        r"postmessage\s*\(",
    ]

    DOM_XSS_SINK_PATTERNS = [
        r"innerhtml\s*=",
        r"outerhtml\s*=",
        r"document\.write\s*\(",
        r"document\.writeln\s*\(",
        r"insertadjacenthtml\s*\(",
        r"eval\s*\(",
        r"new\s+function\s*\(",
        r"settimeout\s*\(\s*[^,]*[\"'`]",
        r"setinterval\s*\(\s*[^,]*[\"'`]",
        r"\.srcdoc\s*=",
    ]

    def _detect_framework_from_text(self, text):
        """
        Return a framework only when strong implementation markers are present.

        Plain words such as "react", "angular" or "vue" are intentionally ignored:
        they are too common in page text, SEO copy, third-party scripts and CSS class
        names, which caused false positives on normal sites.
        """
        if not text:
            return None

        normalized = text.lower()
        for framework, markers in self.FRAMEWORK_STRONG_MARKERS.items():
            evidence = sum(1 for marker in markers if re.search(marker, normalized, re.IGNORECASE))
            if evidence >= 1:
                return framework
        return None

    def _extract_script_paths(self, html):
        paths = []
        if not html:
            return paths

        target_host = str(getattr(self, "target", "") or "").lower().split(":", 1)[0]
        for match in re.finditer(r"<script\b[^>]*\bsrc=[\"']([^\"']+)[\"']", html, re.IGNORECASE):
            src = match.group(1).strip()
            if not src or src.startswith(("data:", "javascript:", "#")):
                continue

            parsed = urllib.parse.urlparse(src)
            if parsed.netloc:
                script_host = parsed.hostname.lower() if parsed.hostname else ""
                if target_host and script_host and script_host != target_host:
                    continue

            path = parsed.path or "/"
            if not path.lower().endswith((".js", ".mjs")):
                continue
            if parsed.query:
                path = f"{path}?{parsed.query}"
            if path not in paths:
                paths.append(path)
            if len(paths) >= 5:
                break
        return paths

    def _fetch_script_corpus(self, html):
        corpus = []
        for path in self._extract_script_paths(html):
            try:
                response = self.http_request(
                    method="GET",
                    path=path,
                    allow_redirects=True,
                    timeout=6,
                )
                if not response or response.status_code >= 400:
                    continue
                content_type = response.headers.get("Content-Type", "").lower()
                if content_type and not any(token in content_type for token in ("javascript", "ecmascript", "text/plain", "octet-stream")):
                    continue
                corpus.append(response.text[:200000])
            except Exception:
                continue
        return "\n".join(corpus)

    def _looks_like_spa_shell(self, html, script_corpus=""):
        text = f"{html or ''}\n{script_corpus or ''}".lower()
        if not text:
            return False
        evidence = sum(1 for marker in self.GENERIC_SPA_MARKERS if re.search(marker, text, re.IGNORECASE))
        return evidence >= 2

    def analyze_dom_xss(self, html, script_corpus=""):
        corpus = f"{html or ''}\n{script_corpus or ''}"
        if not corpus:
            return {
                "suspected": False,
                "sources": [],
                "sinks": [],
                "evidence_score": 0,
            }
        normalized = corpus.lower()
        sources = [
            p for p in self.DOM_XSS_SOURCE_PATTERNS
            if re.search(p, normalized, re.IGNORECASE)
        ]
        sinks = [
            p for p in self.DOM_XSS_SINK_PATTERNS
            if re.search(p, normalized, re.IGNORECASE)
        ]
        score = (len(sources) * 2) + (len(sinks) * 3)
        return {
            "suspected": bool(sources and sinks),
            "sources": sources[:8],
            "sinks": sinks[:8],
            "evidence_score": score,
        }

    def check(self):
        """
        Check if the target is accessible and might be a SPA
        """
        try:
            response = self.http_request(method="GET", path="/")
            if response:
                content = response.text
                headers = str(response.headers).lower()

                if self._detect_framework_from_text(content) or self._looks_like_spa_shell(content):
                    return True

                bundler_indicators = ['app.js', 'main.js', 'bundle.js', 'webpack', 'vite', 'parcel']
                if any(indicator in content.lower() or indicator in headers for indicator in bundler_indicators):
                    return True

                # Check for typical SPA structure (minimal HTML, lots of JS)
                if len(content) < 5000 and '<script' in content.lower():
                    return True

                # Even if not detected, continue scanning
                return True
            return False
        except Exception as e:
            return False

    def detect_spa_framework(self):
        """
        Detect SPA framework
        """
        try:
            response = self.http_request(method="GET", path="/")
            if not response:
                return None
            
            content = response.text or ""

            framework = self._detect_framework_from_text(content)
            if framework:
                return framework

            script_corpus = self._fetch_script_corpus(content)
            framework = self._detect_framework_from_text(script_corpus)
            if framework:
                return framework

            if self._looks_like_spa_shell(content, script_corpus):
                return "SPA (unknown framework)"

            return None
        except Exception as e:
            print_debug(f"Error detecting SPA framework: {str(e)}")
            return None

    def discover_api_endpoints(self):
        """
        Discover API endpoints
        """
        print_status("Discovering API endpoints...")
        discovered = []
        
        for endpoint in self.API_ENDPOINTS:
            try:
                response = self.http_request(
                    method="GET",
                    path=endpoint,
                    allow_redirects=False
                )
                
                if response and response.status_code not in [404, 403]:
                    discovered.append({
                        'endpoint': endpoint,
                        'status_code': response.status_code,
                        'method': 'GET',
                        'accessible': True
                    })
                    
                    # Try POST as well
                    post_response = self.http_request(
                        method="POST",
                        path=endpoint,
                        allow_redirects=False
                    )
                    
                    if post_response and post_response.status_code not in [404, 403, 405]:
                        discovered.append({
                            'endpoint': endpoint,
                            'status_code': post_response.status_code,
                            'method': 'POST',
                            'accessible': True
                        })
            except:
                pass
        
        return discovered

    def check_sensitive_files(self):
        """
        Check for exposed sensitive files
        """
        print_status("Checking for exposed sensitive files...")
        exposed = []
        
        for file_path in self.SENSITIVE_FILES:
            try:
                response = self.http_request(
                    method="GET",
                    path=file_path,
                    allow_redirects=False
                )
                
                if response and response.status_code == 200:
                    content_length = len(response.content)
                    content_type = response.headers.get('Content-Type', 'unknown')
                    
                    is_sensitive = False
                    indicators = []
                    
                    if '.env' in file_path:
                        is_sensitive = True
                        indicators.append('Environment file')
                    
                    if 'config' in file_path.lower() or 'settings' in file_path.lower():
                        is_sensitive = True
                        indicators.append('Configuration file')
                    
                    if 'package.json' in file_path:
                        is_sensitive = True
                        indicators.append('Package manifest')
                    
                    if '.git' in file_path:
                        is_sensitive = True
                        indicators.append('Git repository')
                    
                    if is_sensitive or content_length > 0:
                        exposed.append({
                            'path': file_path,
                            'status_code': response.status_code,
                            'content_length': content_length,
                            'content_type': content_type,
                            'indicators': indicators,
                            'is_sensitive': is_sensitive
                        })
            except:
                pass
        
        return exposed

    def check_authentication(self):
        """
        Check for authentication issues
        """
        print_status("Checking for authentication issues...")
        issues = []
        
        # Check if authentication endpoints are accessible
        auth_endpoints = ['/auth', '/auth/login', '/auth/register', '/login', '/register']
        
        for endpoint in auth_endpoints:
            try:
                response = self.http_request(
                    method="GET",
                    path=endpoint,
                    allow_redirects=False
                )
                
                if response and response.status_code == 200:
                    # Check if it's actually an auth page
                    if 'login' in response.text.lower() or 'password' in response.text.lower():
                        issues.append({
                            'type': 'Information Disclosure',
                            'issue': f'Authentication endpoint accessible: {endpoint}',
                            'severity': 'Low',
                            'details': 'Authentication page is accessible'
                        })
            except:
                pass
        
        return issues

    def check_cors_configuration(self):
        """
        Check CORS configuration
        """
        print_status("Checking CORS configuration...")
        issues = []
        
        try:
            # Try to make a request with Origin header
            headers = {
                'Origin': 'https://evil.com',
                'Access-Control-Request-Method': 'GET'
            }
            
            response = self.http_request(
                method="OPTIONS",
                path="/",
                headers=headers,
                allow_redirects=False
            )
            
            if response:
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acac = response.headers.get('Access-Control-Allow-Credentials', '')
                
                if acao == '*':
                    issues.append({
                        'type': 'CORS Misconfiguration',
                        'issue': 'CORS allows all origins (*)',
                        'severity': 'High',
                        'details': 'Access-Control-Allow-Origin is set to *'
                    })
                
                if acao == 'https://evil.com' and acac.lower() == 'true':
                    issues.append({
                        'type': 'CORS Misconfiguration',
                        'issue': 'CORS reflects Origin header with credentials',
                        'severity': 'High',
                        'details': 'Allows arbitrary origin with credentials'
                    })
        except:
            pass
        
        return issues

    def run(self):
        """
        Execute the SPA scan
        """
        self.discovered_endpoints = []
        self.exposed_files = []
        self.authentication_issues = []
        self.cors_issues = []
        
        print_status("Starting SPA scan...")
        print_info(f"Target: {self.target}")
        print_info("")
        
        # Detect SPA framework
        print_status("Detecting SPA framework...")
        framework = self.detect_spa_framework()
        if framework:
            print_success(f"SPA framework detected: {framework}")
        else:
            print_warning("Could not detect SPA framework")
            print_info("Continuing with generic SPA checks...")
        print_info("")
        
        # Discover API endpoints
        self.discovered_endpoints = self.discover_api_endpoints()
        print_info("")
        
        # Check sensitive files
        self.exposed_files = self.check_sensitive_files()
        print_info("")
        
        # Check authentication
        self.authentication_issues = self.check_authentication()
        print_info("")
        
        # Check CORS
        self.cors_issues = self.check_cors_configuration()
        print_info("")
        
        # Summary
        print_status("=" * 60)
        print_status("SPA Scan Summary")
        print_status("=" * 60)
        
        if framework:
            print_info(f"SPA Framework: {framework}")
        else:
            print_warning("SPA Framework: Not detected")
        
        print_info(f"API Endpoints Found: {len(self.discovered_endpoints)}")
        print_info(f"Exposed Files Found: {len(self.exposed_files)}")
        print_info(f"Authentication Issues: {len(self.authentication_issues)}")
        print_info(f"CORS Issues: {len(self.cors_issues)}")
        print_status("=" * 60)
        print_info("")
        
        # Display discovered endpoints
        if self.discovered_endpoints:
            print_success("Discovered API endpoints:")
            print_info("")
            table_data = []
            for endpoint_info in self.discovered_endpoints:
                table_data.append([
                    endpoint_info['endpoint'],
                    endpoint_info['method'],
                    endpoint_info['status_code']
                ])
            print_table(['Endpoint', 'Method', 'Status'], table_data)
            print_info("")
        
        # Display exposed files
        if self.exposed_files:
            print_warning(f"Found {len(self.exposed_files)} exposed sensitive files")
            table_data = []
            for file_info in self.exposed_files:
                sensitivity = "SENSITIVE" if file_info['is_sensitive'] else "Exposed"
                table_data.append([
                    file_info['path'],
                    file_info['status_code'],
                    f"{file_info['content_length']} bytes",
                    sensitivity
                ])
            print_table(['Path', 'Status', 'Size', 'Type'], table_data)
            print_info("")
        
        # Display authentication issues
        if self.authentication_issues:
            print_status("Authentication Issues:")
            print_info("")
            for issue in self.authentication_issues:
                print_info(f" - [{issue['severity']}] {issue['type']}: {issue['issue']}")
                print_info(f"   - Details: {issue['details']}")
            print_info("")
        
        # Display CORS issues
        if self.cors_issues:
            print_warning("CORS Issues:")
            print_info("")
            for issue in self.cors_issues:
                print_info(f" - [{issue['severity']}] {issue['type']}: {issue['issue']}")
                print_info(f"   - Details: {issue['details']}")
            print_info("")

        # DOM-XSS behavioral analysis (HTML + fetched same-origin scripts)
        dom_xss = {"suspected": False, "sources": [], "sinks": [], "evidence_score": 0}
        try:
            root = self.http_request(method="GET", path="/", allow_redirects=True)
            root_html = root.text if root else ""
            script_corpus = self._fetch_script_corpus(root_html)
            dom_xss = self.analyze_dom_xss(root_html, script_corpus)
            if dom_xss["suspected"]:
                print_warning(
                    f"Potential DOM-XSS behavior detected "
                    f"(sources={len(dom_xss['sources'])}, sinks={len(dom_xss['sinks'])}, score={dom_xss['evidence_score']})"
                )
            else:
                print_info("No strong DOM-XSS behavior pattern detected.")
        except Exception as e:
            print_debug(f"DOM-XSS behavioral analysis failed: {e}")

        severity = "Info"
        reason_parts = []
        if dom_xss["suspected"]:
            severity = "Medium"
            reason_parts.append("Potential DOM-XSS source/sink chain detected in SPA scripts")
        if self.exposed_files:
            severity = "Medium" if severity == "Info" else severity
            reason_parts.append(f"Exposed sensitive files: {len(self.exposed_files)}")
        if self.cors_issues:
            severity = "High" if any(i.get("severity") == "High" for i in self.cors_issues) else severity
            reason_parts.append(f"CORS issues: {len(self.cors_issues)}")
        if not reason_parts:
            reason_parts.append("SPA behavioral scan completed")

        self.vulnerability_info = {
            "reason": " | ".join(reason_parts),
            "severity": severity,
            "dom_xss_suspected": bool(dom_xss.get("suspected")),
            "dom_xss_sources": dom_xss.get("sources", [])[:6],
            "dom_xss_sinks": dom_xss.get("sinks", [])[:6],
            "dom_xss_score": int(dom_xss.get("evidence_score", 0) or 0),
            "discovered_api_endpoints": [row.get("endpoint") for row in self.discovered_endpoints[:12]],
            "auth_issue_count": len(self.authentication_issues),
            "cors_issue_count": len(self.cors_issues),
            "sensitive_file_count": len(self.exposed_files),
        }
        
        return True
