#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.module_result import finalize_http_scanner_run, target_base_url
import re
import urllib.parse

class Module(Auxiliary, Http_client):

    __info__ = {
        'name': 'HTTP Debug Information Leak Scanner',
        'description': 'Scans for debug information leaks in HTTP responses including stack traces, error messages, version information, and sensitive data exposure',
        'author': 'KittySploit Team',
        'tags': ['web', 'scanner', 'debug', 'information-disclosure'],
        'references': [
            'https://owasp.org/www-community/vulnerabilities/Information_exposure_through_debug_information',
            'https://portswigger.net/web-security/information-disclosure'
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
        'chain':         {'produces_capabilities': [{'capability': 'endpoints', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    # Options du module
    paths = OptString("", "Comma-separated list of additional paths to test (e.g., /debug,/test,/api)", required=False)
    depth = OptInteger(2, "Maximum depth for path traversal (default: 2)", required=False)
    timeout = OptInteger(10, "Request timeout in seconds", required=False)
    strict_body_scan = OptBool(
        False,
        "Apply aggressive body patterns on HTML pages (may flag normal client-side JavaScript)",
        required=False,
    )
    output_max_length = OptInteger(
        0,
        "Truncate displayed leak lines longer than N characters (0 = show full value)",
        required=False,
    )

    # Known third-party / CMS client-side snippets — not server debug leaks.
    _BENIGN_JS_MARKERS = re.compile(
        r"gtag|googletagmanager|googleTranslate|revslider|jquery|wp-content|"
        r"analytics|fbq\(|dataLayer|elementor|woocommerce|cloudflare|recaptcha",
        re.IGNORECASE,
    )

    # Patterns de détection pour les fuites d'informations
    DEBUG_PATTERNS = {
        'stack_trace': [
            r'Stack\s+Trace',
            r'Traceback\s+\(most\s+recent\s+call\s+last\)',
            r'at\s+\w+\.\w+\([^)]+\)',
            r'Exception\s+in\s+thread',
            r'java\.lang\.',
            r'python\.exceptions\.',
            r'\.py",\s+line\s+\d+',
            r'File\s+"[^"]+",\s+line\s+\d+',
            r'Caused\s+by:',
            r'RuntimeException',
        ],
        'error_messages': [
            r'Fatal\s+error',
            r'Warning:',
            r'Notice:',
            r'Parse\s+error',
            r'Syntax\s+error',
            r'Internal\s+Server\s+Error',
            r'Error\s+\d+',
            r'Exception\s+occurred',
        ],
        'file_paths': [
            r'(?:/var/www|/home/[\w.-]+|/usr/(?:share|local)|/opt/)[^\s<>"\']{3,}',
            r'[A-Z]:\\(?:Users|Windows|inetpub|Program Files|xampp)[^\s<>"\']{3,}',
        ],
        'version_info': [
            r'PHP\s+\d+\.\d+\.\d+',
            r'Python\s+\d+\.\d+\.\d+',
            r'Apache/\d+\.\d+\.\d+',
            r'nginx/\d+\.\d+\.\d+',
            r'Server:\s+[^\r\n]+',
            r'X-Powered-By:\s+[^\r\n]+',
            r'Framework:\s+[^\r\n]+',
            r'Django/\d+\.\d+',
            r'Flask/\d+\.\d+',
            r'Express/\d+\.\d+',
            r'Laravel\s+\d+\.\d+',
            r'Rails\s+\d+\.\d+',
        ],
        'database_info': [
            r'mysql://[^\s]+',
            r'postgresql://[^\s]+',
            r'mongodb://[^\s]+',
            r'jdbc:[^\s]+',
            r'Database\s+connection\s+failed',
            r'SQLSTATE\[[^\]]+\]',
            r'Access\s+denied\s+for\s+user',
            r'Unknown\s+database',
        ],
        'api_keys': [
            r'api[_-]?key["\s:=]+([A-Za-z0-9_-]{20,})',
            r'apikey["\s:=]+([A-Za-z0-9_-]{20,})',
            r'secret[_-]?key["\s:=]+([A-Za-z0-9_-]{20,})',
            r'access[_-]?token["\s:=]+([A-Za-z0-9_-]{20,})',
            r'aws[_-]?access[_-]?key[_-]?id["\s:=]+([A-Z0-9]{20})',
            r'aws[_-]?secret[_-]?access[_-]?key["\s:=]+([A-Za-z0-9/+=]{40})',
        ],
        'source_code': [
            r'<\?php\s+[^\?]+',
            r'(?m)^\s*def\s+\w+\([^)]*\):',
            r'(?m)^\s*class\s+\w+\s+extends\s+',
            r'(?m)Traceback\s+\(most\s+recent\s+call\s+last\)',
            r'require(?:_once)?\s*\(\s*[\'"][^\'"]+[\'"]\s*\)',
            r'include(?:_once)?\s*\(\s*[\'"][^\'"]+[\'"]\s*\)',
        ],
        'environment_vars': [
            r'(?:^|[\s;])(?:PATH|HOME|USER|JAVA_HOME|DOCUMENT_ROOT)\s*=\s*[^\r\n<]{3,}',
            r'%[A-Z_][A-Z0-9_]*%',
        ],
        'debug_mode': [
            r'DEBUG\s*=\s*True',
            r'debug\s*=\s*true',
            r'debug\s*mode\s*enabled',
            r'development\s+mode',
            r'APP_DEBUG\s*=\s*true',
            r'APP_ENV\s*=\s*local',
        ],
        'config_files': [
            r'config\.php',
            r'\.env',
            r'web\.config',
            r'\.htaccess',
            r'wp-config\.php',
            r'settings\.py',
            r'application\.properties',
        ],
    }

    # Chemins communs à tester pour les fuites de debug
    COMMON_DEBUG_PATHS = [
        '/debug',
        '/test',
        '/api/debug',
        '/api/test',
        '/admin/debug',
        '/dev',
        '/development',
        '/error',
        '/errors',
        '/exception',
        '/trace',
        '/stacktrace',
        '/phpinfo.php',
        '/info.php',
        '/test.php',
        '/debug.php',
        '/.env',
        '/config.php',
        '/web.config',
        '/.git/config',
        '/.svn/entries',
        '/.DS_Store',
        '/Thumbs.db',
        '/robots.txt',
        '/sitemap.xml',
        '/.well-known/security.txt',
    ]

    def check(self):
        """
        Vérifie si la cible est accessible
        """
        try:
            response = self.http_request(method="GET", path="/")
            if response and response.status_code in [200, 301, 302, 403, 404, 500]:
                return True
            return False
        except Exception as e:
            print_error(f"Error checking target: {str(e)}")
            return False

    def analyze_response(self, response, path="/"):
        """
        Analyse une réponse HTTP pour détecter des fuites d'informations
        
        Args:
            response: Objet requests.Response
            path: Chemin testé
            
        Returns:
            dict: Résultats de l'analyse avec les fuites détectées
        """
        if not response:
            return None

        leaks = []
        content = response.text if hasattr(response, 'text') else str(response.content)
        headers = response.headers if hasattr(response, 'headers') else {}

        # Avoid false positives when tested paths are transparently redirected to a login wall.
        # Typical case: /phpinfo.php -> /login.php (200) with generic Server header disclosure.
        if self._is_login_wall_response(response, path, content):
            return {
                'path': path,
                'status_code': response.status_code,
                'leaks': [],
                'has_leaks': False
            }
        
        # Analyser le contenu avec les patterns
        seen_matches = set()
        is_html = self._is_html_page(content, headers)
        conservative_body = (
            is_html
            and not self._opt_bool(self.strict_body_scan)
            and self._is_benign_surface_path(path)
        )

        for leak_type, patterns in self.DEBUG_PATTERNS.items():
            if conservative_body and leak_type in self._HTML_CONSERVATIVE_SKIP:
                continue
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    match_text = match.group(0)
                    dedupe_key = (leak_type, match_text[:160], path)
                    if dedupe_key in seen_matches:
                        continue
                    if not self._is_actionable_leak(
                        leak_type,
                        match_text,
                        content,
                        path,
                        response,
                        is_html=is_html,
                        match_offset=match.start(),
                    ):
                        continue
                    seen_matches.add(dedupe_key)

                    start = max(0, match.start() - 50)
                    end = min(len(content), match.end() + 50)
                    context = content[start:end].replace('\n', ' ').replace('\r', ' ')
                    
                    leaks.append({
                        'type': leak_type,
                        'pattern': pattern,
                        'match': match_text,
                        'context': context.strip(),
                        'path': path,
                        'status_code': response.status_code,
                        'severity': self._get_severity(leak_type),
                        'source': 'response_body',
                    })
        
        # Analyser les en-têtes HTTP
        sensitive_headers = [
            'X-Powered-By',
            'Server',
            'X-AspNet-Version',
            'X-AspNetMvc-Version',
            'X-Debug-Cached',
            'X-Runtime',
            'X-Version',
        ]
        
        for header in sensitive_headers:
            if header in headers:
                header_value = headers[header]
                leaks.append({
                    'type': 'version_info',
                    'header': header,
                    'header_value': header_value,
                    'match': f'{header}: {header_value}',
                    'path': path,
                    'status_code': response.status_code,
                    'severity': self._get_severity('version_info'),
                    'source': 'response_header',
                })
        
        # Vérifier les codes d'erreur qui peuvent révéler des informations
        if response.status_code == 500:
            if any(pattern in content.lower() for pattern in ['exception', 'error', 'traceback', 'stack']):
                leaks.append({
                    'type': 'error_messages',
                    'pattern': 'HTTP 500 Error',
                    'match': 'Internal Server Error with details',
                    'path': path,
                    'status_code': response.status_code,
                    'severity': 'high',
                    'source': 'http_status',
                })
        
        return {
            'path': path,
            'status_code': response.status_code,
            'leaks': leaks,
            'has_leaks': len(leaks) > 0
        }

    def _normalize_path(self, value):
        raw = (value or "").strip()
        if not raw:
            return "/"
        parsed = urllib.parse.urlparse(raw)
        normalized = parsed.path or raw
        if not normalized.startswith("/"):
            normalized = f"/{normalized}"
        return normalized

    def _is_login_like_path(self, value):
        low = self._normalize_path(value).lower()
        return any(token in low for token in (
            "/login",
            "signin",
            "/auth",
            "/session",
            "/account/login",
            "/wp-login.php",
        ))

    def _looks_like_login_page(self, content):
        text = (content or "").lower()
        return (
            ('type="password"' in text or "type='password'" in text)
            and any(token in text for token in (
                "login",
                "sign in",
                "connexion",
                "username",
                "user",
                "email",
                "mot de passe",
                "password",
            ))
        )

    def _is_login_wall_response(self, response, tested_path, content):
        # If we are explicitly testing a login path, keep analysis enabled.
        if self._is_login_like_path(tested_path):
            return False

        final_path = self._normalize_path(getattr(response, "url", "") or "")
        if self._is_login_like_path(final_path):
            return True

        # Defensive fallback: some clients keep final URL unchanged but return login body.
        if self._looks_like_login_page(content):
            return True

        return False

    # On public HTML pages, skip categories that routinely match bundled client JS/CSS.
    _HTML_CONSERVATIVE_SKIP = frozenset({
        "source_code",
        "file_paths",
        "environment_vars",
    })

    def _is_benign_surface_path(self, path):
        """Paths that are usually public HTML surfaces, not debug endpoints."""
        normalized = self._normalize_path(path)
        return normalized in (
            "/",
            "/robots.txt",
            "/sitemap.xml",
            "/.well-known/security.txt",
        )

    def _opt_bool(self, value):
        if hasattr(value, "value"):
            value = value.value
        if isinstance(value, str):
            return value.strip().lower() in ("1", "true", "yes", "on")
        return bool(value)

    def _opt_int(self, value, default=0):
        if hasattr(value, "value"):
            value = value.value
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def _format_output_text(self, text):
        """Format leak text for CLI output without hiding short values."""
        cleaned = (text or "").replace("\n", " ").replace("\r", " ").strip()
        max_len = max(0, self._opt_int(self.output_max_length, 0))
        if max_len <= 0 or len(cleaned) <= max_len:
            return cleaned
        return f"{cleaned[:max_len]}… (+{len(cleaned) - max_len} chars)"

    def _leak_display_fields(self, leak):
        """Return ordered (label, value) pairs with concrete evidence only."""
        fields = []
        header = leak.get("header")
        header_value = leak.get("header_value")
        if header:
            fields.append(("Header", str(header)))
            if header_value is not None:
                fields.append(("Value", str(header_value)))
        else:
            match = leak.get("match", "")
            if match:
                fields.append(("Evidence", match))

        surrounding = (leak.get("context") or "").strip()
        match_text = (leak.get("match") or "").strip()
        if surrounding and surrounding != match_text:
            fields.append(("Surrounding", surrounding))

        status_code = leak.get("status_code")
        if status_code is not None:
            fields.append(("HTTP status", str(status_code)))

        source = leak.get("source")
        if source:
            fields.append(("Source", str(source)))

        return fields

    def _print_leak_block(self, leak, indent="    "):
        leak_type = leak.get("type", "unknown")
        severity = str(leak.get("severity", "medium")).upper()
        path = leak.get("path", "/")
        title = f"{indent}[{severity}] {leak_type} @ {path}"
        severity_low = str(leak.get("severity", "medium")).lower()
        if severity_low in ("critical", "high"):
            print_info(color_red(title))
        elif severity_low == "medium":
            print_info(color_yellow(title))
        else:
            print_info(color_blue(title))
        for label, value in self._leak_display_fields(leak):
            if value:
                print_info(f"{indent}  {label}: {self._format_output_text(value)}")

    def _is_html_page(self, content, headers):
        content_type = str((headers or {}).get("Content-Type") or "").lower()
        if "text/html" in content_type:
            return True
        sample = (content or "")[:8192].lower()
        return "<html" in sample or "<!doctype html" in sample

    def _offset_inside_script_block(self, content, offset):
        lower = (content or "").lower()
        script_open = lower.rfind("<script", 0, offset)
        if script_open < 0:
            return False
        tag_end = lower.find(">", script_open)
        if tag_end < 0 or tag_end > offset:
            return False
        script_close = lower.find("</script>", offset)
        return script_close >= 0

    def _is_json_escaped_url_fragment(self, match_text):
        text = match_text or ""
        if "\\/" in text or ":\\/" in text:
            return True
        if re.fullmatch(r"[a-z]:\\/?", text, flags=re.IGNORECASE):
            return True
        return False

    def _is_actionable_leak(self, leak_type, match_text, content, path, response, *, is_html, match_offset=0):
        text = match_text or ""

        if self._is_json_escaped_url_fragment(text):
            return False

        if leak_type == "source_code":
            if re.match(r"function\s+\w+\s*\(", text, re.IGNORECASE):
                return False
            if self._BENIGN_JS_MARKERS.search(text):
                return False
            if is_html and self._offset_inside_script_block(content, match_offset):
                return False

        if leak_type == "file_paths":
            if self._is_json_escaped_url_fragment(text):
                return False
            if is_html and path in ("", "/"):
                if not re.search(
                    r"(?:/var/|/home/|/usr/|/opt/|"
                    r"[A-Z]:\\(?:Users|Windows|inetpub|Program Files|xampp))",
                    text,
                    re.IGNORECASE,
                ):
                    return False

        if leak_type == "environment_vars":
            if "=" not in text and not text.startswith("%"):
                return False
            if text.startswith("${") or text.startswith("$"):
                return False

        if leak_type == "version_info" and is_html:
            if self._offset_inside_script_block(content, match_offset):
                return False

        if leak_type == "error_messages" and is_html and response.status_code == 200:
            if path in ("", "/") and not any(
                token in text.lower()
                for token in ("fatal error", "parse error", "syntax error", "stack trace", "traceback")
            ):
                return False

        return True

    def _get_severity(self, leak_type):
        """
        Détermine la sévérité d'un type de fuite
        
        Args:
            leak_type: Type de fuite détectée
            
        Returns:
            str: Niveau de sévérité (low, medium, high, critical)
        """
        severity_map = {
            'stack_trace': 'high',
            'file_paths': 'medium',
            'database_info': 'critical',
            'api_keys': 'critical',
            'source_code': 'high',
            'environment_vars': 'high',
            'debug_mode': 'medium',
            'config_files': 'high',
            'version_info': 'low',
            'error_messages': 'medium',
        }
        return severity_map.get(leak_type, 'medium')

    def test_path(self, path):
        """
        Teste un chemin spécifique pour des fuites d'informations
        
        Args:
            path: Chemin à tester
            
        Returns:
            dict: Résultats de l'analyse
        """
        try:
            response = self.http_request(method="GET", path=path)
            return self.analyze_response(response, path)
        except Exception as e:
            print_debug(f"Error testing path {path}: {str(e)}")
            return None

    def run(self):
        """
        Exécute le scan de fuites d'informations de debug
        """
        self.all_leaks = []
        self.vulnerable_paths = []
        
        print_status("Starting HTTP Debug Information Leak Scan...")
        print_info(f"Target: {self.target}")
        print_info("")
        
        # Construire la liste des chemins à tester
        paths_to_test = list(self.COMMON_DEBUG_PATHS)
        
        # Ajouter les chemins personnalisés
        if self.paths:
            custom_paths = [p.strip() for p in self.paths.split(',') if p.strip()]
            paths_to_test.extend(custom_paths)
        
        # Tester le chemin racine
        print_status("Testing root path...")
        root_result = self.test_path("/")
        if root_result and root_result.get('has_leaks'):
            self.vulnerable_paths.append(root_result)
            self.all_leaks.extend(root_result['leaks'])
            print_success("\n[!] INFORMATION LEAK DETECTED: /")
            print_info(f"    HTTP status: {root_result.get('status_code')}")
            print_info(f"    Leaks: {len(root_result.get('leaks', []))}")
            for leak in root_result.get('leaks', []):
                self._print_leak_block(leak)
            print_info("")
        
        # Tester les chemins communs
        print_status(f"Testing {len(paths_to_test)} common debug paths...")
        print_info("")
        
        tested = 0
        vulnerable_count = 0
        
        for path in paths_to_test:
            tested += 1
            print_info(f"[{tested}/{len(paths_to_test)}] Testing: {path}")
            
            result = self.test_path(path)
            
            if result:
                if result.get('has_leaks'):
                    vulnerable_count += 1
                    leaks = result.get('leaks', [])
                    
                    print_success(f"\n[!] INFORMATION LEAK DETECTED: {path}")
                    print_info(f"    HTTP status: {result.get('status_code')}")
                    print_info(f"    Leaks: {len(leaks)}")
                    for leak in leaks:
                        self._print_leak_block(leak)
                    print_info("")
                    
                    self.vulnerable_paths.append(result)
                    self.all_leaks.extend(leaks)
        
        # Résumé
        print_info("")
        print_status("=" * 60)
        print_status("Debug Information Leak Scan Summary")
        print_status("=" * 60)
        print_info(f"Total paths tested: {tested + 1}")  # +1 pour le chemin racine
        print_info(f"Vulnerable paths found: {vulnerable_count + (1 if root_result and root_result.get('has_leaks') else 0)}")
        print_info(f"Total information leaks detected: {len(self.all_leaks)}")
        print_status("=" * 60)
        
        if self.all_leaks:
            print_success("\nInformation Leaks Detected:")
            print_info("")

            table_data = []
            for leak in self.all_leaks:
                evidence = leak.get("header_value") or leak.get("match") or ""
                if leak.get("header"):
                    evidence = f"{leak['header']}: {leak.get('header_value', '')}"
                table_data.append([
                    str(leak.get("path", "/")),
                    str(leak.get("type", "unknown")),
                    str(leak.get("severity", "medium")).upper(),
                    self._format_output_text(evidence),
                    str(leak.get("status_code", "")),
                ])
                self._print_leak_block(leak, indent="  ")

            print_info("")
            print_status("Findings table:")
            if table_data:
                print_table(
                    ["Path", "Type", "Severity", "Evidence", "HTTP status"],
                    table_data,
                )

            print_info("")
            print_status("Summary by Leak Type:")
            
            leak_type_counts = {}
            for leak in self.all_leaks:
                leak_type = leak.get('type', 'unknown')
                leak_type_counts[leak_type] = leak_type_counts.get(leak_type, 0) + 1
            
            table_data = []
            for leak_type, count in sorted(leak_type_counts.items(), key=lambda x: x[1], reverse=True):
                severity = self._get_severity(leak_type)
                table_data.append([
                    leak_type,
                    str(count),
                    severity.upper()
                ])
            
            if table_data:
                print_table(['Leak Type', 'Count', 'Severity'], table_data)

        return finalize_http_scanner_run(
            self,
            self.all_leaks,
            title="Debug Information Leak",
            severity="high",
            category="information-disclosure",
            findings_key="debug_leaks",
            dedupe_keys=("path", "type"),
            hit_mapper=lambda leak: {
                "path": leak.get("path"),
                "method": "GET",
                "request_url": target_base_url(self, path=str(leak.get("path") or "/")),
                "status_code": leak.get("status_code"),
                "type": leak.get("type"),
                "header": leak.get("header"),
                "header_value": leak.get("header_value"),
                "evidence_snippet": leak.get("header_value") or leak.get("match"),
                "severity": leak.get("severity"),
                "source": leak.get("source"),
            },
        )

