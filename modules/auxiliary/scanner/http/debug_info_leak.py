#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
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
        ]
    }

    # Options du module
    paths = OptString("", "Comma-separated list of additional paths to test (e.g., /debug,/test,/api)", required=False)
    depth = OptInteger(2, "Maximum depth for path traversal (default: 2)", required=False)
    timeout = OptInteger(10, "Request timeout in seconds", required=False)

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
            r'[A-Z]:\\[^\\s]+',
            r'/[\w/]+\.(py|php|java|js|rb|pl|asp|aspx|jsp)',
            r'\/var\/www\/[^\s]+',
            r'\/home\/[^\s]+',
            r'\/usr\/[^\s]+',
            r'C:\\[^\s]+',
            r'D:\\[^\s]+',
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
            r'def\s+\w+\([^)]*\):',
            r'function\s+\w+\([^)]*\)\s*\{',
            r'class\s+\w+\s+extends',
            r'import\s+[^\s]+',
            r'require[_\s]+\([^)]+\)',
            r'include[_\s]+\([^)]+\)',
        ],
        'environment_vars': [
            r'\$\{?[A-Z_][A-Z0-9_]*\}?',
            r'%[A-Z_][A-Z0-9_]*%',
            r'PATH\s*=\s*[^\r\n]+',
            r'HOME\s*=\s*[^\r\n]+',
            r'USER\s*=\s*[^\r\n]+',
            r'JAVA_HOME\s*=\s*[^\r\n]+',
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
        
        # Analyser le contenu avec les patterns
        for leak_type, patterns in self.DEBUG_PATTERNS.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    # Extraire le contexte autour du match
                    start = max(0, match.start() - 50)
                    end = min(len(content), match.end() + 50)
                    context = content[start:end].replace('\n', ' ').replace('\r', ' ')
                    
                    leaks.append({
                        'type': leak_type,
                        'pattern': pattern,
                        'match': match.group(0),
                        'context': context.strip(),
                        'path': path,
                        'severity': self._get_severity(leak_type)
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
                leaks.append({
                    'type': 'version_info',
                    'pattern': f'Header: {header}',
                    'match': f'{header}: {headers[header]}',
                    'context': f'HTTP Header disclosure',
                    'path': path,
                    'severity': 'medium'
                })
        
        # Vérifier les codes d'erreur qui peuvent révéler des informations
        if response.status_code == 500:
            if any(pattern in content.lower() for pattern in ['exception', 'error', 'traceback', 'stack']):
                leaks.append({
                    'type': 'error_messages',
                    'pattern': 'HTTP 500 Error',
                    'match': 'Internal Server Error with details',
                    'context': 'Error page may contain sensitive information',
                    'path': path,
                    'severity': 'high'
                })
        
        return {
            'path': path,
            'status_code': response.status_code,
            'leaks': leaks,
            'has_leaks': len(leaks) > 0
        }

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
        if self.paths.value:
            custom_paths = [p.strip() for p in self.paths.value.split(',') if p.strip()]
            paths_to_test.extend(custom_paths)
        
        # Tester le chemin racine
        print_status("Testing root path...")
        root_result = self.test_path("/")
        if root_result and root_result.get('has_leaks'):
            self.vulnerable_paths.append(root_result)
            self.all_leaks.extend(root_result['leaks'])
        
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
                    print_info(f"    Status Code: {result.get('status_code')}")
                    print_info(f"    Leaks Found: {len(leaks)}")
                    
                    # Grouper les fuites par type
                    leaks_by_type = {}
                    for leak in leaks:
                        leak_type = leak.get('type', 'unknown')
                        if leak_type not in leaks_by_type:
                            leaks_by_type[leak_type] = []
                        leaks_by_type[leak_type].append(leak)
                    
                    # Afficher les fuites par type
                    for leak_type, type_leaks in leaks_by_type.items():
                        severity = type_leaks[0].get('severity', 'medium')
                        severity_text = f"    [{severity.upper()}] {leak_type}: {len(type_leaks)} occurrence(s)"
                        
                        if severity in ['critical', 'high']:
                            print_info(color_red(severity_text))
                        elif severity == 'medium':
                            print_info(color_yellow(severity_text))
                        else:
                            print_info(color_blue(severity_text))
                        
                        # Afficher un exemple pour chaque type
                        if type_leaks:
                            example = type_leaks[0]
                            print_info(f"      Example: {example.get('match', '')[:80]}...")
                            print_info(f"      Context: {example.get('context', '')[:100]}...")
                    
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
            
            # Grouper par sévérité
            leaks_by_severity = {
                'critical': [],
                'high': [],
                'medium': [],
                'low': []
            }
            
            for leak in self.all_leaks:
                severity = leak.get('severity', 'medium')
                leaks_by_severity[severity].append(leak)
            
            # Afficher par ordre de sévérité
            for severity in ['critical', 'high', 'medium', 'low']:
                leaks = leaks_by_severity[severity]
                if leaks:
                    severity_text = f"\n[{severity.upper()}] {len(leaks)} leak(s):"
                    
                    if severity in ['critical', 'high']:
                        print_info(color_red(severity_text))
                    elif severity == 'medium':
                        print_info(color_yellow(severity_text))
                    else:
                        print_info(color_blue(severity_text))
                    
                    # Afficher les 5 premiers de chaque catégorie
                    for leak in leaks[:5]:
                        print_info(f"  - {leak.get('type', 'unknown')} at {leak.get('path', '/')}")
                        print_info(f"    Match: {leak.get('match', '')[:60]}...")
                    
                    if len(leaks) > 5:
                        print_info(f"  ... and {len(leaks) - 5} more")
            
            # Tableau récapitulatif
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
        
        return True

