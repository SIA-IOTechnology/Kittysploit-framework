#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Advanced Fingerprinting Engine - Détection avancée de versions, configurations et services
"""

import re
from typing import Dict, List, Optional, Tuple

from mitmproxy import http

class FingerprintEngine:
    """Moteur de fingerprinting avancé pour détecter versions, configurations, services"""
    
    # Patterns de versions pour différentes technologies
    VERSION_PATTERNS = {
        'Flask': [
            (r'werkzeug/([\d\.]+)', 'Werkzeug version'),
            (r'Flask/([\d\.]+)', 'Flask version'),
        ],
        'Django': [
            (r'Django/([\d\.]+)', 'Django version'),
            (r'django\.version\s*=\s*["\']([\d\.]+)["\']', 'Django version'),
        ],
        'WordPress': [
            (r'wp-content/themes/[\w-]+/style\.css\?ver=([\d\.]+)', 'WordPress theme version'),
            (r'WordPress ([\d\.]+)', 'WordPress version'),
            (r'generator" content="WordPress ([\d\.]+)"', 'WordPress version'),
        ],
        'PHP': [
            (r'PHP/([\d\.]+)', 'PHP version'),
            (r'X-Powered-By:\s*PHP/([\d\.]+)', 'PHP version'),
        ],
        'Apache': [
            (r'Server:\s*Apache/([\d\.]+)', 'Apache version'),
            (r'Apache/([\d\.]+)', 'Apache version'),
        ],
        'Nginx': [
            (r'Server:\s*nginx/([\d\.]+)', 'Nginx version'),
            (r'nginx/([\d\.]+)', 'Nginx version'),
        ],
        'React': [
            (r'react@([\d\.]+)', 'React version'),
            (r'react-dom@([\d\.]+)', 'React DOM version'),
        ],
        'jQuery': [
            (r'jquery-([\d\.]+)', 'jQuery version'),
            (r'jQuery v([\d\.]+)', 'jQuery version'),
        ],
    }
    
    # Patterns de configuration et services
    CONFIG_PATTERNS = {
        'debug_mode': [
            (r'DEBUG\s*=\s*True', 'Debug mode enabled'),
            (r'debug\s*:\s*true', 'Debug mode enabled'),
            (r'X-Debug', 'Debug headers present'),
        ],
        'cors': [
            (r'Access-Control-Allow-Origin', 'CORS enabled'),
            (r'Access-Control-Allow-Methods', 'CORS methods configured'),
        ],
        'csp': [
            (r'Content-Security-Policy', 'Content Security Policy present'),
        ],
        'hsts': [
            (r'Strict-Transport-Security', 'HSTS enabled'),
        ],
        'database': [
            (r'mysql', 'MySQL database'),
            (r'postgresql', 'PostgreSQL database'),
            (r'mongodb', 'MongoDB database'),
            (r'sqlite', 'SQLite database'),
        ],
        'cache': [
            (r'X-Cache', 'Caching enabled'),
            (r'Cache-Control', 'Cache control headers'),
        ],
        'cdn': [
            (r'cloudflare', 'Cloudflare CDN'),
            (r'amazonaws', 'AWS CDN'),
            (r'fastly', 'Fastly CDN'),
        ],
    }
    
    # Patterns de services et ports
    SERVICE_PATTERNS = {
        'redis': [
            (r'redis', 'Redis service'),
            (r':6379', 'Redis port'),
        ],
        'elasticsearch': [
            (r'elasticsearch', 'Elasticsearch service'),
            (r':9200', 'Elasticsearch port'),
        ],
        'mongodb': [
            (r'mongodb', 'MongoDB service'),
            (r':27017', 'MongoDB port'),
        ],
        'mysql': [
            (r'mysql', 'MySQL service'),
            (r':3306', 'MySQL port'),
        ],
    }
    
    def fingerprint(self, flow, detected_techs: Dict[str, List[str]]) -> Dict:
        """Effectue un fingerprinting avancé basé sur les technologies détectées"""
        # Load http module dynamically if needed (not used directly, but available if needed)
        fingerprint = {
            'versions': {},
            'configurations': [],
            'services': [],
            'security_features': [],
            'vulnerabilities': [],
        }
        
        if not flow.response:
            return fingerprint
        
        # Extraire le contenu de la réponse
        response_text = self._get_response_text(flow)
        response_headers = {k.lower(): v.lower() for k, v in flow.response.headers.items()}
        
        # Détecter les versions pour chaque technologie détectée
        for category, techs in detected_techs.items():
            for tech in techs:
                if tech in self.VERSION_PATTERNS:
                    versions = self._detect_version(tech, response_text, response_headers)
                    if versions:
                        fingerprint['versions'][tech] = versions
        
        # Détecter les configurations
        for config_type, patterns in self.CONFIG_PATTERNS.items():
            for pattern, description in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    fingerprint['configurations'].append({
                        'type': config_type,
                        'description': description,
                        'pattern': pattern
                    })
                    break
        
        # Détecter les services
        for service, patterns in self.SERVICE_PATTERNS.items():
            for pattern, description in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    fingerprint['services'].append({
                        'name': service,
                        'description': description
                    })
                    break
        
        # Détecter les fonctionnalités de sécurité
        security_features = self._detect_security_features(response_headers, response_text)
        fingerprint['security_features'] = security_features
        
        # Analyser les vulnérabilités potentielles
        vulnerabilities = self._analyze_vulnerabilities(detected_techs, fingerprint)
        fingerprint['vulnerabilities'] = vulnerabilities
        
        return fingerprint
    
    def _detect_version(self, tech: str, text: str, headers: Dict) -> List[Dict]:
        """Détecte la version d'une technologie"""
        versions = []
        
        if tech not in self.VERSION_PATTERNS:
            return versions
        
        for pattern, description in self.VERSION_PATTERNS[tech]:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                version = match.group(1) if match.groups() else match.group(0)
                versions.append({
                    'version': version,
                    'description': description,
                    'confidence': 'high' if 'X-Powered-By' in text or 'Server:' in text else 'medium'
                })
        
        return versions
    
    def _detect_security_features(self, headers: Dict, text: str) -> List[Dict]:
        """Détecte les fonctionnalités de sécurité"""
        features = []
        
        security_headers = {
            'strict-transport-security': 'HSTS (HTTP Strict Transport Security)',
            'content-security-policy': 'CSP (Content Security Policy)',
            'x-frame-options': 'X-Frame-Options (Clickjacking protection)',
            'x-content-type-options': 'X-Content-Type-Options (MIME sniffing protection)',
            'x-xss-protection': 'X-XSS-Protection',
            'referrer-policy': 'Referrer-Policy',
            'permissions-policy': 'Permissions-Policy',
        }
        
        for header, description in security_headers.items():
            if header in headers:
                features.append({
                    'header': header,
                    'description': description,
                    'value': headers[header]
                })
        
        return features
    
    def _analyze_vulnerabilities(self, detected_techs: Dict, fingerprint: Dict) -> List[Dict]:
        """Analyse les vulnérabilités potentielles basées sur les technologies et versions"""
        vulnerabilities = []
        
        # Vérifier les versions vulnérables connues
        vulnerable_versions = {
            'WordPress': {
                '<4.0': 'CVE-2014-0166, Multiple vulnerabilities',
                '<5.0': 'CVE-2018-12895, Multiple vulnerabilities',
            },
            'Django': {
                '<2.0': 'CVE-2017-12794, Multiple vulnerabilities',
                '<3.0': 'CVE-2019-19844, Multiple vulnerabilities',
            },
            'PHP': {
                '<7.0': 'End of life, Multiple vulnerabilities',
                '<7.4': 'Security updates ended',
            },
        }
        
        for tech, versions in fingerprint.get('versions', {}).items():
            if tech in vulnerable_versions:
                for version_info in versions:
                    version = version_info['version']
                    # Comparaison simple (peut être améliorée)
                    for vuln_range, description in vulnerable_versions[tech].items():
                        if self._version_in_range(version, vuln_range):
                            vulnerabilities.append({
                                'technology': tech,
                                'version': version,
                                'severity': 'high',
                                'description': description,
                                'type': 'outdated_version'
                            })
        
        # Vérifier les configurations dangereuses
        configs = fingerprint.get('configurations', [])
        for config in configs:
            if config['type'] == 'debug_mode':
                vulnerabilities.append({
                    'technology': 'Application',
                    'severity': 'medium',
                    'description': 'Debug mode enabled in production',
                    'type': 'misconfiguration'
                })
        
        return vulnerabilities
    
    def _version_in_range(self, version: str, range_str: str) -> bool:
        """Vérifie si une version est dans une plage (simplifié)"""
        try:
            if range_str.startswith('<'):
                target_version = range_str[1:]
                # Comparaison simplifiée
                version_parts = [int(x) for x in version.split('.') if x.isdigit()]
                target_parts = [int(x) for x in target_version.split('.') if x.isdigit()]
                return version_parts < target_parts
        except:
            pass
        return False
    
    def _get_response_text(self, flow) -> str:
        """Extrait le texte de la réponse"""
        if not flow.response:
            return ""
        from .flow_utils import safe_response_content
        res_content = safe_response_content(flow.response)
        text = f"HTTP/{flow.response.http_version} {flow.response.status_code}\n"
        text += "\n".join([f"{k}: {v}" for k, v in flow.response.headers.items()])
        if res_content:
            text += "\n" + res_content.decode('utf-8', errors='ignore')
        return text

# Instance globale
fingerprint_engine = FingerprintEngine()

