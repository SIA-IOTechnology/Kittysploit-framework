#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module Suggester - Suggère des modules pertinents basés sur les technologies détectées
"""

from typing import Dict, List, Set
from collections import defaultdict

class ModuleSuggester:
    """Suggère des modules du framework basés sur les technologies détectées"""
    
    # Mapping technologies -> modules suggérés
    TECHNOLOGY_MODULE_MAPPING = {
        # Frameworks backend
        'Flask': [
            'auxiliary/scanner/http/lfi_fuzzer',
            'auxiliary/scanner/http/sql_injection',
            'exploits/http/flask_debug_rce',
        ],
        'Django': [
            'auxiliary/scanner/http/django_sqli',
            'exploits/http/django_debug_rce',
        ],
        'Express.js': [
            'auxiliary/scanner/http/nodejs_injection',
            'exploits/http/express_rce',
        ],
        'FastAPI': [
            'auxiliary/scanner/http/api_fuzzer',
            'exploits/http/fastapi_injection',
        ],
        
        # CMS
        'WordPress': [
            'auxiliary/scanner/http/wordpress_scanner',
            'exploits/http/wordpress_rce',
            'auxiliary/scanner/http/wp_plugin_scanner',
        ],
        'Drupal': [
            'auxiliary/scanner/http/drupal_scanner',
            'exploits/http/drupal_rce',
        ],
        'Joomla': [
            'auxiliary/scanner/http/joomla_scanner',
            'exploits/http/joomla_rce',
        ],
        
        # Langages
        'PHP': [
            'auxiliary/scanner/http/lfi_fuzzer',
            'auxiliary/scanner/http/php_injection',
            'exploits/http/php_rce',
        ],
        'Python': [
            'auxiliary/scanner/http/python_injection',
            'exploits/http/python_rce',
        ],
        'Java': [
            'auxiliary/scanner/http/java_deserialization',
            'exploits/http/java_rce',
        ],
        'Node.js': [
            'auxiliary/scanner/http/nodejs_injection',
            'exploits/http/nodejs_rce',
        ],
        
        # Serveurs
        'Apache': [
            'auxiliary/scanner/http/apache_vuln_scanner',
            'exploits/http/apache_rce',
        ],
        'Nginx': [
            'auxiliary/scanner/http/nginx_vuln_scanner',
        ],
        
        # Frontend
        'React': [
            'auxiliary/scanner/http/react_xss',
            'auxiliary/scanner/http/spa_scanner',
        ],
        'Angular': [
            'auxiliary/scanner/http/angular_xss',
            'auxiliary/scanner/http/spa_scanner',
        ],
    }
    
    # Mapping vulnérabilités -> modules
    VULNERABILITY_MODULE_MAPPING = {
        'lfi': ['auxiliary/scanner/http/lfi_fuzzer'],
        'sql_injection': ['auxiliary/scanner/http/sql_injection'],
        'xss': ['auxiliary/scanner/http/xss_scanner'],
        'rce': ['exploits/http/rce_scanner'],
        'ssrf': ['auxiliary/scanner/http/ssrf_scanner'],
        'xxe': ['auxiliary/scanner/http/xxe_scanner'],
    }
    
    # Mapping configurations -> modules
    CONFIG_MODULE_MAPPING = {
        'debug_mode': [
            'auxiliary/scanner/http/debug_info_leak',
            'exploits/http/debug_rce',
        ],
        'cors': [
            'auxiliary/scanner/http/cors_misconfig',
        ],
        'csp': [
            'auxiliary/scanner/http/csp_bypass',
        ],
    }
    
    def suggest_modules(self, detected_techs: Dict[str, List[str]], 
                       fingerprint: Dict = None,
                       vulnerabilities: List[Dict] = None) -> List[Dict]:
        """Suggère des modules basés sur les technologies détectées"""
        suggestions = []
        module_scores = defaultdict(int)
        module_reasons = defaultdict(list)
        
        # Analyser les technologies détectées
        for category, techs in detected_techs.items():
            for tech in techs:
                if tech in self.TECHNOLOGY_MODULE_MAPPING:
                    modules = self.TECHNOLOGY_MODULE_MAPPING[tech]
                    for module in modules:
                        module_scores[module] += 10  # Score de base pour technologie
                        module_reasons[module].append(f"Detected technology: {tech}")
        
        # Analyser le fingerprinting
        if fingerprint:
            # Versions détectées
            for tech, versions in fingerprint.get('versions', {}).items():
                if tech in self.TECHNOLOGY_MODULE_MAPPING:
                    modules = self.TECHNOLOGY_MODULE_MAPPING[tech]
                    for module in modules:
                        module_scores[module] += 5  # Bonus pour version détectée
                        module_reasons[module].append(f"Detected version for {tech}")
            
            # Configurations
            for config in fingerprint.get('configurations', []):
                config_type = config.get('type')
                if config_type in self.CONFIG_MODULE_MAPPING:
                    modules = self.CONFIG_MODULE_MAPPING[config_type]
                    for module in modules:
                        module_scores[module] += 8  # Score élevé pour configuration
                        module_reasons[module].append(f"Detected configuration: {config_type}")
        
        # Analyser les vulnérabilités
        if vulnerabilities:
            for vuln in vulnerabilities:
                vuln_type = vuln.get('type', '')
                if vuln_type in self.VULNERABILITY_MODULE_MAPPING:
                    modules = self.VULNERABILITY_MODULE_MAPPING[vuln_type]
                    for module in modules:
                        module_scores[module] += 15  # Very high score for vulnerability
                        module_reasons[module].append(f"Detected vulnerability: {vuln_type}")
        
        # Trier par score et créer les suggestions
        sorted_modules = sorted(module_scores.items(), key=lambda x: x[1], reverse=True)
        
        for module_path, score in sorted_modules[:10]:  # Top 10 suggestions
            suggestions.append({
                'module': module_path,
                'score': score,
                'reasons': module_reasons[module_path],
                'priority': 'high' if score >= 15 else 'medium' if score >= 10 else 'low'
            })
        
        return suggestions
    
    def get_suggestions_summary(self, suggestions: List[Dict]) -> Dict:
        """Retourne un résumé des suggestions"""
        if not suggestions:
            return {
                'total': 0,
                'high_priority': 0,
                'medium_priority': 0,
                'low_priority': 0,
            }
        
        summary = {
            'total': len(suggestions),
            'high_priority': len([s for s in suggestions if s['priority'] == 'high']),
            'medium_priority': len([s for s in suggestions if s['priority'] == 'medium']),
            'low_priority': len([s for s in suggestions if s['priority'] == 'low']),
        }
        
        return summary

# Instance globale
module_suggester = ModuleSuggester()

