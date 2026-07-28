#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The BulletProof Security WordPress plugin is vulnerable to sensitive information disclosure due to a file path."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress BulletProof Security 5.1 Information Disclosure Detection',
        'description': 'The BulletProof Security WordPress plugin is vulnerable to sensitive information disclosure due to a file path disclosure in the publicly accessible ~/db_backup_log.txt file which grants attackers the full path of the site, in addition to the path of database backup files. This affects versions up to, and including, 5.1.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'exposure', 'packetstorm', 'wordpress', 'ait-pro', 'vuln'],
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
            'https://packetstormsecurity.com/files/164420/wpbulletproofsecurity51-disclose.txt',
            'https://www.wordfence.com/vulnerability-advisories/#CVE-2021-39327',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-39327',
            'http://packetstormsecurity.com/files/164420/WordPress-BulletProof-Security-5.1-Information-Disclosure.html',
            'https://plugins.trac.wordpress.org/changeset?sfp_email=&sfph_mail=&reponame=&old=2591118%40bulletproof-security&new=2591118%40bulletproof-security&sfp_email=&sfph_mail=',
        ],
        'cve': 'CVE-2021-39327',
    }

    def run(self):
        for path in ('/wp-content/bps-backup/logs/db_backup_log.txt', '/wp-content/plugins/bulletproof-security/admin/htaccess/db_backup_log.txt'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_all = ('BPS DB BACKUP LOG', '==================',)
            header_any = ('text/plain',)
            body_regexes = ('^BPS\\sDB\\sBACKUP\\sLOG\\r\\n==================\\r\\n==================\\r\\n\\r\\n$',)
            if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='medium',
                    reason="WordPress BulletProof Security 5.1 Information Disclosure detected",
                    path=path,
                )
                return True
        return False

