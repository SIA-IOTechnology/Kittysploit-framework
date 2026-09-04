#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache Solr CVE-2023-50386 detection (backup/restore ConfigSet RCE surface)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache Solr CVE-2023-50386 Backup/Restore RCE Detection',
        'description': (
            'Detects Apache Solr 6.0.0–8.11.2 / 9.0.0–9.4.0 in SolrCloud mode with '
            'reachable ConfigSets API (CVE-2023-50386 attack surface).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2023', 'solr', 'apache', 'backup', 'rce', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                    {'capability': 'admin_surface', 'from_detail': 'SolrCloud ConfigSets API'},
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [
                    'exploits/multi/http/apache_solr_cve_2023_50386_rce',
                    'exploits/multi/http/apache_solr_cve_2019_0193_rce',
                ],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2023-50386',
            'https://solr.apache.org/security.html#cve-2023-50386-apache-solr-backuprestore-apis-allow-for-deployment-of-executables-in-malicious-configsets',
        ],
        'cve': 'CVE-2023-50386',
    }

    port = OptPort(8983, 'Solr HTTP port', True)
    ssl = OptBool(False, 'Use HTTPS', True, advanced=True)
    base_path = OptString('/solr', 'Solr base path', False, advanced=True)

    @staticmethod
    def _version_tuple(version: str) -> tuple[int, ...] | None:
        try:
            return tuple(int(p) for p in version.split('.'))
        except ValueError:
            return None

    @classmethod
    def _version_vulnerable(cls, version: str) -> bool | None:
        parts = cls._version_tuple(version)
        if not parts or len(parts) < 2:
            return None
        if parts[0] in (6, 7):
            return True
        if parts[0] == 8 and (parts[1] < 11 or (parts[1] == 11 and (len(parts) < 3 or parts[2] <= 2))):
            return True
        if parts[0] == 9 and parts[1] == 0 and (len(parts) < 3 or parts[2] <= 4):
            return True
        return False

    def _solr_path(self, suffix: str) -> str:
        base = str(self.base_path or '/solr').strip()
        if not base.startswith('/'):
            base = f'/{base}'
        base = base.rstrip('/')
        if not suffix.startswith('/'):
            suffix = f'/{suffix}'
        return f'{base}{suffix}'

    def run(self):
        solr = self.http_request(method='GET', path=self._solr_path('/'), allow_redirects=False)
        zk = self.http_request(method='GET', path=self._solr_path('/admin/zookeeper'), allow_redirects=False)
        if not solr or int(solr.status_code or 0) != 200:
            return False
        if not zk or int(zk.status_code or 0) != 200:
            return False

        version = None
        match = re.search(r'href="img/favicon.ico\?_=(\d+\.\d+\.\d+)"', solr.text or '')
        if match:
            version = match.group(1)
        if not version:
            info = self.http_request(
                method='GET',
                path=self._solr_path('/admin/info/system'),
                allow_redirects=False,
            )
            if info and int(info.status_code or 0) == 200:
                data, _ = parse_json_response(info)
                if isinstance(data, dict):
                    version = (data.get('lucene') or {}).get('solr-spec-version')

        if version and self._version_vulnerable(str(version)) is False:
            return False

        configs = self.http_request(
            method='GET',
            path=self._solr_path('/admin/configs'),
            params={'action': 'LIST'},
            allow_redirects=False,
        )
        if not configs or int(configs.status_code or 0) not in (200, 401):
            return False

        self.set_info(
            severity='critical',
            reason=(
                'Apache Solr SolrCloud CVE-2023-50386 surface'
                + (f' (version {version})' if version else '')
            ),
            path=self._solr_path('/admin/configs'),
            evidence='zookeeper admin reachable',
        )
        return True
